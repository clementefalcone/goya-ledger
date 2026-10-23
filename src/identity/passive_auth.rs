use x509_parser::der_parser::asn1_rs::{Any, Class, FromDer, Tag};
use x509_parser::prelude::{parse_x509_certificate, X509Certificate};

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::signature::verify::verify_rsa;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PassiveAuthError {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("document signer is not issued by a trusted CSCA")]
    UntrustedSigner,
    #[error("SOD signature does not verify")]
    BadSodSignature,
    #[error("data group {0} is not listed in the SOD")]
    MissingGroup(u32),
    #[error("data group {0} does not match its SOD hash")]
    DigestMismatch(u32),
}

pub struct DataGroup<'a> {
    pub number: u32,
    pub bytes: &'a [u8],
}

pub const CHILE_CSCA: &[&[u8]] = &[
    include_bytes!("csca/cl_4c2daca0fb8d73e1.der"),
    include_bytes!("csca/cl_89f6143b835c2a41.der"),
    include_bytes!("csca/cl_f88b2c0769cf975a.der"),
    include_bytes!("csca/cl_bd10b0cf3addd12c.der"),
    include_bytes!("csca/cl_7585ae3201e93ce4.der"),
    include_bytes!("csca/cl_69a22617cc39b11d.der"),
    include_bytes!("csca/cl_8e82732a4449b7fc.der"),
    include_bytes!("csca/cl_26539f4a222aec83.der"),
    include_bytes!("csca/cl_b5dd74579cd7db82.der"),
];

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_LDS_SECURITY_OBJECT: &str = "2.23.136.1.1.1";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SOD_TAG: u32 = 23;

struct SignedSod<'a> {
    security_object: &'a [u8],
    signer_certificate: &'a [u8],
    signer_info: Vec<Any<'a>>,
}

pub fn verify_data_groups(
    sod: &[u8],
    groups: &[DataGroup],
    trust_anchors: &[&[u8]],
) -> Result<(), PassiveAuthError> {
    let signed = parse_signed_sod(sod)?;
    let (_, signer) = parse_x509_certificate(signed.signer_certificate)
        .map_err(|_| PassiveAuthError::Malformed("document signer certificate"))?;
    if !trust_anchors
        .iter()
        .any(|anchor| is_issued_by(&signer, anchor))
    {
        return Err(PassiveAuthError::UntrustedSigner);
    }
    verify_signer_info(&signed, &signer)?;
    verify_hashes(signed.security_object, groups)
}

fn next<'a>(input: &'a [u8], what: &'static str) -> Result<(Any<'a>, &'a [u8]), PassiveAuthError> {
    let (rest, any) = Any::from_der(input).map_err(|_| PassiveAuthError::Malformed(what))?;
    Ok((any, rest))
}

fn children<'a>(any: &Any<'a>, what: &'static str) -> Result<Vec<Any<'a>>, PassiveAuthError> {
    let mut items = Vec::new();
    let mut input = any.data;
    while !input.is_empty() {
        let (item, rest) = next(input, what)?;
        items.push(item);
        input = rest;
    }
    Ok(items)
}

fn oid_of(any: &Any, what: &'static str) -> Result<String, PassiveAuthError> {
    any.clone()
        .oid()
        .map(|oid| oid.to_id_string())
        .map_err(|_| PassiveAuthError::Malformed(what))
}

fn algorithm_oid(any: &Any, what: &'static str) -> Result<String, PassiveAuthError> {
    let parts = children(any, what)?;
    oid_of(
        parts.first().ok_or(PassiveAuthError::Malformed(what))?,
        what,
    )
}

fn require_oid(actual: String, expected: &str) -> Result<(), PassiveAuthError> {
    if actual == expected {
        return Ok(());
    }
    Err(PassiveAuthError::UnsupportedAlgorithm(actual))
}

fn is_context(any: &Any, tag: u32) -> bool {
    any.class() == Class::ContextSpecific && any.tag() == Tag(tag)
}

fn parse_signed_sod(sod: &[u8]) -> Result<SignedSod<'_>, PassiveAuthError> {
    let (wrapper, _) = next(sod, "SOD wrapper")?;
    if wrapper.class() != Class::Application || wrapper.tag() != Tag(SOD_TAG) {
        return Err(PassiveAuthError::Malformed("SOD wrapper"));
    }
    let (content_info, _) = next(wrapper.data, "content info")?;
    let content_parts = children(&content_info, "content info")?;
    let [content_type, explicit_content] = content_parts.as_slice() else {
        return Err(PassiveAuthError::Malformed("content info"));
    };
    if oid_of(content_type, "content type")? != OID_SIGNED_DATA {
        return Err(PassiveAuthError::Malformed("content type"));
    }
    let (signed_data, _) = next(explicit_content.data, "signed data")?;
    let parts = children(&signed_data, "signed data")?;
    let security_object = parse_encapsulated_content(parts.get(2))?;
    let certificates = parts
        .iter()
        .find(|part| is_context(part, 0))
        .ok_or(PassiveAuthError::Malformed("document signer certificate"))?;
    let signer_infos = parts
        .last()
        .ok_or(PassiveAuthError::Malformed("signer infos"))?;
    let signer_info = children(signer_infos, "signer infos")?
        .into_iter()
        .next()
        .ok_or(PassiveAuthError::Malformed("signer infos"))?;
    Ok(SignedSod {
        security_object,
        signer_certificate: certificates.data,
        signer_info: children(&signer_info, "signer info")?,
    })
}

fn parse_encapsulated_content<'a>(
    encapsulated: Option<&Any<'a>>,
) -> Result<&'a [u8], PassiveAuthError> {
    let encapsulated = encapsulated.ok_or(PassiveAuthError::Malformed("encapsulated content"))?;
    let parts = children(encapsulated, "encapsulated content")?;
    let [content_type, explicit_content] = parts.as_slice() else {
        return Err(PassiveAuthError::Malformed("encapsulated content"));
    };
    if oid_of(content_type, "encapsulated content type")? != OID_LDS_SECURITY_OBJECT {
        return Err(PassiveAuthError::Malformed("encapsulated content type"));
    }
    let (octets, _) = next(explicit_content.data, "security object")?;
    Ok(octets.data)
}

fn is_issued_by(signer: &X509Certificate, anchor_der: &[u8]) -> bool {
    let Ok((_, anchor)) = parse_x509_certificate(anchor_der) else {
        return false;
    };
    anchor.subject().as_raw() == signer.issuer().as_raw()
        && signer.signature_algorithm.algorithm.to_id_string() == OID_SHA256_WITH_RSA
        && verify_rsa(
            &hex::encode(anchor.public_key().subject_public_key.data.as_ref()),
            signer.tbs_certificate.as_ref(),
            &hex::encode(signer.signature_value.data.as_ref()),
        )
}

fn verify_signer_info(
    signed: &SignedSod,
    signer: &X509Certificate,
) -> Result<(), PassiveAuthError> {
    let parts = &signed.signer_info;
    let attributes_index = parts
        .iter()
        .position(|part| is_context(part, 0))
        .ok_or(PassiveAuthError::Malformed("signed attributes"))?;
    let digest_algorithm = parts
        .get(attributes_index - 1)
        .ok_or(PassiveAuthError::Malformed("digest algorithm"))?;
    require_oid(
        algorithm_oid(digest_algorithm, "digest algorithm")?,
        OID_SHA256,
    )?;
    let signature_algorithm = parts
        .get(attributes_index + 1)
        .ok_or(PassiveAuthError::Malformed("signature algorithm"))?;
    let signature_oid = algorithm_oid(signature_algorithm, "signature algorithm")?;
    if signature_oid != OID_RSA_ENCRYPTION && signature_oid != OID_SHA256_WITH_RSA {
        return Err(PassiveAuthError::UnsupportedAlgorithm(signature_oid));
    }
    let signature = parts
        .get(attributes_index + 2)
        .ok_or(PassiveAuthError::Malformed("signature"))?;
    let attributes = &parts[attributes_index];
    if message_digest(attributes)? != sha256(signed.security_object) {
        return Err(PassiveAuthError::BadSodSignature);
    }
    let is_valid = verify_rsa(
        &hex::encode(signer.public_key().subject_public_key.data.as_ref()),
        &signed_attributes_der(attributes),
        &hex::encode(signature.data),
    );
    if !is_valid {
        return Err(PassiveAuthError::BadSodSignature);
    }
    Ok(())
}

fn signed_attributes_der(attributes: &Any) -> Vec<u8> {
    let set_tag = 0x31;
    std::iter::once(set_tag)
        .chain(encode_length(attributes.data.len()))
        .chain(attributes.data.iter().copied())
        .collect()
}

fn encode_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let bytes: Vec<u8> = length
        .to_be_bytes()
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect();
    std::iter::once(0x80 | bytes.len() as u8)
        .chain(bytes)
        .collect()
}

fn message_digest(attributes: &Any) -> Result<Vec<u8>, PassiveAuthError> {
    for attribute in children(attributes, "signed attributes")? {
        let parts = children(&attribute, "signed attribute")?;
        let [attribute_type, values] = parts.as_slice() else {
            return Err(PassiveAuthError::Malformed("signed attribute"));
        };
        if oid_of(attribute_type, "signed attribute type")? == OID_MESSAGE_DIGEST {
            let (digest, _) = next(values.data, "message digest")?;
            return Ok(digest.data.to_vec());
        }
    }
    Err(PassiveAuthError::Malformed("message digest"))
}

fn verify_hashes(security_object: &[u8], groups: &[DataGroup]) -> Result<(), PassiveAuthError> {
    let (object, _) = next(security_object, "security object")?;
    let parts = children(&object, "security object")?;
    let (Some(algorithm), Some(hash_list)) = (parts.get(1), parts.get(2)) else {
        return Err(PassiveAuthError::Malformed("security object"));
    };
    require_oid(algorithm_oid(algorithm, "hash algorithm")?, OID_SHA256)?;
    let hashes = children(hash_list, "data group hashes")?
        .iter()
        .map(parse_group_hash)
        .collect::<Result<Vec<_>, _>>()?;
    groups.iter().try_for_each(|group| {
        let (_, expected) = hashes
            .iter()
            .find(|(number, _)| *number == group.number)
            .ok_or(PassiveAuthError::MissingGroup(group.number))?;
        if *expected != sha256(group.bytes) {
            return Err(PassiveAuthError::DigestMismatch(group.number));
        }
        Ok(())
    })
}

fn parse_group_hash(entry: &Any) -> Result<(u32, Vec<u8>), PassiveAuthError> {
    let parts = children(entry, "data group hash")?;
    let [number, hash] = parts.as_slice() else {
        return Err(PassiveAuthError::Malformed("data group hash"));
    };
    let number = number
        .clone()
        .u32()
        .map_err(|_| PassiveAuthError::Malformed("data group number"))?;
    Ok((number, hash.data.to_vec()))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    hash_with(HashAlgorithm::Sha256, bytes).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOD: &[u8] = include_bytes!("../../tests/fixtures/emrtd/sod.bin");
    const SOD_SELF_SIGNED_DS: &[u8] =
        include_bytes!("../../tests/fixtures/emrtd/sod_self_signed_ds.bin");
    const DG1: &[u8] = include_bytes!("../../tests/fixtures/emrtd/dg1.bin");
    const DG1_TAMPERED: &[u8] = include_bytes!("../../tests/fixtures/emrtd/dg1_tampered.bin");
    const CSCA: &[u8] = include_bytes!("../../tests/fixtures/emrtd/csca.der");
    const ROGUE_CSCA: &[u8] = include_bytes!("../../tests/fixtures/emrtd/rogue_csca.der");

    fn dg1(bytes: &[u8]) -> [DataGroup<'_>; 1] {
        [DataGroup { number: 1, bytes }]
    }

    fn flip_byte(bytes: &[u8], index: usize) -> Vec<u8> {
        let mut copy = bytes.to_vec();
        copy[index] ^= 0x01;
        copy
    }

    #[test]
    fn genuine_document_verifies() {
        assert_eq!(verify_data_groups(SOD, &dg1(DG1), &[CSCA]), Ok(()));
    }

    #[test]
    fn tampered_data_group_is_rejected() {
        assert_eq!(
            verify_data_groups(SOD, &dg1(DG1_TAMPERED), &[CSCA]),
            Err(PassiveAuthError::DigestMismatch(1))
        );
    }

    #[test]
    fn signer_outside_trust_list_is_rejected() {
        assert_eq!(
            verify_data_groups(SOD_SELF_SIGNED_DS, &dg1(DG1), &[CSCA]),
            Err(PassiveAuthError::UntrustedSigner)
        );
    }

    #[test]
    fn rogue_csca_with_same_name_is_rejected() {
        assert_eq!(
            verify_data_groups(SOD, &dg1(DG1), &[ROGUE_CSCA]),
            Err(PassiveAuthError::UntrustedSigner)
        );
    }

    #[test]
    fn tampered_hash_list_is_rejected() {
        let dg1_hash_byte_in_sod = 97;
        let tampered = flip_byte(SOD, dg1_hash_byte_in_sod);
        assert_eq!(
            verify_data_groups(&tampered, &dg1(DG1), &[CSCA]),
            Err(PassiveAuthError::BadSodSignature)
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let tampered = flip_byte(SOD, SOD.len() - 1);
        assert_eq!(
            verify_data_groups(&tampered, &dg1(DG1), &[CSCA]),
            Err(PassiveAuthError::BadSodSignature)
        );
    }

    #[test]
    fn data_group_absent_from_sod_is_rejected() {
        let dg15 = [DataGroup {
            number: 15,
            bytes: DG1,
        }];
        assert_eq!(
            verify_data_groups(SOD, &dg15, &[CSCA]),
            Err(PassiveAuthError::MissingGroup(15))
        );
    }

    #[test]
    fn garbage_is_malformed() {
        assert!(matches!(
            verify_data_groups(b"\x77\x02\x30\x00", &dg1(DG1), &[CSCA]),
            Err(PassiveAuthError::Malformed(_))
        ));
    }

    #[test]
    fn chile_trust_list_matches_bsi_master_list_fingerprints() {
        let prefixes: Vec<String> = CHILE_CSCA
            .iter()
            .map(|der| {
                let digest = crate::crypto::hasher::hash_with(
                    crate::crypto::hasher::HashAlgorithm::Sha256,
                    der,
                );
                hex::encode(&digest[..8])
            })
            .collect();
        assert_eq!(
            prefixes,
            [
                "4c2daca0fb8d73e1",
                "89f6143b835c2a41",
                "f88b2c0769cf975a",
                "bd10b0cf3addd12c",
                "7585ae3201e93ce4",
                "69a22617cc39b11d",
                "8e82732a4449b7fc",
                "26539f4a222aec83",
                "b5dd74579cd7db82",
            ]
        );
    }

    #[test]
    fn chile_2018_link_certificate_chains_to_2013_root_only() {
        let (root_2013, link_2018, root_2021) = (CHILE_CSCA[0], CHILE_CSCA[2], CHILE_CSCA[3]);
        let (_, link) = parse_x509_certificate(link_2018).unwrap();
        assert!(is_issued_by(&link, root_2013));
        assert!(!is_issued_by(&link, root_2021));
    }
}
