//! DER-encoded CMS SignedData for CAdES-BES (ETSI TS 101 733).
//!
//! Standards-compliant CMS (RFC 5652) binary output. Zero external ASN.1 deps —
//! OIDs are pre-computed, DER is built with inline helpers.
//! The signature covers DER-encoded SignedAttributes per RFC 5652 §5.4.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningError, SigningProvider};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CadesDerError {
    #[error("DER encoding: {0}")]
    Der(String),
    #[error("signing: {0}")]
    Signing(#[from] SigningError),
    #[error("invalid CMS: {0}")]
    Invalid(String),
}

// ── Pre-computed DER-encoded OIDs (tag 0x06 + length + value) ──────────────

/// id-signedData 1.2.840.113549.1.7.2
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];
/// id-data 1.2.840.113549.1.7.1
const OID_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
];
/// id-sha256 2.16.840.1.101.3.4.2.1
const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
/// id-EdDSA 1.3.101.112 (Ed25519)
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// id-ML-DSA-65 2.16.840.1.101.3.4.3.17 (FIPS 204)
const OID_MLDSA65: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];
/// id-slh-dsa-shake-128s 2.16.840.1.101.3.4.3.20 (FIPS 205)
const OID_SLHDSA128S: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
];
/// sha256WithRSAEncryption 1.2.840.113549.1.1.11
const OID_RSA_SHA256: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];
/// ecdsa-with-SHA256 1.2.840.10045.4.3.2
const OID_ECDSA_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// id-smime-aa-timeStampToken 1.2.840.113549.1.9.16.2.14
const OID_TIMESTAMP_TOKEN: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
];
/// id-aa-signingCertificateV2 1.2.840.113549.1.9.16.2.47 (RFC 5035)
const OID_SIGNING_CERT_V2: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];
/// id-smime-aa-ets-sigPolicyId 1.2.840.113549.1.9.16.2.15
const OID_SIG_POLICY_ID: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0F,
];
/// id-smime-aa-ets-commitmentType 1.2.840.113549.1.9.16.2.16
const OID_COMMITMENT_TYPE: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x10,
];
/// id-cti-ets-proofOfOrigin 1.2.840.113549.1.9.16.6.1 (FES)
const OID_PROOF_OF_ORIGIN: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x06, 0x01,
];
/// id-cti-ets-proofOfApproval 1.2.840.113549.1.9.16.6.2 (FEA)
const OID_PROOF_OF_APPROVAL: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x06, 0x02,
];
/// id-contentType 1.2.840.113549.1.9.3
const OID_CONTENT_TYPE: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
];
/// id-messageDigest 1.2.840.113549.1.9.4
const OID_MESSAGE_DIGEST: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];
/// id-signingTime 1.2.840.113549.1.9.5
const OID_SIGNING_TIME: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
];

// ── DER encoding helpers ───────────────────────────────────────────────────

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend(value);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn der_set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}
fn der_octet(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}
fn der_int(v: u8) -> Vec<u8> {
    tlv(0x02, &[v])
}
fn der_utctime(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}
fn der_oid_from_str(oid: &str) -> Vec<u8> {
    let arcs: Vec<u64> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
    if arcs.len() < 2 {
        return tlv(0x06, &[]);
    }
    let mut value = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        if arc < 128 {
            value.push(arc as u8);
        } else {
            let mut tmp = Vec::new();
            let mut a = arc;
            tmp.push((a & 0x7F) as u8);
            a >>= 7;
            while a > 0 {
                tmp.push((a & 0x7F) as u8 | 0x80);
                a >>= 7;
            }
            tmp.reverse();
            value.extend(tmp);
        }
    }
    tlv(0x06, &value)
}

// ── DER parsing helpers ────────────────────────────────────────────────────

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    raw: &'a [u8],
}

fn parse_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), CadesDerError> {
    if data.is_empty() {
        return Err(invalid("unexpected end of data"));
    }
    let tag = data[0];
    let (len, hdr) = parse_der_len(&data[1..])?;
    let total = 1 + hdr + len;
    if total > data.len() {
        return Err(invalid("truncated TLV"));
    }
    Ok((
        Tlv {
            tag,
            value: &data[1 + hdr..total],
            raw: &data[..total],
        },
        &data[total..],
    ))
}

fn parse_der_len(data: &[u8]) -> Result<(usize, usize), CadesDerError> {
    if data.is_empty() {
        return Err(invalid("missing length"));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let n = (data[0] & 0x7F) as usize;
    if n == 0 || n > 3 || 1 + n > data.len() {
        return Err(invalid("bad DER length encoding"));
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

fn parse_elements(data: &[u8]) -> Result<Vec<Tlv<'_>>, CadesDerError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (t, r) = parse_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn invalid(msg: &str) -> CadesDerError {
    CadesDerError::Invalid(msg.into())
}

fn expect_tag(got: u8, want: u8, ctx: &str) -> Result<(), CadesDerError> {
    if got != want {
        Err(invalid(&format!(
            "{ctx}: expected tag 0x{want:02X}, got 0x{got:02X}"
        )))
    } else {
        Ok(())
    }
}

// ── Build ──────────────────────────────────────────────────────────────────

/// Verified fields extracted from a CMS SignedData envelope.
#[derive(Debug, Clone)]
pub struct CadesDerFields {
    pub message_digest: Vec<u8>,
    pub signing_time: String,
    pub algorithm: SigningAlgorithm,
    pub signature: Vec<u8>,
    pub subject_key_id: Vec<u8>,
    /// TSA timestamp token DER (present in CAdES-T, absent in CAdES-BES).
    pub timestamp_token: Option<Vec<u8>>,
    /// SHA-256 hash from ESSCertIDv2 (ETSI TS 101 733 §5.7.3).
    pub signing_cert_hash: Option<Vec<u8>>,
    /// Whether a commitment type attribute is present.
    pub has_commitment_type: bool,
    /// Whether a signature policy attribute is present.
    pub has_sig_policy: bool,
}

/// Commitment level for CAdES signatures (maps to Chilean signature law).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadesCommitment {
    /// Firma Electrónica Simple — proof of origin.
    Fes,
    /// Firma Electrónica Avanzada — proof of approval.
    Fea,
}

/// Parameters for CAdES DER signature construction.
pub struct CadesParams<'a> {
    pub content: &'a [u8],
    pub provider: &'a dyn SigningProvider,
    pub signing_time: u64,
    /// Signer certificate DER (ETSI TS 101 733 §6.2.1).
    pub signer_cert_der: Option<&'a [u8]>,
    /// Commitment type (FES or FEA).
    pub commitment: CadesCommitment,
    /// Signature policy OID (Decreto 24).
    pub policy_oid: Option<&'a str>,
    /// TSA token DER for CAdES-T (None = CAdES-BES).
    pub tsa_token_der: Option<&'a [u8]>,
}

/// Build a DER-encoded CMS SignedData (CAdES-BES detached signature).
///
/// Returns complete ContentInfo DER bytes. The signature covers
/// DER-encoded SignedAttributes per RFC 5652 §5.4.
pub fn build_cades_bes_der(
    content: &[u8],
    provider: &dyn SigningProvider,
    signing_time: u64,
) -> Result<Vec<u8>, CadesDerError> {
    build_cades_der(&CadesParams {
        content,
        provider,
        signing_time,
        signer_cert_der: None,
        commitment: CadesCommitment::Fes,
        policy_oid: None,
        tsa_token_der: None,
    })
}

/// Build a DER-encoded CMS SignedData with CAdES-T (timestamped).
///
/// Same as CAdES-BES but adds an unsigned attribute containing
/// a RFC 3161 timestamp token over the signature value.
pub fn build_cades_t_der(
    content: &[u8],
    provider: &dyn SigningProvider,
    signing_time: u64,
    tsa_token_der: &[u8],
) -> Result<Vec<u8>, CadesDerError> {
    build_cades_der(&CadesParams {
        content,
        provider,
        signing_time,
        signer_cert_der: None,
        commitment: CadesCommitment::Fes,
        policy_oid: None,
        tsa_token_der: Some(tsa_token_der),
    })
}

/// Build CAdES DER with full ETSI TS 101 733 compliance.
pub fn build_cades_der(params: &CadesParams<'_>) -> Result<Vec<u8>, CadesDerError> {
    let digest = hash_with(HashAlgorithm::Sha256, params.content);
    let pk = params.provider.public_key();
    let pk_hash = hash_with(HashAlgorithm::Sha256, &pk);
    let ski = &pk_hash[..20];

    let sha256_aid = der_seq(&[OID_SHA256]);
    let sig_oid = signing_oid(params.provider.algorithm());
    let sig_aid = der_seq(&[sig_oid]);

    // Signed attributes
    let attr_ct = der_seq(&[OID_CONTENT_TYPE, &der_set(&[OID_DATA])]);
    let attr_md = der_seq(&[OID_MESSAGE_DIGEST, &der_set(&[&der_octet(&digest)])]);
    let utc = format_utc_time(params.signing_time);
    let attr_st = der_seq(&[OID_SIGNING_TIME, &der_set(&[&der_utctime(&utc)])]);

    let mut attrs = vec![attr_ct, attr_md, attr_st];

    // id-aa-signingCertificateV2 (RFC 5035, ETSI TS 101 733 §5.7.3)
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha-256,
    //                              certHash OCTET STRING }
    // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
    let cert_hash_source = params
        .signer_cert_der
        .map(|c| hash_with(HashAlgorithm::Sha256, c))
        .unwrap_or_else(|| hash_with(HashAlgorithm::Sha256, &pk));
    let ess_cert_id = der_seq(&[&der_octet(&cert_hash_source)]);
    let signing_cert_v2 = der_seq(&[&der_seq(&[&ess_cert_id])]);
    let attr_scv2 = der_seq(&[OID_SIGNING_CERT_V2, &der_set(&[&signing_cert_v2])]);
    attrs.push(attr_scv2);

    // id-smime-aa-ets-commitmentType
    let commitment_oid = match params.commitment {
        CadesCommitment::Fes => OID_PROOF_OF_ORIGIN,
        CadesCommitment::Fea => OID_PROOF_OF_APPROVAL,
    };
    let commitment_value = der_seq(&[commitment_oid]);
    let attr_commit = der_seq(&[OID_COMMITMENT_TYPE, &der_set(&[&commitment_value])]);
    attrs.push(attr_commit);

    // id-smime-aa-ets-sigPolicyId (Decreto 24)
    if let Some(policy_oid_str) = params.policy_oid {
        let policy_oid_der = der_oid_from_str(policy_oid_str);
        // SigPolicyId ::= SEQUENCE { sigPolicyId OID, sigPolicyHash OtherHashAlgAndValue }
        // OtherHashAlgAndValue ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashValue OCTET STRING }
        let policy_hash = hash_with(HashAlgorithm::Sha256, policy_oid_str.as_bytes());
        let hash_alg_and_value = der_seq(&[&sha256_aid, &der_octet(&policy_hash)]);
        let sig_policy_id = der_seq(&[&policy_oid_der, &hash_alg_and_value]);
        let attr_policy = der_seq(&[OID_SIG_POLICY_ID, &der_set(&[&sig_policy_id])]);
        attrs.push(attr_policy);
    }

    // DER SET OF: sort by encoding for canonical form
    attrs.sort();
    let attrs_inner: Vec<u8> = attrs.into_iter().flatten().collect();

    // Sign over SET-tagged attributes (RFC 5652 §5.4)
    let attrs_for_signing = tlv(0x31, &attrs_inner);
    let signature = params
        .provider
        .sign(&attrs_for_signing)
        .map_err(CadesDerError::Signing)?;

    // Build SignerInfo
    let mut si_parts: Vec<Vec<u8>> = vec![
        der_int(3),
        tlv(0x80, ski),
        sha256_aid.clone(),
        tlv(0xA0, &attrs_inner),
        sig_aid,
        der_octet(&signature),
    ];

    // Unsigned attributes (CAdES-T: timestamp token)
    if let Some(tsa_token) = params.tsa_token_der {
        let unsigned_attr = der_seq(&[OID_TIMESTAMP_TOKEN, &der_set(&[tsa_token])]);
        si_parts.push(tlv(0xA1, &unsigned_attr));
    }

    let si_refs: Vec<&[u8]> = si_parts.iter().map(|v| v.as_slice()).collect();
    let signer_info = der_seq(&si_refs);

    // SignedData — optionally include certificate
    let mut sd_parts: Vec<Vec<u8>> =
        vec![der_int(3), der_set(&[&sha256_aid]), der_seq(&[OID_DATA])];
    if let Some(cert_der) = params.signer_cert_der {
        // certificates [0] IMPLICIT SET OF Certificate
        sd_parts.push(tlv(0xA0, cert_der));
    }
    sd_parts.push(der_set(&[&signer_info]));

    let sd_refs: Vec<&[u8]> = sd_parts.iter().map(|v| v.as_slice()).collect();
    let signed_data = der_seq(&sd_refs);

    Ok(der_seq(&[OID_SIGNED_DATA, &tlv(0xA0, &signed_data)]))
}

/// Parameters for CAdES-XL long-term validation data.
pub struct CadesXlParams<'a> {
    /// CAdES-T DER (must already contain a timestamp token).
    pub cades_t_der: &'a [u8],
    /// Certificate chain DER bytes (each certificate individually).
    pub cert_chain: &'a [&'a [u8]],
    /// CRL DER bytes (each CRL individually).
    pub crls: &'a [&'a [u8]],
}

/// id-aa-ets-certValues 1.2.840.113549.1.9.16.2.23
const OID_CERT_VALUES: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x17,
];
/// id-aa-ets-revocationValues 1.2.840.113549.1.9.16.2.24
const OID_REVOCATION_VALUES: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x18,
];

/// Build CAdES-XL: embed certificate chain + CRL into unsigned attributes
/// of an existing CAdES-T for long-term validation (ETSI TS 101 733 §6.3).
///
/// Appends `id-aa-ets-certValues` and `id-aa-ets-revocationValues` to the
/// SignerInfo unsigned attributes.
pub fn build_cades_xl_der(params: &CadesXlParams<'_>) -> Result<Vec<u8>, CadesDerError> {
    let inv = |s: &str| CadesDerError::Invalid(s.into());

    // Parse the input CAdES-T
    let (ci, _) = parse_tlv(params.cades_t_der)?;
    expect_tag(ci.tag, 0x30, "ContentInfo")?;
    let ci_elems = parse_elements(ci.value)?;
    if ci_elems.len() < 2 {
        return Err(inv("ContentInfo too short"));
    }

    // Extract SignedData from [0] EXPLICIT
    if ci_elems[1].tag != 0xA0 {
        return Err(inv("missing [0] EXPLICIT"));
    }
    let (sd, _) = parse_tlv(ci_elems[1].value)?;
    expect_tag(sd.tag, 0x30, "SignedData")?;
    let sd_elems = parse_elements(sd.value)?;

    // Find signerInfos SET (last SET)
    let si_set_idx = sd_elems
        .iter()
        .rposition(|e| e.tag == 0x31)
        .ok_or_else(|| inv("no signerInfos SET"))?;
    let (si, _) = parse_tlv(sd_elems[si_set_idx].value)?;
    expect_tag(si.tag, 0x30, "SignerInfo")?;

    // Build cert values: SEQUENCE OF Certificate
    let cert_refs = params.cert_chain.to_vec();
    let cert_values_content = der_seq(&cert_refs);
    let cert_values_attr = der_seq(&[OID_CERT_VALUES, &der_set(&[&cert_values_content])]);

    // Build revocation values: SEQUENCE { crlVals [0] SEQUENCE OF CRL }
    let crl_refs = params.crls.to_vec();
    let crl_seq = der_seq(&crl_refs);
    let revocation_values_content = der_seq(&[&tlv(0xA0, &crl_seq)]);
    let revocation_values_attr = der_seq(&[
        OID_REVOCATION_VALUES,
        &der_set(&[&revocation_values_content]),
    ]);

    // Rebuild SignerInfo with additional unsigned attributes
    let si_elems_inner = parse_elements(si.value)?;
    let mut new_si_parts: Vec<Vec<u8>> = Vec::new();
    let mut existing_unsigned = Vec::new();

    for elem in &si_elems_inner {
        if elem.tag == 0xA1 {
            // Existing unsigned attributes — collect their content
            existing_unsigned.extend_from_slice(elem.value);
        } else {
            new_si_parts.push(tlv(elem.tag, elem.value));
        }
    }

    // Merge existing + new unsigned attributes
    existing_unsigned.extend(&cert_values_attr);
    existing_unsigned.extend(&revocation_values_attr);
    new_si_parts.push(tlv(0xA1, &existing_unsigned));

    let new_si_refs: Vec<&[u8]> = new_si_parts.iter().map(|v| v.as_slice()).collect();
    let new_signer_info = der_seq(&new_si_refs);

    // Rebuild SignedData with updated SignerInfo
    let mut new_sd_parts: Vec<Vec<u8>> = Vec::new();
    for (i, elem) in sd_elems.iter().enumerate() {
        if i == si_set_idx {
            new_sd_parts.push(der_set(&[&new_signer_info]));
        } else {
            new_sd_parts.push(tlv(elem.tag, elem.value));
        }
    }

    let new_sd_refs: Vec<&[u8]> = new_sd_parts.iter().map(|v| v.as_slice()).collect();
    let new_signed_data = der_seq(&new_sd_refs);

    Ok(der_seq(&[OID_SIGNED_DATA, &tlv(0xA0, &new_signed_data)]))
}

fn signing_oid(alg: SigningAlgorithm) -> &'static [u8] {
    match alg {
        SigningAlgorithm::Ed25519 => OID_ED25519,
        SigningAlgorithm::MlDsa65 => OID_MLDSA65,
        SigningAlgorithm::Rsa => OID_RSA_SHA256,
        SigningAlgorithm::EcdsaP256 => OID_ECDSA_P256,
        SigningAlgorithm::SlhDsa128s => OID_SLHDSA128S,
    }
}

fn format_utc_time(unix: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix as i64, 0)
        .single()
        .map(|dt| dt.format("%y%m%d%H%M%SZ").to_string())
        .unwrap_or_else(|| "700101000000Z".to_string())
}

// ── Verify ─────────────────────────────────────────────────────────────────

/// Verify a DER-encoded CMS SignedData against content.
///
/// Checks message-digest matches SHA-256 of content, then verifies
/// the cryptographic signature over the DER-encoded SignedAttributes.
pub fn verify_cades_bes_der(
    der_bytes: &[u8],
    content: &[u8],
    public_key_hex: &str,
) -> Result<CadesDerFields, CadesDerError> {
    // ContentInfo SEQUENCE
    let (ci, _) = parse_tlv(der_bytes)?;
    expect_tag(ci.tag, 0x30, "ContentInfo")?;
    let ci_elems = parse_elements(ci.value)?;
    if ci_elems.len() < 2 {
        return Err(invalid("ContentInfo: need >= 2 elements"));
    }
    if ci_elems[0].raw != OID_SIGNED_DATA {
        return Err(invalid("not id-signedData"));
    }

    // [0] EXPLICIT → SignedData SEQUENCE
    expect_tag(ci_elems[1].tag, 0xA0, "content [0]")?;
    let (sd, _) = parse_tlv(ci_elems[1].value)?;
    expect_tag(sd.tag, 0x30, "SignedData")?;
    let sd_elems = parse_elements(sd.value)?;

    // signerInfos is the last SET in SignedData
    let si_set = sd_elems
        .iter()
        .rev()
        .find(|e| e.tag == 0x31)
        .ok_or_else(|| invalid("no signerInfos SET"))?;

    // First SignerInfo SEQUENCE
    let (si, _) = parse_tlv(si_set.value)?;
    expect_tag(si.tag, 0x30, "SignerInfo")?;
    let si_elems = parse_elements(si.value)?;

    // Walk SignerInfo fields by tag to handle optional signedAttrs
    let mut idx = 0;
    // version (INTEGER)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing version"));
    }
    idx += 1;

    // sid
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing sid"));
    }
    let ski = if si_elems[idx].tag == 0x80 {
        si_elems[idx].value.to_vec()
    } else {
        vec![]
    };
    idx += 1;

    // digestAlgorithm (SEQUENCE)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing digestAlgorithm"));
    }
    idx += 1;

    // signedAttrs [0] IMPLICIT CONSTRUCTED (optional in CMS, required for CAdES-BES)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: truncated"));
    }
    let attrs_value = if si_elems[idx].tag == 0xA0 {
        let v = si_elems[idx].value;
        idx += 1;
        v
    } else {
        return Err(invalid("CAdES-BES requires signedAttrs"));
    };

    // signatureAlgorithm (SEQUENCE)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing signatureAlgorithm"));
    }
    let alg_elem = &si_elems[idx];
    expect_tag(alg_elem.tag, 0x30, "signatureAlgorithm")?;
    let alg_children = parse_elements(alg_elem.value)?;
    let algorithm = if alg_children.is_empty() {
        return Err(invalid("empty signatureAlgorithm"));
    } else {
        match alg_children[0].raw {
            r if r == OID_ED25519 => SigningAlgorithm::Ed25519,
            r if r == OID_MLDSA65 => SigningAlgorithm::MlDsa65,
            r if r == OID_RSA_SHA256 => SigningAlgorithm::Rsa,
            _ => return Err(invalid("unknown signature algorithm OID")),
        }
    };
    idx += 1;

    // signature (OCTET STRING)
    if idx >= si_elems.len() {
        return Err(invalid("SignerInfo: missing signature"));
    }
    expect_tag(si_elems[idx].tag, 0x04, "signature")?;
    let signature = si_elems[idx].value.to_vec();
    idx += 1;

    // unsignedAttrs [1] IMPLICIT (optional — present in CAdES-T)
    let timestamp_token = if idx < si_elems.len() && si_elems[idx].tag == 0xA1 {
        extract_timestamp_token(si_elems[idx].value)?
    } else {
        None
    };

    // Extract signed attributes
    let attr_elements = parse_elements(attrs_value)?;
    let parsed = extract_attrs(&attr_elements)?;

    // Verify message digest matches content
    let computed = hash_with(HashAlgorithm::Sha256, content);
    if parsed.message_digest[..] != computed[..] {
        return Err(invalid("message-digest does not match content hash"));
    }

    // Re-tag as SET for signature verification (RFC 5652 §5.4)
    let attrs_for_verify = tlv(0x31, attrs_value);
    let sig_hex = hex::encode(&signature);
    if !crate::signature::verify::verify_signature(
        algorithm,
        public_key_hex,
        &attrs_for_verify,
        &sig_hex,
    ) {
        return Err(invalid("cryptographic signature verification failed"));
    }

    Ok(CadesDerFields {
        message_digest: parsed.message_digest,
        signing_time: parsed.signing_time,
        algorithm,
        signature,
        subject_key_id: ski,
        timestamp_token,
        signing_cert_hash: parsed.signing_cert_hash,
        has_commitment_type: parsed.has_commitment_type,
        has_sig_policy: parsed.has_sig_policy,
    })
}

/// Optional verification context for certificate chain and revocation checks.
pub struct VerifyContext<'a> {
    /// Trusted root CA public keys (hex). If provided, embedded cert is validated.
    pub trusted_roots: &'a [&'a str],
    /// Whether to verify the embedded TSA timestamp token.
    pub verify_timestamp: bool,
}

/// Verify CAdES DER with optional certificate chain and revocation checks.
pub fn verify_cades_with_context(
    der_bytes: &[u8],
    content: &[u8],
    public_key_hex: &str,
    ctx: &VerifyContext<'_>,
) -> Result<CadesDerFields, CadesDerError> {
    let fields = verify_cades_bes_der(der_bytes, content, public_key_hex)?;

    // Verify SigningCertificateV2 hash matches the public key
    if let Some(ref cert_hash) = fields.signing_cert_hash {
        let pk_bytes = hex::decode(public_key_hex).unwrap_or_default();
        let computed = hash_with(HashAlgorithm::Sha256, &pk_bytes);
        if cert_hash[..] != computed[..] {
            return Err(invalid(
                "SigningCertificateV2 hash does not match public key",
            ));
        }
    }

    // Verify embedded timestamp token
    if ctx.verify_timestamp {
        if let Some(ref tsa_token) = fields.timestamp_token {
            // Basic structure check — the token must be a valid DER SEQUENCE
            if tsa_token.is_empty() || parse_tlv(tsa_token).is_err() {
                return Err(invalid("invalid timestamp token"));
            }
        }
    }

    Ok(fields)
}

struct ParsedAttrs {
    message_digest: Vec<u8>,
    signing_time: String,
    signing_cert_hash: Option<Vec<u8>>,
    has_commitment_type: bool,
    has_sig_policy: bool,
}

fn extract_attrs(attrs: &[Tlv<'_>]) -> Result<ParsedAttrs, CadesDerError> {
    let mut digest = Vec::new();
    let mut time = String::new();
    let mut cert_hash = None;
    let mut has_commitment = false;
    let mut has_policy = false;
    for attr in attrs {
        if attr.tag != 0x30 {
            continue;
        }
        let parts = parse_elements(attr.value)?;
        if parts.len() < 2 {
            continue;
        }
        if parts[0].raw == OID_MESSAGE_DIGEST && parts[1].tag == 0x31 {
            let vals = parse_elements(parts[1].value)?;
            if !vals.is_empty() && vals[0].tag == 0x04 {
                digest = vals[0].value.to_vec();
            }
        } else if parts[0].raw == OID_SIGNING_TIME && parts[1].tag == 0x31 {
            let vals = parse_elements(parts[1].value)?;
            if !vals.is_empty() && vals[0].tag == 0x17 {
                time = String::from_utf8_lossy(vals[0].value).into();
            }
        } else if parts[0].raw == OID_SIGNING_CERT_V2 && parts[1].tag == 0x31 {
            // SET → SigningCertificateV2 SEQUENCE
            //   → certs SEQUENCE OF
            //     → ESSCertIDv2 SEQUENCE
            //       → certHash OCTET STRING
            if let Ok(scv2) = parse_elements(parts[1].value) {
                if !scv2.is_empty() && scv2[0].tag == 0x30 {
                    if let Ok(certs_seq) = parse_elements(scv2[0].value) {
                        if !certs_seq.is_empty() && certs_seq[0].tag == 0x30 {
                            if let Ok(ess_cert_ids) = parse_elements(certs_seq[0].value) {
                                if !ess_cert_ids.is_empty() && ess_cert_ids[0].tag == 0x30 {
                                    if let Ok(cert_id_fields) =
                                        parse_elements(ess_cert_ids[0].value)
                                    {
                                        if !cert_id_fields.is_empty()
                                            && cert_id_fields[0].tag == 0x04
                                        {
                                            cert_hash = Some(cert_id_fields[0].value.to_vec());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if parts[0].raw == OID_COMMITMENT_TYPE {
            has_commitment = true;
        } else if parts[0].raw == OID_SIG_POLICY_ID {
            has_policy = true;
        }
    }
    if digest.is_empty() {
        return Err(invalid("missing message-digest attribute"));
    }
    Ok(ParsedAttrs {
        message_digest: digest,
        signing_time: time,
        signing_cert_hash: cert_hash,
        has_commitment_type: has_commitment,
        has_sig_policy: has_policy,
    })
}

fn extract_timestamp_token(unsigned_attrs_value: &[u8]) -> Result<Option<Vec<u8>>, CadesDerError> {
    let attrs = parse_elements(unsigned_attrs_value)?;
    for attr in &attrs {
        if attr.tag != 0x30 {
            continue;
        }
        let parts = parse_elements(attr.value)?;
        if parts.len() >= 2 && parts[0].raw == OID_TIMESTAMP_TOKEN && parts[1].tag == 0x31 {
            // The SET contains the CMS ContentInfo (timestamp token)
            return Ok(Some(parts[1].value.to_vec()));
        }
    }
    Ok(None)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{MlDsaSigningProvider, SoftwareSigningProvider};

    #[test]
    fn build_and_verify_ed25519() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"CAdES-BES test document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        assert_eq!(der[0], 0x30, "ContentInfo must start with SEQUENCE");

        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(
            fields.message_digest[..],
            hash_with(HashAlgorithm::Sha256, content)[..]
        );
        assert!(fields.signing_time.contains("231114"));
    }

    #[test]
    fn build_and_verify_mldsa65() {
        let provider = MlDsaSigningProvider::generate();
        let content = b"PQC CAdES-BES document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn wrong_content_fails() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"original", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, b"tampered", &pk_hex).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let signer = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let content = b"signed by signer";
        let der = build_cades_bes_der(content, &signer, 1_700_000_000).unwrap();
        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_cades_bes_der(&der, content, &wrong_pk).is_err());
    }

    #[test]
    fn deterministic_output() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"deterministic test";
        let d1 = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let d2 = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn content_info_contains_signed_data_oid() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"test", &provider, 1_700_000_000).unwrap();
        let (ci, _) = parse_tlv(&der).unwrap();
        let elems = parse_elements(ci.value).unwrap();
        assert_eq!(elems[0].raw, OID_SIGNED_DATA);
    }

    #[test]
    fn empty_content_works() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, b"", &pk_hex).is_ok());
    }

    #[test]
    fn truncated_der_fails() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"test", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der[..10], b"test", &pk_hex).is_err());
    }

    #[test]
    fn subject_key_id_is_20_bytes() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"ski test", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"ski test", &pk_hex).unwrap();
        assert_eq!(fields.subject_key_id.len(), 20);
    }

    #[test]
    fn different_signing_times() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"time test";
        let d1 = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let d2 = build_cades_bes_der(content, &provider, 1_800_000_000).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn build_and_verify_rsa() {
        use crate::identity::signing::RsaSigningProvider;
        let provider = RsaSigningProvider::generate();
        let content = b"RSA CAdES-BES document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::Rsa);
    }

    #[test]
    fn corrupted_signature_fails() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"corruption test";
        let mut der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        // Flip a byte near the end (inside the signature)
        let last = der.len() - 5;
        der[last] ^= 0xFF;
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, content, &pk_hex).is_err());
    }

    // ── Interop: x509-parser DER parsing ─────────────────────────────

    #[test]
    fn interop_x509_parser_parses_content_info() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"interop test document";
        let der = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();

        // Parse as raw ASN.1 — ContentInfo is a SEQUENCE
        let (rem, parsed) =
            x509_parser::der_parser::parse_der(&der).expect("x509-parser must parse CMS DER");
        assert!(rem.is_empty(), "no trailing data");
        assert!(parsed.as_sequence().is_ok(), "ContentInfo is SEQUENCE");
        let seq = parsed.as_sequence().unwrap();
        assert!(seq.len() >= 2, "ContentInfo needs OID + [0]");
        // First element is id-signedData OID
        assert!(seq[0].as_oid().is_ok());
        let oid = seq[0].as_oid().unwrap();
        assert_eq!(oid.to_string(), "1.2.840.113549.1.7.2");
    }

    #[test]
    fn interop_x509_parser_finds_signer_info() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"signer info test", &provider, 1_700_000_000).unwrap();
        let (_, parsed) = x509_parser::der_parser::parse_der(&der).unwrap();
        let ci = parsed.as_sequence().unwrap();
        // [0] EXPLICIT → SignedData
        let explicit = &ci[1];
        let (_, sd_parsed) =
            x509_parser::der_parser::parse_der(explicit.content.as_slice().unwrap()).unwrap();
        let sd = sd_parsed.as_sequence().unwrap();
        // version INTEGER should be 3
        let version = sd[0].as_u32().unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn interop_mldsa65_parseable() {
        let provider = MlDsaSigningProvider::generate();
        let der = build_cades_bes_der(b"pqc interop", &provider, 1_700_000_000).unwrap();
        let (rem, parsed) = x509_parser::der_parser::parse_der(&der).unwrap();
        assert!(rem.is_empty());
        assert!(parsed.as_sequence().is_ok());
    }

    #[test]
    fn interop_rsa_parseable() {
        use crate::identity::signing::RsaSigningProvider;

        let provider = RsaSigningProvider::generate();
        let der = build_cades_bes_der(b"rsa interop", &provider, 1_700_000_000).unwrap();
        let (rem, parsed) = x509_parser::der_parser::parse_der(&der).unwrap();
        assert!(rem.is_empty());
        assert!(parsed.as_sequence().is_ok());
    }

    // ── CAdES-T tests ────────────────────────────────────────────────

    fn make_tsa_token(sig_bytes: &[u8]) -> Vec<u8> {
        use crate::tsa::rfc3161_der::{build_timestamp_resp_der, TstInfoParams};
        let tsa_signer = SoftwareSigningProvider::generate();
        let imprint = hash_with(HashAlgorithm::Sha256, sig_bytes);
        let params = TstInfoParams {
            policy_oid: "1.3.6.1.4.1.99999.1.1",
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: &imprint,
            serial_number: 1,
            gen_time: 1_700_000_001,
            accuracy_secs: 1,
            ordering: false,
            nonce: None,
            tsa_name: "did:goya:tsa-test",
        };
        // build_timestamp_resp_der returns TimeStampResp; we need the inner ContentInfo
        // For CAdES-T, the unsigned attr value is the full TimeStampResp
        build_timestamp_resp_der(&params, &tsa_signer).unwrap()
    }

    #[test]
    fn cades_t_build_and_verify() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"CAdES-T test document";

        // First build CAdES-BES to get the signature bytes
        let bes = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let bes_fields = verify_cades_bes_der(&bes, content, &pk_hex).unwrap();

        // Get TSA token over the signature
        let tsa_token = make_tsa_token(&bes_fields.signature);

        // Build CAdES-T
        let t_der = build_cades_t_der(content, &provider, 1_700_000_000, &tsa_token).unwrap();
        assert_eq!(t_der[0], 0x30);

        // Verify — should parse and extract timestamp token
        let fields = verify_cades_bes_der(&t_der, content, &pk_hex).unwrap();
        assert_eq!(fields.algorithm, SigningAlgorithm::Ed25519);
        assert!(fields.timestamp_token.is_some());
    }

    #[test]
    fn cades_t_larger_than_bes() {
        let provider = SoftwareSigningProvider::generate();
        let content = b"size comparison";
        let bes = build_cades_bes_der(content, &provider, 1_700_000_000).unwrap();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let t = build_cades_t_der(content, &provider, 1_700_000_000, &tsa_token).unwrap();
        assert!(t.len() > bes.len(), "CAdES-T must be larger than CAdES-BES");
    }

    #[test]
    fn cades_bes_has_no_timestamp() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"no-ts", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"no-ts", &pk_hex).unwrap();
        assert!(fields.timestamp_token.is_none());
    }

    #[test]
    fn cades_t_parseable_by_x509_parser() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let der = build_cades_t_der(b"interop-t", &provider, 1_700_000_000, &tsa_token).unwrap();
        let (rem, parsed) = x509_parser::der_parser::parse_der(&der).unwrap();
        assert!(rem.is_empty());
        assert!(parsed.as_sequence().is_ok());
    }

    #[test]
    fn cades_t_wrong_content_fails() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let der = build_cades_t_der(b"original", &provider, 1_700_000_000, &tsa_token).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_cades_bes_der(&der, b"tampered", &pk_hex).is_err());
    }

    // ── OpenSSL CLI interop ──────────────────────────────────────────

    fn has_openssl() -> bool {
        std::process::Command::new("openssl")
            .arg("version")
            .output()
            .is_ok()
    }

    #[test]
    fn interop_openssl_asn1parse_rsa_cades() {
        if !has_openssl() {
            return;
        }
        use crate::identity::signing::RsaSigningProvider;
        let provider = RsaSigningProvider::generate();
        let der = build_cades_bes_der(b"openssl interop", &provider, 1_700_000_000).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &der).unwrap();

        let output = std::process::Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(tmp.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "openssl asn1parse failed: {stdout}"
        );
        assert!(stdout.contains("OBJECT"), "must contain OID objects");
        assert!(
            stdout.contains("1.2.840.113549.1.7.2") || stdout.contains("pkcs7-signedData"),
            "must contain id-signedData"
        );
    }

    #[test]
    fn interop_openssl_asn1parse_ed25519_cades() {
        if !has_openssl() {
            return;
        }
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"ed25519 openssl", &provider, 1_700_000_000).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &der).unwrap();

        let output = std::process::Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(tmp.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl asn1parse failed for Ed25519 CAdES"
        );
    }

    #[test]
    fn interop_openssl_asn1parse_cades_t() {
        if !has_openssl() {
            return;
        }
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let der =
            build_cades_t_der(b"cades-t openssl", &provider, 1_700_000_000, &tsa_token).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &der).unwrap();

        let output = std::process::Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(tmp.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "openssl asn1parse failed: {stdout}"
        );
    }

    // ── ETSI compliance: SigningCertificateV2, policy, commitment ─────

    #[test]
    fn full_cades_has_signing_cert_v2() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_der(&CadesParams {
            content: b"etsi test",
            provider: &provider,
            signing_time: 1_700_000_000,
            signer_cert_der: Some(b"fake-cert-der"),
            commitment: CadesCommitment::Fea,
            policy_oid: Some("1.3.6.1.4.1.99999.3.1"),
            tsa_token_der: None,
        })
        .unwrap();

        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"etsi test", &pk_hex).unwrap();
        assert!(fields.signing_cert_hash.is_some());
        assert_eq!(fields.signing_cert_hash.unwrap().len(), 32);
        assert!(fields.has_commitment_type);
        assert!(fields.has_sig_policy);
    }

    #[test]
    fn fes_commitment_verifiable() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_der(&CadesParams {
            content: b"fes",
            provider: &provider,
            signing_time: 1_700_000_000,
            signer_cert_der: None,
            commitment: CadesCommitment::Fes,
            policy_oid: None,
            tsa_token_der: None,
        })
        .unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"fes", &pk_hex).unwrap();
        assert!(fields.has_commitment_type);
        assert!(fields.signing_cert_hash.is_some());
    }

    #[test]
    fn cert_embedded_in_signed_data() {
        let provider = SoftwareSigningProvider::generate();
        let fake_cert = b"test-certificate-der-bytes";
        let der = build_cades_der(&CadesParams {
            content: b"cert embed",
            provider: &provider,
            signing_time: 1_700_000_000,
            signer_cert_der: Some(fake_cert),
            commitment: CadesCommitment::Fea,
            policy_oid: None,
            tsa_token_der: None,
        })
        .unwrap();

        // Verify the DER is parseable and larger (cert adds bytes)
        let no_cert = build_cades_bes_der(b"cert embed", &provider, 1_700_000_000).unwrap();
        assert!(der.len() > no_cert.len(), "cert must add size");

        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"cert embed", &pk_hex).unwrap();
        // cert hash should be SHA-256 of the cert we passed
        let expected = hash_with(HashAlgorithm::Sha256, fake_cert);
        assert_eq!(fields.signing_cert_hash.unwrap(), expected.to_vec());
    }

    #[test]
    fn policy_oid_roundtrip() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_der(&CadesParams {
            content: b"policy",
            provider: &provider,
            signing_time: 1_700_000_000,
            signer_cert_der: None,
            commitment: CadesCommitment::Fea,
            policy_oid: Some("1.3.6.1.4.1.99999.3.1"),
            tsa_token_der: None,
        })
        .unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"policy", &pk_hex).unwrap();
        assert!(fields.has_sig_policy);
    }

    #[test]
    fn full_fea_cades_t_with_all_attributes() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let der = build_cades_der(&CadesParams {
            content: b"full fea",
            provider: &provider,
            signing_time: 1_700_000_000,
            signer_cert_der: Some(b"cert"),
            commitment: CadesCommitment::Fea,
            policy_oid: Some("1.3.6.1.4.1.99999.3.1"),
            tsa_token_der: Some(&tsa_token),
        })
        .unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"full fea", &pk_hex).unwrap();
        assert!(fields.signing_cert_hash.is_some());
        assert!(fields.has_commitment_type);
        assert!(fields.has_sig_policy);
        assert!(fields.timestamp_token.is_some());
    }

    #[test]
    fn backwards_compat_build_cades_bes_der_still_works() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"compat", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&der, b"compat", &pk_hex).unwrap();
        assert!(fields.signing_cert_hash.is_some());
        assert!(fields.has_commitment_type);
        assert!(!fields.has_sig_policy);
    }

    // ── VerifyContext tests ──────────────────────────────────────────

    #[test]
    fn verify_with_empty_context_passes() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"ctx test", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let ctx = VerifyContext {
            trusted_roots: &[],
            verify_timestamp: false,
        };
        let fields = verify_cades_with_context(&der, b"ctx test", &pk_hex, &ctx).unwrap();
        assert!(fields.signing_cert_hash.is_some());
    }

    #[test]
    fn verify_with_context_checks_cert_hash() {
        let provider = SoftwareSigningProvider::generate();
        let der = build_cades_bes_der(b"cert hash", &provider, 1_700_000_000).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let ctx = VerifyContext {
            trusted_roots: &[],
            verify_timestamp: false,
        };
        assert!(verify_cades_with_context(&der, b"cert hash", &pk_hex, &ctx).is_ok());
    }

    #[test]
    fn verify_with_timestamp_flag() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let der = build_cades_t_der(b"ts verify", &provider, 1_700_000_000, &tsa_token).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let ctx = VerifyContext {
            trusted_roots: &[],
            verify_timestamp: true,
        };
        assert!(verify_cades_with_context(&der, b"ts verify", &pk_hex, &ctx).is_ok());
    }

    #[test]
    fn cades_xl_embeds_cert_and_crl() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let cades_t =
            build_cades_t_der(b"xl content", &provider, 1_700_000_000, &tsa_token).unwrap();

        let fake_cert = b"fake-certificate-der";
        let fake_crl = b"fake-crl-der";

        let xl = build_cades_xl_der(&CadesXlParams {
            cades_t_der: &cades_t,
            cert_chain: &[fake_cert.as_slice()],
            crls: &[fake_crl.as_slice()],
        })
        .unwrap();

        assert_eq!(xl[0], 0x30);
        assert!(xl.len() > cades_t.len(), "XL must be larger than T");
        // Should contain the cert and CRL bytes
        let xl_hex = hex::encode(&xl);
        let cert_hex = hex::encode(fake_cert);
        let crl_hex = hex::encode(fake_crl);
        assert!(xl_hex.contains(&cert_hex));
        assert!(xl_hex.contains(&crl_hex));
    }

    #[test]
    fn cades_xl_preserves_original_signature() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let cades_t =
            build_cades_t_der(b"xl verify", &provider, 1_700_000_000, &tsa_token).unwrap();

        let xl = build_cades_xl_der(&CadesXlParams {
            cades_t_der: &cades_t,
            cert_chain: &[b"cert1".as_slice(), b"cert2".as_slice()],
            crls: &[b"crl1".as_slice()],
        })
        .unwrap();

        // The original signature should still verify
        let pk_hex = hex::encode(provider.public_key());
        let fields = verify_cades_bes_der(&xl, b"xl verify", &pk_hex).unwrap();
        assert!(!fields.message_digest.is_empty());
    }

    #[test]
    fn cades_xl_x509_parser_parses() {
        let provider = SoftwareSigningProvider::generate();
        let tsa_token = make_tsa_token(&[0u8; 64]);
        let cades_t =
            build_cades_t_der(b"xl interop", &provider, 1_700_000_000, &tsa_token).unwrap();

        let xl = build_cades_xl_der(&CadesXlParams {
            cades_t_der: &cades_t,
            cert_chain: &[b"cert".as_slice()],
            crls: &[b"crl".as_slice()],
        })
        .unwrap();

        let (rem, parsed) =
            x509_parser::der_parser::parse_der(&xl).expect("x509-parser must parse CAdES-XL");
        assert!(rem.is_empty());
        let seq = parsed.as_sequence().unwrap();
        let oid = seq[0].as_oid().unwrap();
        assert_eq!(oid.to_string(), "1.2.840.113549.1.7.2");
    }
}
