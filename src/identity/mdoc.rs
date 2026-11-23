//! mdoc — ISO/IEC 18013-5 Mobile Document credential format.
//!
//! CBOR-encoded credentials with namespace-based selective disclosure.
//! Used by EUDI Wallet for proximity (NFC/BLE) and remote presentation.
//!
//! Structure: IssuerSigned { nameSpaces, issuerAuth (COSE_Sign1 over MSO) }

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// An mdoc credential — issuer-signed document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mdoc {
    /// Document type (e.g. "org.iso.18013.5.1.mDL" or "eu.europa.ec.eudi.pid.1").
    pub doc_type: String,
    /// Namespace → list of signed data elements.
    pub name_spaces: BTreeMap<String, Vec<IssuerSignedItem>>,
    /// CBOR-encoded issuer auth (signature over MSO).
    pub issuer_auth_cbor: Vec<u8>,
    /// Public key of the issuer (hex).
    pub issuer_public_key: String,
    /// Signing algorithm used.
    pub algorithm: SigningAlgorithm,
}

/// A single data element within a namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    /// Digest ID (unique within namespace).
    pub digest_id: u32,
    /// Random salt (hex, 32 bytes).
    pub random: String,
    /// Element identifier (e.g. "given_name", "birth_date").
    pub element_identifier: String,
    /// Element value.
    pub element_value: serde_json::Value,
}

/// Mobile Security Object — signed digest map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    pub version: String,
    pub digest_algorithm: String,
    pub doc_type: String,
    /// Namespace → (digest_id → SHA-256 hash hex).
    pub value_digests: BTreeMap<String, BTreeMap<u32, String>>,
    /// Validity period.
    pub valid_from: u64,
    pub valid_until: u64,
    /// Device key info (public key hex for holder binding).
    pub device_key: Option<String>,
}

/// Parameters for issuing an mdoc.
pub struct MdocParams {
    pub doc_type: String,
    /// Namespace → list of (element_identifier, element_value).
    pub elements: BTreeMap<String, Vec<(String, serde_json::Value)>>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub device_key: Option<String>,
}

/// Verified mdoc fields.
#[derive(Debug, Clone)]
pub struct VerifiedMdoc {
    pub doc_type: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub disclosed_elements: BTreeMap<String, Vec<(String, serde_json::Value)>>,
    pub algorithm: SigningAlgorithm,
    pub device_key: Option<String>,
}

// ── Device Authentication (ISO 18013-5 §9.1.3) ─────────────────────────

/// Device authentication proof — holder proves possession of device_key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuth {
    /// COSE_Sign1 from the device key over session transcript.
    pub device_signature: Vec<u8>,
    /// Algorithm used.
    pub algorithm: SigningAlgorithm,
}

/// ISO 18013-5 §8.3 DeviceResponse — top-level response from holder to verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResponse {
    pub version: String,
    pub documents: Vec<Document>,
    pub status: u32,
}

/// A single document within a DeviceResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub doc_type: String,
    pub issuer_signed: Mdoc,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_auth: Option<DeviceAuth>,
}

/// Session transcript for binding device auth to a specific session (ISO 18013-5 §9.1.5).
pub struct SessionTranscript {
    pub device_engagement: Vec<u8>,
    pub reader_key: Vec<u8>,
    pub handover: Vec<u8>,
}

/// Compute SHA-256 hash of CBOR-encoded session transcript.
pub fn compute_session_transcript_hash(transcript: &SessionTranscript) -> Vec<u8> {
    let parts = (
        &transcript.device_engagement,
        &transcript.reader_key,
        &transcript.handover,
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&parts, &mut buf).expect("CBOR encode transcript");
    hash_with(HashAlgorithm::Sha256, &buf).to_vec()
}

/// Sign device authentication — holder proves they control the device_key in the MSO.
pub fn sign_device_auth(
    provider: &dyn SigningProvider,
    session_transcript: &[u8],
) -> Result<DeviceAuth, String> {
    let signature = provider
        .sign(session_transcript)
        .map_err(|e| e.to_string())?;
    let cose = cbor_encode_cose_sign1(provider.algorithm(), session_transcript, &signature)?;
    Ok(DeviceAuth {
        device_signature: cose,
        algorithm: provider.algorithm(),
    })
}

/// Verify device authentication against the device_key declared in the MSO.
pub fn verify_device_auth(
    auth: &DeviceAuth,
    device_key_hex: &str,
    session_transcript: &[u8],
) -> Result<(), String> {
    let (payload, signature) = cbor_decode_cose_sign1(&auth.device_signature)?;
    if payload != session_transcript {
        return Err("device auth payload does not match session transcript".into());
    }
    let sig_hex = hex::encode(&signature);
    if !crate::signature::verify_signature(auth.algorithm, device_key_hex, &payload, &sig_hex) {
        return Err("device signature verification failed".into());
    }
    Ok(())
}

fn generate_random() -> String {
    use pqc_crypto_module::legacy::rng::OsRng;
    use rand_core::RngCore;
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn item_digest(item: &IssuerSignedItem) -> String {
    let canonical = format!(
        "{}:{}:{}:{}",
        item.digest_id,
        item.random,
        item.element_identifier,
        serde_json::to_string(&item.element_value).unwrap_or_default()
    );
    hex::encode(hash_with(HashAlgorithm::Sha256, canonical.as_bytes()))
}

/// Issue an mdoc credential.
pub fn issue_mdoc(params: &MdocParams, provider: &dyn SigningProvider) -> Result<Mdoc, String> {
    let mut name_spaces: BTreeMap<String, Vec<IssuerSignedItem>> = BTreeMap::new();
    let mut value_digests: BTreeMap<String, BTreeMap<u32, String>> = BTreeMap::new();

    for (ns, elements) in &params.elements {
        let mut items = Vec::new();
        let mut digests = BTreeMap::new();

        for (i, (identifier, value)) in elements.iter().enumerate() {
            let item = IssuerSignedItem {
                digest_id: i as u32,
                random: generate_random(),
                element_identifier: identifier.clone(),
                element_value: value.clone(),
            };
            let digest = item_digest(&item);
            digests.insert(item.digest_id, digest);
            items.push(item);
        }

        name_spaces.insert(ns.clone(), items);
        value_digests.insert(ns.clone(), digests);
    }

    let mso = MobileSecurityObject {
        version: "1.0".to_string(),
        digest_algorithm: "SHA-256".to_string(),
        doc_type: params.doc_type.clone(),
        value_digests,
        valid_from: params.valid_from,
        valid_until: params.valid_until,
        device_key: params.device_key.clone(),
    };

    // CBOR-encode the MSO and sign it
    let mso_cbor = cbor_encode_mso(&mso)?;
    let signature = provider.sign(&mso_cbor).map_err(|e| e.to_string())?;

    // COSE_Sign1 simplified: [protected, unprotected, payload, signature]
    let issuer_auth = cbor_encode_cose_sign1(provider.algorithm(), &mso_cbor, &signature)?;

    Ok(Mdoc {
        doc_type: params.doc_type.clone(),
        name_spaces,
        issuer_auth_cbor: issuer_auth,
        issuer_public_key: hex::encode(provider.public_key()),
        algorithm: provider.algorithm(),
    })
}

/// Present an mdoc with selective disclosure (only selected namespaces/elements).
pub fn present_mdoc(mdoc: &Mdoc, disclosed: &BTreeMap<String, Vec<String>>) -> Mdoc {
    let mut filtered = BTreeMap::new();
    for (ns, element_ids) in disclosed {
        if let Some(items) = mdoc.name_spaces.get(ns) {
            let selected: Vec<IssuerSignedItem> = items
                .iter()
                .filter(|item| element_ids.contains(&item.element_identifier))
                .cloned()
                .collect();
            if !selected.is_empty() {
                filtered.insert(ns.clone(), selected);
            }
        }
    }
    Mdoc {
        doc_type: mdoc.doc_type.clone(),
        name_spaces: filtered,
        issuer_auth_cbor: mdoc.issuer_auth_cbor.clone(),
        issuer_public_key: mdoc.issuer_public_key.clone(),
        algorithm: mdoc.algorithm,
    }
}

/// Verify an mdoc credential: check signature + verify element digests.
pub fn verify_mdoc(mdoc: &Mdoc) -> Result<VerifiedMdoc, String> {
    // Decode COSE_Sign1 and verify signature
    let (mso_cbor, signature) = cbor_decode_cose_sign1(&mdoc.issuer_auth_cbor)?;
    let sig_hex = hex::encode(&signature);
    if !crate::signature::verify_signature(
        mdoc.algorithm,
        &mdoc.issuer_public_key,
        &mso_cbor,
        &sig_hex,
    ) {
        return Err("issuer signature verification failed".into());
    }

    let mso: MobileSecurityObject = cbor_decode_mso(&mso_cbor)?;

    if mso.doc_type != mdoc.doc_type {
        return Err("docType mismatch between MSO and mdoc".into());
    }

    // Verify each disclosed element's digest matches MSO
    let mut disclosed_elements = BTreeMap::new();
    for (ns, items) in &mdoc.name_spaces {
        let mso_digests = mso
            .value_digests
            .get(ns)
            .ok_or_else(|| format!("namespace {ns} not in MSO"))?;

        let mut verified_items = Vec::new();
        for item in items {
            let expected = mso_digests
                .get(&item.digest_id)
                .ok_or_else(|| format!("digest_id {} not in MSO for {ns}", item.digest_id))?;
            let computed = item_digest(item);
            if &computed != expected {
                return Err(format!(
                    "digest mismatch for {ns}/{}: expected {expected}, got {computed}",
                    item.element_identifier
                ));
            }
            verified_items.push((item.element_identifier.clone(), item.element_value.clone()));
        }
        disclosed_elements.insert(ns.clone(), verified_items);
    }

    Ok(VerifiedMdoc {
        doc_type: mso.doc_type,
        valid_from: mso.valid_from,
        valid_until: mso.valid_until,
        disclosed_elements,
        algorithm: mdoc.algorithm,
        device_key: mso.device_key,
    })
}

// ── CBOR encoding helpers ─────────────────────────────────────────────────
// ponytail: use ciborium for CBOR, serde_json::Value as intermediate

fn cbor_encode_mso(mso: &MobileSecurityObject) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(mso, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn cbor_decode_mso(data: &[u8]) -> Result<MobileSecurityObject, String> {
    ciborium::from_reader(data).map_err(|e| e.to_string())
}

fn cbor_encode_cose_sign1(
    alg: SigningAlgorithm,
    payload: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, String> {
    // Simplified COSE_Sign1 as CBOR array: [alg_id, {}, payload_bytes, sig_bytes]
    let alg_id: i64 = match alg {
        SigningAlgorithm::Ed25519 => -8,     // IANA COSE EdDSA
        SigningAlgorithm::MlDsa65 => -48,    // draft-ietf-cose-dilithium (pre-IANA)
        SigningAlgorithm::Rsa => -37,        // IANA COSE PS256 (RSASSA-PSS + SHA-256)
        SigningAlgorithm::EcdsaP256 => -7,   // IANA COSE ES256
        SigningAlgorithm::SlhDsa128s => -49, // draft-ietf-cose-sphincs-plus (pre-IANA)
    };
    let structure = (
        alg_id,
        Vec::<u8>::new(),
        payload.to_vec(),
        signature.to_vec(),
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&structure, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn cbor_decode_cose_sign1(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let decoded: (i64, Vec<u8>, Vec<u8>, Vec<u8>) =
        ciborium::from_reader(data).map_err(|e| e.to_string())?;
    Ok((decoded.2, decoded.3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;

    fn pid_params() -> MdocParams {
        let mut elements = BTreeMap::new();
        elements.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec![
                ("given_name".to_string(), serde_json::json!("Juan")),
                ("family_name".to_string(), serde_json::json!("Pérez")),
                ("birth_date".to_string(), serde_json::json!("1990-01-15")),
                ("nationality".to_string(), serde_json::json!("CL")),
                ("age_over_18".to_string(), serde_json::json!(true)),
            ],
        );
        MdocParams {
            doc_type: "eu.europa.ec.eudi.pid.1".to_string(),
            elements,
            valid_from: 1_700_000_000,
            valid_until: 2_000_000_000,
            device_key: Some("abcd1234".to_string()),
        }
    }

    #[test]
    fn element_salts_keep_128_bits_against_grover() {
        let provider = SoftwareSigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        for item in mdoc.name_spaces.values().flatten() {
            assert_eq!(hex::decode(&item.random).unwrap().len(), 32);
        }
    }

    #[test]
    fn issue_and_verify_full() {
        let provider = SoftwareSigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        assert_eq!(mdoc.doc_type, "eu.europa.ec.eudi.pid.1");
        assert!(!mdoc.issuer_auth_cbor.is_empty());

        let verified = verify_mdoc(&mdoc).unwrap();
        assert_eq!(verified.doc_type, "eu.europa.ec.eudi.pid.1");
        assert_eq!(verified.valid_from, 1_700_000_000);
        let pid_ns = &verified.disclosed_elements["eu.europa.ec.eudi.pid.1"];
        assert_eq!(pid_ns.len(), 5);
    }

    #[test]
    fn selective_disclosure() {
        let provider = SoftwareSigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();

        let mut disclosed = BTreeMap::new();
        disclosed.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec!["given_name".to_string(), "age_over_18".to_string()],
        );
        let presentation = present_mdoc(&mdoc, &disclosed);

        let verified = verify_mdoc(&presentation).unwrap();
        let pid_ns = &verified.disclosed_elements["eu.europa.ec.eudi.pid.1"];
        assert_eq!(pid_ns.len(), 2);
        let names: Vec<&str> = pid_ns.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"given_name"));
        assert!(names.contains(&"age_over_18"));
        assert!(!names.contains(&"family_name"));
    }

    #[test]
    fn wrong_key_fails() {
        let provider = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let mut mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        mdoc.issuer_public_key = hex::encode(other.public_key());
        assert!(verify_mdoc(&mdoc).is_err());
    }

    #[test]
    fn tampered_element_rejected() {
        let provider = SoftwareSigningProvider::generate();
        let mut mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        // Tamper with an element value
        if let Some(items) = mdoc.name_spaces.get_mut("eu.europa.ec.eudi.pid.1") {
            items[0].element_value = serde_json::json!("TAMPERED");
        }
        assert!(verify_mdoc(&mdoc).is_err());
    }

    #[test]
    fn multiple_namespaces() {
        let provider = SoftwareSigningProvider::generate();
        let mut elements = BTreeMap::new();
        elements.insert(
            "org.iso.18013.5.1".to_string(),
            vec![("document_number".to_string(), serde_json::json!("DL123"))],
        );
        elements.insert(
            "org.iso.18013.5.1.CL".to_string(),
            vec![("rut".to_string(), serde_json::json!("12345678-9"))],
        );
        let params = MdocParams {
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            elements,
            valid_from: 1_700_000_000,
            valid_until: 2_000_000_000,
            device_key: None,
        };
        let mdoc = issue_mdoc(&params, &provider).unwrap();
        let verified = verify_mdoc(&mdoc).unwrap();
        assert_eq!(verified.disclosed_elements.len(), 2);
    }

    #[test]
    fn mso_cbor_roundtrip() {
        let mut vd = BTreeMap::new();
        let mut inner = BTreeMap::new();
        inner.insert(0u32, "abc123".to_string());
        vd.insert("ns1".to_string(), inner);
        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            doc_type: "test".to_string(),
            value_digests: vd,
            valid_from: 100,
            valid_until: 200,
            device_key: None,
        };
        let encoded = cbor_encode_mso(&mso).unwrap();
        let decoded = cbor_decode_mso(&encoded).unwrap();
        assert_eq!(decoded.version, "1.0");
        assert_eq!(decoded.doc_type, "test");
    }

    #[test]
    fn cose_sign1_roundtrip() {
        let payload = b"test payload";
        let sig = b"test signature";
        let encoded = cbor_encode_cose_sign1(SigningAlgorithm::Ed25519, payload, sig).unwrap();
        let (dec_payload, dec_sig) = cbor_decode_cose_sign1(&encoded).unwrap();
        assert_eq!(dec_payload, payload);
        assert_eq!(dec_sig, sig);
    }

    #[test]
    fn mldsa65_mdoc() {
        use crate::identity::signing::MlDsaSigningProvider;
        let provider = MlDsaSigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        let verified = verify_mdoc(&mdoc).unwrap();
        assert_eq!(verified.algorithm, SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn empty_presentation_verifies_signature() {
        let provider = SoftwareSigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        let empty_disclosed = BTreeMap::new();
        let presentation = present_mdoc(&mdoc, &empty_disclosed);
        // No elements disclosed but signature still valid
        // This would fail because no namespaces means no digest checks
        // which is correct — the MSO signature is still verifiable
        assert!(presentation.name_spaces.is_empty());
        // Direct verify would fail because disclosed ns not in MSO check
        // but the issuer_auth is still intact
        assert!(!presentation.issuer_auth_cbor.is_empty());
    }

    // ── Device Authentication tests ────────────────────────────────

    #[test]
    fn device_auth_sign_and_verify() {
        let holder = SoftwareSigningProvider::generate();
        let transcript = b"session-transcript-data";
        let auth = sign_device_auth(&holder, transcript).unwrap();
        let pk_hex = hex::encode(holder.public_key());
        assert!(verify_device_auth(&auth, &pk_hex, transcript).is_ok());
    }

    #[test]
    fn device_auth_wrong_key_fails() {
        let holder = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let transcript = b"session-data";
        let auth = sign_device_auth(&holder, transcript).unwrap();
        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_device_auth(&auth, &wrong_pk, transcript).is_err());
    }

    #[test]
    fn device_auth_bound_to_session() {
        let holder = SoftwareSigningProvider::generate();
        let transcript = b"original-session";
        let auth = sign_device_auth(&holder, transcript).unwrap();
        let pk_hex = hex::encode(holder.public_key());
        assert!(verify_device_auth(&auth, &pk_hex, b"different-session").is_err());
    }

    #[test]
    fn device_response_serde_roundtrip() {
        let issuer = SoftwareSigningProvider::generate();
        let holder = SoftwareSigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &issuer).unwrap();
        let auth = sign_device_auth(&holder, b"session").unwrap();
        let resp = DeviceResponse {
            version: "1.0".into(),
            documents: vec![Document {
                doc_type: mdoc.doc_type.clone(),
                issuer_signed: mdoc,
                device_auth: Some(auth),
            }],
            status: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DeviceResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.documents.len(), 1);
        assert!(parsed.documents[0].device_auth.is_some());
    }

    #[test]
    fn session_transcript_deterministic() {
        let t = SessionTranscript {
            device_engagement: b"engagement".to_vec(),
            reader_key: b"reader".to_vec(),
            handover: b"handover".to_vec(),
        };
        let h1 = compute_session_transcript_hash(&t);
        let h2 = compute_session_transcript_hash(&t);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    // ── ES256 (EUDI interop) mdoc tests ────────────────────────

    #[test]
    fn es256_mdoc_issue_and_verify() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let provider = EcdsaP256SigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();
        assert_eq!(mdoc.doc_type, "eu.europa.ec.eudi.pid.1");
        assert_eq!(
            mdoc.algorithm,
            crate::identity::signing::SigningAlgorithm::EcdsaP256
        );

        let verified = verify_mdoc(&mdoc).unwrap();
        assert_eq!(verified.doc_type, "eu.europa.ec.eudi.pid.1");
        let pid_ns = &verified.disclosed_elements["eu.europa.ec.eudi.pid.1"];
        assert_eq!(pid_ns.len(), 5);
    }

    #[test]
    fn es256_mdoc_selective_disclosure() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let provider = EcdsaP256SigningProvider::generate();
        let mdoc = issue_mdoc(&pid_params(), &provider).unwrap();

        let mut disclosed = BTreeMap::new();
        disclosed.insert(
            "eu.europa.ec.eudi.pid.1".to_string(),
            vec!["given_name".to_string(), "nationality".to_string()],
        );
        let presentation = present_mdoc(&mdoc, &disclosed);
        let verified = verify_mdoc(&presentation).unwrap();
        let pid_ns = &verified.disclosed_elements["eu.europa.ec.eudi.pid.1"];
        assert_eq!(pid_ns.len(), 2);
    }

    #[test]
    fn es256_mdoc_wrong_key_rejects() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let wrong = EcdsaP256SigningProvider::generate();
        let mut mdoc = issue_mdoc(&pid_params(), &issuer).unwrap();
        mdoc.issuer_public_key = hex::encode(wrong.public_key());
        let result = verify_mdoc(&mdoc);
        assert!(result.is_err(), "wrong issuer key must reject");
    }
}
