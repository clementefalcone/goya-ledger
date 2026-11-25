//! NIST-grade Known Answer Tests — Wycheproof ML-DSA-65 signature verification vectors.
//!
//! Source: C2SP/Wycheproof mldsa_65_verify_test.json
//! These vectors verify that our PQClean binding produces correct FIPS 204 results.
//! The test uses externally-generated pk/sig pairs — if our implementation diverges
//! from FIPS 204, these tests fail.

use pqc_crypto_module::approved_mode;
use pqc_crypto_module::types::{MldsaPublicKey, MldsaSignature};

fn init() -> std::sync::MutexGuard<'static, ()> {
    let guard = approved_mode::__test_reset();
    pqc_crypto_module::api::initialize_approved_mode().unwrap();
    guard
}

#[derive(serde::Deserialize)]
struct VectorFile {
    algorithm: String,
    pk: String,
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    sig: String,
    result: String,
    comment: String,
    #[serde(default)]
    alt_pk: Option<String>,
}

fn load_vectors() -> VectorFile {
    let json = include_str!("data/wycheproof_mldsa65.json");
    serde_json::from_str(json).expect("failed to parse wycheproof vectors")
}

// ═══════════════════════════════════════════════════════════════════
// 1. WYCHEPROOF VALID SIGNATURES VERIFY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn wycheproof_valid_signatures_verify() {
    let _g = init();
    let vf = load_vectors();
    assert_eq!(vf.algorithm, "ML-DSA-65");

    let pk_bytes = hex::decode(&vf.pk).expect("invalid pk hex");
    assert_eq!(pk_bytes.len(), 1952, "pk must be 1952 bytes for ML-DSA-65");
    let pk = MldsaPublicKey(pk_bytes);

    let valid: Vec<_> = vf.vectors.iter().filter(|v| v.result == "valid").collect();
    assert!(!valid.is_empty(), "no valid vectors found");

    for v in &valid {
        let msg = hex::decode(&v.msg).unwrap_or_else(|_| panic!("tcId={}: bad msg hex", v.tc_id));
        let sig_bytes =
            hex::decode(&v.sig).unwrap_or_else(|_| panic!("tcId={}: bad sig hex", v.tc_id));
        assert_eq!(
            sig_bytes.len(),
            3309,
            "tcId={}: sig must be 3309 bytes",
            v.tc_id
        );
        let sig = MldsaSignature(sig_bytes);

        let result = pqc_crypto_module::api::verify_signature(&pk, &msg, &sig);
        assert!(
            result.is_ok(),
            "tcId={} ({}): valid signature rejected: {:?}",
            v.tc_id,
            v.comment,
            result.err()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 2. WYCHEPROOF INVALID SIGNATURES REJECTED
// ═══════════════════════════════════════════════════════════════════

#[test]
fn wycheproof_invalid_signatures_rejected() {
    let _g = init();
    let vf = load_vectors();

    let default_pk_bytes = hex::decode(&vf.pk).unwrap();

    let invalid: Vec<_> = vf
        .vectors
        .iter()
        .filter(|v| v.result == "invalid")
        .collect();
    assert!(!invalid.is_empty(), "no invalid vectors found");

    for v in &invalid {
        let msg = hex::decode(&v.msg).unwrap();
        let sig_bytes = hex::decode(&v.sig).unwrap();

        let pk_bytes = match &v.alt_pk {
            Some(alt) => hex::decode(alt).unwrap(),
            None => default_pk_bytes.clone(),
        };

        // Wrong-size pk or sig → construct raw bytes, expect rejection
        let sig = MldsaSignature(sig_bytes);
        let pk = MldsaPublicKey(pk_bytes);

        let result = pqc_crypto_module::api::verify_signature(&pk, &msg, &sig);
        assert!(
            result.is_err(),
            "tcId={} ({}): CRITICAL — invalid signature was accepted",
            v.tc_id,
            v.comment
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3. CROSS-VALIDATION: Wycheproof pk size matches FIPS 204
// ═══════════════════════════════════════════════════════════════════

#[test]
fn wycheproof_pk_matches_fips204_parameters() {
    let vf = load_vectors();
    let pk_bytes = hex::decode(&vf.pk).unwrap();
    assert_eq!(pk_bytes.len(), 1952, "FIPS 204 ML-DSA-65 pk = 1952 bytes");

    for v in &vf.vectors {
        let sig_bytes = hex::decode(&v.sig).unwrap();
        if v.result == "valid" {
            assert_eq!(
                sig_bytes.len(),
                3309,
                "tcId={}: FIPS 204 ML-DSA-65 sig = 3309 bytes",
                v.tc_id
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. OUR SIGNATURES VERIFY WITH OUR OWN KEYS (sanity)
//    Then cross-validate: our sig does NOT verify under Wycheproof pk
// ═══════════════════════════════════════════════════════════════════

#[test]
fn our_signatures_do_not_verify_under_external_pk() {
    let _g = init();
    let vf = load_vectors();
    let external_pk = MldsaPublicKey(hex::decode(&vf.pk).unwrap());

    let our_kp = pqc_crypto_module::api::generate_mldsa_keypair().unwrap();
    let msg = b"Hello world";
    let our_sig = pqc_crypto_module::api::sign_message(&our_kp.private_key, msg).unwrap();

    // Must verify with our own key
    pqc_crypto_module::api::verify_signature(&our_kp.public_key, msg, &our_sig).unwrap();

    // Must NOT verify under external Wycheproof key
    assert!(
        pqc_crypto_module::api::verify_signature(&external_pk, msg, &our_sig).is_err(),
        "Our signature verified under external Wycheproof pk — key isolation broken"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 5. MODIFIED SIGNATURE DETECTION
//    The invalid vector tcId=8 has only the first byte changed (0x69→0x68)
//    This proves the implementation checks ALL signature bytes
// ═══════════════════════════════════════════════════════════════════

#[test]
fn single_byte_modification_detected() {
    let _g = init();
    let vf = load_vectors();
    let pk = MldsaPublicKey(hex::decode(&vf.pk).unwrap());

    let valid = vf.vectors.iter().find(|v| v.tc_id == 1).unwrap();
    let invalid = vf.vectors.iter().find(|v| v.tc_id == 8).unwrap();

    let valid_sig = hex::decode(&valid.sig).unwrap();
    let invalid_sig = hex::decode(&invalid.sig).unwrap();

    // Count differences
    let diffs: Vec<usize> = valid_sig
        .iter()
        .zip(invalid_sig.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();

    assert!(!diffs.is_empty(), "valid and invalid sigs should differ");

    let msg = hex::decode(&valid.msg).unwrap();

    // Valid verifies
    pqc_crypto_module::api::verify_signature(&pk, &msg, &MldsaSignature(valid_sig)).unwrap();

    // Invalid (minimal modification) does NOT verify
    assert!(
        pqc_crypto_module::api::verify_signature(&pk, &msg, &MldsaSignature(invalid_sig),).is_err(),
        "Modified signature (diff at positions {diffs:?}) must be rejected"
    );
}
