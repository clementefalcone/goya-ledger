//! NIST ACVP ML-DSA-65 KeyGen Known Answer Tests.
//!
//! Source: NIST ACVP-Server gen-val/json-files/ML-DSA-keyGen-FIPS204
//! (official NIST test vectors, not community-derived)
//!
//! Tests deterministic keygen: seed → (pk, sk). If the output diverges
//! from the NIST-published expected values, our PQClean binding is not
//! FIPS 204 conformant.

use pqc_crypto_module::mldsa::generate_keypair_from_seed;

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;

fn init() -> std::sync::MutexGuard<'static, ()> {
    let guard = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();
    guard
}

#[derive(serde::Deserialize)]
struct VectorFile {
    algorithm: String,
    vectors: Vec<KeyGenVector>,
}

#[derive(serde::Deserialize)]
struct KeyGenVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: String,
    pk: String,
    sk: String,
}

fn load_vectors() -> VectorFile {
    let json = include_str!("data/acvp_mldsa65_keygen.json");
    serde_json::from_str(json).expect("parse ACVP keygen vectors")
}

// ═══════════════════════════════════════════════════════════════════
// NIST ACVP KeyGen: seed → expected pk
// ═══════════════════════════════════════════════════════════════════

#[test]
fn acvp_keygen_public_key_matches_nist() {
    let vf = load_vectors();
    assert_eq!(vf.algorithm, "ML-DSA-65");

    for v in &vf.vectors {
        let seed_bytes = hex::decode(&v.seed).unwrap();
        let expected_pk = hex::decode(&v.pk).unwrap();

        assert_eq!(
            seed_bytes.len(),
            32,
            "tcId={}: seed must be 32 bytes",
            v.tc_id
        );
        assert_eq!(
            expected_pk.len(),
            1952,
            "tcId={}: pk must be 1952 bytes",
            v.tc_id
        );

        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let kp = generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(
            kp.public_key.as_bytes(),
            &expected_pk[..],
            "tcId={}: public key does not match NIST ACVP expected value",
            v.tc_id
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// NIST ACVP KeyGen: seed → expected sk
// ═══════════════════════════════════════════════════════════════════

#[test]
fn acvp_keygen_secret_key_matches_nist() {
    let vf = load_vectors();

    for v in &vf.vectors {
        let seed_bytes = hex::decode(&v.seed).unwrap();
        let expected_sk = hex::decode(&v.sk).unwrap();

        assert_eq!(
            expected_sk.len(),
            4032,
            "tcId={}: sk must be 4032 bytes",
            v.tc_id
        );

        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let kp = generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(
            kp.private_key.as_bytes(),
            &expected_sk[..],
            "tcId={}: secret key does not match NIST ACVP expected value",
            v.tc_id
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Cross-validation: sign with ACVP-derived key, verify succeeds
// ═══════════════════════════════════════════════════════════════════

#[test]
fn acvp_derived_key_signs_and_verifies() {
    let _g = init();
    let vf = load_vectors();

    for v in &vf.vectors {
        let seed: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
        let kp = generate_keypair_from_seed(&seed).unwrap();

        let sig = api::sign_message(&kp.private_key, b"ACVP cross-check").unwrap();

        api::verify_signature(&kp.public_key, b"ACVP cross-check", &sig).unwrap_or_else(|e| {
            panic!("tcId={}: ACVP-derived key sign/verify failed: {e}", v.tc_id)
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// Determinism: same seed → same keypair (idempotent)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn acvp_keygen_is_deterministic() {
    let vf = load_vectors();
    let v = &vf.vectors[0];
    let seed: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();

    let kp1 = generate_keypair_from_seed(&seed).unwrap();
    let kp2 = generate_keypair_from_seed(&seed).unwrap();

    assert_eq!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes());
    assert_eq!(kp1.private_key.as_bytes(), kp2.private_key.as_bytes());
}
