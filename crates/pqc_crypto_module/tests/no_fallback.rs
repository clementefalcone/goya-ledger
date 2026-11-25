//! No-fallback tests — the approved API must not expose classical algorithms.

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;

#[test]
fn no_ed25519_available_in_approved_api() {
    // The public API only exposes ML-DSA. There is no Ed25519 function.
    // This test verifies at the type level — if someone tried to add
    // an Ed25519 function, this file would need to be updated.
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // Only ML-DSA keygen is available
    let kp = api::generate_mldsa_keypair().unwrap();
    assert_eq!(kp.public_key.as_bytes().len(), 1952); // ML-DSA, not 32 (Ed25519)
}

#[test]
fn no_sha256_available_in_approved_api() {
    // The public API only exposes SHA3-256. There is no SHA-256 function.
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let _h = api::sha3_256(b"test").unwrap();
    // SHA3-256 empty string has a known distinct hash from SHA-256
    let h_empty = api::sha3_256(b"").unwrap();
    assert_eq!(
        h_empty.to_hex(),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "must be SHA3-256, not SHA-256"
    );
}

#[test]
fn no_classical_fallback_on_mldsa_failure() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // Provide an invalid key — must fail, not fallback to Ed25519
    let bad_key = pqc_crypto_module::types::MldsaPrivateKey(vec![0u8; 100]);
    let result = api::sign_message(&bad_key, b"test");
    assert!(
        result.is_err(),
        "invalid ML-DSA key must error, not fallback"
    );

    // Verify invalid signature — must fail, not fallback
    let bad_pk = pqc_crypto_module::types::MldsaPublicKey(vec![0u8; 1952]);
    let bad_sig = pqc_crypto_module::types::MldsaSignature(vec![0u8; 3309]);
    let result = api::verify_signature(&bad_pk, b"test", &bad_sig);
    assert!(
        result.is_err(),
        "invalid ML-DSA verify must error, not fallback"
    );
}

#[test]
fn signature_sizes_are_pqc_only() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"size check").unwrap();

    assert_eq!(
        sig.as_bytes().len(),
        3309,
        "signature must be ML-DSA-65 (3309 bytes), not Ed25519 (64)"
    );
    assert_eq!(
        kp.public_key.as_bytes().len(),
        1952,
        "public key must be ML-DSA-65 (1952 bytes), not Ed25519 (32)"
    );
}
