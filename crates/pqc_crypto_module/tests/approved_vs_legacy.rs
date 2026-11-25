//! Tests enforcing separation between Approved and Legacy crypto APIs.
//!
//! Legacy APIs must be BLOCKED when the module is in Approved mode.
//! Approved APIs must NOT expose legacy types.

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;
use pqc_crypto_module::errors::CryptoError;
use pqc_crypto_module::legacy;

// ═══════════════════════════════════════════════════════════════════
// 1. Legacy APIs fail in Approved mode
// ═══════════════════════════════════════════════════════════════════

#[test]
fn legacy_ed25519_verify_fails_in_approved_mode() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let result = legacy::legacy_ed25519_verify(&[0u8; 32], b"test", &[0u8; 64]);
    assert!(
        matches!(result, Err(CryptoError::NonApprovedAlgorithm)),
        "legacy Ed25519 verify must fail in Approved mode: {result:?}"
    );
}

#[test]
fn legacy_sha256_fails_in_approved_mode() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let result = legacy::legacy_sha256(b"test");
    assert!(
        matches!(result, Err(CryptoError::NonApprovedAlgorithm)),
        "legacy SHA-256 must fail in Approved mode: {result:?}"
    );
}

#[test]
fn legacy_hmac_sha256_fails_in_approved_mode() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let result = legacy::legacy_hmac_sha256(b"key", b"data");
    assert!(
        matches!(result, Err(CryptoError::NonApprovedAlgorithm)),
        "legacy HMAC-SHA256 must fail in Approved mode: {result:?}"
    );
}

#[test]
fn legacy_ed25519_sign_fails_in_approved_mode() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let sk = pqc_crypto_module::legacy::ed25519::SigningKey::from_bytes(&[1u8; 32]);
    let result = legacy::legacy_ed25519_sign(&sk, b"test");
    assert!(
        matches!(result, Err(CryptoError::NonApprovedAlgorithm)),
        "legacy Ed25519 sign must fail in Approved mode: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 2. Legacy APIs work before initialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn legacy_sha256_works_before_approved_mode() {
    let _state = approved_mode::__test_reset();
    // Module NOT initialized — legacy should work

    let result = legacy::legacy_sha256(b"test");
    assert!(result.is_ok(), "legacy SHA-256 should work before init");
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn legacy_ed25519_verify_works_before_approved_mode() {
    let _state = approved_mode::__test_reset();

    // Generate a valid Ed25519 signature
    use pqc_crypto_module::legacy::ed25519::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let msg = b"legacy test";
    let sig = sk.sign(msg);

    let result = legacy::legacy_ed25519_verify(&pk, msg, &sig.to_bytes());
    assert!(
        result.is_ok(),
        "legacy Ed25519 verify should work before init"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. Approved API is clean of legacy types
// ═══════════════════════════════════════════════════════════════════

#[test]
fn approved_api_does_not_expose_legacy() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // The approved API only returns ML-DSA types, not Ed25519.
    let kp = api::generate_mldsa_keypair().unwrap();
    assert_eq!(kp.public_key.as_bytes().len(), 1952); // ML-DSA, not 32 (Ed25519)

    let sig = api::sign_message(&kp.private_key, b"test").unwrap();
    assert_eq!(sig.as_bytes().len(), 3309); // ML-DSA, not 64 (Ed25519)

    let hash = api::sha3_256(b"test").unwrap();
    assert_eq!(hash.as_bytes().len(), 32); // SHA3-256
}

// ═══════════════════════════════════════════════════════════════════
// 4. No implicit fallback
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa_failure_does_not_fallback_to_ed25519() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // Bad key — must fail, not fallback to Ed25519
    let bad_key = pqc_crypto_module::types::MldsaPrivateKey(vec![0u8; 100]);
    let result = api::sign_message(&bad_key, b"test");
    assert!(result.is_err());

    // Legacy must still be blocked
    let legacy_result = legacy::legacy_ed25519_verify(&[0u8; 32], b"test", &[0u8; 64]);
    assert!(matches!(
        legacy_result,
        Err(CryptoError::NonApprovedAlgorithm)
    ));
}

#[test]
fn sha3_failure_does_not_fallback_to_sha256() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // SHA3 works in approved mode
    assert!(api::sha3_256(b"test").is_ok());

    // SHA256 is blocked
    assert!(matches!(
        legacy::legacy_sha256(b"test"),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
}

// ═══════════════════════════════════════════════════════════════════
// 5. Full approved-mode flow
// ═══════════════════════════════════════════════════════════════════

#[test]
fn approved_mode_allows_only_mldsa_sha3_mlkem() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // Approved APIs work
    assert!(api::generate_mldsa_keypair().is_ok());
    assert!(api::sha3_256(b"data").is_ok());
    assert!(api::generate_mlkem_keypair().is_ok());
    assert!(api::random_bytes(32).is_ok());

    // All legacy APIs fail
    assert!(matches!(
        legacy::legacy_ed25519_verify(&[0u8; 32], b"x", &[0u8; 64]),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
    assert!(matches!(
        legacy::legacy_sha256(b"x"),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
    assert!(matches!(
        legacy::legacy_hmac_sha256(b"k", b"x"),
        Err(CryptoError::NonApprovedAlgorithm)
    ));

    let sk = pqc_crypto_module::legacy::ed25519::SigningKey::from_bytes(&[1u8; 32]);
    assert!(matches!(
        legacy::legacy_ed25519_sign(&sk, b"x"),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
}

// ═══════════════════════════════════════════════════════════════════
// 6. ensure_not_approved guard
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ensure_not_approved_passes_before_init() {
    let _state = approved_mode::__test_reset();
    assert!(legacy::ensure_not_approved().is_ok());
}

#[test]
fn ensure_not_approved_fails_after_init() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();
    assert!(matches!(
        legacy::ensure_not_approved(),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
}
