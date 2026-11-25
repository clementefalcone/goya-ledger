//! FIPS 140-3 readiness tests.
//!
//! Validates that the module's behavior aligns with FIPS 140-3 requirements:
//! approved-mode enforcement, fail-closed on self-test failure, legacy
//! blocking, state transitions, and API cleanliness.

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode::{self, ModuleState};
use pqc_crypto_module::errors::CryptoError;
use pqc_crypto_module::legacy;

// ═══════════════════════════════════════════════════════════════════
// 1. Module cannot operate before Approved mode
// ═══════════════════════════════════════════════════════════════════

#[test]
fn module_rejects_all_operations_before_initialization() {
    let _state = approved_mode::__test_reset();

    assert_eq!(approved_mode::state(), ModuleState::Uninitialized);

    // All approved APIs must fail
    assert!(matches!(
        api::generate_mldsa_keypair(),
        Err(CryptoError::ModuleNotInitialized)
    ));
    assert!(matches!(
        api::sha3_256(b"test"),
        Err(CryptoError::ModuleNotInitialized)
    ));
    assert!(matches!(
        api::random_bytes(32),
        Err(CryptoError::ModuleNotInitialized)
    ));
}

// ═══════════════════════════════════════════════════════════════════
// 2. Self-tests pass and module transitions to Approved
// ═══════════════════════════════════════════════════════════════════

#[test]
fn initialization_runs_self_tests_and_approves() {
    let _state = approved_mode::__test_reset();

    assert_eq!(approved_mode::state(), ModuleState::Uninitialized);
    api::initialize_approved_mode().unwrap();
    assert_eq!(approved_mode::state(), ModuleState::Approved);
}

// ═══════════════════════════════════════════════════════════════════
// 3. All approved operations work after initialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn all_approved_operations_work_after_init() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // ML-DSA sign/verify
    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"fips test").unwrap();
    api::verify_signature(&kp.public_key, b"fips test", &sig).unwrap();

    // SHA3-256
    let h = api::sha3_256(b"fips").unwrap();
    assert_eq!(h.as_bytes().len(), 32);

    // ML-KEM
    let kem_kp = api::generate_mlkem_keypair().unwrap();
    let (ct, _ss) = api::mlkem_encapsulate(&kem_kp.public_key).unwrap();
    let _ss2 = api::mlkem_decapsulate(&kem_kp.private_key, &ct).unwrap();

    // RNG
    let r = api::random_bytes(64).unwrap();
    assert_eq!(r.len(), 64);
}

// ═══════════════════════════════════════════════════════════════════
// 4. Legacy APIs blocked in Approved mode
// ═══════════════════════════════════════════════════════════════════

#[test]
fn legacy_apis_blocked_in_approved_mode() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    assert!(matches!(
        legacy::legacy_sha256(b"test"),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
    assert!(matches!(
        legacy::legacy_ed25519_verify(&[0u8; 32], b"test", &[0u8; 64]),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
    assert!(matches!(
        legacy::legacy_hmac_sha256(b"key", b"data"),
        Err(CryptoError::NonApprovedAlgorithm)
    ));
}

// ═══════════════════════════════════════════════════════════════════
// 5. No approved API exposes legacy types
// ═══════════════════════════════════════════════════════════════════

#[test]
fn approved_api_returns_only_pqc_types() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let kp = api::generate_mldsa_keypair().unwrap();
    // Public key is 1952 bytes (ML-DSA), not 32 (Ed25519)
    assert_eq!(kp.public_key.as_bytes().len(), 1952);
    // Signature is 3309 bytes (ML-DSA), not 64 (Ed25519)
    let sig = api::sign_message(&kp.private_key, b"type check").unwrap();
    assert_eq!(sig.as_bytes().len(), 3309);
    // Hash is SHA3-256, verified by KAT
    let h = api::sha3_256(b"").unwrap();
    assert_eq!(
        h.to_hex(),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. Module state transitions are valid
// ═══════════════════════════════════════════════════════════════════

#[test]
fn state_transitions_follow_finite_state_model() {
    let _state = approved_mode::__test_reset();

    // Start: Uninitialized
    assert_eq!(approved_mode::state(), ModuleState::Uninitialized);

    // Initialize → SelfTesting → Approved
    api::initialize_approved_mode().unwrap();
    assert_eq!(approved_mode::state(), ModuleState::Approved);

    // Cannot go back to Uninitialized from Approved
    // (only __test_reset can do this, which is test-only)
}

// ═══════════════════════════════════════════════════════════════════
// 7. Error state is fail-closed
// ═══════════════════════════════════════════════════════════════════

#[test]
fn error_state_rejects_all_operations() {
    let _state = approved_mode::__test_reset();

    // Force Error state
    approved_mode::set_state(ModuleState::Error);
    assert_eq!(approved_mode::state(), ModuleState::Error);

    // All operations must fail
    assert!(matches!(
        api::generate_mldsa_keypair(),
        Err(CryptoError::ModuleInErrorState)
    ));
    assert!(matches!(
        api::sha3_256(b"test"),
        Err(CryptoError::ModuleInErrorState)
    ));
    assert!(matches!(
        api::random_bytes(32),
        Err(CryptoError::ModuleInErrorState)
    ));
}

// ═══════════════════════════════════════════════════════════════════
// 8. No panic for normal crypto failure
// ═══════════════════════════════════════════════════════════════════

#[test]
fn crypto_failures_return_errors_not_panics() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // Invalid key → error, not panic
    let bad_key = pqc_crypto_module::types::MldsaPrivateKey(vec![0u8; 10]);
    assert!(api::sign_message(&bad_key, b"test").is_err());

    // Invalid signature → error, not panic
    let bad_pk = pqc_crypto_module::types::MldsaPublicKey(vec![0u8; 1952]);
    let bad_sig = pqc_crypto_module::types::MldsaSignature(vec![0u8; 3309]);
    assert!(api::verify_signature(&bad_pk, b"test", &bad_sig).is_err());
}
