//! API boundary tests — crypto calls before init must fail.

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;
use pqc_crypto_module::errors::CryptoError;
use pqc_crypto_module::types::*;

#[test]
fn sign_before_init_fails() {
    let _state = approved_mode::__test_reset();
    let dummy_key = MldsaPrivateKey(vec![0u8; 4032]);
    let result = api::sign_message(&dummy_key, b"test");
    assert!(
        matches!(result, Err(CryptoError::ModuleNotInitialized)),
        "sign before init must fail: {result:?}"
    );
}

#[test]
fn verify_before_init_fails() {
    let _state = approved_mode::__test_reset();
    let dummy_pk = MldsaPublicKey(vec![0u8; 1952]);
    let dummy_sig = MldsaSignature(vec![0u8; 3309]);
    let result = api::verify_signature(&dummy_pk, b"test", &dummy_sig);
    assert!(matches!(result, Err(CryptoError::ModuleNotInitialized)));
}

#[test]
fn hash_before_init_fails() {
    let _state = approved_mode::__test_reset();
    let result = api::sha3_256(b"test");
    assert!(matches!(result, Err(CryptoError::ModuleNotInitialized)));
}

#[test]
fn keygen_before_init_fails() {
    let _state = approved_mode::__test_reset();
    let result = api::generate_mldsa_keypair();
    assert!(matches!(result, Err(CryptoError::ModuleNotInitialized)));
}

#[test]
fn random_bytes_before_init_fails() {
    let _state = approved_mode::__test_reset();
    let result = api::random_bytes(32);
    assert!(matches!(result, Err(CryptoError::ModuleNotInitialized)));
}

#[test]
fn mlkem_before_init_fails() {
    let _state = approved_mode::__test_reset();
    let dummy_pk = MlKemPublicKey(vec![0u8; 32]);
    let result = api::mlkem_encapsulate(&dummy_pk);
    assert!(matches!(result, Err(CryptoError::ModuleNotInitialized)));
}

#[test]
fn full_api_works_after_init() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    // ML-DSA
    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"boundary").unwrap();
    api::verify_signature(&kp.public_key, b"boundary", &sig).unwrap();

    // SHA3
    let h = api::sha3_256(b"boundary").unwrap();
    assert_eq!(h.as_bytes().len(), 32);

    // ML-KEM
    let kem_kp = api::generate_mlkem_keypair().unwrap();
    let (ct, _ss) = api::mlkem_encapsulate(&kem_kp.public_key).unwrap();
    let _ss2 = api::mlkem_decapsulate(&kem_kp.private_key, &ct).unwrap();

    // Random
    let r = api::random_bytes(64).unwrap();
    assert_eq!(r.len(), 64);
}
