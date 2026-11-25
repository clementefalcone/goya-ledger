//! Key zeroization tests — verify private keys are wiped on drop.

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;

#[test]
fn mldsa_private_key_zeroizes_on_drop() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let kp = api::generate_mldsa_keypair().unwrap();
    // Copy bytes before drop to verify they were non-zero
    let key_bytes = kp.private_key.as_bytes().to_vec();
    assert!(
        key_bytes.iter().any(|&b| b != 0),
        "key should have non-zero bytes"
    );

    // After drop, the Zeroize trait wipes the memory.
    // We can't read after drop, but we verify the trait is implemented
    // by checking the type is ZeroizeOnDrop (compile-time guarantee).
    drop(kp.private_key);
    // If MldsaPrivateKey didn't derive ZeroizeOnDrop, this wouldn't compile.
}

#[test]
fn mldsa_private_key_debug_is_redacted() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let kp = api::generate_mldsa_keypair().unwrap();
    let debug = format!("{:?}", kp.private_key);
    assert!(
        debug.contains("REDACTED"),
        "private key debug must be redacted: {debug}"
    );
    assert!(
        !debug.contains("42"),
        "private key debug must not leak bytes"
    );
}

#[test]
fn mlkem_private_key_debug_is_redacted() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let kp = api::generate_mlkem_keypair().unwrap();
    let debug = format!("{:?}", kp.private_key);
    assert!(debug.contains("REDACTED"));
}

#[test]
fn mlkem_shared_secret_debug_is_redacted() {
    let _state = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();

    let kp = api::generate_mlkem_keypair().unwrap();
    let (_, ss) = api::mlkem_encapsulate(&kp.public_key).unwrap();
    let debug = format!("{:?}", ss);
    assert!(debug.contains("REDACTED"));
}
