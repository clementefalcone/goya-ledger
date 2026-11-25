use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;

#[test]
fn self_tests_approve_the_module_and_crypto_then_works() {
    let _state = approved_mode::__test_reset();
    assert_eq!(
        approved_mode::state(),
        approved_mode::ModuleState::Uninitialized
    );

    api::initialize_approved_mode().expect("self-tests must pass");
    assert_eq!(approved_mode::state(), approved_mode::ModuleState::Approved);

    let kp = api::generate_mldsa_keypair().unwrap();
    let sig = api::sign_message(&kp.private_key, b"test").unwrap();
    api::verify_signature(&kp.public_key, b"test", &sig).unwrap();

    let hash = api::sha3_256(b"test").unwrap();
    assert_eq!(hash.as_bytes().len(), 32);
}
