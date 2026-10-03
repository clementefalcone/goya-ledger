//! Tier 3 — PQC End-to-End Integration Tests
//!
//! Proves ML-DSA-65 and ML-KEM-768 work in the real DLT, not just in isolation.
//! 8. Block signed with ML-DSA → stored in RocksDB → retrieved → signature verified
//! 9. TLS PQC handshake — ML-KEM-768 in key exchange

use rust_bc::crypto::hasher::HashAlgorithm;
use rust_bc::identity::signing::{MlDsaSigningProvider, SigningAlgorithm, SigningProvider};
use rust_bc::storage::traits::{Block, BlockStore};
use rust_bc::storage::RocksDbBlockStore;
use tempfile::TempDir;

fn temp_store() -> (RocksDbBlockStore, TempDir) {
    let dir = TempDir::new().unwrap();
    let store = RocksDbBlockStore::new(dir.path().to_str().unwrap()).unwrap();
    (store, dir)
}

// ═══════════════════════════════════════════════════════════════════
// 8. BLOCK: ML-DSA SIGN → STORE → RETRIEVE → VERIFY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pqc_block_sign_store_retrieve_verify() {
    let signer = MlDsaSigningProvider::generate();
    let (store, _dir) = temp_store();

    // Create block payload
    let block = Block {
        height: 0,
        timestamp: 1692300000,
        parent_hash: [0u8; 32],
        merkle_root: [0xAB; 32],
        transactions: vec!["tx_pqc_test_001".to_string()],
        proposer: "pqc-validator-1".to_string(),
        signature: vec![],
        signature_algorithm: SigningAlgorithm::MlDsa65,
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha3_256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    };

    // Sign the block
    let payload = serde_json::to_vec(&block).unwrap();
    let signature = signer.sign(&payload).unwrap();

    assert_eq!(
        signature.len(),
        3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );

    let signed_block = Block {
        signature: signature.clone(),
        ..block
    };

    // Store in RocksDB
    store.write_block(&signed_block).unwrap();

    // Retrieve from RocksDB
    let retrieved = store.read_block(0).unwrap();

    // Verify structural integrity
    assert_eq!(retrieved.height, 0);
    assert_eq!(retrieved.proposer, "pqc-validator-1");
    assert_eq!(retrieved.signature_algorithm, SigningAlgorithm::MlDsa65);
    assert_eq!(retrieved.hash_algorithm, HashAlgorithm::Sha3_256);
    assert_eq!(retrieved.signature.len(), 3309);
    assert_eq!(retrieved.transactions, vec!["tx_pqc_test_001"]);

    // Verify signature matches what was stored
    assert_eq!(
        retrieved.signature, signature,
        "Signature corrupted during storage roundtrip"
    );

    // Verify the signature cryptographically
    let verify_block = Block {
        signature: vec![],
        ..retrieved.clone()
    };
    let verify_payload = serde_json::to_vec(&verify_block).unwrap();
    let valid = signer
        .verify(&verify_payload, &retrieved.signature)
        .unwrap();
    assert!(
        valid,
        "ML-DSA-65 signature verification failed after RocksDB roundtrip"
    );
}

#[test]
fn pqc_block_wrong_signer_rejected() {
    let signer_a = MlDsaSigningProvider::generate();
    let signer_b = MlDsaSigningProvider::generate();

    let payload = b"block payload for cross-key test";
    let sig_a = signer_a.sign(payload).unwrap();

    // Signature from A must not verify under B
    let result = signer_b.verify(payload, &sig_a);
    assert!(
        result.is_err() || matches!(result, Ok(false)),
        "ML-DSA signature from signer A verified under signer B"
    );
}

#[test]
fn pqc_block_tampered_payload_rejected() {
    let signer = MlDsaSigningProvider::generate();
    let (store, _dir) = temp_store();

    let block = Block {
        height: 1,
        timestamp: 1692300001,
        parent_hash: [0u8; 32],
        merkle_root: [0xCD; 32],
        transactions: vec!["tx_honest".to_string()],
        proposer: "honest-node".to_string(),
        signature: vec![],
        signature_algorithm: SigningAlgorithm::MlDsa65,
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha3_256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    };

    let payload = serde_json::to_vec(&block).unwrap();
    let signature = signer.sign(&payload).unwrap();

    let signed_block = Block { signature, ..block };

    store.write_block(&signed_block).unwrap();
    let retrieved = store.read_block(1).unwrap();

    // Tamper: change a transaction
    let tampered = Block {
        transactions: vec!["tx_evil_modified".to_string()],
        signature: vec![],
        ..retrieved.clone()
    };
    let tampered_payload = serde_json::to_vec(&tampered).unwrap();

    let valid = signer
        .verify(&tampered_payload, &retrieved.signature)
        .unwrap();
    assert!(
        !valid,
        "Tampered block payload verified — PQC signature binding is broken"
    );
}

#[test]
fn pqc_block_signature_survives_json_roundtrip() {
    let signer = MlDsaSigningProvider::generate();

    let payload = b"json roundtrip test payload";
    let signature = signer.sign(payload).unwrap();

    assert_eq!(signature.len(), 3309);

    // Simulate network transmission: serialize block to JSON, deserialize
    let block = Block {
        height: 42,
        timestamp: 0,
        parent_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        transactions: vec![],
        proposer: "test".to_string(),
        signature: signature.clone(),
        signature_algorithm: SigningAlgorithm::MlDsa65,
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha3_256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    };

    let json = serde_json::to_string(&block).unwrap();
    let deserialized: Block = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.signature, signature, "Sig corrupted via JSON");
    assert_eq!(deserialized.signature.len(), 3309);
    assert_eq!(deserialized.signature_algorithm, SigningAlgorithm::MlDsa65);

    // Verify after deserialization
    let valid = signer.verify(payload, &deserialized.signature).unwrap();
    assert!(valid, "Sig invalid after JSON roundtrip");
}

#[test]
fn pqc_block_ed25519_sig_not_accepted_as_mldsa() {
    use rust_bc::identity::signing::SoftwareSigningProvider;

    let ed_signer = SoftwareSigningProvider::generate();
    let mldsa_signer = MlDsaSigningProvider::generate();

    let payload = b"cross-algorithm block test";
    let ed_sig = ed_signer.sign(payload).unwrap();

    assert_eq!(ed_sig.len(), 64, "Ed25519 sig is 64 bytes");

    // Ed25519 signature must not verify under ML-DSA provider
    let result = mldsa_signer.verify(payload, &ed_sig);
    assert!(
        result.is_err() || matches!(result, Ok(false)),
        "Ed25519 sig accepted by ML-DSA verifier — algorithm confusion"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 9. TLS PQC KEY EXCHANGE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn tls_pqc_provider_includes_mlkem() {
    let pqc_provider = rustls_post_quantum::provider();

    // PQ provider should include ML-KEM-768 hybrid key exchange
    let group_names: Vec<String> = pqc_provider
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect();

    let has_mlkem = group_names
        .iter()
        .any(|n| n.contains("MLKEM") || n.contains("mlkem"));

    assert!(
        has_mlkem,
        "PQ TLS provider missing ML-KEM group. Available: {group_names:?}"
    );
}

#[test]
fn tls_pqc_provider_builds_valid_config() {
    let pqc_provider = rustls_post_quantum::provider();

    // Must be able to build a rustls ClientConfig with PQ provider
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(pqc_provider))
        .with_safe_default_protocol_versions();

    assert!(
        config.is_ok(),
        "Failed to build TLS config with PQ provider"
    );
}

#[test]
fn tls_pqc_ciphersuites_include_tls13() {
    let pqc_provider = rustls_post_quantum::provider();

    let has_tls13 = pqc_provider
        .cipher_suites
        .iter()
        .any(|cs| cs.version() == &rustls::version::TLS13);

    assert!(
        has_tls13,
        "PQ TLS provider must include TLS 1.3 cipher suites for ML-KEM"
    );
}

#[test]
fn tls_pqc_env_toggle_works() {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap();

    std::env::remove_var("TLS_PQC_KEM");
    assert!(rust_bc::tls::pqc_kem_enabled());

    std::env::set_var("TLS_PQC_KEM", "true");
    assert!(rust_bc::tls::pqc_kem_enabled());

    std::env::set_var("TLS_PQC_KEM", "false");
    assert!(!rust_bc::tls::pqc_kem_enabled());

    std::env::remove_var("TLS_PQC_KEM");
}
