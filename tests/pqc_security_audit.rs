//! PQC Security Audit — Adversarial Tests
//!
//! Tests for bypass, downgrade, and forgery resistance across
//! all PQC-related subsystems: algorithm tags, signature consistency,
//! PQC enforcement, dual-signing, hash migration, and gossip.

use std::sync::Mutex;

use rust_bc::consensus::dag::DagBlock;
use rust_bc::consensus::engine::ConsensusEngine;
use rust_bc::consensus::fork_choice::ForkChoiceRule;
use rust_bc::consensus::ConsensusConfig;

/// Serializes tests that touch env vars (global process state).
static ENV_LOCK: Mutex<()> = Mutex::new(());
use rust_bc::crypto::hasher::{hash_with, HashAlgorithm};
use rust_bc::endorsement::policy::EndorsementPolicy;
use rust_bc::endorsement::registry::{MemoryOrgRegistry, OrgRegistry};
use rust_bc::endorsement::types::Endorsement;
use rust_bc::endorsement::validator::validate_endorsements;
use rust_bc::identity::dual_signing::{dual_sign, verify_dual, DualVerifyMode};
use rust_bc::identity::pqc_policy::{enforce_pqc, validate_signature_consistency};
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};

// ═══════════════════════════════════════════════════════════════════
// 1. ALGORITHM TAG INTEGRITY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn reject_mismatched_signature_algorithm_tag_ed25519_as_mldsa() {
    // Attacker declares MlDsa65 but provides a 64-byte Ed25519 signature.
    let result = validate_signature_consistency(
        SigningAlgorithm::MlDsa65,
        &[0u8; 64], // Ed25519-sized
        "forged block",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("mismatch"));
}

#[test]
fn reject_mismatched_signature_algorithm_tag_mldsa_as_ed25519() {
    // Attacker declares Ed25519 but provides a 3309-byte ML-DSA signature.
    let result = validate_signature_consistency(
        SigningAlgorithm::Ed25519,
        &[0u8; 3309], // ML-DSA-sized
        "forged block",
    );
    assert!(result.is_err());
}

#[test]
fn accept_consistent_ed25519_tag_and_size() {
    let result =
        validate_signature_consistency(SigningAlgorithm::Ed25519, &[0u8; 64], "honest block");
    assert!(result.is_ok());
}

#[test]
fn accept_consistent_mldsa_tag_and_size() {
    let result =
        validate_signature_consistency(SigningAlgorithm::MlDsa65, &[0u8; 3309], "honest block");
    assert!(result.is_ok());
}

#[test]
fn reject_tampered_algorithm_field_in_consensus() {
    // A DagBlock tagged MlDsa65 but with a 64-byte signature must be rejected.
    let validators = vec!["alice".to_string()];
    let mut engine = ConsensusEngine::new(
        ConsensusConfig::default(),
        ForkChoiceRule::HeaviestSubtree,
        validators,
        0,
    );

    let mut block = DagBlock::new(
        [1u8; 32],
        [0u8; 32], // genesis parent
        0,
        0,
        0, // timestamp within slot 0
        "alice".to_string(),
        vec![42u8; 64], // Non-zero 64-byte Ed25519-sized signature
    );
    // Tamper: claim MlDsa65 but keep 64-byte signature
    block.signature_algorithm = SigningAlgorithm::MlDsa65;

    let result = engine.accept_block(block);
    assert!(result.is_err(), "tampered algorithm tag must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("mismatch"),
        "error should mention mismatch: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 2. PQC ENFORCEMENT (POLICY LAYER)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn reject_classic_signature_when_pqc_required() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("REQUIRE_PQC_SIGNATURES", "true");
    let result = enforce_pqc(SigningAlgorithm::Ed25519, "block");
    std::env::remove_var("REQUIRE_PQC_SIGNATURES");
    assert!(result.is_err());
}

#[test]
fn enforce_pqc_on_all_message_types() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("REQUIRE_PQC_SIGNATURES", "true");

    let block_result = enforce_pqc(SigningAlgorithm::Ed25519, "block signature");
    let endorsement_result = enforce_pqc(SigningAlgorithm::Ed25519, "endorsement signature");
    let gossip_result = enforce_pqc(SigningAlgorithm::Ed25519, "gossip alive");
    let dag_result = enforce_pqc(SigningAlgorithm::Ed25519, "DAG block");

    std::env::remove_var("REQUIRE_PQC_SIGNATURES");

    assert!(block_result.is_err(), "block must be rejected");
    assert!(endorsement_result.is_err(), "endorsement must be rejected");
    assert!(gossip_result.is_err(), "gossip must be rejected");
    assert!(dag_result.is_err(), "DAG block must be rejected");
}

#[test]
fn pqc_enforcement_accepts_mldsa_for_all_types() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("REQUIRE_PQC_SIGNATURES", "true");

    let block = enforce_pqc(SigningAlgorithm::MlDsa65, "block");
    let endorsement = enforce_pqc(SigningAlgorithm::MlDsa65, "endorsement");
    let gossip = enforce_pqc(SigningAlgorithm::MlDsa65, "gossip");

    std::env::remove_var("REQUIRE_PQC_SIGNATURES");

    assert!(block.is_ok());
    assert!(endorsement.is_ok());
    assert!(gossip.is_ok());
}

#[test]
fn reject_classic_endorsement_when_pqc_required() {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rust_bc::endorsement::org::Organization;

    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("REQUIRE_PQC_SIGNATURES", "true");

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    let payload = [5u8; 32];
    let sig = sk.sign(&payload).to_bytes().to_vec();

    let endorsement = Endorsement {
        signer_did: "did:bc:org1:signer".to_string(),
        org_id: "org1".to_string(),
        signature: sig,
        signature_algorithm: SigningAlgorithm::Ed25519,
        payload_hash: payload,
        timestamp: 0,
    };

    let reg = MemoryOrgRegistry::new();
    let org = Organization::new(
        "org1",
        "org1MSP",
        vec!["did:bc:org1:admin".into()],
        vec![],
        vec![pk],
    )
    .unwrap();
    reg.register_org(&org).unwrap();

    let policy = EndorsementPolicy::AnyOf(vec!["org1".into()]);
    let result = validate_endorsements(&[endorsement], &policy, &reg, None);

    std::env::remove_var("REQUIRE_PQC_SIGNATURES");

    assert!(
        result.is_err(),
        "classical endorsement must be rejected when PQC required"
    );
}

#[test]
fn reject_gossip_with_classic_signature_when_pqc_required() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("REQUIRE_PQC_SIGNATURES", "true");
    let result = enforce_pqc(SigningAlgorithm::Ed25519, "gossip alive message");
    std::env::remove_var("REQUIRE_PQC_SIGNATURES");
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// 3. DUAL-SIGNING SECURITY
// ═══════════════════════════════════════════════════════════════════

#[test]
fn reject_dual_sign_if_pqc_invalid_in_both_mode() {
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let data = b"critical payload";

    let ds = dual_sign(data, &ed, &pqc).unwrap();

    // Corrupt the PQC signature
    let mut bad_pqc_sig = ds.secondary_signature.clone();
    bad_pqc_sig[0] ^= 0xff;

    let result = verify_dual(
        || ed.verify(data, &ds.primary_signature),
        Some(|| pqc.verify(data, &bad_pqc_sig)),
        DualVerifyMode::Both,
    )
    .unwrap();

    assert!(
        !result,
        "CRITICAL: corrupted PQC signature must cause rejection in Both mode"
    );
}

#[test]
fn either_mode_accepts_classical_only_proving_unsafe() {
    // PROOF that "either" mode is unsafe: valid Ed25519 + invalid PQC = accepted
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let data = b"bypass test";

    let ds = dual_sign(data, &ed, &pqc).unwrap();
    let mut bad_pqc = ds.secondary_signature.clone();
    bad_pqc[0] ^= 0xff;

    let result = verify_dual(
        || ed.verify(data, &ds.primary_signature),
        Some(|| pqc.verify(data, &bad_pqc)),
        DualVerifyMode::Either,
    )
    .unwrap();

    assert!(
        result,
        "Either mode accepts classical-only — this is UNSAFE for production"
    );
}

#[test]
fn both_mode_rejects_when_classical_valid_pqc_invalid() {
    let ed = SoftwareSigningProvider::generate();
    let data = b"strict test";

    let ed_sig = ed.sign(data).unwrap();

    let result = verify_dual(
        || ed.verify(data, &ed_sig),
        Some(|| Ok(false)), // PQC verification fails
        DualVerifyMode::Both,
    )
    .unwrap();

    assert!(
        !result,
        "Both mode must reject when PQC signature is invalid"
    );
}

#[test]
fn both_mode_rejects_when_pqc_valid_classical_invalid() {
    let pqc = MlDsaSigningProvider::generate();
    let data = b"reverse strict test";

    let pqc_sig = pqc.sign(data).unwrap();

    let result = verify_dual(
        || Ok(false), // Classical verification fails
        Some(|| pqc.verify(data, &pqc_sig)),
        DualVerifyMode::Both,
    )
    .unwrap();

    assert!(
        !result,
        "Both mode must reject when classical signature is invalid"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 4. TLS PQC HANDSHAKE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ensure_tls_pqc_provider_differs_from_default() {
    // Verify the PQ provider includes different key exchange groups than default.
    let default_provider = rustls::crypto::aws_lc_rs::default_provider();
    let pqc_provider = rustls_post_quantum::provider();

    // PQ provider should have ML-KEM key exchange groups that differ from default.
    // We compare the named groups; PQ provider includes X25519MLKEM768.
    let default_kx_count = default_provider.kx_groups.len();
    let pqc_kx_count = pqc_provider.kx_groups.len();

    // PQ provider includes X25519MLKEM768 as the preferred group.
    assert!(
        pqc_kx_count >= default_kx_count,
        "PQ provider must include at least as many KX groups as default"
    );

    // Verify they are not identical by checking the first group name.
    // PQ provider's first group should be X25519MLKEM768.
    let pq_first = pqc_provider.kx_groups[0].name();
    assert!(
        format!("{:?}", pq_first).contains("MLKEM")
            || format!("{:?}", pq_first).contains("mlkem")
            || pq_first != default_provider.kx_groups[0].name(),
        "PQ provider's preferred KX group should be ML-KEM hybrid, got {:?}",
        pq_first
    );
}

#[test]
fn tls_pqc_flag_controls_provider_selection() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("TLS_PQC_KEM");
    assert!(rust_bc::tls::pqc_kem_enabled());

    std::env::set_var("TLS_PQC_KEM", "true");
    assert!(rust_bc::tls::pqc_kem_enabled());

    std::env::set_var("TLS_PQC_KEM", "false");
    assert!(!rust_bc::tls::pqc_kem_enabled());

    std::env::remove_var("TLS_PQC_KEM");
}

// ═══════════════════════════════════════════════════════════════════
// 5. HASH ALGORITHM MIGRATION
// ═══════════════════════════════════════════════════════════════════

#[test]
fn hash_changes_with_algorithm_switch() {
    let data = b"block payload for hashing";
    let h256 = hash_with(HashAlgorithm::Sha256, data);
    let h3_256 = hash_with(HashAlgorithm::Sha3_256, data);
    assert_ne!(
        h256, h3_256,
        "different algorithms must produce different hashes for same input"
    );
}

#[test]
fn old_blocks_still_validate_after_sha3_migration() {
    // An old block hashed with SHA-256 must remain verifiable
    // even when the node switches to SHA3-256 by default.
    let block_data = b"genesis block payload";

    // Hash with SHA-256 (as the old block would have been)
    let original_hash = hash_with(HashAlgorithm::Sha256, block_data);

    // Now "switch" to SHA3 — but use the stored hash_algorithm field to verify
    let stored_algorithm = HashAlgorithm::Sha256; // read from block
    let verification_hash = hash_with(stored_algorithm, block_data);

    assert_eq!(
        original_hash, verification_hash,
        "old SHA-256 blocks must be verifiable using their stored hash_algorithm"
    );

    // The node's current algorithm would produce a different hash
    let new_algo_hash = hash_with(HashAlgorithm::Sha3_256, block_data);
    assert_ne!(
        original_hash, new_algo_hash,
        "new algorithm must not accidentally match old hashes"
    );
}

#[test]
fn block_stores_hash_algorithm_field() {
    use rust_bc::crypto::hasher::HashAlgorithm;
    use rust_bc::storage::traits::Block;

    let block = Block {
        height: 0,
        timestamp: 0,
        parent_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        transactions: vec![],
        proposer: "test".to_string(),
        signature: vec![0u8; 64],
        signature_algorithm: Default::default(),
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha3_256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    };

    // Serialize and deserialize — hash_algorithm must survive
    let json = serde_json::to_string(&block).unwrap();
    let decoded: Block = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.hash_algorithm, HashAlgorithm::Sha3_256);
}

#[test]
fn legacy_block_without_hash_algorithm_defaults_to_sha256() {
    use rust_bc::crypto::hasher::HashAlgorithm;
    use rust_bc::storage::traits::Block;

    // Build a block, serialize it, strip hash_algorithm, then deserialize.
    let block = Block {
        height: 0,
        timestamp: 0,
        parent_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        transactions: vec![],
        proposer: "legacy".to_string(),
        signature: vec![0u8; 64],
        signature_algorithm: Default::default(),
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    };
    let full_json = serde_json::to_string(&block).unwrap();
    // Strip the hash_algorithm field to simulate a legacy block
    let legacy_json = full_json
        .replace(",\"hash_algorithm\":\"Sha256\"", "")
        .replace("\"hash_algorithm\":\"Sha256\",", "");

    let decoded: Block = serde_json::from_str(&legacy_json).unwrap();
    assert_eq!(
        decoded.hash_algorithm,
        HashAlgorithm::Sha256,
        "legacy blocks without hash_algorithm must default to SHA-256"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. CROSS-CUTTING: SIGNATURE FORGERY RESISTANCE
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ed25519_signature_does_not_verify_as_mldsa() {
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let data = b"cross-algorithm forgery test";

    let ed_sig = ed.sign(data).unwrap();
    // Try to verify Ed25519 signature with ML-DSA provider — must fail
    let result = pqc.verify(data, &ed_sig);
    assert!(
        result.is_err() || matches!(result, Ok(false)),
        "Ed25519 sig must not verify under ML-DSA"
    );
}

#[test]
fn mldsa_signature_does_not_verify_as_ed25519() {
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let data = b"cross-algorithm forgery test";

    let pqc_sig = pqc.sign(data).unwrap();
    // Try to verify ML-DSA signature with Ed25519 provider — must fail
    let result = ed.verify(data, &pqc_sig);
    assert!(
        result.is_err(),
        "ML-DSA sig must fail verification under Ed25519 (wrong size)"
    );
}

#[test]
fn zero_length_signature_rejected_by_consistency_check() {
    let result = validate_signature_consistency(SigningAlgorithm::Ed25519, &[], "empty signature");
    assert!(result.is_err());
}

#[test]
fn random_bytes_do_not_verify() {
    let ed = SoftwareSigningProvider::generate();
    let pqc = MlDsaSigningProvider::generate();
    let data = b"test data";

    // Random 64 bytes should not verify as Ed25519
    let random_sig = vec![42u8; 64];
    assert!(!ed.verify(data, &random_sig).unwrap());

    // Random 3309 bytes should not verify as ML-DSA
    let random_pqc_sig = vec![42u8; 3309];
    let result = pqc.verify(data, &random_pqc_sig);
    assert!(result.is_err() || matches!(result, Ok(false)));
}
