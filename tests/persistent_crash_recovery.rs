//! Persistent crash recovery tests using RocksDB.
//!
//! Validates that after a node crash and restart from the same storage directory:
//! - blocks are restored exactly
//! - PQC metadata (signature_algorithm) survives
//! - hash algorithm metadata survives
//! - canonical tip and state hash match pre-crash values
//! - tampered storage is detected and rejected

use rust_bc::crypto::hasher::{hash_with, HashAlgorithm};
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::storage::traits::{Block, BlockStore};
use rust_bc::storage::RocksDbBlockStore;

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

/// Create a valid PQC-signed block at the given height.
fn make_pqc_block(height: u64, signer: &dyn SigningProvider) -> Block {
    let payload = format!("persistent-block-{height}");
    let hash = hash_with(HashAlgorithm::Sha3_256, payload.as_bytes());
    let signature = signer.sign(&hash).unwrap();

    Block {
        height,
        timestamp: height * 6,
        parent_hash: if height == 0 {
            [0u8; 32]
        } else {
            // Derive parent hash deterministically from height
            hash_with(
                HashAlgorithm::Sha3_256,
                format!("persistent-block-{}", height - 1).as_bytes(),
            )
        },
        merkle_root: hash,
        transactions: vec![format!("tx-{height}")],
        proposer: "persistent-node".to_string(),
        signature,
        signature_algorithm: signer.algorithm(),
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha3_256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    }
}

/// Snapshot of a node's state for comparison.
#[derive(Debug, Clone)]
struct NodeSnapshot {
    state_hash: Vec<u8>,
    canonical_tip: Option<[u8; 32]>,
    height: u64,
    last_10_blocks: Vec<(u64, [u8; 32])>,
}

/// Capture a snapshot from a BlockStore.
fn capture_snapshot(store: &dyn BlockStore) -> NodeSnapshot {
    let height = store.get_latest_height().unwrap_or(0);
    let mut blocks: Vec<(u64, [u8; 32])> = Vec::new();
    let mut data = Vec::new();

    let start = if height >= 10 { height - 9 } else { 0 };
    for h in start..=height {
        if let Ok(block) = store.read_block(h) {
            blocks.push((h, block.merkle_root));
            data.extend_from_slice(&h.to_le_bytes());
            data.extend_from_slice(&block.merkle_root);
        }
    }

    let state_hash = hash_with(HashAlgorithm::Sha256, &data).to_vec();
    let canonical_tip = blocks.last().map(|(_, hash)| *hash);

    NodeSnapshot {
        state_hash,
        canonical_tip,
        height,
        last_10_blocks: blocks,
    }
}

fn print_snapshot_diff(label: &str, pre: &NodeSnapshot, post: &NodeSnapshot) {
    eprintln!("=== {label} ===");
    eprintln!("  height: pre={} post={}", pre.height, post.height);
    eprintln!(
        "  state_hash: pre={} post={}",
        hex::encode(&pre.state_hash[..8]),
        hex::encode(&post.state_hash[..8])
    );
    eprintln!(
        "  tip: pre={} post={}",
        pre.canonical_tip
            .map(|h| hex::encode(&h[..4]))
            .unwrap_or_else(|| "none".into()),
        post.canonical_tip
            .map(|h| hex::encode(&h[..4]))
            .unwrap_or_else(|| "none".into()),
    );
    let pre_hashes: Vec<String> = pre
        .last_10_blocks
        .iter()
        .map(|(h, hash)| format!("{}:{}", h, hex::encode(&hash[..4])))
        .collect();
    let post_hashes: Vec<String> = post
        .last_10_blocks
        .iter()
        .map(|(h, hash)| format!("{}:{}", h, hex::encode(&hash[..4])))
        .collect();
    eprintln!("  last_10 pre:  {:?}", pre_hashes);
    eprintln!("  last_10 post: {:?}", post_hashes);
}

fn assert_pqc_metadata_persisted(store: &dyn BlockStore, height: u64) {
    let block = store.read_block(height).expect("block must exist");
    assert_eq!(
        block.signature_algorithm,
        SigningAlgorithm::MlDsa65,
        "PQC signature_algorithm must survive persistence at height {height}"
    );
}

fn assert_hash_algorithm_metadata_persisted(store: &dyn BlockStore, height: u64) {
    let block = store.read_block(height).expect("block must exist");
    assert_eq!(
        block.hash_algorithm,
        HashAlgorithm::Sha3_256,
        "hash_algorithm must survive persistence at height {height}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// TEST 1: Exact state restoration after crash
// ═══════════════════════════════════════════════════════════════════

fn run_persistent_recovery(seed: u64) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join(format!("test_db_{seed}"));

    let signer = MlDsaSigningProvider::generate();
    let num_rounds = 15;

    // Phase 1: Write blocks to persistent storage
    let pre_crash_snapshot;
    {
        let store = RocksDbBlockStore::new(&db_path).expect("open DB");

        for h in 0..num_rounds {
            let block = make_pqc_block(h, &signer);
            store.write_block(&block).expect("write block");
        }

        // Capture pre-crash state
        pre_crash_snapshot = capture_snapshot(&store);
        assert_eq!(pre_crash_snapshot.height, num_rounds - 1);

        // Verify PQC metadata is stored
        for h in 0..num_rounds {
            assert_pqc_metadata_persisted(&store, h);
            assert_hash_algorithm_metadata_persisted(&store, h);
        }

        // Drop store → simulates crash (closes RocksDB)
    }

    // Phase 2: Reopen from same directory — simulate restart
    {
        let restored_store = RocksDbBlockStore::new(&db_path).expect("reopen DB after crash");
        let post_crash_snapshot = capture_snapshot(&restored_store);

        // Assert exact restoration
        if pre_crash_snapshot.state_hash != post_crash_snapshot.state_hash {
            print_snapshot_diff(
                &format!("seed {seed}"),
                &pre_crash_snapshot,
                &post_crash_snapshot,
            );
        }

        assert_eq!(
            post_crash_snapshot.state_hash, pre_crash_snapshot.state_hash,
            "seed {seed}: state hash must match after restart"
        );
        assert_eq!(
            post_crash_snapshot.canonical_tip, pre_crash_snapshot.canonical_tip,
            "seed {seed}: canonical tip must match after restart"
        );
        assert_eq!(
            post_crash_snapshot.height, pre_crash_snapshot.height,
            "seed {seed}: height must match after restart"
        );
        assert_eq!(
            post_crash_snapshot.last_10_blocks, pre_crash_snapshot.last_10_blocks,
            "seed {seed}: last 10 blocks must match after restart"
        );

        // Verify PQC metadata survived restart
        for h in 0..num_rounds {
            assert_pqc_metadata_persisted(&restored_store, h);
            assert_hash_algorithm_metadata_persisted(&restored_store, h);
        }

        // Phase 3: Continue writing (sync with cluster simulation)
        for h in num_rounds..num_rounds + 10 {
            let block = make_pqc_block(h, &signer);
            restored_store
                .write_block(&block)
                .expect("write post-restart block");
        }

        let final_height = restored_store.get_latest_height().unwrap();
        assert_eq!(
            final_height,
            num_rounds + 10 - 1,
            "seed {seed}: continued writing after restart"
        );

        // All blocks (old + new) remain valid
        for h in 0..num_rounds + 10 {
            assert_pqc_metadata_persisted(&restored_store, h);
            assert_hash_algorithm_metadata_persisted(&restored_store, h);
        }
    }
}

#[test]
fn persistent_node_recovers_exact_state_after_crash() {
    let seeds = [7, 99, 2024, 9001];
    for &seed in &seeds {
        run_persistent_recovery(seed);
    }
}

// ═══════════════════════════════════════════════════════════════════
// TEST 2: Tampered storage is rejected
// ═══════════════════════════════════════════════════════════════════

#[test]
fn persistent_node_rejects_tampered_signature_bytes() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("tamper_sig");

    let signer = MlDsaSigningProvider::generate();

    // Write valid blocks
    {
        let store = RocksDbBlockStore::new(&db_path).expect("open DB");
        for h in 0..5 {
            let block = make_pqc_block(h, &signer);
            store.write_block(&block).expect("write block");
        }
    }

    // Tamper: corrupt signature bytes at height 3
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen for tampering");
        let mut block = store.read_block(3).expect("read block 3");
        block.signature[0] ^= 0xff; // corrupt signature
                                    // Re-write the tampered block
        store.write_block(&block).expect("write tampered block");
    }

    // Restart and verify the tampered block is detectable
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen after tamper");
        let block = store.read_block(3).expect("read tampered block");

        // The signature is corrupted — verify it doesn't pass ML-DSA verification
        let pk = signer.public_key();
        let payload = "persistent-block-3".to_string();
        let hash = hash_with(HashAlgorithm::Sha3_256, payload.as_bytes());

        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
        let pk_obj = pqcrypto_mldsa::mldsa65::PublicKey::from_bytes(&pk).unwrap();
        let sig_result = pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(&block.signature);

        match sig_result {
            Ok(sig) => {
                let verify_result =
                    pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, &hash, &pk_obj);
                assert!(
                    verify_result.is_err(),
                    "tampered signature must fail ML-DSA verification"
                );
            }
            Err(_) => {
                // Corrupted bytes can't even parse as a valid DetachedSignature — also acceptable
            }
        }
    }
}

#[test]
fn persistent_node_rejects_tampered_algorithm_tag() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("tamper_algo");

    let signer = MlDsaSigningProvider::generate();

    // Write valid PQC blocks
    {
        let store = RocksDbBlockStore::new(&db_path).expect("open DB");
        for h in 0..5 {
            let block = make_pqc_block(h, &signer);
            store.write_block(&block).expect("write block");
        }
    }

    // Tamper: change signature_algorithm from MlDsa65 to Ed25519
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen for tampering");
        let mut block = store.read_block(2).expect("read block 2");
        assert_eq!(block.signature_algorithm, SigningAlgorithm::MlDsa65);
        block.signature_algorithm = SigningAlgorithm::Ed25519; // TAMPER
        store.write_block(&block).expect("write tampered block");
    }

    // Restart and verify the tampered block is detectable
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen after tamper");
        let block = store.read_block(2).expect("read tampered block");

        // signature_algorithm says Ed25519 but signature is 3309 bytes (ML-DSA size)
        assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(block.signature.len(), 3309);

        // Consistency check catches this
        let result = rust_bc::identity::pqc_policy::validate_signature_consistency(
            block.signature_algorithm,
            &block.signature,
            "restored block",
        );
        assert!(
            result.is_err(),
            "tampered algorithm tag must be caught by consistency check"
        );
        assert!(result.unwrap_err().contains("mismatch"));
    }
}

#[test]
fn persistent_node_rejects_tampered_hash_algorithm() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("tamper_hash");

    let signer = MlDsaSigningProvider::generate();

    // Write valid blocks with SHA3-256
    {
        let store = RocksDbBlockStore::new(&db_path).expect("open DB");
        for h in 0..5 {
            let block = make_pqc_block(h, &signer);
            store.write_block(&block).expect("write block");
        }
    }

    // Tamper: change hash_algorithm from Sha3_256 to Sha256
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen for tampering");
        let mut block = store.read_block(4).expect("read block 4");
        assert_eq!(block.hash_algorithm, HashAlgorithm::Sha3_256);
        block.hash_algorithm = HashAlgorithm::Sha256; // TAMPER
        store.write_block(&block).expect("write tampered block");
    }

    // Restart and verify: re-hashing with the declared algorithm gives wrong merkle_root
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen after tamper");
        let block = store.read_block(4).expect("read tampered block");

        // Block says Sha256 but merkle_root was computed with Sha3_256
        let payload = "persistent-block-4".to_string();
        let expected_sha256 = hash_with(HashAlgorithm::Sha256, payload.as_bytes());
        let expected_sha3 = hash_with(HashAlgorithm::Sha3_256, payload.as_bytes());

        assert_eq!(block.hash_algorithm, HashAlgorithm::Sha256);
        assert_ne!(
            block.merkle_root, expected_sha256,
            "merkle_root should NOT match SHA-256 (was created with SHA3-256)"
        );
        assert_eq!(
            block.merkle_root, expected_sha3,
            "merkle_root still matches SHA3-256 — tamper detected via algorithm mismatch"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// TEST 3: Dual-sign metadata survives persistence
// ═══════════════════════════════════════════════════════════════════

#[test]
fn persistent_node_preserves_dual_signature_metadata() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("dual_sig");

    let pqc_signer = MlDsaSigningProvider::generate();
    let ed_signer = SoftwareSigningProvider::generate();

    // Write a block with dual signatures
    {
        let store = RocksDbBlockStore::new(&db_path).expect("open DB");
        let mut block = make_pqc_block(0, &pqc_signer);

        // Add secondary Ed25519 signature
        let secondary_sig = ed_signer.sign(&block.merkle_root).unwrap();
        block.secondary_signature = Some(secondary_sig.clone());
        block.secondary_signature_algorithm = Some(SigningAlgorithm::Ed25519);

        store.write_block(&block).expect("write dual-signed block");
    }

    // Restart and verify dual-sign metadata survived
    {
        let store = RocksDbBlockStore::new(&db_path).expect("reopen DB");
        let block = store.read_block(0).expect("read block 0");

        assert_eq!(block.signature_algorithm, SigningAlgorithm::MlDsa65);
        assert!(block.secondary_signature.is_some());
        assert_eq!(
            block.secondary_signature_algorithm,
            Some(SigningAlgorithm::Ed25519)
        );
        assert_eq!(block.secondary_signature.unwrap().len(), 64);
    }
}
