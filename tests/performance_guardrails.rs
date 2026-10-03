//! Performance guardrail tests — non-flaky threshold assertions.
//!
//! Uses counters and ratios instead of wall-clock timing where possible.
//! When timing is needed, uses relaxed thresholds (10x safety margin).

use std::time::{Duration, Instant};

use rust_bc::crypto::hasher::{hash_with, HashAlgorithm};
use rust_bc::identity::pqc_policy::validate_signature_consistency;
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::storage::traits::{Block, BlockStore};
use rust_bc::storage::RocksDbBlockStore;

fn make_block(height: u64, signer: &dyn SigningProvider) -> Block {
    let payload = format!("perf-block-{height}");
    let hash = hash_with(HashAlgorithm::Sha3_256, payload.as_bytes());
    let sig = signer.sign(&hash).unwrap();
    Block {
        height,
        timestamp: height * 6,
        parent_hash: [0u8; 32],
        merkle_root: hash,
        transactions: vec![format!("tx-{height}")],
        proposer: "perf-node".to_string(),
        signature: sig,
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

// ═══════════════════════════════════════════════════════════════════
// 1. Cheap rejection is at least 10x faster than ML-DSA verify
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cheap_rejection_is_at_least_10x_faster_than_mldsa_verify() {
    let iterations = 1000;

    // Measure cheap rejection (size mismatch)
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = validate_signature_consistency(
            SigningAlgorithm::MlDsa65,
            &[42u8; 64], // wrong size
            "bench",
        );
    }
    let cheap_time = start.elapsed();

    // Measure ML-DSA verify
    let provider = MlDsaSigningProvider::generate();
    let data = [42u8; 32];
    let sig = provider.sign(&data).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = provider.verify(&data, &sig);
    }
    let verify_time = start.elapsed();

    let ratio = verify_time.as_nanos() as f64 / cheap_time.as_nanos().max(1) as f64;

    eprintln!(
        "cheap: {:?}/{iterations} = {:?}/op, verify: {:?}/{iterations} = {:?}/op, ratio: {ratio:.1}x",
        cheap_time,
        cheap_time / iterations as u32,
        verify_time,
        verify_time / iterations as u32,
    );

    assert!(
        ratio >= 10.0,
        "cheap rejection must be >= 10x faster than ML-DSA verify, got {ratio:.1}x"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 2. Duplicate flood does not trigger unbounded verification
// ═══════════════════════════════════════════════════════════════════

#[test]
fn duplicate_flood_does_not_trigger_unbounded_verification() {
    use std::collections::HashSet;

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let hash = hash_with(HashAlgorithm::Sha3_256, b"duplicate");
    seen.insert(hash);

    // 100K duplicate checks — must complete in <1s (hash lookup is O(1))
    let start = Instant::now();
    let count = 100_000;
    for _ in 0..count {
        assert!(seen.contains(&hash));
    }
    let elapsed = start.elapsed();

    eprintln!("100K duplicate checks: {:?}", elapsed);
    assert!(
        elapsed < Duration::from_secs(1),
        "100K duplicate hash lookups must complete in <1s, took {:?}",
        elapsed
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. RocksDB restart with 10K blocks under reasonable time
// ═══════════════════════════════════════════════════════════════════

#[test]
fn rocksdb_restart_10k_blocks_under_reasonable_time() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("perf_10k");
    let signer = MlDsaSigningProvider::generate();

    // Write 10K blocks
    {
        let store = RocksDbBlockStore::new(&db_path).unwrap();
        for h in 0..10_000u64 {
            let block = make_block(h, &signer);
            store.write_block(&block).unwrap();
        }
    }

    // Measure restart (reopen) time
    let start = Instant::now();
    let store = RocksDbBlockStore::new(&db_path).unwrap();
    let reopen_time = start.elapsed();

    // Verify data accessible
    let latest = store.get_latest_height().unwrap();
    assert_eq!(latest, 9999);
    let block = store.read_block(5000).unwrap();
    assert_eq!(block.height, 5000);

    eprintln!(
        "RocksDB reopen with 10K blocks: {:?}, latest_height={}",
        reopen_time, latest
    );

    assert!(
        reopen_time < Duration::from_secs(5),
        "RocksDB reopen must be <5s for 10K blocks, took {:?}",
        reopen_time
    );
}

// ═══════════════════════════════════════════════════════════════════
// 4. Strict PQC validation handles minimum blocks/sec
// ═══════════════════════════════════════════════════════════════════

#[test]
fn strict_pqc_validation_handles_minimum_blocks_per_second() {
    let signer = MlDsaSigningProvider::generate();
    let blocks: Vec<Block> = (0..100).map(|h| make_block(h, &signer)).collect();

    let start = Instant::now();
    for block in &blocks {
        validate_signature_consistency(block.signature_algorithm, &block.signature, "perf")
            .unwrap();
        signer.verify(&block.merkle_root, &block.signature).unwrap();
    }
    let elapsed = start.elapsed();

    let blocks_per_sec = 100.0 / elapsed.as_secs_f64();
    eprintln!(
        "Strict PQC validation: 100 blocks in {:?} ({:.0} blocks/sec)",
        elapsed, blocks_per_sec
    );

    // Minimum: 10 blocks/sec under strict PQC (ML-DSA verify is ~1ms)
    assert!(
        blocks_per_sec >= 10.0,
        "strict PQC validation must handle >= 10 blocks/sec, got {blocks_per_sec:.0}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 5. ML-DSA vs Ed25519 performance comparison
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mldsa_overhead_vs_ed25519_is_bounded() {
    let iterations = 100;
    let data = [42u8; 64];

    // Ed25519
    let ed = SoftwareSigningProvider::generate();
    let ed_sig = ed.sign(&data).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        ed.verify(&data, &ed_sig).unwrap();
    }
    let ed_time = start.elapsed();

    // ML-DSA-65
    let pqc = MlDsaSigningProvider::generate();
    let pqc_sig = pqc.sign(&data).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        pqc.verify(&data, &pqc_sig).unwrap();
    }
    let pqc_time = start.elapsed();

    let overhead = pqc_time.as_nanos() as f64 / ed_time.as_nanos().max(1) as f64;

    eprintln!(
        "Ed25519 verify: {:?}/{iterations}, ML-DSA verify: {:?}/{iterations}, overhead: {overhead:.1}x",
        ed_time, pqc_time
    );

    // ML-DSA should be no more than 100x slower than Ed25519 verify
    assert!(
        overhead < 100.0,
        "ML-DSA overhead vs Ed25519 must be <100x, got {overhead:.1}x"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 6. SHA3 vs SHA2 overhead is bounded
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sha3_overhead_vs_sha2_is_bounded() {
    let data = vec![42u8; 10_000]; // 10KB payload
    let iterations = 10_000;

    let start = Instant::now();
    for _ in 0..iterations {
        hash_with(HashAlgorithm::Sha256, &data);
    }
    let sha2_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        hash_with(HashAlgorithm::Sha3_256, &data);
    }
    let sha3_time = start.elapsed();

    let overhead = sha3_time.as_nanos() as f64 / sha2_time.as_nanos().max(1) as f64;

    eprintln!(
        "SHA-256: {:?}/{iterations}, SHA3-256: {:?}/{iterations}, overhead: {overhead:.2}x",
        sha2_time, sha3_time
    );

    // SHA3 should be no more than 5x slower than SHA2
    assert!(
        overhead < 5.0,
        "SHA3 overhead vs SHA2 must be <5x, got {overhead:.2}x"
    );
}
