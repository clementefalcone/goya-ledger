//! PQC Performance Benchmarks under strict post-quantum mode.
//!
//! Measures: ML-DSA sign/verify, SHA3-256 hashing, block validation,
//! RocksDB persistence, invalid flood rejection, and full node throughput.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use rust_bc::crypto::hasher::{hash_with, HashAlgorithm};
use rust_bc::identity::pqc_policy::validate_signature_consistency;
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::storage::traits::{Block, BlockStore};
use rust_bc::storage::{MemoryStore, RocksDbBlockStore};

// ═══════════════════════════════════════════════════════════════════
// 1. ML-DSA Sign
// ═══════════════════════════════════════════════════════════════════

fn bench_mldsa_sign(c: &mut Criterion) {
    let provider = MlDsaSigningProvider::generate();
    let data = [42u8; 64];

    c.bench_function("mldsa65_sign", |b| {
        b.iter(|| provider.sign(black_box(&data)).unwrap())
    });
}

// ═══════════════════════════════════════════════════════════════════
// 2. ML-DSA Verify
// ═══════════════════════════════════════════════════════════════════

fn bench_mldsa_verify(c: &mut Criterion) {
    let provider = MlDsaSigningProvider::generate();
    let data = [42u8; 64];
    let sig = provider.sign(&data).unwrap();

    c.bench_function("mldsa65_verify", |b| {
        b.iter(|| provider.verify(black_box(&data), black_box(&sig)).unwrap())
    });
}

// ═══════════════════════════════════════════════════════════════════
// Comparison: Ed25519 sign/verify for reference
// ═══════════════════════════════════════════════════════════════════

fn bench_ed25519_sign(c: &mut Criterion) {
    let provider = SoftwareSigningProvider::generate();
    let data = [42u8; 64];

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| provider.sign(black_box(&data)).unwrap())
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let provider = SoftwareSigningProvider::generate();
    let data = [42u8; 64];
    let sig = provider.sign(&data).unwrap();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| provider.verify(black_box(&data), black_box(&sig)).unwrap())
    });
}

// ═══════════════════════════════════════════════════════════════════
// 3. SHA3-256 block hash
// ═══════════════════════════════════════════════════════════════════

fn bench_sha3_block_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_block_hash");

    for tx_count in [10, 100, 1000] {
        let payload: Vec<u8> = (0..tx_count)
            .flat_map(|i| format!("tx-{i}-payload-data-for-hashing").into_bytes())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("sha3_256", tx_count),
            &payload,
            |b, data| b.iter(|| hash_with(HashAlgorithm::Sha3_256, black_box(data))),
        );

        group.bench_with_input(
            BenchmarkId::new("sha256_baseline", tx_count),
            &payload,
            |b, data| b.iter(|| hash_with(HashAlgorithm::Sha256, black_box(data))),
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// 4. Block validation (strict PQC path)
// ═══════════════════════════════════════════════════════════════════

fn make_pqc_block(height: u64, signer: &MlDsaSigningProvider) -> Block {
    let payload = format!("bench-block-{height}");
    let hash = hash_with(HashAlgorithm::Sha3_256, payload.as_bytes());
    let sig = signer.sign(&hash).unwrap();
    Block {
        height,
        timestamp: height * 6,
        parent_hash: [0u8; 32],
        merkle_root: hash,
        transactions: vec![format!("tx-{height}")],
        proposer: "bench-node".to_string(),
        signature: sig,
        signature_algorithm: SigningAlgorithm::MlDsa65,
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: HashAlgorithm::Sha3_256,
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    }
}

fn bench_block_validation_strict_pqc(c: &mut Criterion) {
    let signer = MlDsaSigningProvider::generate();
    let block = make_pqc_block(0, &signer);

    c.bench_function("block_validation_strict_pqc", |b| {
        b.iter(|| {
            // Full validation path: consistency → PQC policy → verify signature
            validate_signature_consistency(block.signature_algorithm, &block.signature, "bench")
                .unwrap();
            rust_bc::identity::pqc_policy::enforce_pqc(block.signature_algorithm, "bench").unwrap();
            signer
                .verify(&block.merkle_root, black_box(&block.signature))
                .unwrap();
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// 5. RocksDB write/read
// ═══════════════════════════════════════════════════════════════════

fn bench_rocksdb_write_read(c: &mut Criterion) {
    let signer = MlDsaSigningProvider::generate();
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbBlockStore::new(dir.path().join("bench_db")).unwrap();

    let block = make_pqc_block(0, &signer);

    c.bench_function("rocksdb_write_block", |b| {
        let mut height = 1000u64;
        b.iter(|| {
            let mut blk = block.clone();
            blk.height = height;
            store.write_block(&blk).unwrap();
            height += 1;
        })
    });

    // Pre-populate for reads
    for h in 0..1000 {
        let mut blk = block.clone();
        blk.height = h;
        let _ = store.write_block(&blk);
    }

    c.bench_function("rocksdb_read_block", |b| {
        let mut h = 0u64;
        b.iter(|| {
            let _ = store.read_block(black_box(h % 1000));
            h += 1;
        })
    });
}

// ═══════════════════════════════════════════════════════════════════
// 6. Invalid flood rejection cost
// ═══════════════════════════════════════════════════════════════════

fn bench_invalid_flood_rejection(c: &mut Criterion) {
    let mut group = c.benchmark_group("invalid_flood_rejection");

    // Size mismatch (cheapest)
    group.bench_function("size_mismatch", |b| {
        b.iter(|| {
            validate_signature_consistency(
                SigningAlgorithm::MlDsa65,
                black_box(&[42u8; 64]),
                "bench",
            )
            .unwrap_err();
        })
    });

    // Duplicate hash (hash set lookup)
    {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let hash = [1u8; 32];
        seen.insert(hash);

        group.bench_function("duplicate_hash_lookup", |b| {
            b.iter(|| seen.contains(black_box(&hash)))
        });
    }

    // PQC policy check
    group.bench_function("pqc_policy_check", |b| {
        std::env::set_var("REQUIRE_PQC_SIGNATURES", "true");
        b.iter(|| {
            rust_bc::identity::pqc_policy::enforce_pqc(
                black_box(SigningAlgorithm::Ed25519),
                "bench",
            )
            .unwrap_err();
        });
        std::env::remove_var("REQUIRE_PQC_SIGNATURES");
    });

    // Invalid ML-DSA verify (expensive — this is the upper bound)
    {
        let provider = MlDsaSigningProvider::generate();
        let bad_sig = vec![42u8; 3309];
        let data = [1u8; 32];

        group.bench_function("invalid_mldsa_verify", |b| {
            b.iter(|| {
                let _ = provider.verify(black_box(&data), black_box(&bad_sig));
            })
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// 7. Full node throughput
// ═══════════════════════════════════════════════════════════════════

fn bench_full_node_throughput(c: &mut Criterion) {
    let signer = MlDsaSigningProvider::generate();

    c.bench_function("full_node_throughput_100_blocks", |b| {
        b.iter(|| {
            let store = MemoryStore::new();
            for h in 0..100u64 {
                let block = make_pqc_block(h, &signer);
                // Validate
                validate_signature_consistency(
                    block.signature_algorithm,
                    &block.signature,
                    "bench",
                )
                .unwrap();
                signer.verify(&block.merkle_root, &block.signature).unwrap();
                // Persist
                store.write_block(&block).unwrap();
            }
        })
    });
}

// ═══════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_mldsa_sign,
    bench_mldsa_verify,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_sha3_block_hash,
    bench_block_validation_strict_pqc,
    bench_rocksdb_write_read,
    bench_invalid_flood_rejection,
    bench_full_node_throughput,
);
criterion_main!(benches);
