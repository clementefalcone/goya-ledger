use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rust_bc::{
    endorsement::{
        org::Organization,
        policy::EndorsementPolicy,
        registry::{MemoryOrgRegistry, OrgRegistry},
        types::Endorsement,
        validator::validate_endorsements,
    },
    ordering::service::OrderingService,
    storage::traits::Transaction,
};

// ─── ordering throughput ───────────────────────────────────────────────────

fn make_tx(id: usize) -> Transaction {
    Transaction {
        id: format!("tx-{id:08}"),
        block_height: 0,
        timestamp: 0,
        input_did: "did:bc:sender".to_string(),
        output_recipient: "did:bc:receiver".to_string(),
        amount: 1,
        state: "endorsed".to_string(),
        fee: 0,
        payload: None,
    }
}

/// Benchmark: submit `batch_size` transactions then cut one block.
/// Reported as throughput in TXs/s.
fn bench_ordering_throughput(c: &mut Criterion) {
    let batch_sizes: &[usize] = &[100];

    let mut group = c.benchmark_group("ordering_service");

    for &batch_size in batch_sizes {
        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("submit_and_cut", batch_size),
            &batch_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let svc = OrderingService::with_config(size, 2000);
                        let txs: Vec<Transaction> = (0..size).map(make_tx).collect();
                        (svc, txs)
                    },
                    |(svc, txs)| {
                        for tx in txs {
                            svc.submit_tx(tx).unwrap();
                        }
                        let block = svc.cut_block(1, [0u8; 32], "orderer").unwrap().unwrap();
                        assert_eq!(block.transactions.len(), size);
                        block
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ─── endorsement validation latency ───────────────────────────────────────

/// Pre-built fixture for an endorsement benchmark run.
struct EndorsementFixture {
    endorsements: Vec<Endorsement>,
    policy: EndorsementPolicy,
    registry: MemoryOrgRegistry,
}

fn build_endorsement_fixture(n_orgs: usize) -> EndorsementFixture {
    let registry = MemoryOrgRegistry::new();
    let payload: [u8; 32] = [0xAB; 32];
    let mut endorsements = Vec::with_capacity(n_orgs);
    let mut org_ids = Vec::with_capacity(n_orgs);

    for i in 0..n_orgs {
        let org_id = format!("org{i}");
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();

        let org = Organization::new(
            &org_id,
            format!("org{i}MSP"),
            vec![format!("did:bc:{org_id}:admin")],
            vec![],
            vec![pk],
        )
        .unwrap();
        registry.register_org(&org).unwrap();

        let sig = sk.sign(&payload).to_bytes();
        endorsements.push(Endorsement {
            signer_did: format!("did:bc:{org_id}:signer"),
            org_id: org_id.clone(),
            signature: sig.to_vec(),
            payload_hash: payload,
            timestamp: 0,
            signature_algorithm: Default::default(),
        });
        org_ids.push(org_id);
    }

    // Policy: ALL orgs must endorse (strictest, exercises full validation path).
    let policy = EndorsementPolicy::AllOf(org_ids);

    EndorsementFixture {
        endorsements,
        policy,
        registry,
    }
}

/// Benchmark: validate N endorsements against an AllOf(N) policy.
/// Measured for N ∈ {1, 3, 5, 10} so we can see the per-endorsement cost.
fn bench_endorsement_validation(c: &mut Criterion) {
    let ns: &[usize] = &[1, 3, 5, 10];

    let mut group = c.benchmark_group("endorsement_validation");

    for &n in ns {
        // One endorsement = one "element" — throughput shows validations/s.
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(
            BenchmarkId::new("validate_endorsements", n),
            &n,
            |b, &size| {
                // Build the fixture once outside the timing loop.
                let fixture = build_endorsement_fixture(size);

                b.iter(|| {
                    validate_endorsements(
                        &fixture.endorsements,
                        &fixture.policy,
                        &fixture.registry,
                        None,
                    )
                    .unwrap();
                });
            },
        );
    }

    group.finish();
}

// ─── event bus fan-out latency ─────────────────────────────────────────────

use rust_bc::events::{BlockEvent, EventBus};

/// Benchmark: publish one event with N active subscribers.
///
/// `publish()` is synchronous — it enqueues the event into the broadcast
/// channel buffer and returns immediately with the receiver count.
/// We vary N ∈ {1, 5, 10, 50} to observe how fan-out overhead scales.
fn bench_event_bus_fanout(c: &mut Criterion) {
    let subscriber_counts: &[usize] = &[1, 5, 10, 50];

    let mut group = c.benchmark_group("event_bus_fanout");

    for &n in subscriber_counts {
        // One publish = one event delivered to N subscribers.
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("publish_1_event", n), &n, |b, &subs| {
            b.iter_batched(
                // Setup: fresh bus + N receivers kept alive.
                || {
                    let bus = EventBus::with_capacity(128);
                    let receivers: Vec<_> = (0..subs).map(|_| bus.subscribe()).collect();
                    (bus, receivers)
                },
                // Routine: publish one event; drop the bus+receivers.
                |(bus, _receivers)| {
                    let sent = bus.publish(BlockEvent::BlockCommitted {
                        channel_id: "bench-channel".to_string(),
                        height: 1,
                        tx_count: 1,
                    });
                    assert_eq!(sent, subs);
                    sent
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ─── RocksDB write throughput ─────────────────────────────────────────────

use rust_bc::storage::{traits::Block, traits::BlockStore, RocksDbBlockStore};

fn make_block(height: u64) -> Block {
    Block {
        height,
        timestamp: 1_700_000_000 + height,
        parent_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        transactions: vec![format!("tx-{height}")],
        proposer: "bench-orderer".to_string(),
        signature: vec![0u8; 64],
        signature_algorithm: Default::default(),
        endorsements: vec![],
        secondary_signature: None,
        secondary_signature_algorithm: None,
        hash_algorithm: Default::default(),
        orderer_signature: None,
        commit_qc: None,
        transaction_data: vec![],
    }
}

/// Benchmark: write N blocks to RocksDB sequentially.
fn bench_rocksdb_write(c: &mut Criterion) {
    let batch_sizes: &[usize] = &[10, 100];

    let mut group = c.benchmark_group("rocksdb_storage");

    for &n in batch_sizes {
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("write_blocks", n), &n, |b, &size| {
            b.iter_batched(
                || {
                    let dir = tempfile::TempDir::new().unwrap();
                    let store = RocksDbBlockStore::new(dir.path()).unwrap();
                    let blocks: Vec<Block> = (0..size as u64).map(make_block).collect();
                    (dir, store, blocks)
                },
                |(_dir, store, blocks)| {
                    for block in &blocks {
                        store.write_block(block).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_ordering_throughput,
    bench_endorsement_validation,
    bench_event_bus_fanout,
    bench_rocksdb_write
);
criterion_main!(benches);
