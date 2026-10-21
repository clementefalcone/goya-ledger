use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rust_bc::storage::traits::Transaction;
use rust_bc::transaction::mempool::TransactionPool;

fn make_tx(id: &str, from: &str, to: &str, amount: u64) -> Transaction {
    Transaction {
        id: id.to_string(),
        block_height: 0,
        timestamp: 1000,
        input_did: from.to_string(),
        output_recipient: to.to_string(),
        amount,
        fee: 0,
        state: "pending".to_string(),
        payload: None,
    }
}

#[test]
fn backpressure_rejects_at_capacity() {
    let max = 50;
    let mut pool = TransactionPool::with_max_size(max);

    for i in 0..max {
        pool.add(make_tx(&format!("tx-{i}"), "alice", "bob", 0))
            .unwrap();
    }
    assert_eq!(pool.len(), max);

    let rejected = pool.add(make_tx("tx-overflow", "alice", "bob", 0));
    assert!(rejected.is_err());
    assert!(rejected.unwrap_err().contains("full"));
    assert_eq!(pool.len(), max);
}

#[test]
fn concurrent_add_no_lost_transactions() {
    let max = 1000;
    let pool = Arc::new(Mutex::new(TransactionPool::with_max_size(max)));
    let threads = 10;
    let per_thread = 100;

    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let pool = pool.clone();
            std::thread::spawn(move || {
                let mut accepted = 0u64;
                let mut rejected = 0u64;
                for i in 0..per_thread {
                    let tx = make_tx(
                        &format!("tx-{t}-{i}"),
                        &format!("sender-{t}"),
                        "recipient",
                        0,
                    );
                    let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                    match p.add(tx) {
                        Ok(()) => accepted += 1,
                        Err(_) => rejected += 1,
                    }
                }
                (accepted, rejected)
            })
        })
        .collect();

    let mut total_accepted = 0u64;
    let mut total_rejected = 0u64;
    for h in handles {
        let (a, r) = h.join().unwrap();
        total_accepted += a;
        total_rejected += r;
    }

    let pool = pool.lock().unwrap();
    assert_eq!(pool.len() as u64, total_accepted);
    assert_eq!(
        total_accepted + total_rejected,
        (threads * per_thread) as u64
    );
    assert!(total_accepted <= max as u64);
}

#[test]
fn concurrent_add_no_duplicates() {
    let pool = Arc::new(Mutex::new(TransactionPool::with_max_size(5000)));
    let threads = 8;
    let per_thread = 500;

    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let pool = pool.clone();
            std::thread::spawn(move || {
                for i in 0..per_thread {
                    let tx = make_tx(
                        &format!("tx-{t}-{i}"),
                        &format!("sender-{t}"),
                        "recipient",
                        0,
                    );
                    let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = p.add(tx);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    let pool = pool.lock().unwrap();
    let ids: HashSet<&str> = pool.all().iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids.len(), pool.len());
}

#[test]
fn drain_under_contention() {
    let max = 2000;
    let pool = Arc::new(Mutex::new(TransactionPool::with_max_size(max)));

    for i in 0..1000 {
        pool.lock()
            .unwrap()
            .add(make_tx(&format!("seed-{i}"), "alice", "bob", 0))
            .unwrap();
    }

    let pool_add = pool.clone();
    let pool_drain = pool.clone();

    let adder = std::thread::spawn(move || {
        let mut added = 0u64;
        for i in 0..500 {
            let tx = make_tx(&format!("new-{i}"), "carol", "dave", 0);
            let mut p = pool_add.lock().unwrap_or_else(|e| e.into_inner());
            if p.add(tx).is_ok() {
                added += 1;
            }
        }
        added
    });

    let drainer = std::thread::spawn(move || {
        let mut drained = Vec::new();
        for _ in 0..10 {
            let mut p = pool_drain.lock().unwrap_or_else(|e| e.into_inner());
            drained.extend(p.drain_for_block(100));
            drop(p);
            std::thread::yield_now();
        }
        drained
    });

    let added = adder.join().unwrap();
    let drained = drainer.join().unwrap();

    let remaining = pool.lock().unwrap().len();

    let drained_ids: HashSet<String> = drained.iter().map(|t| t.id.clone()).collect();
    assert_eq!(drained_ids.len(), drained.len());

    assert_eq!(1000 + added as usize, drained.len() + remaining,);
}

#[test]
fn double_spend_under_concurrent_load() {
    let pool = Arc::new(Mutex::new(TransactionPool::with_max_size(1000)));
    let sender_balance = 100u64;
    let threads = 10;

    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let pool = pool.clone();
            std::thread::spawn(move || {
                let mut accepted = 0u64;
                for i in 0..20 {
                    let tx = make_tx(
                        &format!("spend-{t}-{i}"),
                        "shared-sender",
                        &format!("recipient-{t}"),
                        15,
                    );
                    let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                    if p.add_checked(tx, sender_balance).is_ok() {
                        accepted += 1;
                    }
                }
                accepted
            })
        })
        .collect();

    let total_accepted: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();

    let pool = pool.lock().unwrap();
    let total_committed: u64 = pool
        .all()
        .iter()
        .filter(|t| t.input_did == "shared-sender")
        .map(|t| t.amount)
        .sum();

    assert!(total_committed <= sender_balance);
    assert_eq!(
        total_accepted as usize,
        pool.all()
            .iter()
            .filter(|t| t.input_did == "shared-sender")
            .count()
    );
    assert!(total_accepted <= sender_balance / 15);
}

#[test]
fn saturate_then_drain_then_refill() {
    let max = 100;
    let mut pool = TransactionPool::with_max_size(max);

    for i in 0..max {
        pool.add(make_tx(&format!("batch1-{i}"), "a", "b", 0))
            .unwrap();
    }
    assert!(pool.add(make_tx("overflow", "a", "b", 0)).is_err());

    let drained = pool.drain_for_block(max);
    assert_eq!(drained.len(), max);
    assert!(pool.is_empty());

    for i in 0..max {
        pool.add(make_tx(&format!("batch2-{i}"), "a", "b", 0))
            .unwrap();
    }
    assert_eq!(pool.len(), max);
    assert!(pool.add(make_tx("overflow2", "a", "b", 0)).is_err());
}

#[test]
fn drain_more_than_available() {
    let mut pool = TransactionPool::with_max_size(100);
    for i in 0..5 {
        pool.add(make_tx(&format!("tx-{i}"), "a", "b", 0)).unwrap();
    }
    let drained = pool.drain_for_block(999);
    assert_eq!(drained.len(), 5);
    assert!(pool.is_empty());
}

#[test]
fn remove_under_contention() {
    let pool = Arc::new(Mutex::new(TransactionPool::with_max_size(2000)));

    for i in 0..1000 {
        pool.lock()
            .unwrap()
            .add(make_tx(&format!("tx-{i}"), "alice", "bob", 0))
            .unwrap();
    }

    let pool_remove = pool.clone();
    let pool_add = pool.clone();

    let remover = std::thread::spawn(move || {
        let mut removed = 0u64;
        for i in 0..1000 {
            let mut p = pool_remove.lock().unwrap_or_else(|e| e.into_inner());
            if p.remove(&format!("tx-{i}")) {
                removed += 1;
            }
        }
        removed
    });

    let adder = std::thread::spawn(move || {
        let mut added = 0u64;
        for i in 0..500 {
            let tx = make_tx(&format!("fresh-{i}"), "carol", "dave", 0);
            let mut p = pool_add.lock().unwrap_or_else(|e| e.into_inner());
            if p.add(tx).is_ok() {
                added += 1;
            }
        }
        added
    });

    let removed = remover.join().unwrap();
    let added = adder.join().unwrap();
    let remaining = pool.lock().unwrap().len();

    assert_eq!(1000 - removed as usize + added as usize, remaining);
}
