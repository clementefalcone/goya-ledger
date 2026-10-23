use rust_bc::identity::did::{civil_anchor_hash, did_from_pubkey_hex};
use rust_bc::mining::{MiningConfig, MiningService};
use rust_bc::storage::traits::{BlockStore, IdentityRecord, Transaction, TxPayload};
use rust_bc::storage::MemoryStore;
use std::sync::Arc;

fn identity_tx(pubkey: &str, doc_type: &str, doc_number: &str) -> Transaction {
    let did = did_from_pubkey_hex(pubkey);
    let anchor = civil_anchor_hash(doc_type, doc_number);
    Transaction {
        id: format!("id-{}", &pubkey[..8.min(pubkey.len())]),
        block_height: 0,
        timestamp: 1000,
        input_did: did.clone(),
        output_recipient: did.clone(),
        amount: 0,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(TxPayload::RegisterIdentity {
            record: IdentityRecord {
                did,
                public_key: pubkey.to_string(),
                created_at: 1000,
                updated_at: 1000,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: Some(anchor.clone()),
                recovery_commitment: None,
                vault_entries: Vec::new(),
            },
            civil_anchor: Some(anchor),
            owner_signature: None,
        }),
    }
}

fn simulate_block_reception(source: &dyn BlockStore, target: &dyn BlockStore, height: u64) {
    let block = source.read_block(height).unwrap();
    let _ = target.write_block(&block);
    for tx in &block.transaction_data {
        let mut committed = tx.clone();
        if let Err(_e) = rust_bc::transaction::apply_tx_payload(target, tx) {
            committed.state = "invalid_payload".to_string();
        }
        let _ = target.write_transaction(&committed);
    }
}

#[test]
fn identity_created_on_node_a_visible_on_node_b_after_block() {
    let store_a: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let store_b: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let miner = MiningService::new(store_a.clone(), MiningConfig::default());

    let tx = identity_tx("aabbccdd11223344", "RUT", "12345678-9");
    let expected_did = did_from_pubkey_hex("aabbccdd11223344");
    let expected_anchor = civil_anchor_hash("RUT", "12345678-9");

    miner.mine_block("miner-a", vec![tx]).unwrap();

    assert!(store_a.read_identity(&expected_did).is_ok());
    assert!(store_b.read_identity(&expected_did).is_err());

    simulate_block_reception(store_a.as_ref(), store_b.as_ref(), 0);

    let identity_b = store_b.read_identity(&expected_did).unwrap();
    assert_eq!(identity_b.public_key, "aabbccdd11223344");
    assert_eq!(identity_b.status, "active");

    let resolved = store_b.resolve_by_civil_anchor(&expected_anchor).unwrap();
    assert_eq!(resolved, expected_did);
}

#[test]
fn duplicate_anchor_rejected_on_node_b() {
    let store_a: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let store_b: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let miner_a = MiningService::new(store_a.clone(), MiningConfig::default());
    let miner_b = MiningService::new(store_b.clone(), MiningConfig::default());

    let tx_a = identity_tx("aaaa1111", "RUT", "99999999-9");
    miner_a.mine_block("miner-a", vec![tx_a]).unwrap();

    let tx_b = identity_tx("bbbb2222", "RUT", "99999999-9");
    miner_b.mine_block("miner-b", vec![tx_b]).unwrap();

    simulate_block_reception(store_a.as_ref(), store_b.as_ref(), 0);

    let anchor = civil_anchor_hash("RUT", "99999999-9");
    let resolved = store_b.resolve_by_civil_anchor(&anchor).unwrap();
    let did_b_local = did_from_pubkey_hex("bbbb2222");
    assert_eq!(resolved, did_b_local);
}

#[test]
fn state_sync_replays_multiple_blocks() {
    let store_a: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let store_c: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let miner = MiningService::new(store_a.clone(), MiningConfig::default());

    miner
        .mine_block("m", vec![identity_tx("aa11", "RUT", "11111111-1")])
        .unwrap();
    miner
        .mine_block("m", vec![identity_tx("bb22", "DNI", "22222222-2")])
        .unwrap();
    miner
        .mine_block("m", vec![identity_tx("cc33", "PASSPORT", "33333333-3")])
        .unwrap();

    for h in 0..3 {
        simulate_block_reception(store_a.as_ref(), store_c.as_ref(), h);
    }

    assert!(store_c.read_identity(&did_from_pubkey_hex("aa11")).is_ok());
    assert!(store_c.read_identity(&did_from_pubkey_hex("bb22")).is_ok());
    assert!(store_c.read_identity(&did_from_pubkey_hex("cc33")).is_ok());

    assert!(store_c
        .resolve_by_civil_anchor(&civil_anchor_hash("RUT", "11111111-1"))
        .is_ok());
    assert!(store_c
        .resolve_by_civil_anchor(&civil_anchor_hash("DNI", "22222222-2"))
        .is_ok());
    assert!(store_c
        .resolve_by_civil_anchor(&civil_anchor_hash("PASSPORT", "33333333-3"))
        .is_ok());
}
