use rust_bc::identity::did::{civil_anchor_hash, did_from_pubkey_hex};
use rust_bc::mining::{MiningConfig, MiningService};
use rust_bc::storage::traits::{BlockStore, IdentityRecord, Transaction, TxPayload};
use rust_bc::storage::MemoryStore;
use std::sync::Arc;

fn make_identity_tx(id: &str, pubkey: &str, doc_type: &str, doc_number: &str) -> Transaction {
    let did = did_from_pubkey_hex(pubkey);
    let anchor = civil_anchor_hash(doc_type, doc_number);
    Transaction {
        id: id.to_string(),
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

#[test]
fn two_identity_tx_same_anchor_in_same_block_only_first_wins() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let service = MiningService::new(store.clone(), MiningConfig::default());

    let tx1 = make_identity_tx("tx-alice", "aabbccdd11223344", "RUT", "12345678-9");
    let tx2 = make_identity_tx("tx-bob", "1122334455667788", "RUT", "12345678-9");

    let height = service.mine_block("miner", vec![tx1, tx2]).unwrap();
    assert_eq!(height, 0);

    let committed_tx1 = store.read_transaction("tx-alice").unwrap();
    assert_eq!(committed_tx1.state, "confirmed");

    let committed_tx2 = store.read_transaction("tx-bob").unwrap();
    assert_eq!(committed_tx2.state, "invalid_payload");

    let anchor = civil_anchor_hash("RUT", "12345678-9");
    let resolved_did = store.resolve_by_civil_anchor(&anchor).unwrap();
    let alice_did = did_from_pubkey_hex("aabbccdd11223344");
    assert_eq!(resolved_did, alice_did);
}

#[test]
fn identity_tx_without_anchor_no_dedup() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let service = MiningService::new(store.clone(), MiningConfig::default());

    let did_a = did_from_pubkey_hex("aaaa");
    let did_b = did_from_pubkey_hex("bbbb");

    let tx1 = Transaction {
        id: "tx-no-anchor-1".to_string(),
        block_height: 0,
        timestamp: 1000,
        input_did: did_a.clone(),
        output_recipient: did_a.clone(),
        amount: 0,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(TxPayload::RegisterIdentity {
            record: IdentityRecord {
                did: did_a,
                public_key: "aaaa".to_string(),
                created_at: 1000,
                updated_at: 1000,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            },
            civil_anchor: None,
            owner_signature: None,
        }),
    };

    let tx2 = Transaction {
        id: "tx-no-anchor-2".to_string(),
        block_height: 0,
        timestamp: 1000,
        input_did: did_b.clone(),
        output_recipient: did_b.clone(),
        amount: 0,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(TxPayload::RegisterIdentity {
            record: IdentityRecord {
                did: did_b,
                public_key: "bbbb".to_string(),
                created_at: 1000,
                updated_at: 1000,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            },
            civil_anchor: None,
            owner_signature: None,
        }),
    };

    service.mine_block("miner", vec![tx1, tx2]).unwrap();

    let ct1 = store.read_transaction("tx-no-anchor-1").unwrap();
    let ct2 = store.read_transaction("tx-no-anchor-2").unwrap();
    assert_eq!(ct1.state, "confirmed");
    assert_eq!(ct2.state, "confirmed");
}

#[test]
fn different_anchors_both_succeed() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let service = MiningService::new(store.clone(), MiningConfig::default());

    let tx1 = make_identity_tx("tx-rut", "aabb", "RUT", "12345678-9");
    let tx2 = make_identity_tx("tx-dni", "ccdd", "DNI", "87654321-0");

    service.mine_block("miner", vec![tx1, tx2]).unwrap();

    let ct1 = store.read_transaction("tx-rut").unwrap();
    let ct2 = store.read_transaction("tx-dni").unwrap();
    assert_eq!(ct1.state, "confirmed");
    assert_eq!(ct2.state, "confirmed");

    let anchor_rut = civil_anchor_hash("RUT", "12345678-9");
    let anchor_dni = civil_anchor_hash("DNI", "87654321-0");
    assert!(store.resolve_by_civil_anchor(&anchor_rut).is_ok());
    assert!(store.resolve_by_civil_anchor(&anchor_dni).is_ok());
}
