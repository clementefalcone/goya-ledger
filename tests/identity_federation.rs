use rust_bc::identity::civil_anchor::bind_civil_anchor_message;
use rust_bc::identity::did::did_from_pubkey_hex;
use rust_bc::identity::operations::register_message;
use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};
use rust_bc::mining::{MiningConfig, MiningService};
use rust_bc::storage::traits::{BlockStore, IdentityRecord, Transaction, TxPayload};
use rust_bc::storage::MemoryStore;
use std::sync::{Arc, OnceLock};

const ANCHOR: &str = "4f1c2a9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928170605f4e3";

struct Person {
    key: MlDsaSigningProvider,
    did: String,
}

fn public_key_of(key: &MlDsaSigningProvider) -> String {
    hex::encode(key.public_key())
}

fn sign(key: &MlDsaSigningProvider, message: &str) -> String {
    hex::encode(key.sign(message.as_bytes()).unwrap())
}

fn trusted_issuer() -> &'static MlDsaSigningProvider {
    static ISSUER: OnceLock<MlDsaSigningProvider> = OnceLock::new();
    ISSUER.get_or_init(|| {
        let issuer = MlDsaSigningProvider::generate();
        std::env::set_var("CIVIL_ANCHOR_ISSUERS", public_key_of(&issuer));
        issuer
    })
}

fn person() -> Person {
    let key = MlDsaSigningProvider::generate();
    let did = did_from_pubkey_hex(&public_key_of(&key));
    Person { key, did }
}

fn tx(id: String, author: &str, payload: TxPayload) -> Transaction {
    Transaction {
        id,
        block_height: 0,
        timestamp: 1000,
        input_did: author.to_string(),
        output_recipient: author.to_string(),
        amount: 0,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(payload),
    }
}

fn register_tx(person: &Person) -> Transaction {
    let record = IdentityRecord {
        did: person.did.clone(),
        public_key: public_key_of(&person.key),
        created_at: 1000,
        updated_at: 1000,
        status: "active".to_string(),
        migrated_from: None,
        signature_algorithm: Some("MlDsa65".to_string()),
        civil_anchor: None,
        recovery_commitment: None,
        vault_entries: Vec::new(),
    };
    tx(
        format!("register-{}", &person.did[10..18]),
        &person.did,
        TxPayload::RegisterIdentity {
            record,
            owner_signature: Some(sign(&person.key, &register_message(&person.did, None))),
        },
    )
}

fn bind_tx(person: &Person, replaces: Option<&str>) -> Transaction {
    let issuer = trusted_issuer();
    let message = bind_civil_anchor_message(&person.did, ANCHOR, replaces);
    tx(
        format!("bind-{}", &person.did[10..18]),
        &person.did,
        TxPayload::BindCivilAnchor {
            did: person.did.clone(),
            anchor: ANCHOR.to_string(),
            replaces: replaces.map(str::to_string),
            bound_at: 1001,
            issuer_public_key: public_key_of(issuer),
            issuer_signature: sign(issuer, &message),
            owner_signature: sign(&person.key, &message),
        },
    )
}

fn receive_block(source: &dyn BlockStore, target: &dyn BlockStore, height: u64) {
    let block = source.read_block(height).unwrap();
    target.write_block(&block).unwrap();
    for transaction in &block.transaction_data {
        let mut committed = transaction.clone();
        if rust_bc::transaction::apply_tx_payload(target, transaction).is_err() {
            committed.state = "invalid_payload".to_string();
        }
        target.write_transaction(&committed).unwrap();
    }
}

fn two_nodes() -> (Arc<dyn BlockStore>, Arc<dyn BlockStore>, MiningService) {
    let node_a: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let node_b: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let miner = MiningService::new(node_a.clone(), MiningConfig::default());
    (node_a, node_b, miner)
}

fn holder(node: &dyn BlockStore) -> Option<String> {
    node.resolve_by_civil_anchor(ANCHOR).ok()
}

fn anchor_of(node: &dyn BlockStore, person: &Person) -> Option<String> {
    node.read_identity(&person.did).unwrap().civil_anchor
}

#[test]
fn bound_document_replicates_to_another_node() {
    let (node_a, node_b, miner) = two_nodes();
    let alice = person();

    miner
        .mine_block("miner-a", vec![register_tx(&alice), bind_tx(&alice, None)])
        .unwrap();
    receive_block(node_a.as_ref(), node_b.as_ref(), 0);

    assert_eq!(holder(node_b.as_ref()), Some(alice.did.clone()));
    assert_eq!(anchor_of(node_b.as_ref(), &alice).as_deref(), Some(ANCHOR));
}

#[test]
fn every_node_keeps_the_first_of_two_binds_in_one_block() {
    let (node_a, node_b, miner) = two_nodes();
    let first = person();
    let second = person();

    miner
        .mine_block(
            "miner-a",
            vec![
                register_tx(&first),
                register_tx(&second),
                bind_tx(&first, None),
                bind_tx(&second, None),
            ],
        )
        .unwrap();
    receive_block(node_a.as_ref(), node_b.as_ref(), 0);

    for node in [node_a.as_ref(), node_b.as_ref()] {
        assert_eq!(holder(node), Some(first.did.clone()));
        assert_eq!(anchor_of(node, &second), None);
        let losing_bind = node.read_transaction(&bind_tx(&second, None).id).unwrap();
        assert_eq!(losing_bind.state, "invalid_payload");
    }
}

#[test]
fn rebind_replicates_and_unanchors_the_lost_did_everywhere() {
    let (node_a, node_b, miner) = two_nodes();
    let lost = person();
    let fresh = person();

    miner
        .mine_block("miner-a", vec![register_tx(&lost), bind_tx(&lost, None)])
        .unwrap();
    miner
        .mine_block(
            "miner-a",
            vec![register_tx(&fresh), bind_tx(&fresh, Some(&lost.did))],
        )
        .unwrap();
    for height in 0..2 {
        receive_block(node_a.as_ref(), node_b.as_ref(), height);
    }

    for node in [node_a.as_ref(), node_b.as_ref()] {
        assert_eq!(holder(node), Some(fresh.did.clone()));
        assert_eq!(anchor_of(node, &lost), None);
    }
}
