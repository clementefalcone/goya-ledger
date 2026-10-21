use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use actix_web::{test, web, App};
use rust_bc::{
    api::routes::ApiRoutes,
    identity::did::did_from_pubkey_hex,
    identity::signing::{MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider},
    mining::{MiningConfig, MiningService},
    storage::{
        traits::{Block, IdentityRecord, Transaction, TxPayload},
        BlockStore, MemoryStore, RocksDbBlockStore,
    },
    transaction::mempool::TransactionPool,
    AppState,
};

struct Account {
    did: String,
    signer: Box<dyn SigningProvider>,
}

impl Account {
    fn new(signer: Box<dyn SigningProvider>) -> Self {
        let public_key = hex::encode(signer.public_key());
        Self {
            did: did_from_pubkey_hex(&public_key),
            signer,
        }
    }

    fn sign(&self, message: &str) -> String {
        hex::encode(self.signer.sign(message.as_bytes()).unwrap())
    }

    fn register(&self, store: &dyn BlockStore) {
        store
            .write_identity(&IdentityRecord {
                did: self.did.clone(),
                public_key: hex::encode(self.signer.public_key()),
                created_at: 0,
                updated_at: 0,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
            })
            .unwrap();
    }
}

fn empty_block(height: u64) -> Block {
    Block {
        height,
        timestamp: 1_000_000 + height,
        parent_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        transactions: vec![],
        proposer: "validator".to_string(),
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

fn committed_tx(
    id: &str,
    from: &str,
    to: &str,
    amount: u64,
    payload: Option<TxPayload>,
) -> Transaction {
    Transaction {
        id: id.to_string(),
        block_height: 0,
        timestamp: 1_000_000,
        input_did: from.to_string(),
        output_recipient: to.to_string(),
        amount,
        state: "confirmed".to_string(),
        fee: 0,
        payload,
    }
}

static PROCESS_ENV: Mutex<()> = Mutex::new(());

struct Ledger {
    store: Arc<dyn BlockStore>,
    pool: Arc<Mutex<TransactionPool>>,
    state: AppState,
    _env_guard: MutexGuard<'static, ()>,
}

fn ledger_on(store: Arc<dyn BlockStore>) -> Ledger {
    let env_guard = PROCESS_ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("ACL_MODE", "permissive");
    let mut state = AppState::test_default();
    let stores = std::collections::HashMap::from([("default".to_string(), store.clone())]);
    state.store = Arc::new(RwLock::new(stores));
    state.mining_service = Some(Arc::new(MiningService::new(
        store.clone(),
        MiningConfig::default(),
    )));
    Ledger {
        store,
        pool: state.tx_pool.clone(),
        state,
        _env_guard: env_guard,
    }
}

fn ledger_funding(store: Arc<dyn BlockStore>, account: &Account, amount: u64) -> Ledger {
    store.write_block(&empty_block(0)).unwrap();
    store
        .write_transaction(&committed_tx("fund", "genesis", &account.did, amount, None))
        .unwrap();
    account.register(store.as_ref());
    ledger_on(store)
}

fn ledger_with_funded(account: &Account, amount: u64) -> Ledger {
    ledger_funding(Arc::new(MemoryStore::new()), account, amount)
}

const FAR_FUTURE: u64 = 4_000_000_000;

fn lock_body(owner: &Account, amount: u64, nonce: u64) -> serde_json::Value {
    let message = format!("savings_lock:{}:{amount}:{FAR_FUTURE}:{nonce}", owner.did);
    serde_json::json!({
        "did": owner.did,
        "amount": amount,
        "unlock_at": FAR_FUTURE,
        "nonce": nonce,
        "signature": owner.sign(&message),
    })
}

fn transfer_body(from: &Account, to: &str, amount: u64, nonce: u64) -> serde_json::Value {
    let message = format!("transfer:{}:{to}:{amount}:{nonce}", from.did);
    serde_json::json!({
        "from": from.did,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "fee": 1,
        "signature": from.sign(&message),
    })
}

fn release_body(owner: &Account, lock_id: &str, nonce: u64) -> serde_json::Value {
    let message = format!("savings_release:{}:{lock_id}:{nonce}", owner.did);
    serde_json::json!({
        "did": owner.did,
        "lock_id": lock_id,
        "nonce": nonce,
        "signature": owner.sign(&message),
    })
}

async fn post(state: AppState, uri: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(uri)
            .set_json(body)
            .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    let body = test::read_body_json(resp).await;
    (status, body)
}

fn ed25519_account() -> Account {
    Account::new(Box::new(SoftwareSigningProvider::generate()))
}

#[actix_web::test]
async fn mldsa_signed_transfer_is_admitted() {
    let alice = Account::new(Box::new(MlDsaSigningProvider::generate()));
    let ledger = ledger_with_funded(&alice, 100);
    let (status, body) = post(
        ledger.state,
        "/api/v1/transactions",
        transfer_body(&alice, "bob", 40, 0),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(ledger.pool.lock().unwrap().len(), 1);
}

#[actix_web::test]
async fn transfer_with_invalid_signature_is_rejected() {
    let alice = ed25519_account();
    let mallory = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let mut body = transfer_body(&alice, "bob", 40, 0);
    body["signature"] = transfer_body(&mallory, "bob", 40, 0)["signature"].clone();
    let (status, body) = post(ledger.state, "/api/v1/transactions", body).await;
    assert_eq!(status, 401, "{body}");
    assert!(ledger.pool.lock().unwrap().is_empty());
}

#[actix_web::test]
async fn transfer_without_signature_is_rejected() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let mut body = transfer_body(&alice, "bob", 40, 0);
    body.as_object_mut().unwrap().remove("signature");
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(ledger.state))
            .configure(ApiRoutes::configure),
    )
    .await;
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/transactions")
            .set_json(body)
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
    assert!(ledger.pool.lock().unwrap().is_empty());
}

#[actix_web::test]
async fn transfer_from_unregistered_did_is_rejected() {
    let alice = ed25519_account();
    let stranger = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let (status, body) = post(
        ledger.state,
        "/api/v1/transactions",
        transfer_body(&stranger, "bob", 1, 0),
    )
    .await;
    assert_eq!(status, 404, "{body}");
}

#[actix_web::test]
async fn replayed_nonce_is_rejected() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let body = transfer_body(&alice, "bob", 10, 0);
    let (first, _) = post(ledger.state.clone(), "/api/v1/transactions", body.clone()).await;
    let (replay, replay_body) = post(ledger.state.clone(), "/api/v1/transactions", body).await;
    let (next, next_body) = post(
        ledger.state,
        "/api/v1/transactions",
        transfer_body(&alice, "bob", 10, 1),
    )
    .await;
    assert_eq!(first, 201);
    assert_eq!(replay, 409, "{replay_body}");
    assert_eq!(next, 201, "{next_body}");
}

#[actix_web::test]
async fn mint_requires_configured_issuer_signature() {
    let issuer = ed25519_account();
    let ledger = ledger_with_funded(&issuer, 0);
    let message = "transfer:0:bob:500:0";
    let body = serde_json::json!({
        "from": "0", "to": "bob", "amount": 500, "nonce": 0,
        "signature": issuer.sign(message),
    });

    std::env::remove_var("NOTA_ISSUER_DID");
    let (disabled, disabled_body) =
        post(ledger.state.clone(), "/api/v1/transactions", body.clone()).await;

    std::env::set_var("NOTA_ISSUER_DID", ed25519_account().did);
    let (wrong_issuer, _) = post(ledger.state.clone(), "/api/v1/transactions", body.clone()).await;

    std::env::set_var("NOTA_ISSUER_DID", &issuer.did);
    let (minted, minted_body) = post(ledger.state, "/api/v1/transactions", body).await;
    std::env::remove_var("NOTA_ISSUER_DID");

    assert_eq!(disabled, 403, "{disabled_body}");
    assert_eq!(wrong_issuer, 404);
    assert_eq!(minted, 201, "{minted_body}");
}

#[actix_web::test]
async fn create_block_mines_only_signed_transfers() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let mut forged = transfer_body(&alice, "bob", 10, 0);
    forged["signature"] = serde_json::json!("00");
    let (rejected, rejected_body) = post(
        ledger.state.clone(),
        "/api/v1/blocks",
        serde_json::json!({ "transactions": [transfer_body(&alice, "carol", 5, 0), forged] }),
    )
    .await;
    assert_eq!(rejected, 401, "{rejected_body}");
    assert!(ledger.pool.lock().unwrap().is_empty());
    assert_eq!(ledger.store.calculate_balance("carol").unwrap(), 0);

    let (mined, mined_body) = post(
        ledger.state,
        "/api/v1/blocks",
        serde_json::json!({ "transactions": [transfer_body(&alice, "bob", 10, 0)] }),
    )
    .await;
    assert_eq!(mined, 201, "{mined_body}");
    assert_eq!(ledger.store.calculate_balance("bob").unwrap(), 10);
    assert_eq!(ledger.store.calculate_balance(&alice.did).unwrap(), 90);
}

#[actix_web::test]
async fn store_write_rejects_value_transfer() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let forged = committed_tx("forged", &alice.did, "mallory", 100, None);
    let (status, body) = post(
        ledger.state,
        "/api/v1/store/transactions",
        serde_json::to_value(forged).unwrap(),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(ledger.store.calculate_balance(&alice.did).unwrap(), 100);
}

#[actix_web::test]
async fn savings_lock_moves_funds_out_of_spendable_balance() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let (status, body) = post(
        ledger.state.clone(),
        "/api/v1/savings/lock",
        lock_body(&alice, 60, 0),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["data"]["output_recipient"],
        format!("savings:{}", body["data"]["id"].as_str().unwrap())
    );

    let (overspend, overspend_body) = post(
        ledger.state,
        "/api/v1/transactions",
        transfer_body(&alice, "bob", 50, 1),
    )
    .await;
    assert_eq!(overspend, 400, "{overspend_body}");
}

#[actix_web::test]
async fn release_before_unlock_is_rejected() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let lock = committed_tx(
        "lock-future",
        &alice.did,
        "savings:lock-future",
        60,
        Some(TxPayload::SavingsLock {
            unlock_at: FAR_FUTURE,
            nonce: 0,
        }),
    );
    ledger.store.write_transaction(&lock).unwrap();
    let (status, body) = post(
        ledger.state,
        "/api/v1/savings/release",
        release_body(&alice, "lock-future", 1),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(ledger.pool.lock().unwrap().is_empty());
}

#[actix_web::test]
async fn release_after_unlock_returns_funds_to_owner_only() {
    let alice = ed25519_account();
    let mallory = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    mallory.register(ledger.store.as_ref());
    let lock = committed_tx(
        "lock-past",
        &alice.did,
        "savings:lock-past",
        60,
        Some(TxPayload::SavingsLock {
            unlock_at: 1,
            nonce: 0,
        }),
    );
    ledger.store.write_transaction(&lock).unwrap();

    let (stolen, stolen_body) = post(
        ledger.state.clone(),
        "/api/v1/savings/release",
        release_body(&mallory, "lock-past", 0),
    )
    .await;
    let (forged, forged_body) = post(
        ledger.state.clone(),
        "/api/v1/savings/release",
        serde_json::json!({
            "did": alice.did, "lock_id": "lock-past", "nonce": 1,
            "signature": mallory.sign(&format!("savings_release:{}:lock-past:1", alice.did)),
        }),
    )
    .await;
    let (released, released_body) = post(
        ledger.state,
        "/api/v1/savings/release",
        release_body(&alice, "lock-past", 1),
    )
    .await;

    assert_eq!(stolen, 403, "{stolen_body}");
    assert_eq!(forged, 401, "{forged_body}");
    assert_eq!(released, 201, "{released_body}");
    assert_eq!(released_body["data"]["output_recipient"], alice.did);
    assert_eq!(released_body["data"]["amount"], 60);
}

#[actix_web::test]
async fn savings_lock_survives_node_restart() {
    let alice = ed25519_account();
    let dir = tempfile::TempDir::new().unwrap();
    let lock_id = {
        let ledger = ledger_funding(
            Arc::new(RocksDbBlockStore::new(dir.path()).unwrap()),
            &alice,
            100,
        );
        let (status, body) = post(
            ledger.state.clone(),
            "/api/v1/savings/lock",
            lock_body(&alice, 60, 0),
        )
        .await;
        assert_eq!(status, 201, "{body}");
        let pending = ledger.pool.lock().unwrap().drain_for_block(10);
        ledger
            .state
            .mining_service
            .as_ref()
            .unwrap()
            .mine_block("auto-miner", pending)
            .unwrap();
        body["data"]["id"].as_str().unwrap().to_string()
    };

    let ledger = ledger_on(Arc::new(RocksDbBlockStore::new(dir.path()).unwrap()));
    let vault = format!("savings:{lock_id}");
    assert_eq!(ledger.store.calculate_balance(&vault).unwrap(), 60);
    assert_eq!(ledger.store.calculate_balance(&alice.did).unwrap(), 40);

    let (status, body) = post(
        ledger.state,
        "/api/v1/savings/release",
        release_body(&alice, &lock_id, 1),
    )
    .await;
    assert_eq!(status, 403, "{body}");
}

#[actix_web::test]
async fn mine_never_pays_the_caller() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let (status, body) = post(
        ledger.state,
        "/api/v1/mine",
        serde_json::json!({ "miner_address": "attacker" }),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(ledger.store.calculate_balance("attacker").unwrap(), 0);
}

async fn list_savings(state: AppState, did: &str) -> serde_json::Value {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/api/v1/savings/{did}"))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    test::read_body_json(resp).await
}

#[actix_web::test]
async fn savings_listing_reports_each_lock_status() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    let lock = |id: &str, amount: u64, unlock_at: u64, nonce: u64| {
        committed_tx(
            id,
            &alice.did,
            &format!("savings:{id}"),
            amount,
            Some(TxPayload::SavingsLock { unlock_at, nonce }),
        )
    };
    ledger
        .store
        .write_transaction(&lock("locked", 10, FAR_FUTURE, 0))
        .unwrap();
    ledger
        .store
        .write_transaction(&lock("matured", 20, 1, 1))
        .unwrap();
    ledger
        .store
        .write_transaction(&lock("spent", 30, 1, 2))
        .unwrap();
    ledger
        .store
        .write_transaction(&committed_tx(
            "spent-release",
            "savings:spent",
            &alice.did,
            30,
            Some(TxPayload::SavingsRelease {
                owner: alice.did.clone(),
                lock_id: "spent".to_string(),
                nonce: 3,
            }),
        ))
        .unwrap();
    let (status, body) = post(
        ledger.state.clone(),
        "/api/v1/savings/lock",
        lock_body(&alice, 5, 4),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    let listing = list_savings(ledger.state, &alice.did).await;
    let status_of = |lock_id: &str| {
        listing["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["lock_id"] == lock_id)
            .map(|entry| (entry["status"].clone(), entry["locked_amount"].clone()))
            .unwrap()
    };
    assert_eq!(listing["data"].as_array().unwrap().len(), 4);
    assert_eq!(status_of("locked"), ("locked".into(), 10.into()));
    assert_eq!(status_of("matured"), ("unlockable".into(), 20.into()));
    assert_eq!(status_of("spent"), ("released".into(), 0.into()));
    assert_eq!(
        status_of(body["data"]["id"].as_str().unwrap()),
        ("pending".into(), 5.into())
    );
}

#[actix_web::test]
async fn signed_operations_work_under_strict_acl_but_operator_endpoints_do_not() {
    let alice = ed25519_account();
    let ledger = ledger_with_funded(&alice, 100);
    std::env::remove_var("ACL_MODE");

    let (transfer, transfer_body_json) = post(
        ledger.state.clone(),
        "/api/v1/transactions",
        transfer_body(&alice, "bob", 10, 0),
    )
    .await;
    let (lock, lock_json) = post(
        ledger.state.clone(),
        "/api/v1/savings/lock",
        lock_body(&alice, 20, 1),
    )
    .await;
    let (mine, _) = post(ledger.state.clone(), "/api/v1/mine", serde_json::json!({})).await;
    let (blocks, _) = post(
        ledger.state,
        "/api/v1/blocks",
        serde_json::json!({ "transactions": [] }),
    )
    .await;

    assert_eq!(transfer, 201, "{transfer_body_json}");
    assert_eq!(lock, 201, "{lock_json}");
    assert_eq!(mine, 403);
    assert_eq!(blocks, 403);
}
