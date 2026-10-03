//! Integration tests for GET /api/v1/accounts/{address}.
//!
//! Verifies the wallet-compatible endpoint returns balance and nonce
//! derived from BlockStore transactions.

use std::sync::{Arc, RwLock};

use actix_web::{test, web, App};
use rust_bc::{
    api::routes::ApiRoutes,
    storage::{
        traits::{Block, Transaction},
        BlockStore, MemoryStore,
    },
    AppState,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_state(store: Arc<MemoryStore>) -> AppState {
    let mut state = AppState::test_default();
    let mut m = std::collections::HashMap::new();
    m.insert("default".to_string(), store as Arc<dyn BlockStore>);
    state.store = Arc::new(RwLock::new(m));
    state
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

fn tx(id: &str, from: &str, to: &str, amount: u64, height: u64) -> Transaction {
    Transaction {
        id: id.to_string(),
        block_height: height,
        timestamp: 1_000_000 + height,
        input_did: from.to_string(),
        output_recipient: to.to_string(),
        amount,
        fee: 0,
        state: "confirmed".to_string(),
        payload: None,
    }
}

/// Populate store with blocks at given heights so latest_height advances.
fn seed_blocks(store: &MemoryStore, max_height: u64) {
    (0..=max_height).for_each(|h| {
        store.write_block(&empty_block(h)).unwrap();
    });
}

// ── tests ────────────────────────────────────────────────────────────────────

#[actix_web::test]
async fn accounts_returns_zero_for_unknown_address() {
    let store = Arc::new(MemoryStore::new());
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/accounts/nonexistent")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["address"], "nonexistent");
    assert_eq!(body["data"]["balance"], 0);
    assert_eq!(body["data"]["nonce"], 0);
}

#[actix_web::test]
async fn accounts_returns_balance_and_nonce() {
    let store = Arc::new(MemoryStore::new());
    seed_blocks(&store, 2);
    // alice receives 100, then sends 30 to bob, then sends 20 to carol
    store
        .write_transaction(&tx("t1", "genesis", "alice", 100, 0))
        .unwrap();
    store
        .write_transaction(&tx("t2", "alice", "bob", 30, 1))
        .unwrap();
    store
        .write_transaction(&tx("t3", "alice", "carol", 20, 2))
        .unwrap();

    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // alice: balance = 100 - 30 - 20 = 50, nonce = 2 (two outbound txs)
    let req = test::TestRequest::get()
        .uri("/api/v1/accounts/alice")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["balance"], 50);
    assert_eq!(body["data"]["nonce"], 2);

    // bob: balance = 30, nonce = 0 (no outbound txs)
    let req = test::TestRequest::get()
        .uri("/api/v1/accounts/bob")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["balance"], 30);
    assert_eq!(body["data"]["nonce"], 0);
}

#[actix_web::test]
async fn accounts_response_matches_api_envelope() {
    let store = Arc::new(MemoryStore::new());
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/v1/accounts/test_addr")
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;

    // Verify ApiResponse envelope shape
    assert_eq!(body["status"], "Success");
    assert!(body["trace_id"].is_string());
    assert!(body["data"].is_object());
    assert!(body["data"]["address"].is_string());
    assert!(body["data"]["balance"].is_number());
    assert!(body["data"]["nonce"].is_number());
}
