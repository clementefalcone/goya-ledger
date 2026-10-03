//! Integration tests for nonce validation on POST /api/v1/transactions.
//!
//! Verifies that the ledger rejects transactions with mismatched nonce
//! and accepts transactions with correct nonce.

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

/// ACL_MODE=permissive so enforce_acl doesn't block test requests.
fn setup_env() {
    std::env::set_var("ACL_MODE", "permissive");
}

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

fn stored_tx(id: &str, from: &str, to: &str, amount: u64, height: u64) -> Transaction {
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

fn seed_blocks(store: &MemoryStore, max_height: u64) {
    (0..=max_height).for_each(|h| {
        store.write_block(&empty_block(h)).unwrap();
    });
}

/// Store with funded alice (balance=90, nonce=1).
fn store_with_funded_alice() -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::new());
    seed_blocks(&store, 1);
    store
        .write_transaction(&stored_tx("t0", "genesis", "alice_addr", 100, 0))
        .unwrap();
    store
        .write_transaction(&stored_tx("t1", "alice_addr", "bob_addr_x", 10, 1))
        .unwrap();
    store
}

// ── tests ────────────────────────────────────────────────────────────────────

#[actix_web::test]
async fn rejects_transaction_with_wrong_nonce() {
    setup_env();
    let store = store_with_funded_alice();
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // alice nonce is 1, send with nonce=0 (stale)
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "alice_addr",
            "to": "carol_addr",
            "amount": 5,
            "nonce": 0,
            "signature": "deadbeef"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let error_msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_msg.contains("nonce mismatch"),
        "expected nonce mismatch error, got: {error_msg}"
    );
}

#[actix_web::test]
async fn rejects_transaction_with_future_nonce() {
    setup_env();
    let store = store_with_funded_alice();
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // alice nonce is 1, send with nonce=5 (future)
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "alice_addr",
            "to": "carol_addr",
            "amount": 5,
            "nonce": 5,
            "signature": "deadbeef"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let error_msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_msg.contains("nonce mismatch"),
        "expected nonce mismatch error, got: {error_msg}"
    );
}

#[actix_web::test]
async fn accepts_transaction_with_correct_nonce() {
    setup_env();
    let store = store_with_funded_alice();
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // alice nonce is 1, send with nonce=1 (correct)
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "alice_addr",
            "to": "carol_addr",
            "amount": 5,
            "nonce": 1,
            "signature": "deadbeef"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
}

#[actix_web::test]
async fn accepts_transaction_without_nonce() {
    setup_env();
    // Backwards compatibility: omitting nonce skips validation
    let store = store_with_funded_alice();
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "alice_addr",
            "to": "bob_addr_x",
            "amount": 5,
            "signature": "deadbeef"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
}
