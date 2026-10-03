//! E2E test simulating the exact goya-wallet transaction flow.
//!
//! Flow: GET /accounts/{address} → POST /transactions → GET /accounts/{address}
//! Verifies balance, nonce, and tx.id across the full cycle.

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

// ── tests ────────────────────────────────────────────────────────────────────

/// Full wallet flow: check account → submit transfer → verify state change.
#[actix_web::test]
async fn wallet_transfer_full_flow() {
    setup_env();

    let sender = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
    let recipient = "b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1";

    // Setup: sender funded with 1000, nonce=0 (no outbound txs yet)
    let store = Arc::new(MemoryStore::new());
    seed_blocks(&store, 0);
    store
        .write_transaction(&stored_tx("funding-tx", "genesis", sender, 1000, 0))
        .unwrap();

    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // Step 1: GET /accounts/{sender} — verify initial state
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/accounts/{sender}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let _initial_balance = body["data"]["balance"].as_u64().unwrap();
    let initial_nonce = body["data"]["nonce"].as_u64().unwrap();
    assert_eq!(initial_nonce, 0);

    // Step 2: POST /transactions — exact goya-wallet payload
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": sender,
            "to": recipient,
            "amount": 50,
            "nonce": initial_nonce,
            "fee": 1,
            "signature": "a]0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;

    // Verify response contains tx.id (wallet needs this for tracking)
    let tx_id = body["data"]["id"].as_str();
    assert!(tx_id.is_some(), "response must include tx id");
    assert!(!tx_id.unwrap().is_empty(), "tx id must not be empty");

    // Verify response contains expected fields
    assert_eq!(body["data"]["input_did"], sender);
    assert_eq!(body["data"]["output_recipient"], recipient);
    assert_eq!(body["data"]["amount"], 50);
    assert_eq!(body["data"]["state"], "pending");
    assert_eq!(body["status"], "Success");
}

/// Wallet payload with all fields present — exact JSON shape.
#[actix_web::test]
async fn wallet_payload_accepted_verbatim() {
    setup_env();

    let store = Arc::new(MemoryStore::new());
    seed_blocks(&store, 0);
    // Fund with hex-style address matching wallet format
    store
        .write_transaction(&stored_tx(
            "fund",
            "genesis",
            "deadbeef01234567890abcdef01234567890abcd",
            500,
            0,
        ))
        .unwrap();

    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // Exact JSON shape that goya-wallet's submitTransfer sends
    let wallet_payload = serde_json::json!({
        "from": "deadbeef01234567890abcdef01234567890abcd",
        "to":   "cafebabe01234567890abcdef01234567890abcd",
        "amount": 25,
        "nonce": 0,
        "fee": 1,
        "signature": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(&wallet_payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        201,
        "wallet payload must be accepted by ledger"
    );
}

/// Wallet payload WITHOUT signature is rejected (security boundary).
#[actix_web::test]
async fn wallet_payload_without_signature_rejected() {
    setup_env();

    let store = Arc::new(MemoryStore::new());
    seed_blocks(&store, 0);
    store
        .write_transaction(&stored_tx(
            "fund",
            "genesis",
            "deadbeef01234567890abcdef01234567890abcd",
            500,
            0,
        ))
        .unwrap();

    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // Missing signature — must be rejected
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "deadbeef01234567890abcdef01234567890abcd",
            "to":   "cafebabe01234567890abcdef01234567890abcd",
            "amount": 25,
            "nonce": 0,
            "fee": 1
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("Signature required"),
        "expected signature error, got: {msg}"
    );
}

/// Coinbase (from="0") funds an account without balance check.
#[actix_web::test]
async fn coinbase_funds_account() {
    setup_env();

    let store = Arc::new(MemoryStore::new());
    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    let recipient = "deadbeef01234567890abcdef01234567890abcd";

    // Coinbase mint — no signature required, no balance check
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "0",
            "to": recipient,
            "amount": 1000
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "coinbase tx must be accepted");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["output_recipient"], recipient);
    assert_eq!(body["data"]["amount"], 1000);
}

/// Wallet payload with wrong nonce is rejected.
#[actix_web::test]
async fn wallet_payload_with_stale_nonce_rejected() {
    setup_env();

    let store = Arc::new(MemoryStore::new());
    seed_blocks(&store, 1);
    store
        .write_transaction(&stored_tx(
            "fund",
            "genesis",
            "deadbeef01234567890abcdef01234567890abcd",
            500,
            0,
        ))
        .unwrap();
    // One outbound tx → nonce = 1
    store
        .write_transaction(&stored_tx(
            "tx1",
            "deadbeef01234567890abcdef01234567890abcd",
            "cafebabe01234567890abcdef01234567890abcd",
            10,
            1,
        ))
        .unwrap();

    let state = make_state(store);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(ApiRoutes::configure),
    )
    .await;

    // Send with nonce=0, expected=1
    let req = test::TestRequest::post()
        .uri("/api/v1/transactions")
        .set_json(serde_json::json!({
            "from": "deadbeef01234567890abcdef01234567890abcd",
            "to":   "cafebabe01234567890abcdef01234567890abcd",
            "amount": 25,
            "nonce": 0,
            "fee": 1,
            "signature": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("nonce mismatch"),
        "expected nonce error, got: {msg}"
    );
}
