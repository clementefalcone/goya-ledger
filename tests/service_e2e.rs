//! End-to-end test of the free service against the live seed node.
//!
//! Simulates the exact desktop app flow:
//! 1. Generate Ed25519 identity (like cmd_create_identity)
//! 2. Hash a real document (like drag-and-drop)
//! 3. Sign "notarize:{did}:{hash}" (like cmd_notarize)
//! 4. POST to seed node (like SeedProxy::post_raw)
//! 5. GET /notarize/verify/{hash} (like cmd_verify_notarization)
//! 6. GET /health (like cmd_node_status)
//!
//! Run: cargo test --test service_e2e -- --nocapture

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use reqwest::Client;
use std::time::Duration;

/// Target node for this suite. These tests WRITE — they notarize documents
/// and create on-chain records — so there is no default: point it somewhere
/// deliberately, or the suite stays ignored.
///
///   GOYA_E2E_URL=https://goya-node.fly.dev \
///     cargo test --test service_e2e -- --ignored
fn seed_url() -> String {
    std::env::var("GOYA_E2E_URL")
        .expect("GOYA_E2E_URL must be set — these tests write to a live node")
}

fn setup_client() -> Client {
    rust_bc::tls::install_crypto_provider();
    Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("HTTP client")
}

// ── Step 1: Identity ────────────────────────────────────────────────────────

struct Identity {
    did: String,
    public_key_hex: String,
    signing_key: SigningKey,
}

fn create_identity() -> Identity {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let did = format!("did:goya:{}", &public_key_hex[..16]);
    println!("  ✓ Identity created: {}", did);
    println!("    Public key: {}...", &public_key_hex[..32]);
    Identity {
        did,
        public_key_hex,
        signing_key,
    }
}

// ── Step 2: Hash document ───────────────────────────────────────────────────

fn hash_document(data: &[u8]) -> String {
    // Same path as desktop app: pqc_crypto_module::legacy::legacy_sha256
    let hash = pqc_crypto_module::legacy::legacy_sha256(data).expect("SHA-256 cannot fail");
    hex::encode(hash)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_health_check() {
    println!("\n═══ E2E: Health Check ═══");
    let client = setup_client();

    let resp = client
        .get(format!("{}/api/v1/health", seed_url()))
        .send()
        .await
        .expect("health request failed");

    assert_eq!(resp.status(), 200, "seed node unhealthy");
    let body: serde_json::Value = resp.json().await.unwrap();

    let status = body["data"]["status"].as_str().unwrap();
    let height = body["data"]["blockchain"]["height"].as_u64().unwrap();
    assert_eq!(status, "healthy");
    assert!(height > 0, "chain height must be > 0");

    println!("  ✓ Seed node healthy, chain height: {height}");
}

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_full_notarize_and_verify() {
    println!("\n═══ E2E: Full Notarize & Verify Flow ═══");
    let client = setup_client();

    // Step 1: Create identity
    println!("\n── Step 1: Create identity ──");
    let id = create_identity();

    // Step 2: "Open" a document and hash it
    println!("\n── Step 2: Hash document ──");
    let document_content = format!(
        "GOYA Ledger E2E Test Document\n\
         Generated: {}\n\
         This document proves the notarization service works end-to-end.\n\
         Random nonce: {}",
        chrono::Utc::now().to_rfc3339(),
        uuid::Uuid::new_v4(),
    );
    let content_hash = hash_document(document_content.as_bytes());
    println!("  ✓ Document: {} bytes", document_content.len());
    println!("  ✓ SHA-256:  {content_hash}");

    // Step 3: Sign "notarize:{did}:{hash}" — exact same message as server verifies
    println!("\n── Step 3: Sign notarization ──");
    let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
    let signature = id.signing_key.sign(sign_msg.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());
    println!("  ✓ Signed message: {sign_msg}");
    println!("  ✓ Signature: {}...", &signature_hex[..32]);

    // Step 4: POST to seed node — exact same payload as desktop app
    println!("\n── Step 4: Submit notarization to seed node ──");
    let body = serde_json::json!({
        "content_hash": content_hash,
        "signer": id.did,
        "public_key": id.public_key_hex,
        "signature": signature_hex,
        "metadata": {
            "file_name": "e2e-test-document.txt",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }
    });

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("notarize request failed");

    let status = resp.status().as_u16();
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    println!("  HTTP {status}");
    println!(
        "  Response: {}",
        serde_json::to_string_pretty(&resp_body).unwrap()
    );

    assert_eq!(
        status, 201,
        "notarization should return 201 Created: {resp_body}"
    );
    assert_eq!(resp_body["status"], "Success");
    println!("  ✓ Notarization registered on-chain");

    // Step 4b: Verify duplicate is rejected (409)
    println!("\n── Step 4b: Verify duplicate rejection ──");
    let dup_resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("duplicate request failed");

    assert_eq!(dup_resp.status(), 409, "duplicate should be rejected");
    println!("  ✓ Duplicate correctly rejected with 409");

    // Step 5: Verify the notarization via GET
    println!("\n── Step 5: Verify notarization ──");
    let verify_resp = client
        .get(format!(
            "{}/api/v1/notarize/verify/{content_hash}",
            seed_url()
        ))
        .send()
        .await
        .expect("verify request failed");

    assert_eq!(verify_resp.status(), 200);
    let verify_body: serde_json::Value = verify_resp.json().await.unwrap();
    println!(
        "  Response: {}",
        serde_json::to_string_pretty(&verify_body).unwrap()
    );

    assert_eq!(verify_body["data"]["verified"], true);
    assert_eq!(verify_body["data"]["content_hash"], content_hash);
    assert_eq!(verify_body["data"]["signer"], id.did);
    println!("  ✓ Document verified on-chain");
    println!("    Signer: {}", id.did);
    println!("    Block height: {}", verify_body["data"]["block_height"]);

    // Step 6: Verify a non-existent hash returns 404
    println!("\n── Step 6: Verify non-existent hash ──");
    let fake_hash = hex::encode([0xde, 0xad].repeat(16)); // 64 hex chars
    let not_found = client
        .get(format!("{}/api/v1/notarize/verify/{fake_hash}", seed_url()))
        .send()
        .await
        .expect("verify-not-found request failed");

    assert_eq!(not_found.status(), 404);
    println!("  ✓ Non-existent hash correctly returns 404");

    println!("\n═══ ALL STEPS PASSED ═══\n");
}

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_invalid_signature_rejected() {
    println!("\n═══ E2E: Invalid Signature Rejected ═══");
    let client = setup_client();
    let id = create_identity();

    let tampered_doc = format!("tampered-{}", uuid::Uuid::new_v4());
    let content_hash = hash_document(tampered_doc.as_bytes());

    // Sign with correct message but then tamper the hash in the payload
    let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
    let signature = id.signing_key.sign(sign_msg.as_bytes());

    // Send a DIFFERENT hash than what was signed — server must reject
    let tampered_hash = hash_document(b"different-document");
    let body = serde_json::json!({
        "content_hash": tampered_hash,
        "signer": id.did,
        "public_key": id.public_key_hex,
        "signature": hex::encode(signature.to_bytes()),
    });

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&body)
        .send()
        .await
        .expect("tampered request failed");

    assert_eq!(resp.status(), 401, "tampered signature must be rejected");
    println!("  ✓ Tampered payload rejected with 401");
}

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_invalid_hash_format_rejected() {
    println!("\n═══ E2E: Invalid Hash Format Rejected ═══");
    let client = setup_client();

    let body = serde_json::json!({
        "content_hash": "not-a-valid-sha256",
        "signer": "did:goya:test",
        "public_key": "aa".repeat(32),
        "signature": "bb".repeat(64),
    });

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&body)
        .send()
        .await
        .expect("invalid hash request failed");

    assert_eq!(resp.status(), 400, "invalid hash format must be rejected");
    println!("  ✓ Invalid hash format rejected with 400");
}

// ── Concurrency: 5 identities notarize in parallel ─────────────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_concurrent_notarizations() {
    println!("\n═══ E2E: 5 Concurrent Notarizations ═══");
    let client = setup_client();

    let handles: Vec<_> = (0..5)
        .map(|i| {
            let c = client.clone();
            tokio::spawn(async move {
                let id = create_identity();
                let doc = format!("concurrent-doc-{i}-{}", uuid::Uuid::new_v4());
                let content_hash = hash_document(doc.as_bytes());
                let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
                let sig = hex::encode(id.signing_key.sign(sign_msg.as_bytes()).to_bytes());

                let body = serde_json::json!({
                    "content_hash": content_hash,
                    "signer": id.did,
                    "public_key": id.public_key_hex,
                    "signature": sig,
                    "metadata": { "file_name": format!("concurrent-{i}.txt") }
                });

                let resp = c
                    .post(format!("{}/api/v1/notarize", seed_url()))
                    .json(&body)
                    .send()
                    .await
                    .expect("concurrent notarize failed");

                let status = resp.status().as_u16();
                assert_eq!(status, 201, "concurrent notarize {i} failed with {status}");
                println!("  ✓ Identity {i} ({}) notarized", id.did);
                (id.did, content_hash)
            })
        })
        .collect();

    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked"))
        .collect();

    // Verify all 5 exist on-chain
    println!("\n  Verifying all 5...");
    for (did, hash) in &results {
        let resp = client
            .get(format!("{}/api/v1/notarize/verify/{hash}", seed_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["data"]["signer"], *did);
    }
    println!("  ✓ All 5 verified on-chain");
}

// ── Large document: 10MB hashed and notarized ───────────────────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_large_document_10mb() {
    println!("\n═══ E2E: 10MB Document Notarization ═══");
    let client = setup_client();
    let id = create_identity();

    // Generate 10MB of pseudo-random data with unique seed per run
    println!("\n── Generating 10MB document ──");
    let size = 10 * 1024 * 1024;
    let mut data = Vec::with_capacity(size);
    let nonce = uuid::Uuid::new_v4();
    data.extend_from_slice(nonce.as_bytes());
    let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
    while data.len() < size {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.extend_from_slice(&state.to_le_bytes());
    }
    data.truncate(size);
    println!(
        "  ✓ Generated {} bytes ({:.1} MB)",
        data.len(),
        data.len() as f64 / 1_048_576.0
    );

    // Hash — this is the CPU-intensive part the desktop app does locally
    let t0 = std::time::Instant::now();
    let content_hash = hash_document(&data);
    let hash_ms = t0.elapsed().as_millis();
    println!("  ✓ SHA-256: {content_hash}");
    println!("  ✓ Hashed in {hash_ms}ms");

    // Sign and submit — only the 64-char hash goes over the wire, not the 10MB
    let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
    let sig = hex::encode(id.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let body = serde_json::json!({
        "content_hash": content_hash,
        "signer": id.did,
        "public_key": id.public_key_hex,
        "signature": sig,
        "metadata": {
            "file_name": "large-test-10mb.bin",
            "size_bytes": size,
        }
    });

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&body)
        .send()
        .await
        .expect("large doc notarize failed");

    assert_eq!(resp.status(), 201, "large doc should be accepted");
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    println!("  ✓ Notarized on-chain (id: {})", resp_body["data"]["id"]);

    // Verify
    let verify = client
        .get(format!(
            "{}/api/v1/notarize/verify/{content_hash}",
            seed_url()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(verify.status(), 200);
    let vb: serde_json::Value = verify.json().await.unwrap();
    assert_eq!(vb["data"]["verified"], true);
    assert_eq!(vb["data"]["metadata"]["size_bytes"], size);
    println!("  ✓ Verified on-chain with metadata preserved");
}

// ── Multiple docs, same identity, filter by signer ──────────────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_multiple_docs_same_identity_and_list() {
    println!("\n═══ E2E: Multiple Docs Same Identity + List Filter ═══");
    let client = setup_client();

    // Two identities: Alice notarizes 3 docs, Bob notarizes 1
    let alice = create_identity();
    let bob = create_identity();
    println!("  Alice: {}", alice.did);
    println!("  Bob:   {}", bob.did);

    async fn notarize_for(client: &Client, id: &Identity, doc_name: &str) -> String {
        let content = format!("{}-{}", doc_name, uuid::Uuid::new_v4());
        let content_hash = hash_document(content.as_bytes());
        let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
        let sig = hex::encode(id.signing_key.sign(sign_msg.as_bytes()).to_bytes());

        let body = serde_json::json!({
            "content_hash": content_hash,
            "signer": id.did,
            "public_key": id.public_key_hex,
            "signature": sig,
            "metadata": { "file_name": doc_name }
        });

        let resp = client
            .post(format!("{}/api/v1/notarize", seed_url()))
            .json(&body)
            .send()
            .await
            .expect("notarize failed");
        assert_eq!(resp.status(), 201);
        content_hash
    }

    // Alice notarizes 3 documents
    println!("\n── Alice notarizes 3 docs ──");
    let alice_hashes: Vec<String> = {
        let mut hashes = Vec::new();
        for i in 0..3 {
            let name = format!("alice-doc-{i}.pdf");
            let h = notarize_for(&client, &alice, &name).await;
            println!("  ✓ {name} → {}", &h[..16]);
            hashes.push(h);
        }
        hashes
    };

    // Bob notarizes 1 document
    println!("\n── Bob notarizes 1 doc ──");
    let bob_hash = notarize_for(&client, &bob, "bob-contract.pdf").await;
    println!("  ✓ bob-contract.pdf → {}", &bob_hash[..16]);

    // List all notarizations filtered by Alice's DID
    println!("\n── List by signer: Alice ──");
    let resp = client
        .get(format!(
            "{}/api/v1/notarize?signer={}",
            seed_url(),
            alice.did
        ))
        .send()
        .await
        .expect("list request failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let notarizations = body["data"]["notarizations"].as_array().unwrap();

    // Alice's results must contain all 3 hashes
    let returned_hashes: Vec<&str> = notarizations
        .iter()
        .map(|n| n["content_hash"].as_str().unwrap())
        .collect();
    for h in &alice_hashes {
        assert!(
            returned_hashes.contains(&h.as_str()),
            "Alice's hash {h} missing from list"
        );
    }
    // Bob's hash must NOT appear in Alice's filtered list
    assert!(
        !returned_hashes.contains(&bob_hash.as_str()),
        "Bob's hash should not appear in Alice's filtered list"
    );
    println!(
        "  ✓ Alice's list: {} notarizations (all 3 present)",
        returned_hashes.len()
    );
    println!("  ✓ Bob's hash correctly excluded");

    // List by Bob — should contain exactly his hash
    println!("\n── List by signer: Bob ──");
    let resp = client
        .get(format!("{}/api/v1/notarize?signer={}", seed_url(), bob.did))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let bob_results = body["data"]["notarizations"].as_array().unwrap();
    let bob_returned: Vec<&str> = bob_results
        .iter()
        .map(|n| n["content_hash"].as_str().unwrap())
        .collect();
    assert!(bob_returned.contains(&bob_hash.as_str()));
    for h in &alice_hashes {
        assert!(
            !bob_returned.contains(&h.as_str()),
            "Alice's hash leaked into Bob's list"
        );
    }
    println!(
        "  ✓ Bob's list: {} notarization(s), isolated from Alice",
        bob_returned.len()
    );
}

// ── Impersonation: sign with key A, claim to be identity B ──────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_impersonation_rejected() {
    println!("\n═══ E2E: Impersonation Attack ═══");
    let client = setup_client();

    let victim = create_identity();
    let attacker = create_identity();
    println!("  Victim:   {}", victim.did);
    println!("  Attacker: {}", attacker.did);

    let content_hash = hash_document(b"fraudulent-document");

    // Attack 1: Attacker signs with own key but claims victim's DID
    println!("\n── Attack 1: Attacker's key + victim's DID ──");
    let sign_msg = format!("notarize:{}:{}", victim.did, content_hash);
    let sig = hex::encode(attacker.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "signer": victim.did,
            "public_key": attacker.public_key_hex,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "impersonation must be rejected");
    println!("  ✓ Rejected — attacker's public key doesn't match victim's signature context");

    // Attack 2: Attacker signs as themselves but swaps signer field to victim
    println!("\n── Attack 2: Valid self-signature + swapped signer field ──");
    let self_sign_msg = format!("notarize:{}:{}", attacker.did, content_hash);
    let self_sig = hex::encode(
        attacker
            .signing_key
            .sign(self_sign_msg.as_bytes())
            .to_bytes(),
    );

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "signer": victim.did,
            "public_key": attacker.public_key_hex,
            "signature": self_sig,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "signer swap must be rejected");
    println!("  ✓ Rejected — signature was over attacker's DID, not victim's");

    // Attack 3: Attacker uses victim's public key but signs with own private key
    println!("\n── Attack 3: Victim's public key + attacker's private key ──");
    let sign_msg = format!("notarize:{}:{}", victim.did, content_hash);
    let forged_sig = hex::encode(attacker.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "signer": victim.did,
            "public_key": victim.public_key_hex,
            "signature": forged_sig,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "forged signature must be rejected");
    println!("  ✓ Rejected — signature doesn't match victim's public key");

    // Sanity: victim can still notarize legitimately
    println!("\n── Sanity: victim notarizes legitimately ──");
    let legit_doc = format!("legitimate-{}", uuid::Uuid::new_v4());
    let legit_content = hash_document(legit_doc.as_bytes());
    let legit_msg = format!("notarize:{}:{}", victim.did, legit_content);
    let legit_sig = hex::encode(victim.signing_key.sign(legit_msg.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": legit_content,
            "signer": victim.did,
            "public_key": victim.public_key_hex,
            "signature": legit_sig,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "legitimate notarization should succeed");
    println!("  ✓ Victim's legitimate notarization accepted (201)");
}

// ── Account endpoint: balance, nonce, non-existent address ──────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_account_endpoint() {
    println!("\n═══ E2E: Account Endpoint ═══");
    let client = setup_client();

    // Query a fresh identity that has never transacted — should return 0/0
    let id = create_identity();
    println!("\n── Query fresh account (never transacted) ──");
    let resp = client
        .get(format!("{}/api/v1/accounts/{}", seed_url(), id.did))
        .send()
        .await
        .expect("account request failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let data = &body["data"];
    assert_eq!(data["address"], id.did);
    let balance = data["balance"].as_u64().unwrap();
    let nonce = data["nonce"].as_u64().unwrap();
    println!("  ✓ Address: {}", id.did);
    println!("  ✓ Balance: {balance} (expected 0)");
    println!("  ✓ Nonce:   {nonce} (expected 0)");
    assert_eq!(balance, 0, "fresh account should have 0 balance");
    assert_eq!(nonce, 0, "fresh account should have 0 nonce");

    // Query a totally bogus address — should still return 200 with 0/0
    println!("\n── Query nonexistent address ──");
    let resp = client
        .get(format!(
            "{}/api/v1/accounts/did:goya:does_not_exist",
            seed_url()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "nonexistent address should return 200 with defaults"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["balance"], 0);
    assert_eq!(body["data"]["nonce"], 0);
    println!("  ✓ Nonexistent address returns 200 with balance=0, nonce=0");

    // Query via wallets endpoint too — should match
    println!("\n── Cross-check: /wallets/{{address}} ──");
    let resp = client
        .get(format!("{}/api/v1/wallets/{}", seed_url(), id.did))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["balance"], 0);
    println!("  ✓ /wallets/ endpoint consistent with /accounts/");
}

// ── Malformed payloads: the server must reject gracefully ───────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_malformed_payloads() {
    println!("\n═══ E2E: Malformed Payloads ═══");
    let client = setup_client();

    // 1. Completely empty body
    println!("\n── 1. Empty body ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "empty body should be 4xx, got {}",
        resp.status()
    );
    println!("  ✓ Empty body → {}", resp.status());

    // 2. Raw garbage (not JSON)
    println!("\n── 2. Non-JSON body ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .header("Content-Type", "application/json")
        .body("this is not json at all")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "garbage body should be 4xx, got {}",
        resp.status()
    );
    println!("  ✓ Non-JSON body → {}", resp.status());

    // 3. Missing required fields (only content_hash, no signer/key/sig)
    println!("\n── 3. Missing required fields ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": "aa".repeat(32),
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "missing fields should be 4xx, got {}",
        resp.status()
    );
    println!("  ✓ Missing fields → {}", resp.status());

    // 4. Truncated public key (31 bytes instead of 32)
    println!("\n── 4. Truncated public key (31 bytes) ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": "aa".repeat(32),
            "signer": "did:goya:test",
            "public_key": "bb".repeat(31),
            "signature": "cc".repeat(64),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "truncated key should be 400");
    println!("  ✓ Truncated public key → 400");

    // 5. Oversized public key (33 bytes)
    println!("\n── 5. Oversized public key (33 bytes) ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": "aa".repeat(32),
            "signer": "did:goya:test",
            "public_key": "bb".repeat(33),
            "signature": "cc".repeat(64),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "oversized key should be 400");
    println!("  ✓ Oversized public key → 400");

    // 6. Hash too short (31 bytes)
    println!("\n── 6. Hash too short ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": "aa".repeat(31),
            "signer": "did:goya:test",
            "public_key": "bb".repeat(32),
            "signature": "cc".repeat(64),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "short hash should be 400");
    println!("  ✓ Hash too short → 400");

    // 7. Non-hex characters in hash
    println!("\n── 7. Non-hex hash ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": "zz".repeat(32),
            "signer": "did:goya:test",
            "public_key": "bb".repeat(32),
            "signature": "cc".repeat(64),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "non-hex hash should be 400");
    println!("  ✓ Non-hex hash → 400");

    // 8. Empty string fields
    println!("\n── 8. Empty string fields ──");
    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": "",
            "signer": "",
            "public_key": "",
            "signature": "",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "empty strings should be 4xx, got {}",
        resp.status()
    );
    println!("  ✓ Empty strings → {}", resp.status());

    // 9. SQL injection attempt in signer field
    println!("\n── 9. SQL injection in signer ──");
    let id = create_identity();
    let content_hash = hash_document(b"sql-injection-test");
    let signer_sqli = "did:goya:test'; DROP TABLE notarizations; --";
    let sign_msg = format!("notarize:{signer_sqli}:{content_hash}");
    let sig = hex::encode(id.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "signer": signer_sqli,
            "public_key": id.public_key_hex,
            "signature": sig,
        }))
        .send()
        .await
        .unwrap();
    // Should be rejected (signer doesn't match pubkey DID) or at worst accepted harmlessly
    assert!(
        !resp.status().is_server_error(),
        "SQL injection must not cause 5xx, got {}",
        resp.status()
    );
    println!("  ✓ SQL injection attempt → {} (no 5xx)", resp.status());

    // 10. XSS attempt in metadata
    println!("\n── 10. XSS in metadata ──");
    let content_hash = hash_document(b"xss-test");
    let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
    let sig = hex::encode(id.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "signer": id.did,
            "public_key": id.public_key_hex,
            "signature": sig,
            "metadata": {
                "file_name": "<script>alert('xss')</script>",
                "onload": "javascript:alert(1)",
            }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_server_error(),
        "XSS payload must not cause 5xx, got {}",
        resp.status()
    );
    println!("  ✓ XSS in metadata → {} (no 5xx)", resp.status());

    // 11. Massive metadata (1MB JSON blob)
    println!("\n── 11. Oversized metadata (1MB) ──");
    let big_value = "A".repeat(1_000_000);
    let content_hash = hash_document(b"bigmeta-test");
    let sign_msg = format!("notarize:{}:{}", id.did, content_hash);
    let sig = hex::encode(id.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/notarize", seed_url()))
        .json(&serde_json::json!({
            "content_hash": content_hash,
            "signer": id.did,
            "public_key": id.public_key_hex,
            "signature": sig,
            "metadata": { "payload": big_value }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_server_error(),
        "1MB metadata must not crash server, got {}",
        resp.status()
    );
    println!("  ✓ 1MB metadata → {} (server survived)", resp.status());
}

// ── Wallet: faucet → balance → transfer → verify ───────────────────────────

async fn post_json(client: &Client, path: &str, body: &serde_json::Value) -> serde_json::Value {
    for attempt in 0..10u64 {
        tokio::time::sleep(std::time::Duration::from_secs(attempt * 2)).await;
        let resp = client
            .post(format!("{}{path}", seed_url()))
            .json(body)
            .send()
            .await
            .expect("request failed");
        match resp.status().as_u16() {
            429 => continue,
            _ => {
                let text = resp.text().await.unwrap();
                return serde_json::from_str(&text)
                    .unwrap_or_else(|_| serde_json::json!({"raw": text}));
            }
        }
    }
    panic!("post_json exhausted retries on {path}");
}

async fn get_json(client: &Client, path: &str) -> serde_json::Value {
    for attempt in 0..10u64 {
        tokio::time::sleep(std::time::Duration::from_secs(attempt * 2)).await;
        let resp = client
            .get(format!("{}{path}", seed_url()))
            .send()
            .await
            .expect("request failed");
        match resp.status().as_u16() {
            429 => continue,
            _ => {
                let text = resp.text().await.unwrap();
                return serde_json::from_str(&text)
                    .unwrap_or_else(|_| serde_json::json!({"raw": text}));
            }
        }
    }
    panic!("get_json exhausted retries on {path}");
}

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_wallet_full_flow() {
    println!("\n═══ E2E: Wallet Full Flow ═══");
    let client = setup_client();

    let alice = create_identity();
    let bob = create_identity();
    println!("  Alice: {}", alice.did);
    println!("  Bob:   {}", bob.did);

    // Step 1: Faucet — fund Alice with 5000 via coinbase (retry on 429)
    println!("\n── Step 1: Faucet fund Alice ──");
    let faucet_tx: serde_json::Value = {
        let mut resp = None;
        for attempt in 0..10 {
            tokio::time::sleep(std::time::Duration::from_secs(attempt * 2)).await;
            let r = client
                .post(format!("{}/api/v1/transactions", seed_url()))
                .json(&serde_json::json!({
                    "from": "0", "to": alice.did, "amount": 5000
                }))
                .send()
                .await
                .expect("faucet request failed");
            match r.status().as_u16() {
                429 => println!("  ⏳ Rate limited, retry {attempt}..."),
                _ => {
                    resp = Some(r);
                    break;
                }
            }
        }
        let r = resp.expect("all faucet retries exhausted (429)");
        assert!(
            r.status().is_success(),
            "coinbase tx failed: {}",
            r.status()
        );
        r.json().await.unwrap()
    };
    println!("  ✓ Coinbase tx created: {}", faucet_tx["data"]["id"]);

    // Commit block
    let block = post_json(
        &client,
        "/api/v1/blocks",
        &serde_json::json!({
            "transactions": [{ "from": "0", "to": alice.did, "amount": 5000 }]
        }),
    )
    .await;
    println!("  ✓ Block committed: {}", block["data"]);

    // Step 2: Check Alice balance
    println!("\n── Step 2: Check Alice balance ──");
    let alice_acc = get_json(&client, &format!("/api/v1/accounts/{}", alice.did)).await;
    let alice_balance = alice_acc["data"]["balance"].as_u64().unwrap();
    assert!(
        alice_balance >= 5000,
        "Alice should have >= 5000, got {alice_balance}"
    );
    println!("  ✓ Alice balance: {alice_balance}");

    // Step 3: Alice transfers 2000 to Bob
    println!("\n── Step 3: Transfer Alice → Bob (2000) ──");
    let nonce = alice_acc["data"]["nonce"].as_u64().unwrap();
    let sign_msg = format!("transfer:{}:{}:2000:{nonce}", alice.did, bob.did);
    let signature = hex::encode(alice.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let transfer_tx = post_json(
        &client,
        "/api/v1/transactions",
        &serde_json::json!({
            "from": alice.did,
            "to": bob.did,
            "amount": 2000,
            "nonce": nonce,
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(
        transfer_tx["status"], "Success",
        "transfer should succeed: {transfer_tx}"
    );
    let tx_id = transfer_tx["data"]["id"].as_str().unwrap();
    println!("  ✓ Transfer tx: {tx_id}");

    // Commit block
    post_json(
        &client,
        "/api/v1/blocks",
        &serde_json::json!({
            "transactions": [{
                "from": alice.did, "to": bob.did, "amount": 2000,
                "signature": signature,
            }]
        }),
    )
    .await;
    println!("  ✓ Block committed");

    // Step 4: Verify balances
    println!("\n── Step 4: Verify balances ──");
    let alice_after = get_json(&client, &format!("/api/v1/accounts/{}", alice.did)).await;
    let bob_after = get_json(&client, &format!("/api/v1/accounts/{}", bob.did)).await;

    let alice_bal = alice_after["data"]["balance"].as_u64().unwrap();
    let bob_bal = bob_after["data"]["balance"].as_u64().unwrap();
    println!("  Alice: {alice_bal} (was {alice_balance}, sent 2000)");
    println!("  Bob:   {bob_bal}");

    assert!(
        alice_bal < alice_balance,
        "Alice balance should decrease after transfer"
    );
    assert!(bob_bal >= 2000, "Bob should have >= 2000");

    // Step 5: Transaction history
    println!("\n── Step 5: Transaction history ──");
    let alice_txs = get_json(
        &client,
        &format!("/api/v1/wallets/{}/transactions", alice.did),
    )
    .await;
    let alice_tx_list = alice_txs["data"].as_array().unwrap();
    assert!(
        alice_tx_list.len() >= 2,
        "Alice should have >= 2 txs (faucet + transfer)"
    );
    println!("  ✓ Alice history: {} transactions", alice_tx_list.len());

    let bob_txs = get_json(
        &client,
        &format!("/api/v1/wallets/{}/transactions", bob.did),
    )
    .await;
    let bob_tx_list = bob_txs["data"].as_array().unwrap();
    assert!(!bob_tx_list.is_empty(), "Bob should have >= 1 tx");
    println!("  ✓ Bob history: {} transactions", bob_tx_list.len());

    // Step 6: Insufficient balance rejected
    println!("\n── Step 6: Insufficient balance ──");
    let big_sign = format!("transfer:{}:{}:999999:1", alice.did, bob.did);
    let big_sig = hex::encode(alice.signing_key.sign(big_sign.as_bytes()).to_bytes());

    let resp = client
        .post(format!("{}/api/v1/transactions", seed_url()))
        .json(&serde_json::json!({
            "from": alice.did,
            "to": bob.did,
            "amount": 999999,
            "nonce": 1,
            "signature": big_sig,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "insufficient balance should be rejected"
    );
    println!("  ✓ Insufficient balance rejected");

    println!("\n═══ WALLET FLOW COMPLETE ═══\n");
}

// ── Governance: create proposal → vote → tally ─────────────────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_governance_full_flow() {
    println!("\n═══ E2E: Governance Full Flow ═══");
    let client = setup_client();

    let proposer = create_identity();
    let voter_yes = create_identity();
    let voter_no = create_identity();
    println!("  Proposer: {}", proposer.did);
    println!("  Voter A:  {}", voter_yes.did);
    println!("  Voter B:  {}", voter_no.did);

    // Step 1: Create a text proposal
    println!("\n── Step 1: Create proposal ──");
    let proposal = post_json(
        &client,
        "/api/v1/governance/proposals",
        &serde_json::json!({
            "proposer": proposer.did,
            "description": format!("E2E test proposal {}", uuid::Uuid::new_v4()),
            "deposit": 10000,
            "action": {
                "type": "text",
                "title": "Increase block size to 2MB",
                "description": "Proposal to increase maximum block size for better throughput",
            }
        }),
    )
    .await;
    let proposal_id = proposal["data"]["id"]
        .as_u64()
        .expect("proposal must have id");
    println!("  ✓ Proposal #{proposal_id} created");

    // Step 2: List proposals — should include ours
    println!("\n── Step 2: List proposals ──");
    let list = get_json(&client, "/api/v1/governance/proposals").await;
    let items = list["data"]["data"]
        .as_array()
        .or_else(|| list["data"]["items"].as_array())
        .or_else(|| list["data"].as_array())
        .expect("proposals list");
    let found = items.iter().any(|p| p["id"].as_u64() == Some(proposal_id));
    assert!(found, "our proposal should appear in list");
    println!(
        "  ✓ Proposal #{proposal_id} found in list ({} total)",
        items.len()
    );

    // Step 3: Get proposal by ID
    println!("\n── Step 3: Get proposal by ID ──");
    let detail = get_json(
        &client,
        &format!("/api/v1/governance/proposals/{proposal_id}"),
    )
    .await;
    assert_eq!(detail["data"]["id"], proposal_id);
    println!("  ✓ Proposal detail retrieved");

    // Step 4: Vote Yes (signed)
    println!("\n── Step 4: Voter A votes Yes (signed) ──");
    let option_str = "Yes";
    let vote_payload = format!(
        "vote:{proposal_id}:{option_str}:{}",
        voter_yes.public_key_hex
    );
    let vote_sig = hex::encode(
        voter_yes
            .signing_key
            .sign(vote_payload.as_bytes())
            .to_bytes(),
    );

    let tally = post_json(
        &client,
        &format!("/api/v1/governance/proposals/{proposal_id}/vote"),
        &serde_json::json!({
            "voter": voter_yes.did,
            "option": "Yes",
            "signature": vote_sig,
            "public_key": voter_yes.public_key_hex,
        }),
    )
    .await;
    println!(
        "  ✓ Vote recorded, yes_power: {}",
        tally["data"]["yes_power"]
    );

    // Step 5: Vote No (signed)
    println!("\n── Step 5: Voter B votes No (signed) ──");
    let no_payload = format!("vote:{proposal_id}:No:{}", voter_no.public_key_hex);
    let no_sig = hex::encode(voter_no.signing_key.sign(no_payload.as_bytes()).to_bytes());

    post_json(
        &client,
        &format!("/api/v1/governance/proposals/{proposal_id}/vote"),
        &serde_json::json!({
            "voter": voter_no.did,
            "option": "No",
            "signature": no_sig,
            "public_key": voter_no.public_key_hex,
        }),
    )
    .await;
    println!("  ✓ No vote recorded");

    // Step 6: Get tally
    println!("\n── Step 6: Get tally ──");
    let tally = get_json(
        &client,
        &format!("/api/v1/governance/proposals/{proposal_id}/tally"),
    )
    .await;
    let yes = tally["data"]["yes_power"].as_u64().unwrap_or(0);
    let no = tally["data"]["no_power"].as_u64().unwrap_or(0);
    assert!(yes > 0, "yes_power should be > 0");
    assert!(no > 0, "no_power should be > 0");
    println!("  ✓ Tally — Yes: {yes}, No: {no}");

    // Step 7: Duplicate vote rejected
    println!("\n── Step 7: Duplicate vote rejected ──");
    let dup_result = post_json(
        &client,
        &format!("/api/v1/governance/proposals/{proposal_id}/vote"),
        &serde_json::json!({
            "voter": voter_yes.did,
            "option": "Yes",
            "signature": vote_sig,
            "public_key": voter_yes.public_key_hex,
        }),
    )
    .await;
    // Duplicate should return error status (not "Success")
    assert_ne!(
        dup_result["status"], "Success",
        "duplicate vote should be rejected"
    );
    println!("  ✓ Duplicate vote rejected");

    // Step 8: Vote on nonexistent proposal
    println!("\n── Step 8: Vote on nonexistent proposal ──");
    let fake_result = post_json(
        &client,
        "/api/v1/governance/proposals/999999/vote",
        &serde_json::json!({
            "voter": voter_yes.did,
            "option": "Yes",
        }),
    )
    .await;
    assert_ne!(fake_result["status"], "Success");
    println!("  ✓ Nonexistent proposal rejected");

    println!("\n═══ GOVERNANCE FLOW COMPLETE ═══\n");
}

// ── Document ownership transfer ─────────────────────────────────────────────

#[tokio::test]
#[ignore = "writes to a live node; set GOYA_E2E_URL and run with --ignored"]
async fn e2e_document_transfer_flow() {
    println!("\n═══ E2E: Document Ownership Transfer ═══");
    let client = setup_client();

    let alice = create_identity();
    let bob = create_identity();
    let charlie = create_identity();
    println!("  Alice:   {}", alice.did);
    println!("  Bob:     {}", bob.did);
    println!("  Charlie: {}", charlie.did);

    // Step 1: Alice notarizes a document
    println!("\n── Step 1: Alice notarizes document ──");
    let doc = format!("transfer-test-{}", uuid::Uuid::new_v4());
    let content_hash = hash_document(doc.as_bytes());
    let sign_msg = format!("notarize:{}:{}", alice.did, content_hash);
    let sig = hex::encode(alice.signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let notarize_resp = post_json(
        &client,
        "/api/v1/notarize",
        &serde_json::json!({
            "content_hash": content_hash,
            "signer": alice.did,
            "public_key": alice.public_key_hex,
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(notarize_resp["status"], "Success");
    println!("  ✓ Document notarized: {}", &content_hash[..16]);

    // Step 2: Check owner — should be Alice
    println!("\n── Step 2: Check owner (Alice) ──");
    let owner = get_json(&client, &format!("/api/v1/notarize/{content_hash}/owner")).await;
    assert_eq!(owner["data"]["owner"], alice.did);
    assert_eq!(owner["data"]["transfer_count"], 0);
    println!("  ✓ Owner: {} (0 transfers)", alice.did);

    // Step 3: Alice transfers to Bob
    println!("\n── Step 3: Transfer Alice → Bob ──");
    let transfer_msg = format!("transfer_doc:{}:0:{}:{}", content_hash, alice.did, bob.did);
    let transfer_sig = hex::encode(alice.signing_key.sign(transfer_msg.as_bytes()).to_bytes());

    let transfer_resp = post_json(
        &client,
        &format!("/api/v1/notarize/{content_hash}/transfer"),
        &serde_json::json!({
            "from_did": alice.did,
            "to_did": bob.did,
            "public_key": alice.public_key_hex,
            "signature": transfer_sig,
        }),
    )
    .await;
    assert_eq!(
        transfer_resp["status"], "Success",
        "transfer should succeed: {transfer_resp}"
    );
    println!("  ✓ Transferred to Bob");

    // Step 4: Check owner — should be Bob
    println!("\n── Step 4: Check owner (Bob) ──");
    let owner = get_json(&client, &format!("/api/v1/notarize/{content_hash}/owner")).await;
    assert_eq!(owner["data"]["owner"], bob.did);
    assert_eq!(owner["data"]["transfer_count"], 1);
    println!("  ✓ Owner: {} (1 transfer)", bob.did);

    // Step 5: Bob transfers to Charlie (brief pause to avoid rate limit)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    println!("\n── Step 5: Transfer Bob → Charlie ──");
    let transfer_msg2 = format!(
        "transfer_doc:{}:1:{}:{}",
        content_hash, bob.did, charlie.did
    );
    let transfer_sig2 = hex::encode(bob.signing_key.sign(transfer_msg2.as_bytes()).to_bytes());

    let transfer_resp2 = post_json(
        &client,
        &format!("/api/v1/notarize/{content_hash}/transfer"),
        &serde_json::json!({
            "from_did": bob.did,
            "to_did": charlie.did,
            "public_key": bob.public_key_hex,
            "signature": transfer_sig2,
        }),
    )
    .await;
    assert_eq!(
        transfer_resp2["status"], "Success",
        "Bob→Charlie transfer should succeed: {transfer_resp2}"
    );
    println!("  ✓ Transferred to Charlie");

    // Step 6: Check provenance — full chain
    println!("\n── Step 6: Provenance chain ──");
    let prov = get_json(
        &client,
        &format!("/api/v1/notarize/{content_hash}/provenance"),
    )
    .await;
    assert_eq!(prov["data"]["original_signer"], alice.did);
    let transfers = prov["data"]["transfers"].as_array().unwrap();
    assert_eq!(transfers.len(), 2, "should have 2 transfers");
    assert_eq!(transfers[0]["from_did"], alice.did);
    assert_eq!(transfers[0]["to_did"], bob.did);
    assert_eq!(transfers[1]["from_did"], bob.did);
    assert_eq!(transfers[1]["to_did"], charlie.did);
    println!("  ✓ Provenance: Alice → Bob → Charlie");

    // Step 7: Alice tries to transfer (no longer owner) — rejected
    println!("\n── Step 7: Unauthorized transfer (Alice no longer owner) ──");
    let bad_msg = format!(
        "transfer_doc:{}:2:{}:{}",
        content_hash, alice.did, alice.did
    );
    let bad_sig = hex::encode(alice.signing_key.sign(bad_msg.as_bytes()).to_bytes());

    let bad_resp = post_json(
        &client,
        &format!("/api/v1/notarize/{content_hash}/transfer"),
        &serde_json::json!({
            "from_did": alice.did,
            "to_did": alice.did,
            "public_key": alice.public_key_hex,
            "signature": bad_sig,
        }),
    )
    .await;
    assert_ne!(
        bad_resp["status"], "Success",
        "non-owner transfer must be rejected"
    );
    println!("  ✓ Unauthorized transfer rejected");

    // Step 8: Transfer nonexistent document — rejected
    println!("\n── Step 8: Transfer nonexistent document ──");
    let fake_hash = "ff".repeat(32);
    let fake_msg = format!("transfer_doc:{}:0:{}:{}", fake_hash, alice.did, bob.did);
    let fake_sig = hex::encode(alice.signing_key.sign(fake_msg.as_bytes()).to_bytes());

    let fake_resp = post_json(
        &client,
        &format!("/api/v1/notarize/{fake_hash}/transfer"),
        &serde_json::json!({
            "from_did": alice.did,
            "to_did": bob.did,
            "public_key": alice.public_key_hex,
            "signature": fake_sig,
        }),
    )
    .await;
    assert_ne!(fake_resp["status"], "Success");
    println!("  ✓ Nonexistent document rejected");

    println!("\n═══ DOCUMENT TRANSFER COMPLETE ═══\n");
}
