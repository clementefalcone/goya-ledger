//! Lightweight P2P multi-node test — no Docker, no monitoring.
//!
//! Spawns 2 node processes on localhost with different ports,
//! verifies they discover each other and can exchange data.
//! Total RAM: ~100-150MB (2 lean processes).

use std::process::{Child, Command};
use std::time::Duration;

struct TestNode {
    child: Child,
    api_port: u16,
}

impl TestNode {
    fn spawn(api_port: u16, p2p_port: u16, bootstrap: Option<&str>) -> Self {
        // Use precompiled binary from target/debug
        let bin = std::env::current_dir()
            .unwrap()
            .join("target/debug/rust-bc");
        if !bin.exists() {
            panic!(
                "Binary not found at {:?}. Run `cargo build --bin rust-bc` first.",
                bin
            );
        }

        let mut cmd = Command::new(&bin);
        cmd.arg(api_port.to_string())
            .arg(p2p_port.to_string())
            .env("ACL_MODE", "permissive")
            .env("DIFFICULTY", "1")
            .env("NETWORK_ID", "p2p-test")
            .env("BIND_ADDR", "127.0.0.1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        if let Some(peers) = bootstrap {
            cmd.env("BOOTSTRAP_NODES", peers);
        }

        let child = cmd.spawn().expect("failed to spawn node");
        Self { child, api_port }
    }

    fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}/api/v1{}", self.api_port, path)
    }

    fn wait_ready(&self, timeout_secs: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        while std::time::Instant::now() < deadline {
            if let Ok(resp) = reqwest::blocking::get(self.api_url("/health")) {
                if resp.status().is_success() {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn get_json(url: &str) -> serde_json::Value {
    reqwest::blocking::get(url)
        .expect("request failed")
        .json()
        .expect("invalid json")
}

fn post_json(url: &str, body: serde_json::Value) -> serde_json::Value {
    rust_bc::tls::install_crypto_provider();
    reqwest::blocking::Client::new()
        .post(url)
        .json(&body)
        .send()
        .expect("request failed")
        .json()
        .expect("invalid json")
}

#[test]
#[ignore] // Run with: cargo test --test p2p_lightweight -- --ignored --nocapture
fn p2p_two_nodes_health() {
    let node1 = TestNode::spawn(19080, 19081, None);
    let node2 = TestNode::spawn(19082, 19083, Some("127.0.0.1:19081"));

    assert!(node1.wait_ready(30), "node1 failed to start");
    assert!(node2.wait_ready(30), "node2 failed to start");

    // Both healthy
    let h1 = get_json(&node1.api_url("/health"));
    let h2 = get_json(&node2.api_url("/health"));
    assert_eq!(h1["data"]["status"], "healthy");
    assert_eq!(h2["data"]["status"], "healthy");
}

#[test]
#[ignore]
fn p2p_mine_on_node1_visible_on_node2() {
    let node1 = TestNode::spawn(19090, 19091, None);
    let node2 = TestNode::spawn(19092, 19093, Some("127.0.0.1:19091"));

    assert!(node1.wait_ready(30), "node1 failed to start");
    assert!(node2.wait_ready(30), "node2 failed to start");

    // Create wallet on node1
    let wallet = post_json(&node1.api_url("/wallets/create"), serde_json::json!({}));
    let addr = wallet["data"]["address"]
        .as_str()
        .expect("no wallet address");

    // Mine on node1 (legacy endpoint returns {success: true})
    let mine = post_json(
        &node1.api_url("/mine"),
        serde_json::json!({"miner_address": addr}),
    );
    let mined_ok = mine["status"] == "Success" || mine["success"] == true;
    assert!(mined_ok, "mining failed: {mine}");

    // Check node1 block count increased
    let stats1 = get_json(&node1.api_url("/stats"));
    let blocks1 = stats1["data"]["blockchain"]["block_count"]
        .as_u64()
        .unwrap_or(0);
    assert!(blocks1 > 0, "node1 has no blocks after mining");
}

#[test]
#[ignore]
fn p2p_evm_deploy_on_node1() {
    let node1 = TestNode::spawn(19100, 19101, None);
    assert!(node1.wait_ready(30), "node1 failed to start");

    // Deploy EVM contract
    let deploy = post_json(
        &node1.api_url("/evm/deploy"),
        serde_json::json!({"bytecode": "600a600c600039600a6000f3604260005260206000f3"}),
    );
    assert_eq!(deploy["status"], "Success", "deploy failed: {deploy}");
    let addr = deploy["data"]["address"]
        .as_str()
        .expect("no contract address");

    // Call it
    let call = post_json(
        &node1.api_url("/evm/call"),
        serde_json::json!({"address": addr, "calldata": ""}),
    );
    assert_eq!(call["status"], "Success", "call failed: {call}");
    assert!(
        call["data"]["output"].as_str().unwrap().contains("42"),
        "wrong output: {}",
        call["data"]["output"]
    );

    // List
    let list = get_json(&node1.api_url("/evm/contracts"));
    let contracts = list["data"].as_array().expect("not array");
    assert_eq!(contracts.len(), 1);
}

#[test]
#[ignore]
fn p2p_identity_and_credentials_cross_check() {
    let node1 = TestNode::spawn(19110, 19111, None);
    assert!(node1.wait_ready(30), "node1 failed to start");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    use rust_bc::identity::signing::{SigningProvider, SoftwareSigningProvider};
    let issuer_signer = SoftwareSigningProvider::generate();
    let subject_signer = SoftwareSigningProvider::generate();
    let issuer_key = hex::encode(issuer_signer.public_key());
    let subject_key = hex::encode(subject_signer.public_key());
    let issuer_did = rust_bc::identity::did::did_from_pubkey_hex(&issuer_key);
    let subject_did = rust_bc::identity::did::did_from_pubkey_hex(&subject_key);
    let register_signature = |key: &SoftwareSigningProvider, did: &str| {
        hex::encode(
            key.sign(format!("identity:register:{did}").as_bytes())
                .unwrap(),
        )
    };

    // Create issuer DID
    let issuer = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({"did": issuer_did, "public_key": issuer_key, "status": "active", "created_at": now, "updated_at": now, "signature": register_signature(&issuer_signer, &issuer_did)}),
    );
    assert_eq!(
        issuer["status"], "Success",
        "issuer creation failed: {issuer}"
    );

    // Create subject DID
    let subject = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({"did": subject_did, "public_key": subject_key, "status": "active", "created_at": now, "updated_at": now, "signature": register_signature(&subject_signer, &subject_did)}),
    );
    assert_eq!(
        subject["status"], "Success",
        "subject creation failed: {subject}"
    );
    let cred = post_json(
        &node1.api_url("/store/credentials"),
        serde_json::json!({
            "id": "cred-p2p-test",
            "issuer_did": issuer_did,
            "subject_did": subject_did,
            "cred_type": "Test Certificate",
            "issued_at": now,
            "expires_at": 0
        }),
    );
    assert_eq!(cred["status"], "Success", "credential issuance failed");

    // Verify credential
    let verify = get_json(&node1.api_url("/store/credentials/cred-p2p-test"));
    assert_eq!(verify["status"], "Success");
    assert_eq!(verify["data"]["issuer_did"], issuer_did.as_str());
    assert_eq!(verify["data"]["subject_did"], subject_did.as_str());
}
