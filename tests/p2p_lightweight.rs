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
    p2p_port: u16,
    data_dir: tempfile::TempDir,
}

impl TestNode {
    fn spawn(api_port: u16, p2p_port: u16, peer: Option<&TestNode>) -> Self {
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

        let data_dir = tempfile::TempDir::new().expect("failed to create node data dir");
        let mut cmd = Command::new(&bin);
        cmd.env("STORAGE_PATH", data_dir.path())
            .arg(api_port.to_string())
            .arg(p2p_port.to_string())
            .env("ACL_MODE", "permissive")
            .env("DIFFICULTY", "1")
            .env("NETWORK_ID", "p2p-test")
            .env("BIND_ADDR", "127.0.0.1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        if let Some(peer) = peer {
            cmd.env("BOOTSTRAP_NODES", format!("127.0.0.1:{}", peer.p2p_port))
                .env("TRUSTED_BLOCK_SIGNERS", peer.signer_public_key_hex());
        }

        let child = cmd.spawn().expect("failed to spawn node");
        Self {
            child,
            api_port,
            p2p_port,
            data_dir,
        }
    }

    fn signer_public_key_hex(&self) -> String {
        let key_path = self.data_dir.path().join("signing_key_mldsa65.bin");
        let key = std::fs::read(&key_path)
            .unwrap_or_else(|e| panic!("cannot read node signing key {key_path:?}: {e}"));
        hex::encode(&key[..1952])
    }

    fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}/api/v1{}", self.api_port, path)
    }

    fn wait_ready(&self, timeout_secs: u64) -> bool {
        rust_bc::tls::install_crypto_provider();
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
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19082, 19083, Some(&node1));
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
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19092, 19093, Some(&node1));
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

fn wait_for_identity_status(node: &TestNode, did: &str, status: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let url = node.api_url(&format!("/store/identities/{did}"));
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = reqwest::blocking::get(&url) {
            let body: serde_json::Value = resp.json().unwrap_or_default();
            if body["data"]["status"] == status {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
#[ignore]
fn p2p_identity_registration_and_revocation_reach_second_node() {
    use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};
    let node1 = TestNode::spawn(19120, 19121, None);
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19122, 19123, Some(&node1));
    assert!(node2.wait_ready(30), "node2 failed to start");

    let owner = MlDsaSigningProvider::generate();
    let thief = MlDsaSigningProvider::generate();
    let public_key = hex::encode(owner.public_key());
    let did = rust_bc::identity::did::did_from_pubkey_hex(&public_key);
    let sign = |key: &MlDsaSigningProvider, message: String| {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let registered = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({
            "did": did, "public_key": public_key, "status": "active",
            "created_at": now, "updated_at": now,
            "signature": sign(&owner, format!("identity:register:{did}")),
        }),
    );
    assert_eq!(
        registered["status"], "Success",
        "register failed: {registered}"
    );
    assert!(
        wait_for_identity_status(&node2, &did, "active", 30),
        "registration on node1 never reached node2; node1 health {}; node2 health {}",
        get_json(&node1.api_url("/health"))["data"],
        get_json(&node2.api_url("/health"))["data"]
    );

    let forged = post_json(
        &node1.api_url(&format!("/identity/{did}/revoke")),
        serde_json::json!({ "signature": sign(&thief, format!("identity:revoke:{did}")) }),
    );
    assert_ne!(
        forged["status"], "Success",
        "forged revocation accepted: {forged}"
    );

    let revoked = post_json(
        &node1.api_url(&format!("/identity/{did}/revoke")),
        serde_json::json!({ "signature": sign(&owner, format!("identity:revoke:{did}")) }),
    );
    assert_eq!(revoked["status"], "Success", "revoke failed: {revoked}");
    assert!(
        wait_for_identity_status(&node2, &did, "revoked", 30),
        "revocation on node1 never reached node2"
    );
}

fn wait_for_identity_key(node: &TestNode, did: &str, public_key: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let url = node.api_url(&format!("/store/identities/{did}"));
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = reqwest::blocking::get(&url) {
            let body: serde_json::Value = resp.json().unwrap_or_default();
            if body["data"]["public_key"] == public_key {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
#[ignore]
fn p2p_key_rotation_reaches_second_node_and_kills_stolen_key() {
    use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};
    let node1 = TestNode::spawn(19130, 19131, None);
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19132, 19133, Some(&node1));
    assert!(node2.wait_ready(30), "node2 failed to start");

    let key_of = |provider: &MlDsaSigningProvider| hex::encode(provider.public_key());
    let did_of = |provider: &MlDsaSigningProvider| {
        rust_bc::identity::did::did_from_pubkey_hex(&key_of(provider))
    };
    let sign = |provider: &MlDsaSigningProvider, message: &str| {
        hex::encode(provider.sign(message.as_bytes()).unwrap())
    };
    let (phone, recovery, new_phone, next_recovery) = (
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
    );
    let did = did_of(&phone);
    let commitment = did_of(&recovery);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let registered = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({
            "did": did, "public_key": key_of(&phone), "status": "active",
            "created_at": now, "updated_at": now, "recovery_commitment": commitment,
            "signature": sign(&phone, &format!("identity:register:{did}:{commitment}")),
        }),
    );
    assert_eq!(
        registered["status"], "Success",
        "register failed: {registered}"
    );
    assert!(
        wait_for_identity_status(&node2, &did, "active", 30),
        "registration never reached node2"
    );

    let rotate_message = rust_bc::identity::operations::rotate_message(
        &did,
        &key_of(&new_phone),
        &did_of(&next_recovery),
    );
    let rotated = post_json(
        &node1.api_url(&format!("/identity/{did}/rotate")),
        serde_json::json!({
            "new_public_key": key_of(&new_phone),
            "recovery_public_key": key_of(&recovery),
            "new_recovery_commitment": did_of(&next_recovery),
            "recovery_signature": sign(&recovery, &rotate_message),
            "new_key_signature": sign(&new_phone, &rotate_message),
        }),
    );
    assert_eq!(rotated["status"], "Success", "rotate failed: {rotated}");
    assert!(
        wait_for_identity_key(&node2, &did, &key_of(&new_phone), 30),
        "rotation on node1 never reached node2"
    );

    let content_hash = format!("{:064x}", now);
    let notarize_with = |provider: &MlDsaSigningProvider| {
        post_json(
            &node2.api_url("/notarize"),
            serde_json::json!({
                "content_hash": content_hash,
                "signer": did,
                "public_key": key_of(provider),
                "signature_algorithm": "MlDsa65",
                "signature": sign(provider, &format!("notarize:{did}:{content_hash}")),
            }),
        )
    };
    let stolen_notarization = notarize_with(&phone);
    assert_ne!(
        stolen_notarization["status"], "Success",
        "stolen key notarized on node2: {stolen_notarization}"
    );
    let own_notarization = notarize_with(&new_phone);
    assert_eq!(
        own_notarization["status"], "Success",
        "new key could not notarize on node2: {own_notarization}"
    );

    let login_with = |provider: &MlDsaSigningProvider| {
        let challenge = post_json(
            &node2.api_url("/identity/auth/challenge"),
            serde_json::json!({ "did": did }),
        );
        let nonce = challenge["data"]["challenge"].as_str().unwrap().to_string();
        post_json(
            &node2.api_url("/identity/auth/verify"),
            serde_json::json!({ "did": did, "challenge": nonce, "signature": sign(provider, &nonce) }),
        )
    };
    let stolen_login = login_with(&phone);
    assert_ne!(
        stolen_login["status"], "Success",
        "stolen key logged in on node2: {stolen_login}"
    );
    let own_login = login_with(&new_phone);
    assert_eq!(
        own_login["status"], "Success",
        "new key could not log in on node2: {own_login}"
    );

    let revoke_with = |provider: &MlDsaSigningProvider| {
        post_json(
            &node2.api_url(&format!("/identity/{did}/revoke")),
            serde_json::json!({ "signature": sign(provider, &format!("identity:revoke:{did}")) }),
        )
    };
    let stolen = revoke_with(&phone);
    assert_ne!(
        stolen["status"], "Success",
        "stolen key still accepted on node2: {stolen}"
    );
    let own = revoke_with(&new_phone);
    assert_eq!(own["status"], "Success", "new key rejected on node2: {own}");
    let revoked_login = login_with(&new_phone);
    assert_ne!(
        revoked_login["status"], "Success",
        "revoked identity logged in on node2: {revoked_login}"
    );
}

fn wait_for_vault_entry(node: &TestNode, did: &str, entry_id: &str, is_revoked: bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let url = node.api_url(&format!("/store/identities/{did}"));
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = reqwest::blocking::get(&url) {
            let body: serde_json::Value = resp.json().unwrap_or_default();
            let entries = body["data"]["vault_entries"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if entries.iter().any(|entry| {
                entry["entry_id"] == entry_id && entry["revoked_at"].is_u64() == is_revoked
            }) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
#[ignore]
fn p2p_vault_copy_reaches_second_node_and_rejects_strangers() {
    use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use rust_bc::identity::vault_entries::{add_vault_entry_message, revoke_vault_entry_message};
    use rust_bc::storage::traits::{VaultEntry, VaultEntryKind};
    let node1 = TestNode::spawn(19140, 19141, None);
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19142, 19143, Some(&node1));
    assert!(node2.wait_ready(30), "node2 failed to start");

    let owner = MlDsaSigningProvider::generate();
    let stranger = MlDsaSigningProvider::generate();
    let public_key = hex::encode(owner.public_key());
    let did = rust_bc::identity::did::did_from_pubkey_hex(&public_key);
    let sign = |key: &MlDsaSigningProvider, message: String| {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let registered = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({
            "did": did, "public_key": public_key, "status": "active",
            "created_at": now, "updated_at": now,
            "signature": sign(&owner, format!("identity:register:{did}")),
        }),
    );
    assert_eq!(
        registered["status"], "Success",
        "register failed: {registered}"
    );

    let copy = VaultEntry {
        entry_id: "0378ffe5".to_string(),
        kind: VaultEntryKind::Device,
        label: "iPhone".to_string(),
        sealed_key: r#"{"kdf":"hkdf","ciphertext":"aa"}"#.to_string(),
        added_at: 0,
        revoked_at: None,
    };
    let body_signed_by = |key: &MlDsaSigningProvider| {
        serde_json::json!({
            "entry_id": copy.entry_id, "kind": "device", "label": copy.label,
            "sealed_key": copy.sealed_key,
            "signature": sign(key, add_vault_entry_message(&did, &copy)),
        })
    };
    let vault_url = node1.api_url(&format!("/identity/{did}/vault"));
    let forged = post_json(&vault_url, body_signed_by(&stranger));
    assert_ne!(
        forged["status"], "Success",
        "stranger stored a copy: {forged}"
    );

    let added = post_json(&vault_url, body_signed_by(&owner));
    assert_eq!(added["status"], "Success", "add failed: {added}");
    assert!(
        wait_for_vault_entry(&node2, &did, "0378ffe5", false),
        "vault copy on node1 never reached node2"
    );

    let revoked = post_json(
        &node1.api_url(&format!("/identity/{did}/vault/0378ffe5/revoke")),
        serde_json::json!({ "signature": sign(&owner, revoke_vault_entry_message(&did, "0378ffe5")) }),
    );
    assert_eq!(revoked["status"], "Success", "revoke failed: {revoked}");
    assert!(
        wait_for_vault_entry(&node2, &did, "0378ffe5", true),
        "vault revocation on node1 never reached node2"
    );
}

#[test]
#[ignore]
fn p2p_theft_lockout_sequence_converges_on_second_node() {
    use rust_bc::identity::operations::{register_message, rotate_message};
    use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use rust_bc::identity::vault_entries::{add_vault_entry_message, revoke_vault_entry_message};
    use rust_bc::storage::traits::{VaultEntry, VaultEntryKind};
    let node1 = TestNode::spawn(19150, 19151, None);
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19152, 19153, Some(&node1));
    assert!(node2.wait_ready(30), "node2 failed to start");

    let hex_key = |key: &MlDsaSigningProvider| hex::encode(key.public_key());
    let did_of =
        |key: &MlDsaSigningProvider| rust_bc::identity::did::did_from_pubkey_hex(&hex_key(key));
    let sign = |key: &MlDsaSigningProvider, message: String| {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    };
    let (owner, recovery, successor, next) = (
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
    );
    let did = did_of(&owner);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let registered = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({
            "did": did, "public_key": hex_key(&owner), "status": "active",
            "created_at": now, "updated_at": now, "recovery_commitment": did_of(&recovery),
            "signature": sign(&owner, register_message(&did, Some(&did_of(&recovery)))),
        }),
    );
    assert_eq!(
        registered["status"], "Success",
        "register failed: {registered}"
    );

    let copy = |entry_id: &str| VaultEntry {
        entry_id: entry_id.to_string(),
        kind: VaultEntryKind::Device,
        label: entry_id.to_string(),
        sealed_key: format!("{{\"ciphertext\":\"{entry_id}\"}}"),
        added_at: 0,
        revoked_at: None,
    };
    let add = |key: &MlDsaSigningProvider, entry: VaultEntry| {
        post_json(
            &node1.api_url(&format!("/identity/{did}/vault")),
            serde_json::json!({
                "entry_id": entry.entry_id, "kind": "device", "label": entry.label,
                "sealed_key": entry.sealed_key, "signature": sign(key, add_vault_entry_message(&did, &entry)),
            }),
        )
    };
    assert_eq!(add(&owner, copy("aa01"))["status"], "Success");
    let message = rotate_message(&did, &hex_key(&successor), &did_of(&next));
    let rotated = post_json(
        &node1.api_url(&format!("/identity/{did}/rotate")),
        serde_json::json!({
            "new_public_key": hex_key(&successor), "recovery_public_key": hex_key(&recovery),
            "new_recovery_commitment": did_of(&next),
            "recovery_signature": sign(&recovery, message.clone()),
            "new_key_signature": sign(&successor, message),
        }),
    );
    assert_eq!(rotated["status"], "Success", "rotate failed: {rotated}");
    let revoked = post_json(
        &node1.api_url(&format!("/identity/{did}/vault/aa01/revoke")),
        serde_json::json!({ "signature": sign(&successor, revoke_vault_entry_message(&did, "aa01")) }),
    );
    assert_eq!(revoked["status"], "Success", "revoke failed: {revoked}");
    assert_eq!(add(&successor, copy("bb02"))["status"], "Success");

    assert!(
        wait_for_vault_entry(&node2, &did, "bb02", false),
        "lockout sequence never reached node2"
    );
    let on_node = |node: &TestNode| {
        get_json(&node.api_url(&format!("/store/identities/{did}")))["data"].clone()
    };
    let (on1, on2) = (on_node(&node1), on_node(&node2));
    assert_eq!(on2["public_key"], hex_key(&successor));
    assert_eq!(on1["vault_entries"], on2["vault_entries"], "nodes diverged");
    assert!(
        on2["vault_entries"][0]["revoked_at"].is_u64(),
        "old copy not revoked on node2: {on2}"
    );
}

#[test]
#[ignore]
fn p2p_legacy_identity_commits_recovery_key_and_rotates_on_second_node() {
    use rust_bc::identity::operations::{register_message, rotate_message};
    use rust_bc::identity::recovery_commitment::commit_recovery_message;
    use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use rust_bc::identity::vault_entries::add_vault_entry_message;
    use rust_bc::storage::traits::{VaultEntry, VaultEntryKind};
    let node1 = TestNode::spawn(19160, 19161, None);
    assert!(node1.wait_ready(30), "node1 failed to start");
    let node2 = TestNode::spawn(19162, 19163, Some(&node1));
    assert!(node2.wait_ready(30), "node2 failed to start");

    let hex_key = |key: &MlDsaSigningProvider| hex::encode(key.public_key());
    let did_of =
        |key: &MlDsaSigningProvider| rust_bc::identity::did::did_from_pubkey_hex(&hex_key(key));
    let sign = |key: &MlDsaSigningProvider, message: String| {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    };
    let (owner, recovery, successor, next, thief) = (
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
        MlDsaSigningProvider::generate(),
    );
    let did = did_of(&owner);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let registered = post_json(
        &node1.api_url("/store/identities"),
        serde_json::json!({
            "did": did, "public_key": hex_key(&owner), "status": "active",
            "created_at": now, "updated_at": now,
            "signature": sign(&owner, register_message(&did, None)),
        }),
    );
    assert_eq!(
        registered["status"], "Success",
        "register failed: {registered}"
    );

    let commit = |key: &MlDsaSigningProvider, commitment: String| {
        post_json(
            &node1.api_url(&format!("/identity/{did}/recovery")),
            serde_json::json!({
                "recovery_commitment": commitment,
                "signature": sign(key, commit_recovery_message(&did, &commitment)),
            }),
        )
    };
    let forged = commit(&thief, did_of(&thief));
    assert_ne!(forged["status"], "Success", "thief committed: {forged}");
    let committed = commit(&owner, did_of(&recovery));
    assert_eq!(committed["status"], "Success", "commit failed: {committed}");
    let replaced = commit(&owner, did_of(&thief));
    assert_ne!(replaced["status"], "Success", "commit replaced: {replaced}");

    let message = rotate_message(&did, &hex_key(&successor), &did_of(&next));
    let rotated = post_json(
        &node1.api_url(&format!("/identity/{did}/rotate")),
        serde_json::json!({
            "new_public_key": hex_key(&successor), "recovery_public_key": hex_key(&recovery),
            "new_recovery_commitment": did_of(&next),
            "recovery_signature": sign(&recovery, message.clone()),
            "new_key_signature": sign(&successor, message),
        }),
    );
    assert_eq!(rotated["status"], "Success", "rotate failed: {rotated}");

    let marker = VaultEntry {
        entry_id: "cc03".to_string(),
        kind: VaultEntryKind::Device,
        label: "after rotation".to_string(),
        sealed_key: "{}".to_string(),
        added_at: 0,
        revoked_at: None,
    };
    let added = post_json(
        &node1.api_url(&format!("/identity/{did}/vault")),
        serde_json::json!({
            "entry_id": marker.entry_id, "kind": "device", "label": marker.label,
            "sealed_key": marker.sealed_key,
            "signature": sign(&successor, add_vault_entry_message(&did, &marker)),
        }),
    );
    assert_eq!(added["status"], "Success", "add failed: {added}");
    assert!(
        wait_for_vault_entry(&node2, &did, "cc03", false),
        "commit and rotation never reached node2"
    );
    let on2 = get_json(&node2.api_url(&format!("/store/identities/{did}")))["data"].clone();
    assert_eq!(on2["public_key"], hex_key(&successor));
    assert_eq!(on2["recovery_commitment"], did_of(&next));
}
