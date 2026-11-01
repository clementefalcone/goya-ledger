//! Tauri IPC commands — bridge between frontend and light client.
//!
//! Each command is a plain async fn that can be tested independently.
//! Tauri's `#[command]` macro is applied in `main.rs` via re-export.

use chrono::Utc;
use rust_bc::light_client::local_store::{LocalIdentityStore, StoredIdentity};
use rust_bc::light_client::proxy::SeedProxy;
use serde::{Deserialize, Serialize};

use crate::key_crypto;

/// Shared error type for all commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandError {
    pub message: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<rust_bc::light_client::proxy::ProxyError> for CommandError {
    fn from(e: rust_bc::light_client::proxy::ProxyError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<rust_bc::light_client::local_store::LocalStoreError> for CommandError {
    fn from(e: rust_bc::light_client::local_store::LocalStoreError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl From<key_crypto::KeyCryptoError> for CommandError {
    fn from(e: key_crypto::KeyCryptoError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

// ── Response types ──

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct IdentityInfo {
    pub did: String,
    pub public_key_hex: String,
    pub algorithm: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizeResult {
    pub hash: String,
    pub timestamp: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub seed_url: String,
    pub connected: bool,
    pub chain_height: Option<u64>,
    pub local_identities: usize,
}

// ── Commands ──

/// Create a new DID identity, encrypt private key with password, persist locally.
pub fn create_identity(
    store: &LocalIdentityStore,
    algorithm: &str,
    password: &str,
) -> Result<IdentityInfo, CommandError> {
    let keypair = generate_keypair(algorithm);
    let did = rust_bc::identity::did::did_from_pubkey_hex(&keypair.public_key_hex);
    let now = Utc::now().to_rfc3339();

    let encrypted = key_crypto::encrypt_key(&keypair.private_key_raw, password)?;

    let stored = StoredIdentity {
        did: did.clone(),
        public_key_hex: keypair.public_key_hex.clone(),
        private_key_enc: encrypted,
        algorithm: algorithm.to_string(),
        created_at: now.clone(),
    };
    store.save(stored)?;

    Ok(IdentityInfo {
        did,
        public_key_hex: keypair.public_key_hex,
        algorithm: algorithm.to_string(),
        created_at: now,
    })
}

/// Decrypt and return the private key for a stored identity.
pub fn unlock_identity(
    store: &LocalIdentityStore,
    did: &str,
    password: &str,
) -> Result<String, CommandError> {
    store
        .get(did)?
        .ok_or_else(|| CommandError {
            message: format!("identity not found: {did}"),
        })
        .and_then(|identity| {
            key_crypto::decrypt_key(&identity.private_key_enc, password)
                .map(hex::encode)
                .map_err(CommandError::from)
        })
}

/// List all locally stored identities.
pub fn list_identities(store: &LocalIdentityStore) -> Result<Vec<IdentityInfo>, CommandError> {
    let identities = store
        .list()?
        .into_iter()
        .map(|s| IdentityInfo {
            did: s.did,
            public_key_hex: s.public_key_hex,
            algorithm: s.algorithm,
            created_at: s.created_at,
        })
        .collect();
    Ok(identities)
}

/// Hash a document (bytes) and return the SHA-256 hex digest.
pub fn hash_document(data: &[u8]) -> String {
    let hash = pqc_crypto_module::legacy::legacy_sha256(data)
        .expect("SHA-256 hashing cannot fail for valid input");
    hex::encode(hash)
}

/// Submit a signed notarization to the seed node.
///
/// Signs `"notarize:{signer}:{content_hash}"` with the identity's Ed25519 key,
/// matching the server's verification in `notarize.rs`.
pub async fn notarize_document(
    proxy: &SeedProxy,
    store: &LocalIdentityStore,
    did: &str,
    password: &str,
    file_name: &str,
    file_bytes: &[u8],
) -> Result<NotarizeResult, CommandError> {
    let identity = store.get(did)?.ok_or_else(|| CommandError {
        message: format!("identity not found: {did}"),
    })?;

    let private_key_bytes = key_crypto::decrypt_key(&identity.private_key_enc, password)?;
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&private_key_bytes.try_into().map_err(|_| {
            CommandError {
                message: "invalid Ed25519 key length".to_string(),
            }
        })?);

    let content_hash = hash_document(file_bytes);
    let sign_msg = format!("notarize:{did}:{content_hash}");

    use ed25519_dalek::Signer;
    let signature = signing_key.sign(sign_msg.as_bytes());
    let now = Utc::now().to_rfc3339();

    let body = serde_json::json!({
        "content_hash": content_hash,
        "signer": did,
        "public_key": identity.public_key_hex,
        "signature": hex::encode(signature.to_bytes()),
        "metadata": {
            "file_name": file_name,
            "timestamp": now,
        }
    });

    proxy
        .post_raw("/api/v1/notarize", body.to_string().as_bytes())
        .await
        .map(|_| NotarizeResult {
            hash: content_hash,
            timestamp: now,
            status: "registered".to_string(),
        })
        .map_err(|e| CommandError {
            message: format!("notarization failed: {e}"),
        })
}

/// Verify a hash exists on the seed node.
pub async fn verify_notarization(
    proxy: &SeedProxy,
    hash: &str,
) -> Result<serde_json::Value, CommandError> {
    let path = format!("/api/v1/notarize/verify/{hash}");
    proxy
        .get::<serde_json::Value>(&path)
        .await
        .map_err(CommandError::from)
}

/// Query seed node status and local identity count.
pub async fn get_node_status(
    proxy: &SeedProxy,
    store: &LocalIdentityStore,
) -> Result<NodeStatus, CommandError> {
    let local_count = store.count().unwrap_or(0);
    let health: Result<serde_json::Value, _> = proxy.get("/api/v1/health").await;

    let (connected, chain_height) = match health {
        Ok(resp) => {
            let height = resp
                .pointer("/data/blockchain/height")
                .and_then(|v| v.as_u64());
            (true, height)
        }
        Err(_) => (false, None),
    };

    Ok(NodeStatus {
        seed_url: proxy.base_url().to_string(),
        connected,
        chain_height,
        local_identities: local_count,
    })
}

// ── Wallet commands ──

/// Response types for wallet operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletBalance {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferResult {
    pub tx_id: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FaucetResult {
    pub tx_id: String,
    pub amount: u64,
    pub status: String,
}

/// Query account balance and nonce from seed node.
pub async fn get_balance(proxy: &SeedProxy, address: &str) -> Result<WalletBalance, CommandError> {
    let resp: serde_json::Value = proxy
        .get(&format!("/api/v1/accounts/{address}"))
        .await
        .map_err(CommandError::from)?;

    let data = &resp["data"];
    Ok(WalletBalance {
        address: address.to_string(),
        balance: data["balance"].as_u64().unwrap_or(0),
        nonce: data["nonce"].as_u64().unwrap_or(0),
    })
}

/// Request testnet tokens via coinbase transaction + block commit.
pub async fn request_faucet(
    proxy: &SeedProxy,
    recipient: &str,
    amount: u64,
) -> Result<FaucetResult, CommandError> {
    // Coinbase transaction (from="0") — exempt from signature/balance checks
    let tx_body = serde_json::json!({
        "from": "0",
        "to": recipient,
        "amount": amount,
    });

    let tx_resp: serde_json::Value =
        proxy
            .post("/api/v1/transactions", &tx_body)
            .await
            .map_err(|e| CommandError {
                message: format!("faucet tx failed: {e}"),
            })?;

    let tx_id = tx_resp["data"]["id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    // Commit to block so balance registers immediately
    let block_body = serde_json::json!({
        "transactions": [{ "from": "0", "to": recipient, "amount": amount }]
    });
    proxy
        .post::<_, serde_json::Value>("/api/v1/blocks", &block_body)
        .await
        .map_err(|e| CommandError {
            message: format!("block commit failed: {e}"),
        })?;

    Ok(FaucetResult {
        tx_id,
        amount,
        status: "funded".to_string(),
    })
}

/// Send a signed transfer from one identity to another.
pub async fn send_transfer(
    proxy: &SeedProxy,
    store: &LocalIdentityStore,
    from_did: &str,
    password: &str,
    to_address: &str,
    amount: u64,
) -> Result<TransferResult, CommandError> {
    let identity = store.get(from_did)?.ok_or_else(|| CommandError {
        message: format!("identity not found: {from_did}"),
    })?;

    // Unlock private key
    let private_key_bytes = key_crypto::decrypt_key(&identity.private_key_enc, password)?;
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&private_key_bytes.try_into().map_err(|_| {
            CommandError {
                message: "invalid Ed25519 key length".to_string(),
            }
        })?);

    // Get current nonce
    let balance_info = get_balance(proxy, from_did).await?;
    let nonce = balance_info.nonce;

    (balance_info.balance >= amount)
        .then_some(())
        .ok_or_else(|| CommandError {
            message: format!(
                "insufficient balance: have {}, need {amount}",
                balance_info.balance
            ),
        })?;

    // Sign "transfer:{from}:{to}:{amount}:{nonce}"
    let sign_msg = format!("transfer:{from_did}:{to_address}:{amount}:{nonce}");
    use ed25519_dalek::Signer;
    let signature = hex::encode(signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let tx_body = serde_json::json!({
        "from": from_did,
        "to": to_address,
        "amount": amount,
        "nonce": nonce,
        "signature": signature,
    });

    let tx_resp: serde_json::Value =
        proxy
            .post("/api/v1/transactions", &tx_body)
            .await
            .map_err(|e| CommandError {
                message: format!("transfer failed: {e}"),
            })?;

    let tx_id = tx_resp["data"]["id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    // Commit to block
    let block_body = serde_json::json!({
        "transactions": [{
            "from": from_did,
            "to": to_address,
            "amount": amount,
            "signature": signature,
        }]
    });
    proxy
        .post::<_, serde_json::Value>("/api/v1/blocks", &block_body)
        .await
        .map_err(|e| CommandError {
            message: format!("block commit failed: {e}"),
        })?;

    Ok(TransferResult {
        tx_id,
        from: from_did.to_string(),
        to: to_address.to_string(),
        amount,
        status: "confirmed".to_string(),
    })
}

/// Get transaction history for an address.
pub async fn get_transactions(
    proxy: &SeedProxy,
    address: &str,
) -> Result<Vec<serde_json::Value>, CommandError> {
    let resp: serde_json::Value = proxy
        .get(&format!("/api/v1/wallets/{address}/transactions"))
        .await
        .map_err(CommandError::from)?;

    resp["data"]
        .as_array()
        .map(|arr| arr.to_vec())
        .ok_or_else(|| CommandError {
            message: "unexpected response format".to_string(),
        })
}

// ── Governance commands ──

/// Proposal summary returned to the frontend.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProposalSummary {
    pub id: u64,
    pub proposer: String,
    pub description: String,
    pub status: String,
    pub deposit: u64,
}

/// Vote tally returned after casting a vote.
#[derive(Debug, Serialize, Deserialize)]
pub struct VoteTally {
    pub proposal_id: u64,
    pub yes_power: u64,
    pub no_power: u64,
    pub abstain_power: u64,
    pub quorum_reached: bool,
    pub passed: bool,
}

/// List governance proposals from seed node.
pub async fn list_proposals(proxy: &SeedProxy) -> Result<Vec<ProposalSummary>, CommandError> {
    let resp: serde_json::Value = proxy
        .get("/api/v1/governance/proposals")
        .await
        .map_err(CommandError::from)?;

    let items = resp["data"]["data"]
        .as_array()
        .or_else(|| resp["data"]["items"].as_array())
        .or_else(|| resp["data"].as_array())
        .cloned()
        .unwrap_or_default();

    Ok(items
        .iter()
        .filter_map(|p| {
            Some(ProposalSummary {
                id: p["id"].as_u64()?,
                proposer: p["proposer"].as_str()?.to_string(),
                description: p["description"].as_str()?.to_string(),
                status: format!("{:?}", p["status"]).replace('"', ""),
                deposit: p["deposit"].as_u64().unwrap_or(0),
            })
        })
        .collect())
}

/// Create a text proposal on the seed node.
pub async fn create_proposal(
    proxy: &SeedProxy,
    proposer: &str,
    title: &str,
    description: &str,
    deposit: u64,
) -> Result<serde_json::Value, CommandError> {
    let body = serde_json::json!({
        "proposer": proposer,
        "description": description,
        "deposit": deposit,
        "action": {
            "type": "text",
            "title": title,
            "description": description,
        }
    });

    proxy
        .post::<_, serde_json::Value>("/api/v1/governance/proposals", &body)
        .await
        .map_err(|e| CommandError {
            message: format!("create proposal failed: {e}"),
        })
}

/// Cast a signed vote on a proposal.
pub async fn cast_vote(
    proxy: &SeedProxy,
    store: &LocalIdentityStore,
    did: &str,
    password: &str,
    proposal_id: u64,
    option: &str,
) -> Result<VoteTally, CommandError> {
    let identity = store.get(did)?.ok_or_else(|| CommandError {
        message: format!("identity not found: {did}"),
    })?;

    let private_key_bytes = key_crypto::decrypt_key(&identity.private_key_enc, password)?;
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&private_key_bytes.try_into().map_err(|_| {
            CommandError {
                message: "invalid Ed25519 key length".to_string(),
            }
        })?);

    // Sign "vote:{proposal_id}:{option}:{public_key}"
    let sign_msg = format!("vote:{proposal_id}:{option}:{}", identity.public_key_hex);
    use ed25519_dalek::Signer;
    let signature = hex::encode(signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let body = serde_json::json!({
        "voter": did,
        "option": option,
        "signature": signature,
        "public_key": identity.public_key_hex,
    });

    let resp: serde_json::Value = proxy
        .post(
            &format!("/api/v1/governance/proposals/{proposal_id}/vote"),
            &body,
        )
        .await
        .map_err(|e| CommandError {
            message: format!("vote failed: {e}"),
        })?;

    let data = &resp["data"];
    Ok(VoteTally {
        proposal_id: data["proposal_id"].as_u64().unwrap_or(proposal_id),
        yes_power: data["yes_power"].as_u64().unwrap_or(0),
        no_power: data["no_power"].as_u64().unwrap_or(0),
        abstain_power: data["abstain_power"].as_u64().unwrap_or(0),
        quorum_reached: data["quorum_reached"].as_bool().unwrap_or(false),
        passed: data["passed"].as_bool().unwrap_or(false),
    })
}

/// Get tally for a proposal.
pub async fn get_tally(proxy: &SeedProxy, proposal_id: u64) -> Result<VoteTally, CommandError> {
    let resp: serde_json::Value = proxy
        .get(&format!("/api/v1/governance/proposals/{proposal_id}/tally"))
        .await
        .map_err(CommandError::from)?;

    let data = &resp["data"];
    Ok(VoteTally {
        proposal_id: data["proposal_id"].as_u64().unwrap_or(proposal_id),
        yes_power: data["yes_power"].as_u64().unwrap_or(0),
        no_power: data["no_power"].as_u64().unwrap_or(0),
        abstain_power: data["abstain_power"].as_u64().unwrap_or(0),
        quorum_reached: data["quorum_reached"].as_bool().unwrap_or(false),
        passed: data["passed"].as_bool().unwrap_or(false),
    })
}

// ── Document transfer commands ──

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferDocResult {
    pub content_hash: String,
    pub from: String,
    pub to: String,
    pub transferred_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentOwner {
    pub content_hash: String,
    pub owner: String,
    pub original_signer: String,
    pub transfer_count: u64,
}

/// Transfer ownership of a notarized document.
pub async fn transfer_document(
    proxy: &SeedProxy,
    store: &LocalIdentityStore,
    did: &str,
    password: &str,
    content_hash: &str,
    to_did: &str,
) -> Result<TransferDocResult, CommandError> {
    let identity = store.get(did)?.ok_or_else(|| CommandError {
        message: format!("identity not found: {did}"),
    })?;

    let private_key_bytes = key_crypto::decrypt_key(&identity.private_key_enc, password)?;
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&private_key_bytes.try_into().map_err(|_| {
            CommandError {
                message: "invalid Ed25519 key length".to_string(),
            }
        })?);

    let sequence = get_document_owner(proxy, content_hash)
        .await?
        .transfer_count;
    let sign_msg = format!("transfer_doc:{content_hash}:{sequence}:{did}:{to_did}");
    use ed25519_dalek::Signer;
    let signature = hex::encode(signing_key.sign(sign_msg.as_bytes()).to_bytes());

    let body = serde_json::json!({
        "from_did": did,
        "to_did": to_did,
        "public_key": identity.public_key_hex,
        "signature": signature,
    });

    let resp: serde_json::Value = proxy
        .post(&format!("/api/v1/notarize/{content_hash}/transfer"), &body)
        .await
        .map_err(|e| CommandError {
            message: format!("transfer failed: {e}"),
        })?;

    let data = &resp["data"];
    Ok(TransferDocResult {
        content_hash: content_hash.to_string(),
        from: did.to_string(),
        to: to_did.to_string(),
        transferred_at: data["transferred_at"].as_u64().unwrap_or(0),
    })
}

/// Get current owner of a notarized document.
pub async fn get_document_owner(
    proxy: &SeedProxy,
    content_hash: &str,
) -> Result<DocumentOwner, CommandError> {
    let resp: serde_json::Value = proxy
        .get(&format!("/api/v1/notarize/{content_hash}/owner"))
        .await
        .map_err(CommandError::from)?;

    let data = &resp["data"];
    Ok(DocumentOwner {
        content_hash: content_hash.to_string(),
        owner: data["owner"].as_str().unwrap_or("").to_string(),
        original_signer: data["original_signer"].as_str().unwrap_or("").to_string(),
        transfer_count: data["transfer_count"].as_u64().unwrap_or(0),
    })
}

/// Get provenance (transfer chain) for a notarized document.
pub async fn get_provenance(
    proxy: &SeedProxy,
    content_hash: &str,
) -> Result<serde_json::Value, CommandError> {
    proxy
        .get(&format!("/api/v1/notarize/{content_hash}/provenance"))
        .await
        .map_err(CommandError::from)
}

// ── Internal helpers ──

struct KeypairOutput {
    public_key_hex: String,
    private_key_raw: Vec<u8>,
}

fn generate_keypair(algorithm: &str) -> KeypairOutput {
    match algorithm.to_lowercase().as_str() {
        "ed25519" => generate_ed25519(),
        _ => generate_ed25519(),
    }
}

fn generate_ed25519() -> KeypairOutput {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    KeypairOutput {
        public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
        private_key_raw: signing_key.to_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "test-passphrase-2026";

    fn temp_store() -> (tempfile::TempDir, LocalIdentityStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalIdentityStore::open(dir.path().join("test_ids.json"));
        (dir, store)
    }

    #[test]
    fn create_identity_encrypts_private_key() {
        let (_dir, store) = temp_store();
        let info = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        assert!(info.did.starts_with("did:goya:"));
        assert_eq!(info.algorithm, "Ed25519");

        // Stored value must be encrypted (salt:nonce:ciphertext), not raw hex.
        let stored = store.get(&info.did).unwrap().unwrap();
        let parts: Vec<&str> = stored.private_key_enc.splitn(3, ':').collect();
        assert_eq!(
            parts.len(),
            3,
            "encrypted format must be salt:nonce:ciphertext"
        );
    }

    #[test]
    fn unlock_identity_returns_valid_ed25519_key() {
        let (_dir, store) = temp_store();
        let info = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let private_hex = unlock_identity(&store, &info.did, TEST_PASSWORD).unwrap();
        assert_eq!(
            private_hex.len(),
            64,
            "Ed25519 private key = 32 bytes = 64 hex chars"
        );
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let (_dir, store) = temp_store();
        let info = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let result = unlock_identity(&store, &info.did, "wrong-password");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().message.contains("wrong password"),
            "error must mention wrong password"
        );
    }

    #[test]
    fn unlock_missing_identity_fails() {
        let (_dir, store) = temp_store();
        let result = unlock_identity(&store, "did:goya:nonexistent", TEST_PASSWORD);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("not found"));
    }

    #[test]
    fn create_multiple_identities_unique_dids() {
        let (_dir, store) = temp_store();

        let ids: Vec<IdentityInfo> = (0..3)
            .map(|_| create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap())
            .collect();

        assert_eq!(store.count().unwrap(), 3);
        let unique_dids: std::collections::HashSet<_> = ids.iter().map(|i| &i.did).collect();
        assert_eq!(unique_dids.len(), 3);
    }

    #[test]
    fn each_identity_has_unique_encryption() {
        let (_dir, store) = temp_store();

        let infos: Vec<IdentityInfo> = (0..2)
            .map(|_| create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap())
            .collect();

        let enc_values: Vec<String> = infos
            .iter()
            .map(|info| store.get(&info.did).unwrap().unwrap().private_key_enc)
            .collect();

        assert_ne!(enc_values[0], enc_values[1]);
    }

    #[test]
    fn list_identities_returns_all() {
        let (_dir, store) = temp_store();
        (0..3).for_each(|_| {
            create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();
        });

        let list = list_identities(&store).unwrap();
        assert_eq!(list.len(), 3);
        list.iter().for_each(|id| {
            assert!(id.did.starts_with("did:goya:"));
        });
    }

    #[test]
    fn list_empty_store() {
        let (_dir, store) = temp_store();
        let list = list_identities(&store).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn notarize_builds_valid_signature() {
        let (_dir, store) = temp_store();
        let info = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        // Decrypt key and verify we can sign + verify the notarize message
        let private_bytes = key_crypto::decrypt_key(
            &store.get(&info.did).unwrap().unwrap().private_key_enc,
            TEST_PASSWORD,
        )
        .unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_bytes.try_into().unwrap());
        let content_hash = hash_document(b"test-file-content");
        let sign_msg = format!("notarize:{}:{}", info.did, content_hash);

        use ed25519_dalek::{Signer, Verifier};
        let sig = signing_key.sign(sign_msg.as_bytes());
        let vk = signing_key.verifying_key();
        assert!(vk.verify(sign_msg.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn hash_document_is_deterministic() {
        let data = b"hello goya ledger";
        let hash1 = hash_document(data);
        let hash2 = hash_document(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn hash_document_different_inputs() {
        let h1 = hash_document(b"file_a");
        let h2 = hash_document(b"file_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn generate_keypair_ed25519_valid() {
        let kp = generate_keypair("Ed25519");
        assert_eq!(kp.public_key_hex.len(), 64);
        assert_eq!(kp.private_key_raw.len(), 32);
    }

    #[test]
    fn generate_keypair_unique() {
        let kp1 = generate_keypair("Ed25519");
        let kp2 = generate_keypair("Ed25519");
        assert_ne!(kp1.public_key_hex, kp2.public_key_hex);
    }

    #[test]
    fn unknown_algorithm_falls_back_to_ed25519() {
        let kp = generate_keypair("unknown_algo");
        assert_eq!(kp.public_key_hex.len(), 64);
        assert_eq!(kp.private_key_raw.len(), 32);
    }

    #[tokio::test]
    async fn node_status_offline_seed() {
        let (_dir, store) = temp_store();
        create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let proxy = SeedProxy::new("http://localhost:1".into());
        let status = get_node_status(&proxy, &store).await.unwrap();

        assert!(!status.connected);
        assert!(status.chain_height.is_none());
        assert_eq!(status.local_identities, 1);
    }

    // ── Wallet command tests ──

    #[test]
    fn transfer_builds_valid_signature() {
        let (_dir, store) = temp_store();
        let sender = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let private_bytes = key_crypto::decrypt_key(
            &store.get(&sender.did).unwrap().unwrap().private_key_enc,
            TEST_PASSWORD,
        )
        .unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_bytes.try_into().unwrap());

        let to = "did:goya:recipient0000000";
        let amount = 500u64;
        let nonce = 0u64;
        let sign_msg = format!("transfer:{}:{to}:{amount}:{nonce}", sender.did);

        use ed25519_dalek::{Signer, Verifier};
        let sig = signing_key.sign(sign_msg.as_bytes());
        assert!(signing_key
            .verifying_key()
            .verify(sign_msg.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn transfer_wrong_password_fails_unlock() {
        let (_dir, store) = temp_store();
        let sender = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let result = key_crypto::decrypt_key(
            &store.get(&sender.did).unwrap().unwrap().private_key_enc,
            "wrong-password",
        );
        assert!(result.is_err());
    }

    #[test]
    fn wallet_balance_struct_serializes() {
        let wb = WalletBalance {
            address: "did:goya:test".to_string(),
            balance: 1000,
            nonce: 3,
        };
        let json = serde_json::to_value(&wb).unwrap();
        assert_eq!(json["balance"], 1000);
        assert_eq!(json["nonce"], 3);
    }

    #[test]
    fn transfer_result_struct_serializes() {
        let tr = TransferResult {
            tx_id: "tx-001".to_string(),
            from: "did:goya:alice".to_string(),
            to: "did:goya:bob".to_string(),
            amount: 250,
            status: "confirmed".to_string(),
        };
        let json = serde_json::to_value(&tr).unwrap();
        assert_eq!(json["amount"], 250);
        assert_eq!(json["status"], "confirmed");
    }

    #[test]
    fn faucet_result_struct_serializes() {
        let fr = FaucetResult {
            tx_id: "tx-002".to_string(),
            amount: 1000,
            status: "funded".to_string(),
        };
        let json = serde_json::to_value(&fr).unwrap();
        assert_eq!(json["amount"], 1000);
        assert_eq!(json["status"], "funded");
    }

    // ── Governance tests ──

    #[test]
    fn vote_builds_valid_signature() {
        let (_dir, store) = temp_store();
        let info = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let private_bytes = key_crypto::decrypt_key(
            &store.get(&info.did).unwrap().unwrap().private_key_enc,
            TEST_PASSWORD,
        )
        .unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_bytes.try_into().unwrap());

        let proposal_id = 42u64;
        let option = "Yes";
        let stored = store.get(&info.did).unwrap().unwrap();
        let sign_msg = format!("vote:{proposal_id}:{option}:{}", stored.public_key_hex);

        use ed25519_dalek::{Signer, Verifier};
        let sig = signing_key.sign(sign_msg.as_bytes());
        assert!(signing_key
            .verifying_key()
            .verify(sign_msg.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn proposal_summary_serializes() {
        let ps = ProposalSummary {
            id: 1,
            proposer: "did:goya:alice".to_string(),
            description: "Increase block size".to_string(),
            status: "Voting".to_string(),
            deposit: 10000,
        };
        let json = serde_json::to_value(&ps).unwrap();
        assert_eq!(json["id"], 1);
        assert_eq!(json["status"], "Voting");
    }

    #[test]
    fn vote_tally_serializes() {
        let vt = VoteTally {
            proposal_id: 1,
            yes_power: 100,
            no_power: 20,
            abstain_power: 5,
            quorum_reached: true,
            passed: true,
        };
        let json = serde_json::to_value(&vt).unwrap();
        assert_eq!(json["yes_power"], 100);
        assert!(json["passed"].as_bool().unwrap());
    }

    // ── Document transfer tests ──

    #[test]
    fn transfer_doc_builds_valid_signature() {
        let (_dir, store) = temp_store();
        let info = create_identity(&store, "Ed25519", TEST_PASSWORD).unwrap();

        let private_bytes = key_crypto::decrypt_key(
            &store.get(&info.did).unwrap().unwrap().private_key_enc,
            TEST_PASSWORD,
        )
        .unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_bytes.try_into().unwrap());

        let hash = hash_document(b"my-contract.pdf");
        let to = "did:goya:recipient0000000";
        let sign_msg = format!("transfer_doc:{hash}:0:{}:{to}", info.did);

        use ed25519_dalek::{Signer, Verifier};
        let sig = signing_key.sign(sign_msg.as_bytes());
        assert!(signing_key
            .verifying_key()
            .verify(sign_msg.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn transfer_doc_result_serializes() {
        let tr = TransferDocResult {
            content_hash: "aa".repeat(32),
            from: "did:goya:alice".to_string(),
            to: "did:goya:bob".to_string(),
            transferred_at: 1700000000,
        };
        let json = serde_json::to_value(&tr).unwrap();
        assert_eq!(json["from"], "did:goya:alice");
        assert_eq!(json["to"], "did:goya:bob");
    }

    #[test]
    fn document_owner_serializes() {
        let owner = DocumentOwner {
            content_hash: "bb".repeat(32),
            owner: "did:goya:bob".to_string(),
            original_signer: "did:goya:alice".to_string(),
            transfer_count: 1,
        };
        let json = serde_json::to_value(&owner).unwrap();
        assert_eq!(json["owner"], "did:goya:bob");
        assert_eq!(json["transfer_count"], 1);
    }
}
