use crate::{http_client, now_secs, read_json, Wallet};
use clap::Subcommand;
use rust_bc::api::handlers::issuers::pending_issuances_message;
use rust_bc::api::handlers::oid4vci::offer_message;
use rust_bc::identity::issuer_credentials::{
    issue_holder_credential, sign_anchor, CredentialDraft, StatusListEntry,
};
use rust_bc::identity::issuer_keys::{credential_key_message, p256_public_jwk};
use rust_bc::identity::signing::EcdsaP256SigningProvider;
use rust_bc::identity::status_lists::{sign_status_list_jwt, StatusListDraft};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum IssuerCommand {
    /// Create (once) and register the ES256 key wallets verify, bound to this DID
    RegisterCredentialKey,
    /// Create a credential offer for a wallet and print its URI
    Offer {
        /// Credential configuration id advertised by the node (e.g. eudi_pid_sd_jwt)
        configuration_id: String,
    },
    /// List credential requests waiting for this issuer
    Pending,
    /// Sign and deliver a credential for a pending request
    Deliver {
        /// Transaction id shown by `issuer pending`
        transaction_id: String,
        /// JSON object with the claims to put in the credential
        claims: PathBuf,
        /// Status list the credential points to
        #[arg(long, requires = "status_index")]
        status_list: Option<String>,
        /// Index of the credential in that status list
        #[arg(long, requires = "status_list")]
        status_index: Option<usize>,
    },
    /// Sign and publish a status list
    #[command(subcommand)]
    Status(StatusCommand),
}

#[derive(Subcommand)]
pub enum StatusCommand {
    /// Publish a status list where the given indices are revoked
    Publish {
        list_id: String,
        revoked_indices: Vec<usize>,
    },
}

pub fn run(node: &str, command: &IssuerCommand) -> Result<(), String> {
    match command {
        IssuerCommand::RegisterCredentialKey => register_credential_key(node),
        IssuerCommand::Offer { configuration_id } => create_offer(node, configuration_id),
        IssuerCommand::Pending => list_pending(node),
        IssuerCommand::Deliver {
            transaction_id,
            claims,
            status_list,
            status_index,
        } => deliver(
            node,
            transaction_id,
            claims,
            status_list.clone().zip(*status_index),
        ),
        IssuerCommand::Status(StatusCommand::Publish {
            list_id,
            revoked_indices,
        }) => publish_status_list(node, list_id, revoked_indices),
    }
}

fn credential_key(wallet: &Wallet) -> Result<EcdsaP256SigningProvider, String> {
    let secret_hex = wallet
        .credential_key_hex
        .as_deref()
        .ok_or("no credential key yet; run `cerulean issuer register-credential-key` first")?;
    let secret = hex::decode(secret_hex).map_err(|e| format!("decode credential key: {e}"))?;
    EcdsaP256SigningProvider::from_secret_bytes(&secret).map_err(|e| e.to_string())
}

fn issuer_url(node: &str, did: &str) -> Result<String, String> {
    let resp = http_client()
        .get(format!("{node}/.well-known/openid-credential-issuer"))
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    let metadata = read_json(resp)?;
    let credential_issuer = metadata["credential_issuer"]
        .as_str()
        .ok_or("node metadata has no credential_issuer")?;
    Ok(format!(
        "{}/api/v1/issuers/{did}",
        credential_issuer.trim_end_matches('/')
    ))
}

fn register_credential_key(node: &str) -> Result<(), String> {
    let mut wallet = Wallet::load()?;
    let key = match wallet.credential_key_hex {
        Some(_) => credential_key(&wallet)?,
        None => EcdsaP256SigningProvider::generate(),
    };
    let jwk = p256_public_jwk(&key);
    let registered_at = now_secs();
    let body = serde_json::json!({
        "jwk": jwk,
        "registered_at": registered_at,
        "public_key": wallet.public_key_hex,
        "signature": wallet.sign_hex(&credential_key_message(&wallet.did, &jwk, registered_at))?,
    });
    let resp = http_client()
        .post(format!(
            "{node}/api/v1/issuers/{}/credential-key",
            wallet.did
        ))
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    read_json(resp)?;
    wallet.credential_key_hex = Some(hex::encode(key.secret_bytes().as_slice()));
    wallet.save()?;
    println!("Credential key registered for {}", wallet.did);
    println!("  x: {}\n  y: {}", jwk.x, jwk.y);
    Ok(())
}

fn create_offer(node: &str, configuration_id: &str) -> Result<(), String> {
    let wallet = Wallet::load()?;
    let issued_at = now_secs();
    let body = serde_json::json!({
        "issuer_did": wallet.did,
        "issuer_public_key": wallet.public_key_hex,
        "credential_configuration_id": configuration_id,
        "issued_at": issued_at,
        "signature": wallet.sign_hex(&offer_message(&wallet.did, configuration_id, issued_at))?,
    });
    let resp = http_client()
        .post(format!("{node}/credential_offer"))
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    let offer = read_json(resp)?;
    println!(
        "{}",
        offer["credential_offer_uri"]
            .as_str()
            .ok_or("node returned no credential_offer_uri")?
    );
    Ok(())
}

fn fetch_pending(node: &str, wallet: &Wallet) -> Result<Vec<serde_json::Value>, String> {
    let issued_at = now_secs();
    let signature = wallet.sign_hex(&pending_issuances_message(&wallet.did, issued_at))?;
    let resp = http_client()
        .get(format!("{node}/api/v1/issuers/{}/issuances", wallet.did))
        .query(&[
            ("public_key", wallet.public_key_hex.as_str()),
            ("issued_at", &issued_at.to_string()),
            ("signature", &signature),
        ])
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    let body = read_json(resp)?;
    Ok(body["data"].as_array().cloned().unwrap_or_default())
}

fn list_pending(node: &str) -> Result<(), String> {
    let pending = fetch_pending(node, &Wallet::load()?)?;
    if pending.is_empty() {
        println!("No pending credential requests.");
        return Ok(());
    }
    for request in &pending {
        println!(
            "{}  {}  {}",
            request["transaction_id"].as_str().unwrap_or("-"),
            request["configuration_id"].as_str().unwrap_or("-"),
            request["vct"].as_str().unwrap_or("-"),
        );
    }
    Ok(())
}

fn read_claims(path: &PathBuf) -> Result<Vec<(String, serde_json::Value)>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read claims {}: {e}", path.display()))?;
    let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text)
        .map_err(|e| format!("claims {} must be a JSON object: {e}", path.display()))?;
    Ok(claims.into_iter().collect())
}

fn deliver(
    node: &str,
    transaction_id: &str,
    claims: &PathBuf,
    status: Option<(String, usize)>,
) -> Result<(), String> {
    let wallet = Wallet::load()?;
    let request = fetch_pending(node, &wallet)?
        .into_iter()
        .find(|request| request["transaction_id"] == transaction_id)
        .ok_or_else(|| format!("no pending request {transaction_id} for {}", wallet.did))?;
    let issued = issue_holder_credential(
        &credential_key(&wallet)?,
        &CredentialDraft {
            issuer_url: issuer_url(node, &wallet.did)?,
            vct: request["vct"]
                .as_str()
                .ok_or("pending request has no vct")?
                .to_string(),
            holder_jwk: request["holder_jwk"].clone(),
            claims: read_claims(claims)?,
            status: status.map(|(list_id, index)| StatusListEntry { list_id, index }),
        },
        now_secs(),
    )?;

    let client = http_client();
    let resp = client
        .post(format!(
            "{node}/api/v1/issuers/{}/issuances/{transaction_id}",
            wallet.did
        ))
        .json(&serde_json::json!({ "credential": issued.compact }))
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    read_json(resp)?;

    let anchor = sign_anchor(&wallet.did_key()?, &wallet.did, &issued)?;
    let mut body = serde_json::to_value(&anchor).map_err(|e| e.to_string())?;
    body["issuer_public_key"] = wallet.public_key_hex.clone().into();
    let resp = client
        .post(format!("{node}/api/v1/store/credentials"))
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    read_json(resp)?;

    println!("Credential delivered for {transaction_id}");
    println!("  Post-quantum anchor: {}", anchor.id);
    Ok(())
}

fn publish_status_list(node: &str, list_id: &str, revoked_indices: &[usize]) -> Result<(), String> {
    let wallet = Wallet::load()?;
    let jwt = sign_status_list_jwt(
        &credential_key(&wallet)?,
        &StatusListDraft {
            issuer_url: &issuer_url(node, &wallet.did)?,
            list_id,
            revoked_indices,
            issued_at: now_secs(),
        },
    )
    .map_err(|e| e.to_string())?;
    let resp = http_client()
        .put(format!(
            "{node}/api/v1/issuers/{}/status-lists/{list_id}",
            wallet.did
        ))
        .json(&serde_json::json!({ "status_list_jwt": jwt }))
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    read_json(resp)?;
    println!(
        "Status list {list_id} published with {} revoked",
        revoked_indices.len()
    );
    Ok(())
}
