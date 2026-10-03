//! Cerulean CLI — digital signature tool for Cerulean Ledger.
//!
//! Commands:
//!   init   — Generate keypair and register DID on the network
//!   sign   — Sign a file and register the credential on-chain
//!   verify — Verify a credential by ID
//!   list   — List credentials issued by this identity

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pqc_crypto_module::legacy::ed25519::{SigningKey, VerifyingKey};
use pqc_crypto_module::legacy::rng::OsRng;
use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
use serde::{Deserialize, Serialize};

// ── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "cerulean", about = "Cerulean Ledger — digital signature CLI")]
struct Cli {
    /// Node URL (default: http://localhost:8080)
    #[arg(long, default_value = "http://localhost:8080")]
    node: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate keypair and register identity on the network
    Init {
        /// Your display name
        name: String,
        /// Organization ID
        #[arg(long, default_value = "default")]
        org: String,
    },
    /// Sign a file and register the credential on-chain
    Sign {
        /// Path to the file to sign
        file: PathBuf,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// Verify a credential by its ID
    Verify {
        /// Credential ID
        credential_id: String,
    },
    /// List credentials issued by this identity
    List,
}

// ── Wallet ───────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Wallet {
    did: String,
    name: String,
    org: String,
    /// Ed25519 secret key (32 bytes, hex-encoded)
    secret_key_hex: String,
    /// Ed25519 public key (32 bytes, hex-encoded)
    public_key_hex: String,
    /// Credential IDs signed by this wallet (local index)
    #[serde(default)]
    credentials: Vec<String>,
}

impl Wallet {
    fn wallet_dir() -> PathBuf {
        dirs_next().join("wallet.json")
    }

    fn load() -> Result<Self, String> {
        let path = Self::wallet_dir();
        if !path.exists() {
            return Err(format!(
                "No wallet found. Run `cerulean init \"Your Name\"` first.\n  Expected: {}",
                path.display()
            ));
        }
        let data = fs::read_to_string(&path).map_err(|e| format!("read wallet: {e}"))?;
        serde_json::from_str(&data).map_err(|e| format!("parse wallet: {e}"))
    }

    fn save(&self) -> Result<(), String> {
        let dir = dirs_next();
        fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;
        let json = serde_json::to_string_pretty(self).unwrap();
        fs::write(Self::wallet_dir(), json).map_err(|e| format!("write wallet: {e}"))
    }

    #[allow(dead_code)]
    fn signing_key(&self) -> Result<SigningKey, String> {
        let bytes = hex::decode(&self.secret_key_hex).map_err(|e| format!("decode key: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "invalid key length".to_string())?;
        Ok(SigningKey::from_bytes(&arr))
    }
}

fn dirs_next() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cerulean")
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

fn http_client() -> reqwest::blocking::Client {
    rust_bc::tls::install_crypto_provider();
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client")
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn cmd_init(node: &str, name: &str, org: &str) -> Result<(), String> {
    let path = Wallet::wallet_dir();
    if path.exists() {
        return Err(format!(
            "Wallet already exists at {}\n  Delete it first if you want to re-initialize.",
            path.display()
        ));
    }

    // Generate Ed25519 keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();

    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());
    let did = rust_bc::identity::did::did_from_pubkey_hex(&public_hex);

    // Register DID on the node (IdentityRecord struct)
    let client = http_client();
    let now_ts = chrono::Utc::now().timestamp() as u64;
    let body = serde_json::json!({
        "did": did,
        "public_key": public_hex,
        "created_at": now_ts,
        "updated_at": now_ts,
        "status": "active"
    });

    let resp = client
        .post(format!("{node}/api/v1/store/identities"))
        .header("Content-Type", "application/json")
        .header("X-Org-Id", org)
        .header("X-Msp-Role", "client")
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("Node returned {status}: {text}"));
    }

    // Save wallet
    let wallet = Wallet {
        did: did.clone(),
        name: name.to_string(),
        org: org.to_string(),
        secret_key_hex: secret_hex,
        public_key_hex: public_hex,
        credentials: Vec::new(),
    };
    wallet.save()?;

    println!("Identity created successfully!\n");
    println!("  DID:    {did}");
    println!("  Name:   {name}");
    println!("  Org:    {org}");
    println!("  Wallet: {}", path.display());
    println!("\nYour private key is stored locally. Never share it.");
    Ok(())
}

fn cmd_sign(node: &str, file: &PathBuf, description: Option<&str>) -> Result<(), String> {
    let mut wallet = Wallet::load()?;
    let signing_key = wallet.signing_key()?;

    // Read and hash the file
    if !file.exists() {
        return Err(format!("File not found: {}", file.display()));
    }
    let file_bytes = fs::read(file).map_err(|e| format!("read file: {e}"))?;
    let file_hash = Sha256::digest(&file_bytes);
    let hash_hex = hex::encode(file_hash);

    // Sign the hash with private key
    use pqc_crypto_module::legacy::ed25519::Signer;
    let signature = signing_key.sign(&file_hash[..]);
    let sig_hex = hex::encode(signature.to_bytes());

    // Build credential
    let file_name = file
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let cred_id = format!("sig-{}", &hash_hex[..12]);
    let now_ts = chrono::Utc::now().timestamp() as u64;
    let now = chrono::Utc::now().to_rfc3339();

    // Store credential on-chain with claims + signature
    let body = serde_json::json!({
        "id": cred_id,
        "issuer_did": wallet.did,
        "subject_did": format!("did:goya:doc:{}", &hash_hex[..16]),
        "cred_type": "DigitalSignature",
        "issued_at": now_ts,
        "expires_at": 0,
        "revoked_at": null,
        "claims": {
            "file_name": file_name,
            "file_hash_sha256": hash_hex,
            "file_size_bytes": file_bytes.len(),
            "description": description.unwrap_or(""),
            "signed_at": now,
            "signer_public_key": wallet.public_key_hex,
        },
        "signature": sig_hex,
        "status": "active",
    });

    let client = http_client();
    let resp = client
        .post(format!("{node}/api/v1/store/credentials"))
        .header("Content-Type", "application/json")
        .header("X-Org-Id", &wallet.org)
        .header("X-Msp-Role", "client")
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("Node returned {status}: {text}"));
    }

    // Save credential ID to local wallet index
    wallet.credentials.push(cred_id.clone());
    wallet.save()?;

    println!("Document signed and registered!\n");
    println!("  Credential ID: {cred_id}");
    println!("  File:          {file_name}");
    println!("  SHA-256:       {hash_hex}");
    println!("  Signer:        {}", wallet.did);
    println!("  Timestamp:     {now}");
    println!("\nAnyone can verify with: cerulean verify {cred_id}");
    Ok(())
}

fn cmd_verify(node: &str, credential_id: &str) -> Result<(), String> {
    let client = http_client();
    let resp = client
        .get(format!("{node}/api/v1/store/credentials/{credential_id}"))
        .send()
        .map_err(|e| format!("Failed to connect to node: {e}"))?;

    if resp.status().as_u16() == 404 {
        return Err(format!(
            "Credential '{credential_id}' not found on the network."
        ));
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("Node returned {status}: {text}"));
    }

    let body: serde_json::Value = resp.json().map_err(|e| format!("parse response: {e}"))?;

    // Extract credential from response envelope
    let cred = body.get("data").unwrap_or(&body);

    let issuer = cred["issuer_did"].as_str().unwrap_or("unknown");
    let cred_type = cred["cred_type"].as_str().unwrap_or("unknown");
    let status = cred["status"].as_str().unwrap_or("unknown");
    let issued_at = cred["issued_at"].as_u64().unwrap_or(0);
    let claims = &cred["claims"];
    let sig_hex = cred["signature"].as_str().unwrap_or("");

    // Extract info from claims
    let file_name = claims["file_name"].as_str().unwrap_or("");
    let file_hash = claims["file_hash_sha256"].as_str().unwrap_or("");
    let signer_pk = claims["signer_public_key"].as_str().unwrap_or("");

    // Format timestamp
    let issued_str = chrono::DateTime::from_timestamp(issued_at as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| issued_at.to_string());

    // Verify signature if we have all the pieces
    let sig_status = if !sig_hex.is_empty() && !file_hash.is_empty() && !signer_pk.is_empty() {
        if verify_ed25519(signer_pk, file_hash, sig_hex) {
            "VALID"
        } else {
            "INVALID"
        }
    } else if sig_hex.is_empty() {
        "NO SIGNATURE"
    } else {
        "UNVERIFIABLE (missing public key or hash)"
    };

    println!("Credential: {credential_id}\n");
    println!("  Type:        {cred_type}");
    println!("  Status:      {status}");
    println!("  Issuer:      {issuer}");
    if !file_name.is_empty() {
        println!("  File:        {file_name}");
    }
    if !file_hash.is_empty() {
        println!("  SHA-256:     {file_hash}");
    }
    println!("  Issued at:   {issued_str}");
    if let Some(desc) = claims["description"].as_str() {
        if !desc.is_empty() {
            println!("  Description: {desc}");
        }
    }
    println!();
    println!("  Signature:   {sig_status}");

    Ok(())
}

fn cmd_list(node: &str) -> Result<(), String> {
    let wallet = Wallet::load()?;

    if wallet.credentials.is_empty() {
        println!(
            "No credentials signed yet by {} ({})",
            wallet.name, wallet.did
        );
        println!("Sign a document with: cerulean sign <file>");
        return Ok(());
    }

    let client = http_client();

    println!("Credentials signed by {} ({}):\n", wallet.name, wallet.did);
    println!("{:<20} {:<20} {:<26} Status", "ID", "File", "Issued at");
    println!("{}", "-".repeat(75));

    let mut found = 0;
    for cred_id in &wallet.credentials {
        let resp = client
            .get(format!("{node}/api/v1/store/credentials/{cred_id}"))
            .send();

        match resp {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().unwrap_or_default();
                let cred = body.get("data").unwrap_or(&body);
                let claims = &cred["claims"];
                let issued_at = cred["issued_at"].as_u64().unwrap_or(0);
                let doc_name = claims["file_name"].as_str().unwrap_or("-");

                let issued_str = chrono::DateTime::from_timestamp(issued_at as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".to_string());

                println!(
                    "{:<20} {:<20} {:<26} on-chain",
                    cred_id, doc_name, issued_str
                );
                found += 1;
            }
            _ => {
                println!("{:<20} {:<20} {:<26} not found", cred_id, "-", "-");
            }
        }
    }

    println!("\nTotal: {} ({} on-chain)", wallet.credentials.len(), found);
    Ok(())
}

// ── Crypto helpers ───────────────────────────────────────────────────────────

/// Verify an Ed25519 signature: public_key and message are hex-encoded raw bytes,
/// signature is hex-encoded 64-byte Ed25519 signature.
fn verify_ed25519(public_key_hex: &str, message_hex: &str, signature_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(msg_bytes) = hex::decode(message_hex) else {
        return false;
    };

    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let signature = pqc_crypto_module::legacy::ed25519::Signature::from_bytes(&sig_arr);

    use pqc_crypto_module::legacy::ed25519::Verifier;
    verifying_key.verify(&msg_bytes, &signature).is_ok()
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let node = &cli.node;

    let result = match cli.command {
        Commands::Init { ref name, ref org } => cmd_init(node, name, org),
        Commands::Sign {
            ref file,
            ref description,
        } => cmd_sign(node, file, description.as_deref()),
        Commands::Verify { ref credential_id } => cmd_verify(node, credential_id),
        Commands::List => cmd_list(node),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
