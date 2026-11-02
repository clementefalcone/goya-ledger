//! Cerulean CLI — digital signature tool for Cerulean Ledger.
//!
//! Commands:
//!   init   — Generate keypair and register DID on the network
//!   sign   — Sign a file and register the credential on-chain
//!   verify — Verify a credential by ID
//!   list   — List credentials issued by this identity
//!   issuer — Issue EUDI wallet credentials signed by this identity

mod issuer;

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pqc_crypto_module::legacy::ed25519::{SigningKey, VerifyingKey};
use pqc_crypto_module::legacy::rng::OsRng;
use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
use rust_bc::identity::credential_ops::issue_message;
use rust_bc::identity::operations::is_signed_by;
use rust_bc::identity::signing::{SigningProvider, SoftwareSigningProvider};
use rust_bc::storage::traits::Credential;
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
    },
    /// Verify a credential by its ID
    Verify {
        /// Credential ID
        credential_id: String,
    },
    /// List credentials issued by this identity
    List,
    /// Issue EUDI wallet credentials signed by this identity
    #[command(subcommand)]
    Issuer(issuer::IssuerCommand),
}

// ── Wallet ───────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    pub did: String,
    name: String,
    org: String,
    /// Ed25519 secret key (32 bytes, hex-encoded)
    secret_key_hex: String,
    /// Ed25519 public key (32 bytes, hex-encoded)
    pub public_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_key_hex: Option<String>,
    /// Credential IDs signed by this wallet (local index)
    #[serde(default)]
    credentials: Vec<String>,
}

impl Wallet {
    fn wallet_dir() -> PathBuf {
        dirs_next().join("wallet.json")
    }

    pub fn load() -> Result<Self, String> {
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

    pub fn save(&self) -> Result<(), String> {
        let dir = dirs_next();
        fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;
        let json = serde_json::to_string_pretty(self).unwrap();
        fs::write(Self::wallet_dir(), json).map_err(|e| format!("write wallet: {e}"))
    }

    pub fn did_key(&self) -> Result<SoftwareSigningProvider, String> {
        let bytes = hex::decode(&self.secret_key_hex).map_err(|e| format!("decode key: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "invalid key length".to_string())?;
        Ok(SoftwareSigningProvider::from_key(SigningKey::from_bytes(
            &arr,
        )))
    }

    pub fn sign_hex(&self, message: &str) -> Result<String, String> {
        self.did_key()?
            .sign(message.as_bytes())
            .map(hex::encode)
            .map_err(|e| format!("DID key could not sign: {e}"))
    }
}

fn dirs_next() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cerulean")
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

pub fn http_client() -> reqwest::blocking::Client {
    rust_bc::tls::install_crypto_provider();
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client")
}

pub fn read_json(resp: reqwest::blocking::Response) -> Result<serde_json::Value, String> {
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Node returned {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("parse response: {e}"))
}

pub fn now_secs() -> u64 {
    chrono::Utc::now().timestamp() as u64
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

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let wallet = Wallet {
        did: rust_bc::identity::did::did_from_pubkey_hex(&hex::encode(verifying_key.to_bytes())),
        name: name.to_string(),
        org: org.to_string(),
        secret_key_hex: hex::encode(signing_key.to_bytes()),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        credential_key_hex: None,
        credentials: Vec::new(),
    };

    let now_ts = now_secs();
    let body = serde_json::json!({
        "did": wallet.did,
        "public_key": wallet.public_key_hex,
        "created_at": now_ts,
        "updated_at": now_ts,
        "status": "active",
        "signature": wallet.sign_hex(&format!("identity:register:{}", wallet.did))?,
    });
    let resp = http_client()
        .post(format!("{node}/api/v1/store/identities"))
        .header("X-Org-Id", org)
        .header("X-Msp-Role", "client")
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node at {node}: {e}"))?;
    read_json(resp)?;
    wallet.save()?;

    println!("Identity created successfully!\n");
    println!("  DID:    {}", wallet.did);
    println!("  Name:   {name}");
    println!("  Org:    {org}");
    println!("  Wallet: {}", path.display());
    println!("\nYour private key is stored locally. Never share it.");
    Ok(())
}

fn cmd_sign(node: &str, file: &PathBuf) -> Result<(), String> {
    let mut wallet = Wallet::load()?;
    if !file.exists() {
        return Err(format!("File not found: {}", file.display()));
    }
    let file_bytes = fs::read(file).map_err(|e| format!("read file: {e}"))?;
    let hash_hex = hex::encode(Sha256::digest(&file_bytes));
    let cred_id = format!("sig-{}", &hash_hex[..12]);

    let mut credential = Credential {
        id: cred_id.clone(),
        issuer_did: wallet.did.clone(),
        subject_did: format!("did:goya:doc:{}", &hash_hex[..16]),
        cred_type: "DigitalSignature".to_string(),
        issued_at: now_secs(),
        expires_at: 0,
        revoked_at: None,
        claims: serde_json::Value::Null,
        signature: String::new(),
        status: "active".to_string(),
        claims_commitment: Some(hash_hex.clone()),
        claims_salt: None,
    };
    credential.signature = wallet.sign_hex(&issue_message(&credential))?;
    let mut body = serde_json::to_value(&credential).map_err(|e| e.to_string())?;
    body["issuer_public_key"] = wallet.public_key_hex.clone().into();

    let resp = http_client()
        .post(format!("{node}/api/v1/store/credentials"))
        .header("X-Org-Id", &wallet.org)
        .header("X-Msp-Role", "client")
        .json(&body)
        .send()
        .map_err(|e| format!("Failed to connect to node: {e}"))?;
    read_json(resp)?;

    wallet.credentials.push(cred_id.clone());
    wallet.save()?;

    println!("Document signed and registered!\n");
    println!("  Credential ID: {cred_id}");
    println!("  File:          {}", file.display());
    println!("  SHA-256:       {hash_hex}");
    println!("  Signer:        {}", wallet.did);
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
    let body = read_json(resp)?;
    let credential: Credential = serde_json::from_value(body["data"].clone())
        .map_err(|e| format!("parse credential: {e}"))?;

    let resp = client
        .get(format!(
            "{node}/api/v1/store/identities/{}",
            credential.issuer_did
        ))
        .send()
        .map_err(|e| format!("Failed to connect to node: {e}"))?;
    let issuer = read_json(resp)?;
    let issuer_public_key = issuer["data"]["public_key"].as_str().unwrap_or_default();
    let signature_status = if is_signed_by(
        issuer_public_key,
        &issue_message(&credential),
        &credential.signature,
    ) {
        "VALID (signed by the issuer's registered key)"
    } else {
        "INVALID"
    };

    let issued_str = chrono::DateTime::from_timestamp(credential.issued_at as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| credential.issued_at.to_string());
    println!("Credential: {credential_id}\n");
    println!("  Type:        {}", credential.cred_type);
    println!("  Status:      {}", credential.status);
    println!("  Issuer:      {}", credential.issuer_did);
    println!(
        "  Commitment:  {}",
        credential.claims_commitment.unwrap_or_default()
    );
    println!("  Issued at:   {issued_str}");
    println!();
    println!("  Signature:   {signature_status}");
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
    println!("{:<20} {:<26} Status", "ID", "Issued at");
    println!("{}", "-".repeat(60));
    for cred_id in &wallet.credentials {
        let credential = client
            .get(format!("{node}/api/v1/store/credentials/{cred_id}"))
            .send()
            .map_err(|e| e.to_string())
            .and_then(read_json);
        let (issued_str, status) = match credential {
            Ok(body) => (
                chrono::DateTime::from_timestamp(
                    body["data"]["issued_at"].as_i64().unwrap_or(0),
                    0,
                )
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "-".to_string()),
                body["data"]["status"].as_str().unwrap_or("-").to_string(),
            ),
            Err(_) => ("-".to_string(), "not found".to_string()),
        };
        println!("{cred_id:<20} {issued_str:<26} {status}");
    }
    Ok(())
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let node = &cli.node;

    let result = match cli.command {
        Commands::Init { ref name, ref org } => cmd_init(node, name, org),
        Commands::Sign { ref file } => cmd_sign(node, file),
        Commands::Verify { ref credential_id } => cmd_verify(node, credential_id),
        Commands::List => cmd_list(node),
        Commands::Issuer(ref command) => issuer::run(node, command),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
