//! Storage trait definitions
//!
//! Defines the BlockStore trait and related interfaces for storage operations.

use std::sync::Arc;

use super::errors::StorageResult;
use crate::crypto::hasher::HashAlgorithm;
use crate::endorsement::types::Endorsement;
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{BiometricEvidence, SignatureLevel, SignerProof};

/// Block structure for storage
///
/// Signature fields are variable-length (`Vec<u8>`) to support both Ed25519
/// (64 bytes) and post-quantum algorithms like ML-DSA-65 (3309 bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub transactions: Vec<String>,
    pub proposer: String,
    #[serde(with = "vec_hex")]
    pub signature: Vec<u8>,
    /// Cryptographic algorithm used for the proposer signature.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Endorsements collected for this block (empty for legacy blocks)
    #[serde(default)]
    pub endorsements: Vec<Endorsement>,
    /// Secondary (dual) signature for crypto-agility migration.
    ///
    /// During a PQC transition, blocks carry both a primary (classical) and
    /// secondary (post-quantum) signature — or vice versa. Validators accept
    /// the block if either signature is valid.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_vec_hex")]
    pub secondary_signature: Option<Vec<u8>>,
    /// Algorithm used for the secondary signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_signature_algorithm: Option<SigningAlgorithm>,
    /// Hash algorithm used for merkle_root and block hashing.
    /// Defaults to SHA-256 for backwards compatibility with legacy blocks.
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,
    /// Orderer signature over the block hash (absent for legacy blocks).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_vec_hex")]
    pub orderer_signature: Option<Vec<u8>>,
    /// BFT commit quorum certificate (absent for solo-ordered blocks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_qc: Option<crate::consensus::bft::types::QuorumCertificate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data: Vec<Transaction>,
}

mod vec_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str = String::deserialize(d)?;
        hex::decode(&hex_str).map_err(serde::de::Error::custom)
    }
}

mod opt_vec_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match sig {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
        }
    }
}

/// Typed transaction payload — extends Transaction beyond value transfers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum TxPayload {
    Transfer {
        amount: u64,
    },
    RegisterIdentity {
        record: IdentityRecord,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        civil_anchor: Option<String>,
    },
    Notarize {
        entry: Box<NotarizationEntry>,
    },
}

/// Transaction structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub id: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub input_did: String,
    pub output_recipient: String,
    pub amount: u64,
    pub state: String,
    #[serde(default)]
    pub fee: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<TxPayload>,
}

/// Identity record structure
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityRecord {
    pub did: String,
    #[serde(default)]
    pub public_key: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub civil_anchor: Option<String>,
}

/// Credential structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub cred_type: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    #[serde(default)]
    pub claims: serde_json::Value,
    #[serde(default)]
    pub signature: String,
    #[serde(default = "default_credential_status")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_salt: Option<String>,
}

fn default_credential_status() -> String {
    "active".to_string()
}

impl Credential {
    /// Get the eIDAS assurance level from claims.
    /// Convention: `claims.eidas_level` = "none" | "low" | "substantial" | "high".
    pub fn eidas_level(&self) -> &str {
        self.claims
            .get("eidas_level")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
    }

    /// Set the eIDAS assurance level in claims.
    pub fn set_eidas_level(&mut self, level: &str) {
        if let Some(obj) = self.claims.as_object_mut() {
            obj.insert("eidas_level".to_string(), serde_json::json!(level));
        }
    }
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            id: String::new(),
            issuer_did: String::new(),
            subject_did: String::new(),
            cred_type: String::new(),
            issued_at: 0,
            expires_at: 0,
            revoked_at: None,
            claims: serde_json::Value::Null,
            signature: String::new(),
            status: default_credential_status(),
            claims_commitment: None,
            claims_salt: None,
        }
    }
}

// ── Institutional governance entities (Cerulean Voto) ────────────────────

/// A scope is a generic organizational unit (department, committee, branch).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Scope {
    pub id: String,
    pub name: String,
    pub label: String,
    pub parent_id: Option<String>,
    pub channel_id: String,
    pub members: Vec<ScopeMember>,
    pub created_at: u64,
}

/// A member of a scope with a specific role.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScopeMember {
    pub did: String,
    pub name: String,
    pub role: String, // "admin", "voter", "observer"
    pub added_at: u64,
}

/// An assembly (asamblea) — a formal convocation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Assembly {
    pub id: String,
    pub folio: u64,
    pub name: String,
    pub assembly_type: String, // "ordinaria", "extraordinaria"
    pub date: String,
    pub location: String,
    pub description: String,
    pub convocatoria_date: String,
    pub convocatoria_method: String,
    pub scope_id: String,
    pub created_at: u64,
}

/// A session within an assembly (first/second citation, quorum, agenda).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub assembly_id: String,
    pub number: u64,
    pub citation: String, // "primera", "segunda"
    pub status: String,   // "planificada", "en_curso", "cerrada"
    pub started_at: Option<String>,
    pub closed_at: Option<String>,
    pub agenda: Vec<AgendaItem>,
    pub attendees: Vec<String>,
    pub quorum_required: u64,
    pub quorum_met: bool,
    pub notes: String,
    pub convocante: String,
}

/// An item on a session's agenda.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgendaItem {
    pub id: String,
    pub title: String,
    pub item_type: String, // "informativo", "votacion", "debate"
    pub proposal_id: Option<u64>,
    pub resolved: bool,
    pub resolution: String,
}

/// An acta — permanent record of a session (ISO 15489).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Acta {
    pub id: String,
    pub folio: u64,
    pub session_id: String,
    pub assembly_id: String,
    pub generated_at: u64,
    pub content: serde_json::Value, // ActaContent as free-form JSON
    pub integrity_hash: String,
    pub blockchain_tx: Option<String>,
}

/// A single entry in the history of a world-state key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryEntry {
    pub version: u64,
    pub data: Vec<u8>,
    pub tx_id: String,
    pub timestamp: u64,
    pub is_delete: bool,
}

/// Notarization entry — proof of existence for a document hash.
///
/// The node stores only the SHA-256 hash of the document, never the document itself.
/// Clients compute the hash locally and submit it for on-chain timestamping.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NotarizationEntry {
    /// Unique identifier (UUID).
    pub id: String,
    /// SHA-256 hash of the document (64 hex chars).
    pub content_hash: String,
    /// DID or address of the signer.
    pub signer: String,
    /// Optional metadata (document name, description, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Unix timestamp when notarized.
    pub notarized_at: u64,
    /// Block height at time of notarization (0 if not yet anchored).
    pub block_height: u64,
    /// Signature over the signing payload (hex-encoded).
    ///
    /// Payload depends on level:
    /// - Simple:   `"fes:{signer}:{content_hash}"`
    /// - Advanced: `"fea:{signer}:{content_hash}:{biometrics_hash}"`
    pub signature: String,
    /// Public key used to produce the signature (hex-encoded).
    #[serde(default)]
    pub public_key: String,
    /// CAdES DER envelope (hex-encoded, present for FEA signatures).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cades_der: Option<String>,
    /// Signing algorithm used.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Electronic signature level (Simple/Advanced/Qualified).
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Biometric evidence commitments (required for Advanced/Qualified).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_proof: Option<SignerProof>,
}

/// Records a transfer of ownership for a notarized document.
///
/// Current owner = last `to_did` in the chain, or `signer` of the original
/// notarization if no transfers exist.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OwnershipTransfer {
    /// Content hash of the notarized document.
    pub content_hash: String,
    /// DID of the current owner (sender).
    pub from_did: String,
    /// DID of the new owner (recipient).
    pub to_did: String,
    /// Signature over the transfer payload (hex-encoded).
    pub signature: String,
    /// Public key of the sender (hex).
    pub public_key: String,
    /// Unix timestamp.
    pub transferred_at: u64,
    /// Signing algorithm used.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Electronic signature level.
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Biometric evidence commitments (required for Advanced/Qualified).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// Alias registry entry — maps a SHA3-256 commitment to a DID.
///
/// The commitment is `SHA3-256(salt || alias)` where the salt is deterministic:
/// `SHA3-256("cerulean:alias:salt:" || alias)[0..16]`. The node never sees the
/// plaintext alias — only the commitment and an encrypted blob for self-recovery.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AliasEntry {
    /// SHA3-256 commitment (64 hex chars).
    pub commitment: String,
    /// DID that owns this alias.
    pub did: String,
    /// Deterministic salt (32 hex chars = 16 bytes).
    pub salt: String,
    /// AES-256-GCM encrypted alias (opaque, hex-encoded). Only the wallet owner can decrypt.
    pub encrypted_alias: String,
    /// Unix timestamp of registration.
    pub registered_at: u64,
    /// "active" or "revoked".
    pub status: String,
    /// Unix timestamp when revoked (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    /// Electronic signature level.
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm used.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence commitments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// Status of an inference claim in the optimistic oracle.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClaimStatus {
    /// Waiting for dispute window to expire.
    #[default]
    Pending,
    /// Dispute window expired with no challenge — result accepted.
    Finalized,
    /// A challenge was submitted (Phase 2).
    Disputed,
    /// Oracle was slashed after a successful challenge (Phase 2).
    Slashed,
    /// Challenge was rejected (Phase 2).
    Rejected,
}

/// Tolerance mode for comparing inference outputs during dispute resolution.
///
/// Deterministic models use `Exact` (hash comparison). Non-deterministic models
/// (temperature > 0) use `Numeric` or `Cosine` to allow acceptable variation.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OutputTolerance {
    /// Outputs must have identical hashes.
    #[default]
    Exact,
    /// Numeric outputs must be within `threshold` of each other (absolute difference).
    Numeric { threshold: f64 },
    /// Vector outputs must have cosine similarity ≥ `min_similarity` (0.0–1.0).
    Cosine { min_similarity: f64 },
}

impl Eq for OutputTolerance {}

/// An inference claim submitted by an oracle in the Optimistic ML Oracle.
///
/// The oracle asserts that `model_hash` produced `output` given `input_hash`.
/// The claim is pending during the dispute window; if unchallenged, it finalizes.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct InferenceClaim {
    /// Unique claim ID (UUID).
    pub id: String,
    /// Oracle that submitted this claim (must be staked).
    pub oracle_id: String,
    /// SHA3-256 hash of model weights/ONNX file (64 hex chars).
    pub model_hash: String,
    /// Human-readable model version tag.
    pub model_version: String,
    /// SHA3-256 hash of the input data (64 hex chars).
    pub input_hash: String,
    /// Optional URI where challengers can fetch the input for re-execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_uri: Option<String>,
    /// The inference result (JSON-serialized).
    pub output: String,
    /// SHA3-256 of the output (for quick comparison).
    pub output_hash: String,
    /// Unix timestamp of submission.
    pub timestamp: u64,
    /// Ed25519 signature over `"inference:{id}:{model_hash}:{output_hash}"`.
    pub signature: String,
    /// Current status.
    #[serde(default)]
    pub status: ClaimStatus,
    /// Tolerance mode for output comparison during challenges.
    #[serde(default)]
    pub tolerance: OutputTolerance,
    /// Unix timestamp after which the claim can be finalized.
    pub dispute_deadline: u64,
    /// Unix timestamp when finalized (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<u64>,
    /// Electronic signature level.
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm used.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence commitments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// A challenge against a pending inference claim.
///
/// The challenger re-executes the model and submits a different output.
/// If the outputs differ, the oracle is slashed and the challenger is rewarded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InferenceChallenge {
    /// Unique challenge ID (UUID).
    pub id: String,
    /// ID of the claim being challenged.
    pub claim_id: String,
    /// Challenger's address (must be staked).
    pub challenger_id: String,
    /// Re-executed output (JSON-serialized).
    pub challenger_output: String,
    /// SHA3-256 of the challenger's output.
    pub challenger_output_hash: String,
    /// Bond locked by the challenger (anti-spam).
    pub bond: u64,
    /// Unix timestamp.
    pub timestamp: u64,
    /// Ed25519 signature over `"challenge:{claim_id}:{challenger_output_hash}"`.
    pub signature: String,
    /// Whether the challenge succeeded (oracle output differs from challenger output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<bool>,
    /// Electronic signature level.
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm used.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence commitments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// An invitation to participate in governance proposals.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Invitation {
    /// Unique invitation ID.
    pub id: String,
    /// DID of the inviter.
    pub from_did: String,
    /// Alias commitment of the invitee (resolved to DID on lookup).
    pub to_commitment: String,
    /// Proposal IDs included in this invitation (max 20).
    pub proposal_ids: Vec<u64>,
    /// Ed25519 signature from the inviter (hex).
    pub signature: String,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Whether the invitee has responded.
    pub responded: bool,
    /// true = accepted, false = rejected (meaningful only when responded = true).
    pub accepted: bool,
    /// Electronic signature level.
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm used.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence commitments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// BlockStore trait - main storage interface
pub trait BlockStore: Send + Sync {
    /// Write a block to storage
    fn write_block(&self, block: &Block) -> StorageResult<()>;

    /// Read a block by height
    fn read_block(&self, height: u64) -> StorageResult<Block>;

    /// Write a transaction
    fn write_transaction(&self, tx: &Transaction) -> StorageResult<()>;

    /// Read a transaction by ID
    fn read_transaction(&self, tx_id: &str) -> StorageResult<Transaction>;

    /// Write an identity record
    fn write_identity(&self, identity: &IdentityRecord) -> StorageResult<()>;

    /// Read an identity record by DID
    fn read_identity(&self, did: &str) -> StorageResult<IdentityRecord>;

    /// List all identity records
    fn list_identities(&self) -> StorageResult<Vec<IdentityRecord>>;

    fn write_civil_anchor(&self, anchor_hash: &str, did: &str) -> StorageResult<()>;

    fn resolve_by_civil_anchor(&self, anchor_hash: &str) -> StorageResult<String>;

    /// Write a credential
    fn write_credential(&self, credential: &Credential) -> StorageResult<()>;

    /// Read a credential by ID
    fn read_credential(&self, cred_id: &str) -> StorageResult<Credential>;

    /// List all credentials
    fn list_credentials(&self) -> StorageResult<Vec<Credential>>;

    /// Batch write operations (atomic)
    fn write_batch(&self, blocks: &[Block], txs: &[Transaction]) -> StorageResult<()>;

    /// Get latest block height
    fn get_latest_height(&self) -> StorageResult<u64>;

    /// Check if block exists
    fn block_exists(&self, height: u64) -> StorageResult<bool>;

    /// Return all transactions belonging to a given block height.
    ///
    /// Returns an empty `Vec` when no transactions are indexed for that height.
    fn transactions_by_block_height(&self, height: u64) -> StorageResult<Vec<Transaction>>;

    /// Return all credentials issued to a given subject DID.
    ///
    /// Returns an empty `Vec` when no credentials are indexed for that subject.
    fn credentials_by_subject_did(&self, subject_did: &str) -> StorageResult<Vec<Credential>>;

    /// Return all credentials issued by a given issuer DID.
    ///
    /// Default implementation scans all credentials (slow). Backends with
    /// secondary indexes should override.
    fn credentials_by_issuer_did(&self, _issuer_did: &str) -> StorageResult<Vec<Credential>> {
        Ok(vec![]) // Override in implementations with issuer index
    }

    /// Mark a transaction ID as seen (for replay prevention).
    /// Stores `tx_id → timestamp` so it survives node restarts.
    fn mark_tx_seen(&self, _tx_id: &str, _timestamp: u64) -> StorageResult<()> {
        Ok(()) // No-op default for stores that don't support persistence
    }

    /// Check if a transaction ID has been seen before.
    fn is_tx_seen(&self, _tx_id: &str) -> StorageResult<bool> {
        Ok(false) // Default: not seen (no persistence)
    }

    /// Load all seen transaction IDs. Returns `(tx_id, timestamp)` pairs.
    fn load_seen_txs(&self) -> StorageResult<Vec<(String, u64)>> {
        Ok(vec![]) // Default: empty
    }

    /// Remove seen transaction IDs older than `max_age_secs`.
    fn cleanup_seen_txs(&self, _max_age_secs: u64) -> StorageResult<u64> {
        Ok(0) // Default: no-op
    }

    // ── Governance persistence ─────────────────────────────────────────────

    /// Write a governance proposal to persistent storage.
    fn write_proposal(
        &self,
        _proposal: &crate::governance::proposals::Proposal,
    ) -> StorageResult<()> {
        Ok(())
    }

    /// Read a governance proposal by ID.
    fn read_proposal(&self, _id: u64) -> StorageResult<crate::governance::proposals::Proposal> {
        Err(super::errors::StorageError::KeyNotFound(
            "proposal not found".into(),
        ))
    }

    /// List all governance proposals.
    fn list_proposals(&self) -> StorageResult<Vec<crate::governance::proposals::Proposal>> {
        Ok(vec![])
    }

    /// Write a governance vote to persistent storage.
    fn write_vote(&self, _vote: &crate::governance::voting::Vote) -> StorageResult<()> {
        Ok(())
    }

    /// List all votes for a given proposal.
    fn list_votes(&self, _proposal_id: u64) -> StorageResult<Vec<crate::governance::voting::Vote>> {
        Ok(vec![])
    }

    // ── Vault (encrypted wallet backup) ────────────────────────────────────

    /// Store an encrypted wallet blob keyed by DID. Overwrites if exists.
    fn write_vault(&self, _did: &str, _encrypted_wallet: &serde_json::Value) -> StorageResult<()> {
        Ok(())
    }

    /// Read an encrypted wallet blob by DID.
    fn read_vault(&self, _did: &str) -> StorageResult<serde_json::Value> {
        Err(super::errors::StorageError::KeyNotFound(
            "vault entry not found".into(),
        ))
    }

    /// Store a vault recovery index: blind_index → DID.
    fn write_vault_recovery(&self, _blind_index: &str, _did: &str) -> StorageResult<()> {
        Ok(())
    }

    /// Look up a DID by vault recovery blind index.
    fn read_vault_by_recovery(&self, _blind_index: &str) -> StorageResult<String> {
        Err(super::errors::StorageError::KeyNotFound(
            "vault recovery entry not found".into(),
        ))
    }

    // ── Institutional governance (Cerulean Voto) ──────────────────────────

    fn write_scope(&self, _scope: &Scope) -> StorageResult<()> {
        Ok(())
    }
    fn read_scope(&self, _id: &str) -> StorageResult<Scope> {
        Err(super::errors::StorageError::KeyNotFound(
            "scope not found".into(),
        ))
    }
    fn list_scopes(&self) -> StorageResult<Vec<Scope>> {
        Ok(vec![])
    }
    fn delete_scope(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    fn write_assembly(&self, _assembly: &Assembly) -> StorageResult<()> {
        Ok(())
    }
    fn read_assembly(&self, _id: &str) -> StorageResult<Assembly> {
        Err(super::errors::StorageError::KeyNotFound(
            "assembly not found".into(),
        ))
    }
    fn list_assemblies(&self) -> StorageResult<Vec<Assembly>> {
        Ok(vec![])
    }
    fn list_assemblies_by_scope(&self, _scope_id: &str) -> StorageResult<Vec<Assembly>> {
        Ok(vec![])
    }
    fn delete_assembly(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    fn write_session(&self, _session: &Session) -> StorageResult<()> {
        Ok(())
    }
    fn read_session(&self, _id: &str) -> StorageResult<Session> {
        Err(super::errors::StorageError::KeyNotFound(
            "session not found".into(),
        ))
    }
    fn list_sessions_by_assembly(&self, _assembly_id: &str) -> StorageResult<Vec<Session>> {
        Ok(vec![])
    }
    fn delete_session(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    fn write_acta(&self, _acta: &Acta) -> StorageResult<()> {
        Ok(())
    }
    fn read_acta(&self, _id: &str) -> StorageResult<Acta> {
        Err(super::errors::StorageError::KeyNotFound(
            "acta not found".into(),
        ))
    }
    fn list_actas(&self) -> StorageResult<Vec<Acta>> {
        Ok(vec![])
    }
    fn delete_acta(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    // ── Asset Registry ────────────────────────────────────────────────────

    fn write_asset(&self, _asset: &crate::registry::types::Asset) -> StorageResult<()> {
        Ok(())
    }
    fn read_asset(&self, _id: &str) -> StorageResult<crate::registry::types::Asset> {
        Err(super::errors::StorageError::KeyNotFound(
            "asset not found".into(),
        ))
    }
    fn list_assets(&self) -> StorageResult<Vec<crate::registry::types::Asset>> {
        Ok(vec![])
    }
    fn delete_asset(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    fn write_asset_event(&self, _event: &crate::registry::types::AssetEvent) -> StorageResult<()> {
        Ok(())
    }
    fn read_asset_event(&self, _id: &str) -> StorageResult<crate::registry::types::AssetEvent> {
        Err(super::errors::StorageError::KeyNotFound(
            "asset event not found".into(),
        ))
    }
    fn list_asset_events(
        &self,
        _asset_id: &str,
    ) -> StorageResult<Vec<crate::registry::types::AssetEvent>> {
        Ok(vec![])
    }

    /// Bulk write asset events (for telemetry ingestion).
    fn write_asset_events_batch(
        &self,
        events: &[crate::registry::types::AssetEvent],
    ) -> StorageResult<()> {
        for event in events {
            self.write_asset_event(event)?;
        }
        Ok(())
    }

    // ── RWA Tokenization ──────────────────────────────────────────────────

    fn write_asset_token(
        &self,
        _token: &crate::registry::tokenization::AssetToken,
    ) -> StorageResult<()> {
        Ok(())
    }
    fn read_asset_token(
        &self,
        _id: &str,
    ) -> StorageResult<crate::registry::tokenization::AssetToken> {
        Err(super::errors::StorageError::KeyNotFound(
            "token not found".into(),
        ))
    }
    fn list_asset_tokens(&self) -> StorageResult<Vec<crate::registry::tokenization::AssetToken>> {
        Ok(vec![])
    }
    fn delete_asset_token(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    // ── Compliance Automation ────────────────────────────────────────────

    fn write_compliance_rule(
        &self,
        _rule: &crate::registry::compliance::ComplianceRule,
    ) -> StorageResult<()> {
        Ok(())
    }
    fn read_compliance_rule(
        &self,
        _id: &str,
    ) -> StorageResult<crate::registry::compliance::ComplianceRule> {
        Err(super::errors::StorageError::KeyNotFound(
            "rule not found".into(),
        ))
    }
    fn list_compliance_rules(
        &self,
    ) -> StorageResult<Vec<crate::registry::compliance::ComplianceRule>> {
        Ok(vec![])
    }
    fn delete_compliance_rule(&self, _id: &str) -> StorageResult<()> {
        Ok(())
    }

    fn write_compliance_result(
        &self,
        _result: &crate::registry::compliance::ComplianceResult,
    ) -> StorageResult<()> {
        Ok(())
    }
    fn list_compliance_results(
        &self,
        _asset_id: &str,
    ) -> StorageResult<Vec<crate::registry::compliance::ComplianceResult>> {
        Ok(vec![])
    }

    // ── Notarization (Proof of Existence) ──────────────────────────────

    /// Store a notarization entry keyed by ID.
    fn write_notarization(&self, _entry: &NotarizationEntry) -> StorageResult<()> {
        Ok(())
    }

    /// Read a notarization entry by ID.
    fn read_notarization(&self, _id: &str) -> StorageResult<NotarizationEntry> {
        Err(super::errors::StorageError::KeyNotFound(
            "notarization not found".into(),
        ))
    }

    /// Find a notarization by content hash (reverse lookup).
    fn read_notarization_by_hash(&self, _content_hash: &str) -> StorageResult<NotarizationEntry> {
        Err(super::errors::StorageError::KeyNotFound(
            "notarization not found for hash".into(),
        ))
    }

    /// List all notarizations, optionally filtered by signer DID.
    fn list_notarizations(&self, _signer: Option<&str>) -> StorageResult<Vec<NotarizationEntry>> {
        Ok(vec![])
    }

    // ── Ownership Transfer ──────────────────────────────────────────────

    /// Record an ownership transfer for a notarized document.
    fn write_ownership_transfer(&self, _transfer: &OwnershipTransfer) -> StorageResult<()> {
        Ok(())
    }

    /// Read the transfer chain for a notarized document (ordered by timestamp).
    fn read_ownership_transfers(
        &self,
        _content_hash: &str,
    ) -> StorageResult<Vec<OwnershipTransfer>> {
        Ok(vec![])
    }

    // ── Alias Registry ────────────────────────────────────────────────────

    /// Store an alias entry keyed by commitment.
    fn write_alias(&self, _entry: &AliasEntry) -> StorageResult<()> {
        Ok(())
    }

    /// Read an alias entry by commitment.
    fn read_alias(&self, _commitment: &str) -> StorageResult<AliasEntry> {
        Err(super::errors::StorageError::KeyNotFound(
            "alias not found".into(),
        ))
    }

    /// Find the active alias entry for a DID (reverse lookup).
    fn read_alias_by_did(&self, _did: &str) -> StorageResult<AliasEntry> {
        Err(super::errors::StorageError::KeyNotFound(
            "alias not found for DID".into(),
        ))
    }

    /// Delete an alias entry by commitment.
    fn delete_alias(&self, _commitment: &str) -> StorageResult<()> {
        Ok(())
    }

    // ── Invitations ─────────────────────────────────────────────────────

    /// Store an invitation.
    fn write_invitation(&self, _invitation: &Invitation) -> StorageResult<()> {
        Ok(())
    }

    /// Read an invitation by ID.
    fn read_invitation(&self, _id: &str) -> StorageResult<Invitation> {
        Err(super::errors::StorageError::KeyNotFound(
            "invitation not found".into(),
        ))
    }

    /// List invitations where the invitee commitment matches.
    fn list_invitations_by_commitment(
        &self,
        _to_commitment: &str,
    ) -> StorageResult<Vec<Invitation>> {
        Ok(vec![])
    }

    /// List invitations sent by a given DID.
    fn list_invitations_by_sender(&self, _from_did: &str) -> StorageResult<Vec<Invitation>> {
        Ok(vec![])
    }

    // ── Balance & transaction queries (migration helpers) ──────────────────

    /// Calculate the balance of an address by scanning all transactions.
    ///
    /// Default implementation iterates all blocks — O(n). Backends with
    /// balance indexes should override for O(1) lookups.
    fn calculate_balance(&self, address: &str) -> StorageResult<u64> {
        let latest = self.get_latest_height().unwrap_or(0);
        let mut balance: u64 = 0;
        for h in 0..=latest {
            let txs = self.transactions_by_block_height(h).unwrap_or_default();
            for tx in &txs {
                if tx.output_recipient == address {
                    balance = balance.saturating_add(tx.amount);
                }
                if tx.input_did == address {
                    balance = balance.saturating_sub(tx.amount);
                }
            }
        }
        Ok(balance)
    }

    /// Return all transactions where the given address is sender or recipient.
    ///
    /// Default implementation scans all blocks — O(n). Override for indexed lookups.
    fn transactions_for_address(&self, address: &str) -> StorageResult<Vec<Transaction>> {
        let latest = self.get_latest_height().unwrap_or(0);
        let mut result = Vec::new();
        for h in 0..=latest {
            let txs = self.transactions_by_block_height(h).unwrap_or_default();
            for tx in txs {
                if tx.input_did == address || tx.output_recipient == address {
                    result.push(tx);
                }
            }
        }
        Ok(result)
    }

    // ── Inference Claims (Optimistic ML Oracle) ──────────────────────────

    /// Store an inference claim keyed by ID.
    fn write_inference_claim(&self, _claim: &InferenceClaim) -> StorageResult<()> {
        Ok(())
    }

    /// Read an inference claim by ID.
    fn read_inference_claim(&self, _id: &str) -> StorageResult<InferenceClaim> {
        Err(super::errors::StorageError::KeyNotFound(
            "inference claim not found".into(),
        ))
    }

    /// List inference claims, optionally filtered by status, oracle, or model.
    fn list_inference_claims(
        &self,
        _status: Option<&ClaimStatus>,
        _oracle_id: Option<&str>,
        _model_hash: Option<&str>,
    ) -> StorageResult<Vec<InferenceClaim>> {
        Ok(vec![])
    }

    /// Store an inference challenge.
    fn write_inference_challenge(&self, _challenge: &InferenceChallenge) -> StorageResult<()> {
        Ok(())
    }

    /// List challenges for a given claim.
    fn list_challenges_by_claim(&self, _claim_id: &str) -> StorageResult<Vec<InferenceChallenge>> {
        Ok(vec![])
    }

    /// Return a page of blocks plus the total count for pagination.
    ///
    /// Default implementation iterates `[offset, offset+limit)` by height.
    fn list_blocks(&self, offset: usize, limit: usize) -> StorageResult<(Vec<Block>, usize)> {
        let latest = self.get_latest_height().unwrap_or(0) as usize;
        let total = if latest == 0 && self.read_block(0).is_err() {
            0
        } else {
            latest + 1
        };
        let mut blocks = Vec::new();
        let start = offset;
        let end = (offset + limit).min(total);
        for h in start..end {
            if let Ok(b) = self.read_block(h as u64) {
                blocks.push(b);
            }
        }
        Ok((blocks, total))
    }

    // ── LexChain contract persistence ─────────────────────────────────────

    fn write_lexcontract(
        &self,
        _contract: &crate::lexchain::types::LexContract,
    ) -> StorageResult<()> {
        Ok(())
    }

    fn read_lexcontract(&self, _id: &str) -> StorageResult<crate::lexchain::types::LexContract> {
        Err(super::errors::StorageError::KeyNotFound(
            "lexcontract".into(),
        ))
    }

    fn list_lexcontracts(&self) -> StorageResult<Vec<crate::lexchain::types::LexContract>> {
        Ok(vec![])
    }
}

/// Blanket impl so `Arc<T>` can be used wherever `Box<dyn BlockStore>` is expected.
///
/// All methods delegate to the inner `T`.  Because `MemoryStore` uses interior
/// mutability (`Mutex`), `&self` is sufficient for writes.
impl<T: BlockStore> BlockStore for Arc<T> {
    fn write_block(&self, block: &Block) -> StorageResult<()> {
        (**self).write_block(block)
    }
    fn read_block(&self, height: u64) -> StorageResult<Block> {
        (**self).read_block(height)
    }
    fn write_transaction(&self, tx: &Transaction) -> StorageResult<()> {
        (**self).write_transaction(tx)
    }
    fn read_transaction(&self, tx_id: &str) -> StorageResult<Transaction> {
        (**self).read_transaction(tx_id)
    }
    fn write_identity(&self, identity: &IdentityRecord) -> StorageResult<()> {
        (**self).write_identity(identity)
    }
    fn read_identity(&self, did: &str) -> StorageResult<IdentityRecord> {
        (**self).read_identity(did)
    }
    fn list_identities(&self) -> StorageResult<Vec<IdentityRecord>> {
        (**self).list_identities()
    }
    fn write_civil_anchor(&self, anchor_hash: &str, did: &str) -> StorageResult<()> {
        (**self).write_civil_anchor(anchor_hash, did)
    }
    fn resolve_by_civil_anchor(&self, anchor_hash: &str) -> StorageResult<String> {
        (**self).resolve_by_civil_anchor(anchor_hash)
    }
    fn write_credential(&self, credential: &Credential) -> StorageResult<()> {
        (**self).write_credential(credential)
    }
    fn read_credential(&self, cred_id: &str) -> StorageResult<Credential> {
        (**self).read_credential(cred_id)
    }
    fn list_credentials(&self) -> StorageResult<Vec<Credential>> {
        (**self).list_credentials()
    }
    fn write_batch(&self, blocks: &[Block], txs: &[Transaction]) -> StorageResult<()> {
        (**self).write_batch(blocks, txs)
    }
    fn get_latest_height(&self) -> StorageResult<u64> {
        (**self).get_latest_height()
    }
    fn block_exists(&self, height: u64) -> StorageResult<bool> {
        (**self).block_exists(height)
    }

    fn transactions_by_block_height(&self, height: u64) -> StorageResult<Vec<Transaction>> {
        (**self).transactions_by_block_height(height)
    }

    fn credentials_by_subject_did(&self, subject_did: &str) -> StorageResult<Vec<Credential>> {
        (**self).credentials_by_subject_did(subject_did)
    }

    fn list_blocks(&self, offset: usize, limit: usize) -> StorageResult<(Vec<Block>, usize)> {
        (**self).list_blocks(offset, limit)
    }
    fn write_proposal(
        &self,
        proposal: &crate::governance::proposals::Proposal,
    ) -> StorageResult<()> {
        (**self).write_proposal(proposal)
    }
    fn read_proposal(&self, id: u64) -> StorageResult<crate::governance::proposals::Proposal> {
        (**self).read_proposal(id)
    }
    fn list_proposals(&self) -> StorageResult<Vec<crate::governance::proposals::Proposal>> {
        (**self).list_proposals()
    }
    fn write_vote(&self, vote: &crate::governance::voting::Vote) -> StorageResult<()> {
        (**self).write_vote(vote)
    }
    fn list_votes(&self, proposal_id: u64) -> StorageResult<Vec<crate::governance::voting::Vote>> {
        (**self).list_votes(proposal_id)
    }
    fn mark_tx_seen(&self, tx_id: &str, timestamp: u64) -> StorageResult<()> {
        (**self).mark_tx_seen(tx_id, timestamp)
    }
    fn is_tx_seen(&self, tx_id: &str) -> StorageResult<bool> {
        (**self).is_tx_seen(tx_id)
    }
    fn load_seen_txs(&self) -> StorageResult<Vec<(String, u64)>> {
        (**self).load_seen_txs()
    }
    fn cleanup_seen_txs(&self, max_age_secs: u64) -> StorageResult<u64> {
        (**self).cleanup_seen_txs(max_age_secs)
    }
    fn write_inference_claim(&self, claim: &InferenceClaim) -> StorageResult<()> {
        (**self).write_inference_claim(claim)
    }
    fn read_inference_claim(&self, id: &str) -> StorageResult<InferenceClaim> {
        (**self).read_inference_claim(id)
    }
    fn list_inference_claims(
        &self,
        status: Option<&ClaimStatus>,
        oracle_id: Option<&str>,
        model_hash: Option<&str>,
    ) -> StorageResult<Vec<InferenceClaim>> {
        (**self).list_inference_claims(status, oracle_id, model_hash)
    }
    fn write_inference_challenge(&self, challenge: &InferenceChallenge) -> StorageResult<()> {
        (**self).write_inference_challenge(challenge)
    }
    fn list_challenges_by_claim(&self, claim_id: &str) -> StorageResult<Vec<InferenceChallenge>> {
        (**self).list_challenges_by_claim(claim_id)
    }
    fn write_notarization(&self, entry: &NotarizationEntry) -> StorageResult<()> {
        (**self).write_notarization(entry)
    }
    fn read_notarization(&self, id: &str) -> StorageResult<NotarizationEntry> {
        (**self).read_notarization(id)
    }
    fn read_notarization_by_hash(&self, content_hash: &str) -> StorageResult<NotarizationEntry> {
        (**self).read_notarization_by_hash(content_hash)
    }
    fn list_notarizations(&self, signer: Option<&str>) -> StorageResult<Vec<NotarizationEntry>> {
        (**self).list_notarizations(signer)
    }
    fn write_ownership_transfer(&self, transfer: &OwnershipTransfer) -> StorageResult<()> {
        (**self).write_ownership_transfer(transfer)
    }
    fn read_ownership_transfers(
        &self,
        content_hash: &str,
    ) -> StorageResult<Vec<OwnershipTransfer>> {
        (**self).read_ownership_transfers(content_hash)
    }
    fn write_lexcontract(
        &self,
        contract: &crate::lexchain::types::LexContract,
    ) -> StorageResult<()> {
        (**self).write_lexcontract(contract)
    }
    fn read_lexcontract(&self, id: &str) -> StorageResult<crate::lexchain::types::LexContract> {
        (**self).read_lexcontract(id)
    }
    fn list_lexcontracts(&self) -> StorageResult<Vec<crate::lexchain::types::LexContract>> {
        (**self).list_lexcontracts()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::storage::MemoryStore;

    use super::*;

    fn sample_block(height: u64) -> Block {
        Block {
            height,
            timestamp: 1_000,
            parent_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            transactions: vec![],
            proposer: "node-1".to_string(),
            signature: vec![2u8; 64],
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

    #[test]
    fn block_serde_roundtrip_without_endorsements() {
        let block = sample_block(1);
        let json = serde_json::to_string(&block).unwrap();
        let decoded: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.height, 1);
        assert!(decoded.endorsements.is_empty());
    }

    #[test]
    fn block_serde_roundtrip_with_endorsements() {
        use crate::endorsement::types::Endorsement;
        let e = Endorsement {
            signer_did: "did:goya:alice".to_string(),
            org_id: "org1".to_string(),
            signature: vec![1u8; 64],
            signature_algorithm: Default::default(),
            payload_hash: [2u8; 32],
            timestamp: 9999,
        };
        let block = Block {
            height: 5,
            timestamp: 1_000,
            parent_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            transactions: vec![],
            proposer: "node-1".to_string(),
            signature: vec![2u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![e.clone()],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        };
        let json = serde_json::to_string(&block).unwrap();
        let decoded: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.endorsements.len(), 1);
        assert_eq!(decoded.endorsements[0].org_id, "org1");
    }

    #[test]
    fn block_serde_with_orderer_signature() {
        let mut block = sample_block(10);
        block.orderer_signature = Some(vec![42u8; 64]);
        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("orderer_signature"));
        let decoded: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.orderer_signature, Some(vec![42u8; 64]));
    }

    #[test]
    fn block_serde_without_orderer_signature() {
        let block = sample_block(11);
        let json = serde_json::to_string(&block).unwrap();
        assert!(!json.contains("orderer_signature"));
        let decoded: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.orderer_signature, None);
    }

    #[test]
    fn block_without_endorsements_field_deserializes_to_empty_vec() {
        // Serialize a block, strip the endorsements field, then deserialize — simulates legacy JSON.
        let block = sample_block(3);
        let full_json = serde_json::to_string(&block).unwrap();
        // Remove `,"endorsements":[]` or `"endorsements":[],` from the JSON.
        let legacy_json = full_json
            .replace(",\"endorsements\":[]", "")
            .replace("\"endorsements\":[],", "");
        let decoded: Block = serde_json::from_str(&legacy_json).unwrap();
        assert!(decoded.endorsements.is_empty());
    }

    #[test]
    fn arc_store_write_and_read() {
        let store = Arc::new(MemoryStore::new());
        store.write_block(&sample_block(1)).unwrap();
        let block = store.read_block(1).unwrap();
        assert_eq!(block.height, 1);
    }

    #[test]
    fn shared_arc_sees_writes_from_all_clones() {
        let store = Arc::new(MemoryStore::new());
        let writer = Arc::clone(&store);
        let reader = Arc::clone(&store);

        writer.write_block(&sample_block(7)).unwrap();
        assert!(reader.block_exists(7).unwrap());
        assert_eq!(reader.get_latest_height().unwrap(), 7);
    }

    #[test]
    fn arc_store_passed_as_box_dyn() {
        let store: Arc<MemoryStore> = Arc::new(MemoryStore::new());
        let boxed: Box<dyn BlockStore> = Box::new(Arc::clone(&store));
        boxed.write_block(&sample_block(3)).unwrap();
        assert!(store.block_exists(3).unwrap());
    }

    #[test]
    fn tx_serde_roundtrip_without_payload() {
        let tx = Transaction {
            id: "tx-1".into(),
            block_height: 0,
            timestamp: 1000,
            input_did: "did:goya:a".into(),
            output_recipient: "did:goya:b".into(),
            amount: 100,
            state: "valid".into(),
            fee: 0,
            payload: None,
        };
        let json = serde_json::to_string(&tx).unwrap();
        assert!(!json.contains("payload"));
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        assert!(decoded.payload.is_none());
    }

    #[test]
    fn tx_serde_roundtrip_with_register_identity() {
        let record = IdentityRecord {
            did: "did:goya:abc123".into(),
            public_key: "deadbeef".into(),
            created_at: 1000,
            updated_at: 1000,
            status: "active".into(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: Some("cafebabe".into()),
        };
        let tx = Transaction {
            id: "tx-id-1".into(),
            block_height: 0,
            timestamp: 1000,
            input_did: "did:goya:a".into(),
            output_recipient: "did:goya:b".into(),
            amount: 0,
            state: "valid".into(),
            fee: 0,
            payload: Some(TxPayload::RegisterIdentity {
                record: record.clone(),
                civil_anchor: Some("cafebabe".into()),
            }),
        };
        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        match decoded.payload.unwrap() {
            TxPayload::RegisterIdentity {
                record: r,
                civil_anchor,
            } => {
                assert_eq!(r.did, record.did);
                assert_eq!(civil_anchor, Some("cafebabe".into()));
            }
            _ => panic!("wrong payload variant"),
        }
    }

    #[test]
    fn tx_serde_roundtrip_with_transfer() {
        let tx = Transaction {
            id: "tx-xfer".into(),
            block_height: 1,
            timestamp: 2000,
            input_did: "did:goya:sender".into(),
            output_recipient: "did:goya:recv".into(),
            amount: 500,
            state: "valid".into(),
            fee: 10,
            payload: Some(TxPayload::Transfer { amount: 500 }),
        };
        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.payload, Some(TxPayload::Transfer { amount: 500 }));
    }

    #[test]
    fn legacy_tx_json_deserializes_with_payload_none() {
        let legacy = r#"{"id":"old","block_height":0,"timestamp":0,"input_did":"a","output_recipient":"b","amount":0,"state":"valid"}"#;
        let decoded: Transaction = serde_json::from_str(legacy).unwrap();
        assert!(decoded.payload.is_none());
        assert_eq!(decoded.fee, 0);
    }
}
