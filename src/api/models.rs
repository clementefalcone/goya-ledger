use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Request body for creating a transaction (shared with legacy handlers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTransactionRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default)]
    pub fee: Option<u64>,
    pub data: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

/// Request body for `POST /api/v1/blocks`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBlockRequest {
    pub transactions: Vec<CreateTransactionRequest>,
}

/// Identity creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityRequest {
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub document_type: Option<String>,
    #[serde(default)]
    pub document_number: Option<String>,
}

/// Identity response with public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub did: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

/// Signature verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySignatureRequest {
    pub message: String,
    pub signature: String, // hex encoded
    /// Public key (hex encoded).
    #[serde(default)]
    pub public_key: String,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: crate::identity::signing::SigningAlgorithm,
}

/// Signature verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySignatureResponse {
    pub valid: bool,
    pub key_index: usize,
    pub verified_at: DateTime<Utc>,
}

/// Block proposal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposBlockRequest {
    pub parent_hash: String,
    pub timestamp: DateTime<Utc>,
    pub transactions: Vec<serde_json::Value>,
    pub proposer_did: String,
    pub signature: String,
}

/// Block proposal response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeBlockResponse {
    pub block_hash: String,
    pub accepted: bool,
    pub reason: String,
}

/// Block detail response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: DateTime<Utc>,
    pub proposer_did: String,
    pub transaction_count: usize,
    pub slot_number: u64,
}

/// Consensus state response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStateResponse {
    pub validators: Vec<String>,
    pub total_slots: u64,
    pub canonical_head: String,
    pub blockchain_height: u64,
    pub active_forks: usize,
}

/// Chain verification summary (GET /chain/verify)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerifyResponse {
    pub valid: bool,
    pub block_count: usize,
    /// Height of the first block that failed validation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_invalid_height: Option<u64>,
}

/// Chain metadata (GET /chain/info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfoResponse {
    pub block_count: usize,
    pub latest_block_hash: String,
    pub is_valid: bool,
}

/// Credential issuance request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCredentialRequest {
    pub issuer_did: String,
    pub subject_did: String,
    pub claims: serde_json::Value,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Credential issuance response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCredentialResponse {
    pub credential_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub issued_at: DateTime<Utc>,
    pub proof: ProofResponse,
}

/// Proof response (Ed25519 signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    pub verification_method: String,
    pub signature_value: String,
    pub created: DateTime<Utc>,
}

/// Credential response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub claims: serde_json::Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub proof: ProofResponse,
}

/// Credential verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCredentialRequest {
    // Empty - credential ID is in path
}

/// Credential verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCredentialResponse {
    pub valid: bool,
    pub issuer_did: String,
    pub subject_did: String,
    pub verified_at: DateTime<Utc>,
}

/// Credential revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeCredentialRequest {
    pub reason: String,
}

/// Credential revocation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeCredentialResponse {
    pub credential_id: String,
    pub revoked: bool,
    pub revoked_at: DateTime<Utc>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub blockchain: BlockchainHealthResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<HealthChecks>,
}

/// Dependency health checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthChecks {
    pub storage: String,
    pub peers: String,
    pub ordering: String,
}

/// Blockchain health response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainHealthResponse {
    pub height: u64,
    pub last_block_hash: String,
    pub validators_count: usize,
}

/// Version response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub api_version: String,
    pub rust_bc_version: String,
    pub blockchain_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_identity_request_serialization() {
        let req = CreateIdentityRequest {
            metadata: Some(serde_json::json!({"key": "value"})),
            document_type: None,
            document_number: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: CreateIdentityRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.metadata.is_some());
    }

    #[test]
    fn test_identity_response_serialization() {
        let resp = IdentityResponse {
            did: "did:goya:test".to_string(),
            public_key: "test_key".to_string(),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("did:goya:test"));
    }
}
