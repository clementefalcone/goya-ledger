use chrono::Utc;
use rust_bc::api::errors::{ApiError, ApiResponse, ErrorDto};
use rust_bc::api::models::{
    BlockResponse, BlockchainHealthResponse, ConsensusStateResponse, CreateIdentityRequest,
    CredentialResponse, HealthResponse, IdentityResponse, ProofResponse, VersionResponse,
};

#[test]
fn test_api_error_creation() {
    let err = ApiError::NotFound {
        resource: "DID".to_string(),
    };
    assert_eq!(err.code(), "NOT_FOUND");
}

#[test]
fn test_api_error_status_codes() {
    let not_found = ApiError::NotFound {
        resource: "test".to_string(),
    };
    assert_eq!(not_found.status_code().as_u16(), 404);

    let validation_err = ApiError::ValidationError {
        field: "test".to_string(),
        reason: "invalid".to_string(),
    };
    assert_eq!(validation_err.status_code().as_u16(), 400);
}

#[test]
fn test_identity_response_serialization() {
    let resp = IdentityResponse {
        did: "did:bc:test123".to_string(),
        public_key: "test_public_key".to_string(),
        created_at: Utc::now(),
    };

    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("did:bc:test123"));

    let deserialized: IdentityResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.did, "did:bc:test123");
}

#[test]
fn test_block_response_serialization() {
    let resp = BlockResponse {
        hash: "hash_abc123".to_string(),
        parent_hash: "hash_parent".to_string(),
        timestamp: Utc::now(),
        proposer_did: "did:bc:proposer".to_string(),
        transaction_count: 5,
        slot_number: 10,
    };

    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: BlockResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.hash, "hash_abc123");
    assert_eq!(deserialized.transaction_count, 5);
}

#[test]
fn test_credential_response_serialization() {
    let resp = CredentialResponse {
        id: "cred_123".to_string(),
        issuer_did: "did:bc:issuer".to_string(),
        subject_did: "did:bc:subject".to_string(),
        claims: serde_json::json!({"name": "John Doe"}),
        issued_at: Utc::now(),
        expires_at: None,
        proof: ProofResponse {
            verification_method: "did:bc:issuer#key-0".to_string(),
            signature_value: "signature_value".to_string(),
            created: Utc::now(),
        },
    };

    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: CredentialResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, "cred_123");
}

#[test]
fn test_api_response_success_wrapper() {
    let data = "test_data".to_string();
    let trace_id = "trace_123".to_string();
    let resp: ApiResponse<String> = ApiResponse::success(data.clone(), trace_id.clone());

    assert_eq!(resp.status, "Success");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.data, Some(data));
    assert_eq!(resp.trace_id, trace_id);
}

#[test]
fn test_api_response_error_wrapper() {
    let error_dto = ErrorDto {
        code: "TEST_ERROR".to_string(),
        message: "Test error message".to_string(),
        field: Some("test_field".to_string()),
    };

    let resp: ApiResponse<()> = ApiResponse::error(error_dto, 400);
    assert_eq!(resp.status, "Failure");
    assert_eq!(resp.status_code, 400);
    assert!(resp.error.is_some());
}

#[test]
fn test_create_identity_request_validation() {
    let req = CreateIdentityRequest {
        metadata: Some(serde_json::json!({"org": "test_org"})),
        document_type: None,
        document_number: None,
    };

    let json = serde_json::to_string(&req).unwrap();
    let deserialized: CreateIdentityRequest = serde_json::from_str(&json).unwrap();
    assert!(deserialized.metadata.is_some());
}

#[test]
fn test_consensus_state_response() {
    let resp = ConsensusStateResponse {
        validators: vec!["validator1".to_string(), "validator2".to_string()],
        total_slots: 1000,
        canonical_head: "head_hash".to_string(),
        blockchain_height: 500,
        active_forks: 2,
    };

    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: ConsensusStateResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.validators.len(), 2);
    assert_eq!(deserialized.total_slots, 1000);
}

#[test]
fn test_health_response() {
    let resp = HealthResponse {
        status: "healthy".to_string(),
        uptime_seconds: 3600,
        blockchain: BlockchainHealthResponse {
            height: 1000,
            last_block_hash: "hash_last".to_string(),
            validators_count: 3,
        },
        checks: None,
    };

    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.status, "healthy");
    assert_eq!(deserialized.blockchain.height, 1000);
}

#[test]
fn test_version_response() {
    let resp = VersionResponse {
        api_version: "1.0.0".to_string(),
        rust_bc_version: "0.1.0".to_string(),
        blockchain_height: 250,
    };

    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: VersionResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.api_version, "1.0.0");
    assert_eq!(deserialized.blockchain_height, 250);
}

#[test]
fn test_error_field_extraction() {
    let err = ApiError::ValidationError {
        field: "phoneNumber".to_string(),
        reason: "invalid format".to_string(),
    };

    assert_eq!(err.field(), Some("phoneNumber".to_string()));
}
