//! Optimistic ML Oracle endpoints — verifiable inference claims.
//!
//! Phase 1: submit claims, finalize after dispute window, query.
//! Phase 2: challenge claims, resolve disputes (slash/reward).
//!
//! Endpoints:
//! - POST /inference/submit         — submit an inference claim (staked oracle)
//! - POST /inference/challenge      — challenge a pending claim (staked)
//! - POST /inference/finalize/{id}  — finalize a claim after dispute window
//! - GET  /inference/claims         — list claims (filter by status/oracle/model)
//! - GET  /inference/claims/{id}    — get claim details
//! - GET  /inference/models         — list known model hashes

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::app_state::AppState;
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{BiometricEvidence, SignatureLevel};
use crate::storage::traits::{ClaimStatus, InferenceChallenge, InferenceClaim, OutputTolerance};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::collections::HashMap;

/// Default dispute window: 24 hours.
const DEFAULT_DISPUTE_WINDOW_SECS: u64 = 86_400;
/// Default minimum stake to submit inference claims.
const DEFAULT_MIN_ORACLE_STAKE: u64 = 5_000;
/// Default bond required to challenge a claim.
const DEFAULT_CHALLENGE_BOND: u64 = 1_000;

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

/// Validate FES/FEA constraints. Returns Err(HttpResponse) on failure.
fn validate_fes_fea(
    level: SignatureLevel,
    algorithm: SigningAlgorithm,
    evidence: &[BiometricEvidence],
    public_key_hex: &str,
) -> Result<(), Box<HttpResponse>> {
    if !level.algorithm_satisfies(algorithm) {
        return Err(Box::new(HttpResponse::BadRequest().json(
            ApiResponse::<()>::error(
                err_dto(
                    "ALGORITHM_MISMATCH",
                    &format!("signature level {level} requires ML-DSA-65, got {algorithm}"),
                ),
                400,
            ),
        )));
    }
    if level.requires_biometric() && evidence.is_empty() {
        return Err(Box::new(HttpResponse::BadRequest().json(
            ApiResponse::<()>::error(
                err_dto(
                    "BIOMETRIC_REQUIRED",
                    &format!("signature level {level} requires biometric evidence"),
                ),
                400,
            ),
        )));
    }
    for e in evidence {
        if let Err(err) = e.validate() {
            return Err(Box::new(HttpResponse::BadRequest().json(
                ApiResponse::<()>::error(err_dto("INVALID_BIOMETRIC", &err.to_string()), 400),
            )));
        }
    }
    if let Err(msg) = crate::signature::validate_public_key(algorithm, public_key_hex) {
        return Err(Box::new(HttpResponse::BadRequest().json(
            ApiResponse::<()>::error(err_dto("INVALID_PUBLIC_KEY", &msg), 400),
        )));
    }
    Ok(())
}

/// Build signing payload with optional biometric hash suffix for FEA.
fn build_inference_payload(
    level: SignatureLevel,
    base_payload: &str,
    evidence: &[BiometricEvidence],
) -> String {
    match level {
        SignatureLevel::Simple => base_payload.to_string(),
        _ => {
            let bio_hash = crate::signature::compute_biometrics_hash(evidence);
            format!("{base_payload}:{bio_hash}")
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn dispute_window() -> u64 {
    std::env::var("INFERENCE_DISPUTE_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DISPUTE_WINDOW_SECS)
}

fn min_oracle_stake() -> u64 {
    std::env::var("INFERENCE_MIN_ORACLE_STAKE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MIN_ORACLE_STAKE)
}

fn challenge_bond() -> u64 {
    std::env::var("INFERENCE_CHALLENGE_BOND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CHALLENGE_BOND)
}

#[derive(Deserialize)]
pub struct SubmitInferenceRequest {
    /// Oracle ID (must be registered and staked).
    pub oracle_id: String,
    /// SHA3-256 hash of model weights (64 hex chars).
    pub model_hash: String,
    /// Human-readable model version.
    pub model_version: String,
    /// SHA3-256 hash of input data (64 hex chars).
    pub input_hash: String,
    /// Optional URI for challengers to fetch input.
    pub input_uri: Option<String>,
    /// Inference output (JSON-serialized).
    pub output: String,
    /// SHA3-256 of output (64 hex chars).
    pub output_hash: String,
    /// Signature over the signing payload (hex).
    pub signature: String,
    /// Public key (hex).
    pub public_key: String,
    /// Tolerance mode: "exact" (default), {"numeric": threshold}, {"cosine": min_similarity}.
    #[serde(default)]
    pub tolerance: OutputTolerance,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: crate::signature::SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: crate::identity::signing::SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<crate::signature::BiometricEvidence>,
}

/// POST /inference/submit-proven — claim with ZK proof (instant finalization).
#[derive(Deserialize)]
pub struct SubmitProvenRequest {
    /// Oracle ID (must be registered and staked).
    pub oracle_id: String,
    /// SHA3-256 hash of model weights (64 hex chars).
    pub model_hash: String,
    /// Human-readable model version.
    pub model_version: String,
    /// SHA3-256 hash of input data (64 hex chars).
    pub input_hash: String,
    /// Optional URI for re-execution.
    pub input_uri: Option<String>,
    /// Inference output (JSON-serialized).
    pub output: String,
    /// SHA3-256 of output (64 hex chars).
    pub output_hash: String,
    /// Signature over the signing payload (hex).
    pub signature: String,
    /// Public key (hex).
    pub public_key: String,
    /// The ZK proof attesting to the inference computation.
    pub proof: crate::inference::proof::ZkInferenceProof,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: crate::signature::SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: crate::identity::signing::SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<crate::signature::BiometricEvidence>,
}

#[derive(Deserialize)]
pub struct ChallengeInferenceRequest {
    /// Claim ID to challenge.
    pub claim_id: String,
    /// Challenger's address (must be staked).
    pub challenger_id: String,
    /// Re-executed output (JSON-serialized).
    pub challenger_output: String,
    /// SHA3-256 of the challenger's output (64 hex chars).
    pub challenger_output_hash: String,
    /// Signature over the challenge payload (hex).
    pub signature: String,
    /// Public key (hex).
    pub public_key: String,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: crate::signature::SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: crate::identity::signing::SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<crate::signature::BiometricEvidence>,
}

#[derive(Deserialize)]
pub struct ListClaimsQuery {
    pub status: Option<String>,
    pub oracle_id: Option<String>,
    pub model_hash: Option<String>,
}

fn parse_status(s: &str) -> Option<ClaimStatus> {
    match s.to_lowercase().as_str() {
        "pending" => Some(ClaimStatus::Pending),
        "finalized" => Some(ClaimStatus::Finalized),
        "disputed" => Some(ClaimStatus::Disputed),
        "slashed" => Some(ClaimStatus::Slashed),
        "rejected" => Some(ClaimStatus::Rejected),
        _ => None,
    }
}

/// Compare two inference outputs using the claim's tolerance mode.
///
/// Returns `true` if the outputs are considered equivalent (no fraud).
fn resolve_outputs(
    tolerance: &OutputTolerance,
    oracle_output: &str,
    oracle_hash: &str,
    challenger_output: &str,
    challenger_hash: &str,
) -> bool {
    match tolerance {
        OutputTolerance::Exact => oracle_hash == challenger_hash,
        OutputTolerance::Numeric { threshold } => {
            // Parse both outputs as f64, compare within threshold
            match (
                parse_numeric_output(oracle_output),
                parse_numeric_output(challenger_output),
            ) {
                (Some(a), Some(b)) => (a - b).abs() <= *threshold,
                // If either can't be parsed, fall back to exact hash comparison
                _ => oracle_hash == challenger_hash,
            }
        }
        OutputTolerance::Cosine { min_similarity } => {
            // Parse both outputs as f64 vectors, compute cosine similarity
            match (
                parse_vector_output(oracle_output),
                parse_vector_output(challenger_output),
            ) {
                (Some(a), Some(b)) if a.len() == b.len() && !a.is_empty() => {
                    cosine_similarity(&a, &b) >= *min_similarity
                }
                // If either can't be parsed or lengths differ, fall back to exact
                _ => oracle_hash == challenger_hash,
            }
        }
    }
}

/// Parse a JSON output as a single f64 number.
fn parse_numeric_output(output: &str) -> Option<f64> {
    // Try direct number parse
    if let Ok(v) = output.trim().parse::<f64>() {
        return Some(v);
    }
    // Try JSON with "result" field
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(n) = obj.get("result").and_then(|v| v.as_f64()) {
            return Some(n);
        }
        // Try root-level number
        if let Some(n) = obj.as_f64() {
            return Some(n);
        }
    }
    None
}

/// Parse a JSON output as a vector of f64.
fn parse_vector_output(output: &str) -> Option<Vec<f64>> {
    if let Ok(arr) = serde_json::from_str::<Vec<f64>>(output) {
        return Some(arr);
    }
    // Try JSON with "embedding" or "vector" field
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(output) {
        for key in &["embedding", "vector", "result"] {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                let nums: Option<Vec<f64>> = arr.iter().map(|v| v.as_f64()).collect();
                if let Some(v) = nums {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Cosine similarity between two vectors. Returns 0.0 for zero-magnitude vectors.
fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

/// POST /api/v1/inference/submit
#[post("/inference/submit")]
pub async fn submit_inference(
    state: web::Data<AppState>,
    body: web::Json<SubmitInferenceRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate hex fields
    for (name, val, len) in [
        ("model_hash", &body.model_hash, 64),
        ("input_hash", &body.input_hash, 64),
        ("output_hash", &body.output_hash, 64),
    ] {
        if val.len() != len || hex::decode(val).is_err() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "INVALID_HASH",
                    &format!("{name} must be {len} hex characters"),
                ),
                400,
            )));
        }
    }

    // Verify oracle is registered
    let oracle_registry = state
        .oracle_registry
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if oracle_registry.get_oracle(&body.oracle_id).is_none() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("ORACLE_NOT_REGISTERED", "oracle is not registered"),
            400,
        )));
    }
    drop(oracle_registry);

    // Verify oracle is staked above minimum
    if let Some(validator) = state.staking_manager.get_validator(&body.oracle_id) {
        if validator.staked_amount < min_oracle_stake() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "INSUFFICIENT_STAKE",
                    &format!(
                        "oracle must stake at least {} tokens (current: {})",
                        min_oracle_stake(),
                        validator.staked_amount
                    ),
                ),
                400,
            )));
        }
    } else {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "ORACLE_NOT_STAKED",
                "oracle must be staked to submit claims",
            ),
            400,
        )));
    }

    // Generate claim ID and verify signature.
    let claim_id = uuid::Uuid::new_v4().to_string();
    if let Err(resp) = validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(*resp);
    }
    let submit_msg = build_inference_payload(
        body.signature_level,
        &format!("inference:submit:{}:{}", body.model_hash, body.output_hash),
        &body.biometric_evidence,
    );
    if !crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        submit_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    let now = now_secs();
    let claim = InferenceClaim {
        id: claim_id,
        oracle_id: body.oracle_id.clone(),
        model_hash: body.model_hash.clone(),
        model_version: body.model_version.clone(),
        input_hash: body.input_hash.clone(),
        input_uri: body.input_uri.clone(),
        output: body.output.clone(),
        output_hash: body.output_hash.clone(),
        timestamp: now,
        signature: body.signature.clone(),
        status: ClaimStatus::Pending,
        tolerance: body.tolerance.clone(),
        dispute_deadline: now + dispute_window(),
        finalized_at: None,
        signature_level: body.signature_level,
        signature_algorithm: body.signature_algorithm,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_inference_claim(&claim)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({
            "id": claim.id,
            "status": "Pending",
            "dispute_deadline": claim.dispute_deadline,
        }),
        trace,
    )))
}

/// POST /api/v1/inference/submit-proven — claim with ZK proof, instant finalization.
#[post("/inference/submit-proven")]
pub async fn submit_proven(
    state: web::Data<AppState>,
    body: web::Json<SubmitProvenRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate hex fields
    for (name, val, len) in [
        ("model_hash", &body.model_hash, 64),
        ("input_hash", &body.input_hash, 64),
        ("output_hash", &body.output_hash, 64),
    ] {
        if val.len() != len || hex::decode(val).is_err() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "INVALID_HASH",
                    &format!("{name} must be {len} hex characters"),
                ),
                400,
            )));
        }
    }

    // Verify oracle is registered
    {
        let oracle_registry = state
            .oracle_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if oracle_registry.get_oracle(&body.oracle_id).is_none() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("ORACLE_NOT_REGISTERED", "oracle is not registered"),
                400,
            )));
        }
    }

    // Verify oracle is staked
    if let Some(validator) = state.staking_manager.get_validator(&body.oracle_id) {
        if validator.staked_amount < min_oracle_stake() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "INSUFFICIENT_STAKE",
                    &format!("oracle must stake at least {} tokens", min_oracle_stake()),
                ),
                400,
            )));
        }
    } else {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("ORACLE_NOT_STAKED", "oracle must be staked"),
            400,
        )));
    }

    // Verify signature (FES/FEA)
    if let Err(resp) = validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(*resp);
    }
    let submit_msg = build_inference_payload(
        body.signature_level,
        &format!("inference:submit:{}:{}", body.model_hash, body.output_hash),
        &body.biometric_evidence,
    );
    if !crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        submit_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    // Verify the ZK proof
    use crate::inference::proof::ProofPublicInputs;
    let inputs = ProofPublicInputs {
        model_hash: &body.model_hash,
        input_hash: &body.input_hash,
        output_hash: &body.output_hash,
    };

    match state.proof_verifier.verify(&body.proof, &inputs) {
        Ok(true) => { /* proof valid — proceed to instant finalization */ }
        Ok(false) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_PROOF", "proof verification failed"),
                400,
            )));
        }
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto("PROOF_ERROR", &e), 400)));
        }
    }

    // Create claim — immediately Finalized (no dispute window needed)
    let now = now_secs();
    let claim = InferenceClaim {
        id: uuid::Uuid::new_v4().to_string(),
        oracle_id: body.oracle_id.clone(),
        model_hash: body.model_hash.clone(),
        model_version: body.model_version.clone(),
        input_hash: body.input_hash.clone(),
        input_uri: body.input_uri.clone(),
        output: body.output.clone(),
        output_hash: body.output_hash.clone(),
        timestamp: now,
        signature: body.signature.clone(),
        status: ClaimStatus::Finalized,
        tolerance: OutputTolerance::Exact, // proven claims don't need tolerance
        dispute_deadline: now,             // no window
        finalized_at: Some(now),
        signature_level: body.signature_level,
        signature_algorithm: body.signature_algorithm,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_inference_claim(&claim)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    // Update oracle reputation
    {
        let mut registry = state
            .oracle_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(node) = registry.nodes.get_mut(&claim.oracle_id) {
            node.update_reputation(true);
        }
    }

    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({
            "id": claim.id,
            "status": "Finalized",
            "proof_type": format!("{:?}", body.proof.proof_type),
            "finalized_at": claim.finalized_at,
        }),
        trace,
    )))
}

/// POST /api/v1/inference/challenge
#[post("/inference/challenge")]
pub async fn challenge_inference(
    state: web::Data<AppState>,
    body: web::Json<ChallengeInferenceRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate output hash format
    if body.challenger_output_hash.len() != 64 || hex::decode(&body.challenger_output_hash).is_err()
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_HASH",
                "challenger_output_hash must be 64 hex characters",
            ),
            400,
        )));
    }

    // Read the claim being challenged
    let mut claim = match store.read_inference_claim(&body.claim_id) {
        Ok(c) => c,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", "inference claim not found"),
                404,
            )));
        }
    };

    // Only pending claims can be challenged
    if claim.status != ClaimStatus::Pending {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto(
                "NOT_PENDING",
                &format!("claim is {:?}, not Pending", claim.status),
            ),
            409,
        )));
    }

    // Must be within dispute window
    let now = now_secs();
    if now >= claim.dispute_deadline {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("DISPUTE_WINDOW_CLOSED", "dispute window has expired"),
            400,
        )));
    }

    // Cannot self-challenge
    if body.challenger_id == claim.oracle_id {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("SELF_CHALLENGE", "cannot challenge your own claim"),
            400,
        )));
    }

    // Verify challenger is staked
    let bond = challenge_bond();
    if let Some(validator) = state.staking_manager.get_validator(&body.challenger_id) {
        if validator.staked_amount < bond {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(
                    "INSUFFICIENT_STAKE",
                    &format!(
                        "challenger must stake at least {} tokens (current: {})",
                        bond, validator.staked_amount
                    ),
                ),
                400,
            )));
        }
    } else {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "CHALLENGER_NOT_STAKED",
                "challenger must be staked to submit challenges",
            ),
            400,
        )));
    }

    // Verify signature (FES/FEA)
    if let Err(resp) = validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(*resp);
    }
    let challenge_msg = build_inference_payload(
        body.signature_level,
        &format!(
            "challenge:{}:{}",
            body.claim_id, body.challenger_output_hash
        ),
        &body.biometric_evidence,
    );
    if !crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        challenge_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    // Create the challenge
    let challenge_id = uuid::Uuid::new_v4().to_string();

    // Resolution: compare outputs using claim's tolerance mode
    let outputs_match = resolve_outputs(
        &claim.tolerance,
        &claim.output,
        &claim.output_hash,
        &body.challenger_output,
        &body.challenger_output_hash,
    );
    let challenge_succeeded = !outputs_match;

    let challenge = InferenceChallenge {
        id: challenge_id.clone(),
        claim_id: body.claim_id.clone(),
        challenger_id: body.challenger_id.clone(),
        challenger_output: body.challenger_output.clone(),
        challenger_output_hash: body.challenger_output_hash.clone(),
        bond,
        timestamp: now,
        signature: body.signature.clone(),
        succeeded: Some(challenge_succeeded),
        signature_level: body.signature_level,
        signature_algorithm: body.signature_algorithm,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_inference_challenge(&challenge)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    // Update claim status based on resolution
    if challenge_succeeded {
        // Oracle was wrong — slash oracle, reward challenger
        claim.status = ClaimStatus::Slashed;

        // Slash oracle reputation
        {
            let mut registry = state
                .oracle_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(node) = registry.nodes.get_mut(&claim.oracle_id) {
                node.update_reputation(false);
                node.update_reputation(false); // Double penalty for fraud
            }
        }

        crate::audit::emit_if_present(
            &state.audit_store,
            crate::audit::AuditAction::TokenStaked, // closest available action
            &claim.oracle_id,
            Some(format!(
                "inference_slashed: claim={}, challenger={}",
                body.claim_id, body.challenger_id
            )),
        );
    } else {
        // Challenge failed — oracle was correct
        claim.status = ClaimStatus::Rejected;

        // Reward oracle reputation
        {
            let mut registry = state
                .oracle_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(node) = registry.nodes.get_mut(&claim.oracle_id) {
                node.update_reputation(true);
            }
        }
    }

    store
        .write_inference_claim(&claim)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "challenge_id": challenge_id,
            "claim_id": body.claim_id,
            "succeeded": challenge_succeeded,
            "claim_status": format!("{:?}", claim.status),
            "oracle_id": claim.oracle_id,
            "challenger_id": body.challenger_id,
        }),
        trace,
    )))
}

/// POST /api/v1/inference/finalize/{id}
#[post("/inference/finalize/{id}")]
pub async fn finalize_inference(
    state: web::Data<AppState>,
    id: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let mut claim = match store.read_inference_claim(&id) {
        Ok(c) => c,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", "inference claim not found"),
                404,
            )));
        }
    };

    if claim.status != ClaimStatus::Pending {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto(
                "NOT_PENDING",
                &format!("claim is {:?}, not Pending", claim.status),
            ),
            409,
        )));
    }

    let now = now_secs();
    if now < claim.dispute_deadline {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "DISPUTE_WINDOW_OPEN",
                &format!(
                    "dispute window ends in {} seconds",
                    claim.dispute_deadline - now
                ),
            ),
            400,
        )));
    }

    claim.status = ClaimStatus::Finalized;
    claim.finalized_at = Some(now);

    store
        .write_inference_claim(&claim)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    // Update oracle reputation
    {
        let mut registry = state
            .oracle_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(node) = registry.nodes.get_mut(&claim.oracle_id) {
            node.update_reputation(true);
        }
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "id": claim.id,
            "status": "Finalized",
            "finalized_at": claim.finalized_at,
        }),
        trace,
    )))
}

/// GET /api/v1/inference/claims
#[get("/inference/claims")]
pub async fn list_claims(
    state: web::Data<AppState>,
    query: web::Query<ListClaimsQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let status = query.status.as_deref().and_then(parse_status);
    let claims = store
        .list_inference_claims(
            status.as_ref(),
            query.oracle_id.as_deref(),
            query.model_hash.as_deref(),
        )
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(claims, trace)))
}

/// GET /api/v1/inference/claims/{id}
#[get("/inference/claims/{id}")]
pub async fn get_claim(
    state: web::Data<AppState>,
    id: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    match store.read_inference_claim(&id) {
        Ok(claim) => Ok(HttpResponse::Ok().json(ApiResponse::success(claim, trace))),
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "inference claim not found"),
            404,
        ))),
    }
}

/// GET /api/v1/inference/models
#[get("/inference/models")]
pub async fn list_models(state: web::Data<AppState>, req: HttpRequest) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let claims =
        store
            .list_inference_claims(None, None, None)
            .map_err(|e| ApiError::StorageError {
                reason: e.to_string(),
            })?;

    // Aggregate by model_hash
    let mut models: HashMap<String, ModelSummary> = HashMap::new();
    for claim in &claims {
        let entry = models
            .entry(claim.model_hash.clone())
            .or_insert_with(|| ModelSummary {
                model_hash: claim.model_hash.clone(),
                model_version: claim.model_version.clone(),
                total_claims: 0,
                finalized: 0,
                pending: 0,
            });
        entry.total_claims += 1;
        match claim.status {
            ClaimStatus::Finalized => entry.finalized += 1,
            ClaimStatus::Pending => entry.pending += 1,
            _ => {}
        }
    }

    let summaries: Vec<ModelSummary> = models.into_values().collect();
    Ok(HttpResponse::Ok().json(ApiResponse::success(summaries, trace)))
}

#[derive(serde::Serialize)]
struct ModelSummary {
    model_hash: String,
    model_version: String,
    total_claims: u64,
    finalized: u64,
    pending: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_returns_reasonable_value() {
        assert!(now_secs() > 1_700_000_000);
    }

    #[test]
    fn parse_status_variants() {
        assert_eq!(parse_status("pending"), Some(ClaimStatus::Pending));
        assert_eq!(parse_status("Finalized"), Some(ClaimStatus::Finalized));
        assert_eq!(parse_status("DISPUTED"), Some(ClaimStatus::Disputed));
        assert_eq!(parse_status("slashed"), Some(ClaimStatus::Slashed));
        assert_eq!(parse_status("rejected"), Some(ClaimStatus::Rejected));
        assert_eq!(parse_status("unknown"), None);
    }

    // ── parse_numeric_output ────────────────────────────────────────

    #[test]
    fn parse_numeric_direct() {
        assert_eq!(parse_numeric_output("42.5"), Some(42.5));
    }

    #[test]
    fn parse_numeric_json_result_field() {
        assert_eq!(parse_numeric_output(r#"{"result": 7.25}"#), Some(7.25));
    }

    #[test]
    fn parse_numeric_json_root() {
        assert_eq!(parse_numeric_output("99"), Some(99.0));
    }

    #[test]
    fn parse_numeric_unparseable() {
        assert_eq!(parse_numeric_output("not a number"), None);
    }

    // ── parse_vector_output ─────────────────────────────────────────

    #[test]
    fn parse_vector_direct_array() {
        assert_eq!(
            parse_vector_output("[1.0, 2.0, 3.0]"),
            Some(vec![1.0, 2.0, 3.0])
        );
    }

    #[test]
    fn parse_vector_embedding_field() {
        let json = r#"{"embedding": [0.1, 0.2]}"#;
        assert_eq!(parse_vector_output(json), Some(vec![0.1, 0.2]));
    }

    #[test]
    fn parse_vector_vector_field() {
        let json = r#"{"vector": [4.0, 5.0]}"#;
        assert_eq!(parse_vector_output(json), Some(vec![4.0, 5.0]));
    }

    #[test]
    fn parse_vector_unparseable() {
        assert_eq!(parse_vector_output("not a vector"), None);
    }

    // ── cosine_similarity ───────────────────────────────────────────

    #[test]
    fn cosine_identical_vectors() {
        let v = vec![1.0, 2.0, 3.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-10);
    }

    #[test]
    fn cosine_zero_magnitude_returns_zero() {
        let zero = vec![0.0, 0.0];
        let v = vec![1.0, 2.0];
        assert_eq!(cosine_similarity(&zero, &v), 0.0);
    }

    // ── resolve_outputs ─────────────────────────────────────────────

    #[test]
    fn resolve_exact_match() {
        assert!(resolve_outputs(
            &OutputTolerance::Exact,
            "out",
            "aabb",
            "out2",
            "aabb"
        ));
    }

    #[test]
    fn resolve_exact_mismatch() {
        assert!(!resolve_outputs(
            &OutputTolerance::Exact,
            "out",
            "aabb",
            "out2",
            "ccdd"
        ));
    }

    #[test]
    fn resolve_numeric_within_threshold() {
        assert!(resolve_outputs(
            &OutputTolerance::Numeric { threshold: 0.5 },
            "10.0",
            "h1",
            "10.3",
            "h2"
        ));
    }

    #[test]
    fn resolve_numeric_outside_threshold() {
        assert!(!resolve_outputs(
            &OutputTolerance::Numeric { threshold: 0.1 },
            "10.0",
            "h1",
            "11.0",
            "h2"
        ));
    }

    #[test]
    fn resolve_numeric_unparseable_falls_back_to_exact() {
        assert!(resolve_outputs(
            &OutputTolerance::Numeric { threshold: 1.0 },
            "text",
            "same",
            "text2",
            "same"
        ));
        assert!(!resolve_outputs(
            &OutputTolerance::Numeric { threshold: 1.0 },
            "text",
            "aaa",
            "text2",
            "bbb"
        ));
    }

    #[test]
    fn resolve_cosine_above_threshold() {
        assert!(resolve_outputs(
            &OutputTolerance::Cosine {
                min_similarity: 0.99
            },
            "[1.0, 2.0, 3.0]",
            "h1",
            "[1.0, 2.0, 3.0]",
            "h2"
        ));
    }

    #[test]
    fn resolve_cosine_below_threshold() {
        assert!(!resolve_outputs(
            &OutputTolerance::Cosine {
                min_similarity: 0.99
            },
            "[1.0, 0.0]",
            "h1",
            "[0.0, 1.0]",
            "h2"
        ));
    }

    #[test]
    fn resolve_cosine_different_lengths_falls_back() {
        assert!(resolve_outputs(
            &OutputTolerance::Cosine {
                min_similarity: 0.5
            },
            "[1.0, 2.0]",
            "same",
            "[1.0]",
            "same"
        ));
        assert!(!resolve_outputs(
            &OutputTolerance::Cosine {
                min_similarity: 0.5
            },
            "[1.0, 2.0]",
            "aaa",
            "[1.0]",
            "bbb"
        ));
    }

    // ── build_inference_payload ──────────────────────────────────────

    #[test]
    fn payload_simple_no_bio_hash() {
        let p = build_inference_payload(SignatureLevel::Simple, "base", &[]);
        assert_eq!(p, "base");
    }

    #[test]
    fn payload_advanced_appends_bio_hash() {
        let bio = vec![crate::signature::BiometricEvidence {
            evidence_type: crate::signature::BiometricType::Fingerprint,
            commitment: "a".repeat(64),
            captured_at: 1700000000,
            capture_device: None,
        }];
        let p = build_inference_payload(SignatureLevel::Advanced, "base", &bio);
        assert!(p.starts_with("base:"));
        assert_eq!(p.len(), "base:".len() + 64);
    }
}
