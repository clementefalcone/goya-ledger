use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{
    channel_id_from_req, enforce_channel_membership, get_channel_store,
};
use crate::api::models::*;
use crate::app_state::AppState;
use crate::identity::keys::KeyManager;
use crate::identity::login_factors::{has_repeated_factor, login_message, DeviceFactor};
use crate::identity::operations::{self, IdentityOpError};
use crate::storage::traits::{BlockStore, Transaction, TxPayload};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use chrono::Utc;

pub(crate) fn identity_op_error(error: IdentityOpError) -> ApiError {
    match error {
        IdentityOpError::NotFound(resource) => ApiError::NotFound { resource },
        IdentityOpError::BadSignature(message) => ApiError::UnauthorizedWithMessage { message },
        IdentityOpError::Conflict(reason) => ApiError::Conflict { reason },
        IdentityOpError::Invalid(reason) => ApiError::ValidationError {
            field: "identity".to_string(),
            reason,
        },
    }
}

pub(crate) fn commit_identity_op(
    state: &AppState,
    store: &dyn BlockStore,
    channel: &str,
    author: &str,
    payload: TxPayload,
) -> Result<(), ApiError> {
    let tx = Transaction {
        id: format!("identity-{}", uuid::Uuid::new_v4()),
        block_height: 0,
        timestamp: now_secs(),
        input_did: author.to_string(),
        output_recipient: author.to_string(),
        amount: 0,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(payload),
    };
    if channel == "default" {
        let mut pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.add(tx.clone())
            .map_err(|reason| ApiError::ConsensusError {
                reason: format!("identity transaction {} not queued: {reason}", tx.id),
            })?;
    } else {
        store
            .write_transaction(&tx)
            .map_err(|e| ApiError::StorageError {
                reason: format!("identity transaction {} not recorded: {e}", tx.id),
            })?;
    }
    crate::transaction::apply_tx_payload(store, &tx).map_err(|e| ApiError::StorageError {
        reason: format!("identity transaction {} not applied: {e}", tx.id),
    })
}

/// POST /identity/create - Create a new DID, generate Ed25519 keypair, persist to store.
#[post("/identity/create")]
pub async fn create_identity(
    state: web::Data<AppState>,
    body: web::Json<CreateIdentityRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let algorithm = state
        .signing_provider
        .as_ref()
        .map(|p| p.algorithm())
        .unwrap_or_default();
    let key_mgr = KeyManager::with_algorithm(algorithm, now);
    let public_key_hex = hex::encode(key_mgr.public_key());
    let did = crate::identity::did::did_from_pubkey_hex(&public_key_hex);

    // Persist to store
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;
    let civil_anchor = match (&body.document_type, &body.document_number) {
        (Some(doc_type), Some(doc_number)) => Some(crate::identity::did::civil_anchor_hash(
            doc_type, doc_number,
        )),
        _ => None,
    };

    let record = crate::storage::traits::IdentityRecord {
        did: did.clone(),
        public_key: public_key_hex.clone(),
        created_at: now,
        updated_at: now,
        status: "active".to_string(),
        migrated_from: None,
        signature_algorithm: Some(format!("{:?}", algorithm)),
        civil_anchor: civil_anchor.clone(),
        recovery_commitment: None,
        vault_entries: Vec::new(),
    };

    operations::check_register(store.as_ref(), &record, civil_anchor.as_deref(), None)
        .map_err(identity_op_error)?;
    commit_identity_op(
        &state,
        store.as_ref(),
        _channel,
        &did,
        crate::storage::traits::TxPayload::RegisterIdentity {
            record,
            civil_anchor: civil_anchor.clone(),
            owner_signature: None,
        },
    )?;

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRegistered,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("did={did}")),
    );

    let response = IdentityResponse {
        did,
        public_key: public_key_hex,
        created_at: Utc::now(),
    };
    Ok(HttpResponse::Created().json(ApiResponse::success(response, trace_id)))
}

/// GET /identity/{did} - Fetch DID document from store.
#[get("/identity/{did}")]
async fn get_identity(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;

    let record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    let response = IdentityResponse {
        did: record.did,
        public_key: record.public_key,
        created_at: chrono::DateTime::from_timestamp(record.created_at as i64, 0)
            .unwrap_or_else(Utc::now),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
}

#[get("/identity/resolve/{doc_type}/{doc_number}")]
pub async fn resolve_by_document(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let (doc_type, doc_number) = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;

    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Identity",
        &req,
    )?;

    let anchor = crate::identity::did::civil_anchor_hash(&doc_type, &doc_number);
    let did = store
        .resolve_by_civil_anchor(&anchor)
        .map_err(|_| ApiError::NotFound {
            resource: format!("identity for {doc_type}:{doc_number}"),
        })?;

    let record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    let response = IdentityResponse {
        did: record.did,
        public_key: record.public_key,
        created_at: chrono::DateTime::from_timestamp(record.created_at as i64, 0)
            .unwrap_or_else(Utc::now),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
}

/// GET /identity/{did}/methods - List available auth methods for a DID.
#[get("/identity/{did}/methods")]
pub async fn get_identity_methods(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    let has_pin = state
        .pin_store
        .as_ref()
        .and_then(|ps| ps.get_hash(&did).ok())
        .flatten()
        .is_some();

    let has_vault = store.read_vault(&did).is_ok();

    let credentials: Vec<_> = store
        .credentials_by_subject_did(&did)
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "type": c.cred_type,
                "status": c.status,
            })
        })
        .collect();

    let mut methods = Vec::new();
    methods.push("signature");
    if has_pin {
        methods.push("pin");
    }
    if has_vault {
        methods.push("vault");
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "did": did,
            "methods": methods,
            "credentials": credentials,
            "has_vault": has_vault,
        }),
        trace_id,
    )))
}

/// POST /identity/{did}/revoke - Revoke a DID (mark as revoked, not deleted).
#[post("/identity/{did}/revoke")]
pub async fn revoke_identity(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<OwnerActionRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let change = operations::check_revoke(store.as_ref(), &did, &body.signature)
        .map_err(identity_op_error)?;
    if change == operations::Change::AlreadyApplied {
        return Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({ "did": did, "status": "already_revoked" }),
            trace_id,
        )));
    }

    let now = now_secs();
    commit_identity_op(
        &state,
        store.as_ref(),
        channel,
        &did,
        TxPayload::RevokeIdentity {
            did: did.clone(),
            revoked_at: now,
            owner_signature: body.signature.clone(),
        },
    )?;

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRevoked,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("did={did} revoked")),
    );

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "did": did, "status": "revoked", "revoked_at": now }),
        trace_id,
    )))
}

/// POST /identity/{did}/verify-signature - Verify Ed25519 signature.
#[post("/identity/{did}/verify-signature")]
async fn verify_signature(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VerifySignatureRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    // Verify DID exists
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;
    let _record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    // Verify signature using the declared algorithm
    let valid = crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        body.message.as_bytes(),
        &body.signature,
    );

    let response = VerifySignatureResponse {
        valid,
        key_index: 0,
        verified_at: Utc::now(),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
}

// ── Key rotation ────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct RotateKeyRequest {
    pub new_public_key: String,
    pub recovery_public_key: String,
    pub new_recovery_commitment: String,
    pub recovery_signature: String,
    pub new_key_signature: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct OwnerActionRequest {
    pub signature: String,
}

#[post("/identity/{did}/rotate")]
pub async fn rotate_key(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RotateKeyRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let request = operations::RotateRequest {
        did: &did,
        new_public_key: &body.new_public_key,
        recovery_public_key: &body.recovery_public_key,
        new_recovery_commitment: &body.new_recovery_commitment,
        recovery_signature: &body.recovery_signature,
        new_key_signature: &body.new_key_signature,
    };
    let change = operations::check_rotate(store.as_ref(), &request).map_err(identity_op_error)?;
    if change == operations::Change::AlreadyApplied {
        return Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({ "did": did, "status": "already_rotated" }),
            trace_id,
        )));
    }

    let now = now_secs();
    commit_identity_op(
        &state,
        store.as_ref(),
        channel,
        &did,
        TxPayload::RotateIdentity {
            did: did.clone(),
            new_public_key: body.new_public_key.clone(),
            recovery_public_key: body.recovery_public_key.clone(),
            new_recovery_commitment: body.new_recovery_commitment.clone(),
            rotated_at: now,
            recovery_signature: body.recovery_signature.clone(),
            new_key_signature: body.new_key_signature.clone(),
        },
    )?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "did": did,
            "public_key": body.new_public_key,
            "recovery_commitment": body.new_recovery_commitment,
            "rotated_at": now,
        }),
        trace_id,
    )))
}

// ── Store-backed identity endpoints ──────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct RegisterIdentityRequest {
    #[serde(flatten)]
    pub record: crate::storage::traits::IdentityRecord,
    pub signature: String,
}

/// POST /api/v1/store/identities — persiste un IdentityRecord en el store.
#[post("/store/identities")]
pub async fn store_write_identity(
    state: web::Data<AppState>,
    body: web::Json<RegisterIdentityRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let RegisterIdentityRequest { record, signature } = body.into_inner();
    super::validation::validate_store_identity(&record)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let change = operations::check_register(store.as_ref(), &record, None, Some(&signature))
        .map_err(identity_op_error)?;
    if change == operations::Change::AlreadyApplied {
        return Err(ApiError::Conflict {
            reason: format!("identity {} already registered", record.did),
        });
    }
    commit_identity_op(
        &state,
        store.as_ref(),
        _channel,
        &record.did,
        TxPayload::RegisterIdentity {
            record: record.clone(),
            civil_anchor: None,
            owner_signature: Some(signature),
        },
    )?;
    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRegistered,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("did={}", record.did)),
    );
    Ok(HttpResponse::Created().json(ApiResponse::success(record, trace_id)))
}

/// GET /api/v1/store/identities/{did} — lee un IdentityRecord del store.
#[get("/store/identities/{did}")]
pub async fn store_get_identity(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    match store.read_identity(&did) {
        Ok(identity) => Ok(HttpResponse::Ok().json(ApiResponse::success(identity, trace_id))),
        Err(_) => Err(ApiError::NotFound {
            resource: format!("identity {did}"),
        }),
    }
}

/// Pagination query params for list endpoints.
#[derive(serde::Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// GET /api/v1/store/identities?limit=100&offset=0 — list identity records with pagination.
#[get("/store/identities")]
pub async fn store_list_identities(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<PaginationQuery>,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let all = store
        .list_identities()
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);
    let page: Vec<_> = all.into_iter().skip(offset).take(limit).collect();
    Ok(HttpResponse::Ok().json(ApiResponse::success(page, trace_id)))
}

// ── DID Auth: challenge-response ────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static AUTH_CHALLENGES: std::sync::LazyLock<Mutex<HashMap<String, AuthChallenge>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

struct AuthChallenge {
    did: String,
    nonce: String,
    expires_at: u64,
}

#[derive(serde::Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

#[derive(serde::Serialize)]
struct ChallengeResponse {
    challenge: String,
    did: String,
    expires_in_secs: u64,
}

#[derive(serde::Deserialize)]
pub struct AuthenticateRequest {
    pub did: String,
    pub challenge: String,
    pub signature: String,
    #[serde(default)]
    pub device_factors: Vec<DeviceFactor>,
}

#[derive(serde::Serialize)]
struct AuthenticateResponse {
    authenticated: bool,
    did: String,
    algorithm: Option<String>,
    session_token: Option<String>,
    session_expires_at: Option<u64>,
}

const CHALLENGE_TTL_SECS: u64 = 300;

fn b64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

struct SessionClaims<'a> {
    did: &'a str,
    exp: u64,
    device_factors: &'a [DeviceFactor],
}

fn jose_algorithm(
    algorithm: crate::identity::signing::SigningAlgorithm,
) -> Result<&'static str, String> {
    match algorithm {
        crate::identity::signing::SigningAlgorithm::Ed25519 => Ok("EdDSA"),
        crate::identity::signing::SigningAlgorithm::MlDsa65 => Ok("ML-DSA-65"),
        other => Err(format!("session tokens cannot be signed with {other:?}")),
    }
}

fn mint_session_jwt(
    claims: &SessionClaims,
    signer: &dyn crate::identity::signing::SigningProvider,
) -> Result<String, String> {
    let now = now_secs();
    let header = serde_json::json!({"alg": jose_algorithm(signer.algorithm())?, "typ": "JWT"});
    let payload = serde_json::json!({
        "sub": claims.did,
        "iat": now,
        "exp": claims.exp,
        "iss": "goya-ledger",
        "type": "session",
        "verified_factors": ["key"],
        "device_factors": claims.device_factors,
    });
    let h = b64url_encode(&serde_json::to_vec(&header).unwrap_or_default());
    let p = b64url_encode(&serde_json::to_vec(&payload).unwrap_or_default());
    let signing_input = format!("{h}.{p}");
    let sig = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(format!("{signing_input}.{}", b64url_encode(&sig)))
}

fn session_signer(
    state: &AppState,
) -> Result<&dyn crate::identity::signing::SigningProvider, ApiError> {
    state
        .signing_provider
        .as_deref()
        .ok_or_else(|| ApiError::InternalError {
            reason: "this node has no session signing key".to_string(),
        })
}

#[get("/identity/auth/session-key")]
pub async fn session_key(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let signer = session_signer(&state)?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "issuer": "goya-ledger",
            "alg": jose_algorithm(signer.algorithm())
                .map_err(|reason| ApiError::InternalError { reason })?,
            "public_key": hex::encode(signer.public_key()),
        }),
        uuid::Uuid::new_v4().to_string(),
    )))
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[post("/identity/auth/challenge")]
pub async fn auth_challenge(
    state: web::Data<AppState>,
    body: web::Json<ChallengeRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    store
        .read_identity(&body.did)
        .map_err(|_| ApiError::NotFound {
            resource: format!("identity {}", body.did),
        })?;

    let nonce = uuid::Uuid::new_v4().to_string();
    let expires_at = now_secs() + CHALLENGE_TTL_SECS;

    AUTH_CHALLENGES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            nonce.clone(),
            AuthChallenge {
                did: body.did.clone(),
                nonce: nonce.clone(),
                expires_at,
            },
        );

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        ChallengeResponse {
            challenge: nonce,
            did: body.did.clone(),
            expires_in_secs: CHALLENGE_TTL_SECS,
        },
        trace_id,
    )))
}

#[post("/identity/auth/verify")]
pub async fn auth_verify(
    state: web::Data<AppState>,
    body: web::Json<AuthenticateRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    if has_repeated_factor(&body.device_factors) {
        return Err(ApiError::ValidationError {
            field: "device_factors".into(),
            reason: format!("repeated factor in {:?}", body.device_factors),
        });
    }
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let challenge = AUTH_CHALLENGES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&body.challenge);

    let challenge = match challenge {
        Some(c) if c.did == body.did && c.expires_at > now_secs() => c,
        _ => {
            return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "AUTH_FAILED".into(),
                    message: "invalid or expired challenge".into(),
                    field: None,
                },
                401,
            )));
        }
    };

    let identity = store
        .read_identity(&body.did)
        .map_err(|_| ApiError::NotFound {
            resource: format!("identity {}", body.did),
        })?;
    if identity.status != "active" {
        return Err(ApiError::Forbidden {
            reason: format!("identity {} is {}", body.did, identity.status),
        });
    }

    let algorithm = identity
        .signature_algorithm
        .as_deref()
        .and_then(|a| match a {
            "Ed25519" => Some(crate::identity::signing::SigningAlgorithm::Ed25519),
            "MlDsa65" => Some(crate::identity::signing::SigningAlgorithm::MlDsa65),
            _ => None,
        })
        .unwrap_or(crate::identity::signing::SigningAlgorithm::Ed25519);

    let valid = crate::signature::verify_signature(
        algorithm,
        &identity.public_key,
        login_message(&challenge.nonce, &body.device_factors).as_bytes(),
        &body.signature,
    );

    if !valid {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            ErrorDto {
                code: "AUTH_FAILED".into(),
                message: "signature verification failed".into(),
                field: None,
            },
            401,
        )));
    }

    let session_ttl = 3600u64;
    let session_exp = now_secs() + session_ttl;
    let session_token = mint_session_jwt(
        &SessionClaims {
            did: &body.did,
            exp: session_exp,
            device_factors: &body.device_factors,
        },
        session_signer(&state)?,
    )
    .map_err(|e| ApiError::InternalError {
        reason: format!("session token for {} not signed: {e}", body.did),
    })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        AuthenticateResponse {
            authenticated: true,
            did: body.did.clone(),
            algorithm: identity.signature_algorithm,
            session_token: Some(session_token),
            session_expires_at: Some(session_exp),
        },
        trace_id,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_identity_handlers_are_public() {
        let _ = (store_write_identity, store_get_identity);
    }

    fn identity_record(
        did: &str,
        public_key: &str,
        status: &str,
    ) -> crate::storage::traits::IdentityRecord {
        crate::storage::traits::IdentityRecord {
            did: did.to_string(),
            public_key: public_key.to_string(),
            created_at: 1,
            updated_at: 1,
            status: status.to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: Vec::new(),
        }
    }

    #[test]
    fn challenge_store_insert_and_remove() {
        let nonce = "test-nonce-123".to_string();
        AUTH_CHALLENGES.lock().unwrap().insert(
            nonce.clone(),
            AuthChallenge {
                did: "did:goya:abc123".into(),
                nonce: nonce.clone(),
                expires_at: now_secs() + 60,
            },
        );
        let removed = AUTH_CHALLENGES.lock().unwrap().remove(&nonce);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().did, "did:goya:abc123");
        assert!(AUTH_CHALLENGES.lock().unwrap().remove(&nonce).is_none());
    }

    #[test]
    fn expired_challenge_rejected() {
        let nonce = "expired-nonce".to_string();
        AUTH_CHALLENGES.lock().unwrap().insert(
            nonce.clone(),
            AuthChallenge {
                did: "did:goya:abc123".into(),
                nonce: nonce.clone(),
                expires_at: 0,
            },
        );
        let challenge = AUTH_CHALLENGES.lock().unwrap().remove(&nonce);
        let c = challenge.unwrap();
        assert!(c.expires_at <= now_secs());
    }

    #[test]
    fn session_jwt_has_correct_structure() {
        let provider = crate::identity::signing::SoftwareSigningProvider::generate();
        let token = mint_session_jwt(
            &SessionClaims {
                did: "did:goya:test1234",
                exp: now_secs() + 3600,
                device_factors: &[],
            },
            &provider,
        )
        .unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["sub"], "did:goya:test1234");
        assert_eq!(payload["iss"], "goya-ledger");
        assert_eq!(payload["type"], "session");
        assert!(payload["iat"].as_u64().unwrap() > 0);
        assert!(payload["exp"].as_u64().unwrap() > payload["iat"].as_u64().unwrap());

        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[2])
                .unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    struct RegisteredOwner {
        state: web::Data<AppState>,
        did: String,
        key: crate::identity::signing::SoftwareSigningProvider,
    }

    fn state_with_session_key() -> AppState {
        AppState {
            signing_provider: Some(std::sync::Arc::new(
                crate::identity::signing::MlDsaSigningProvider::generate(),
            )),
            ..AppState::test_default()
        }
    }

    fn registered_owner() -> RegisteredOwner {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let state = web::Data::new(state_with_session_key());
        let key = SoftwareSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        get_channel_store(&state, "default")
            .unwrap()
            .write_identity(&identity_record(&did, &public_key, "active"))
            .unwrap();
        RegisteredOwner { state, did, key }
    }

    fn sign_hex(key: &crate::identity::signing::SoftwareSigningProvider, message: &str) -> String {
        use crate::identity::signing::SigningProvider;
        hex::encode(key.sign(message.as_bytes()).unwrap())
    }

    async fn post_owner_action(
        owner: &RegisteredOwner,
        action: &str,
        body: serde_json::Value,
    ) -> actix_web::http::StatusCode {
        let app = actix_web::test::init_service(
            actix_web::App::new().app_data(owner.state.clone()).service(
                web::scope("/api/v1")
                    .service(revoke_identity)
                    .service(rotate_key),
            ),
        )
        .await;
        let req = actix_web::test::TestRequest::post()
            .uri(&format!("/api/v1/identity/{}/{action}", owner.did))
            .set_json(body)
            .to_request();
        actix_web::test::call_service(&app, req).await.status()
    }

    fn owner_status(owner: &RegisteredOwner) -> String {
        get_channel_store(&owner.state, "default")
            .unwrap()
            .read_identity(&owner.did)
            .unwrap()
            .status
    }

    async fn post_registration(
        state: &web::Data<AppState>,
        key: &crate::identity::signing::SoftwareSigningProvider,
        signer: &crate::identity::signing::SoftwareSigningProvider,
    ) -> (actix_web::http::StatusCode, String) {
        use crate::identity::signing::SigningProvider;
        let public_key = hex::encode(key.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        let app = actix_web::test::init_service(
            actix_web::App::new()
                .app_data(state.clone())
                .service(web::scope("/api/v1").service(store_write_identity)),
        )
        .await;
        let req = actix_web::test::TestRequest::post()
            .uri("/api/v1/store/identities")
            .set_json(serde_json::json!({
                "did": did,
                "public_key": public_key,
                "created_at": 1,
                "updated_at": 1,
                "status": "active",
                "signature": sign_hex(signer, &format!("identity:register:{did}")),
            }))
            .to_request();
        (actix_web::test::call_service(&app, req).await.status(), did)
    }

    #[actix_web::test]
    async fn register_rejects_signature_from_another_key() {
        let state = web::Data::new(AppState::test_default());
        let key = crate::identity::signing::SoftwareSigningProvider::generate();
        let attacker = crate::identity::signing::SoftwareSigningProvider::generate();
        let (status, did) = post_registration(&state, &key, &attacker).await;
        assert_eq!(status, 401);
        assert!(get_channel_store(&state, "default")
            .unwrap()
            .read_identity(&did)
            .is_err());
    }

    #[actix_web::test]
    async fn register_with_key_holder_signature_stores_identity() {
        let state = web::Data::new(AppState::test_default());
        let key = crate::identity::signing::SoftwareSigningProvider::generate();
        let (status, did) = post_registration(&state, &key, &key).await;
        assert_eq!(status, 201);
        assert!(get_channel_store(&state, "default")
            .unwrap()
            .read_identity(&did)
            .is_ok());
    }

    #[actix_web::test]
    async fn revoke_rejects_signature_from_another_key() {
        let owner = registered_owner();
        let attacker = crate::identity::signing::SoftwareSigningProvider::generate();
        let message = format!("identity:revoke:{}", owner.did);
        let body = serde_json::json!({ "signature": sign_hex(&attacker, &message) });
        assert_eq!(post_owner_action(&owner, "revoke", body).await, 401);
        assert_eq!(owner_status(&owner), "active");
    }

    #[actix_web::test]
    async fn revoke_with_owner_signature_revokes() {
        let owner = registered_owner();
        let message = format!("identity:revoke:{}", owner.did);
        let body = serde_json::json!({ "signature": sign_hex(&owner.key, &message) });
        assert_eq!(post_owner_action(&owner, "revoke", body).await, 200);
        assert_eq!(owner_status(&owner), "revoked");
    }

    fn owner_with_recovery() -> (
        RegisteredOwner,
        crate::identity::signing::MlDsaSigningProvider,
    ) {
        use crate::identity::signing::SigningProvider;
        let owner = registered_owner();
        let recovery = crate::identity::signing::MlDsaSigningProvider::generate();
        let store = get_channel_store(&owner.state, "default").unwrap();
        let record = store.read_identity(&owner.did).unwrap();
        store
            .write_identity(&crate::storage::traits::IdentityRecord {
                recovery_commitment: Some(crate::identity::did::did_from_pubkey_hex(&hex::encode(
                    recovery.public_key(),
                ))),
                ..record
            })
            .unwrap();
        (owner, recovery)
    }

    fn rotation_body(
        did: &str,
        recovery_signer: &dyn crate::identity::signing::SigningProvider,
        new_key: &crate::identity::signing::MlDsaSigningProvider,
    ) -> serde_json::Value {
        use crate::identity::signing::SigningProvider;
        let next = crate::identity::signing::MlDsaSigningProvider::generate();
        let new_public_key = hex::encode(new_key.public_key());
        let next_commitment =
            crate::identity::did::did_from_pubkey_hex(&hex::encode(next.public_key()));
        let message = operations::rotate_message(did, &new_public_key, &next_commitment);
        serde_json::json!({
            "new_public_key": new_public_key,
            "recovery_public_key": hex::encode(recovery_signer.public_key()),
            "new_recovery_commitment": next_commitment,
            "recovery_signature": hex::encode(recovery_signer.sign(message.as_bytes()).unwrap()),
            "new_key_signature": hex::encode(new_key.sign(message.as_bytes()).unwrap()),
        })
    }

    fn owner_public_key(owner: &RegisteredOwner) -> String {
        get_channel_store(&owner.state, "default")
            .unwrap()
            .read_identity(&owner.did)
            .unwrap()
            .public_key
    }

    #[actix_web::test]
    async fn rotate_rejects_classical_current_key_posing_as_recovery() {
        let (owner, _recovery) = owner_with_recovery();
        let thief_key = crate::identity::signing::MlDsaSigningProvider::generate();
        let before = owner_public_key(&owner);
        let body = rotation_body(&owner.did, &owner.key, &thief_key);
        assert_eq!(post_owner_action(&owner, "rotate", body).await, 400);
        assert_eq!(owner_public_key(&owner), before);
    }

    #[actix_web::test]
    async fn rotate_with_recovery_key_replaces_key_and_keeps_did() {
        use crate::identity::signing::SigningProvider;
        let (owner, recovery) = owner_with_recovery();
        let new_key = crate::identity::signing::MlDsaSigningProvider::generate();
        let body = rotation_body(&owner.did, &recovery, &new_key);
        assert_eq!(post_owner_action(&owner, "rotate", body).await, 200);
        assert_eq!(owner_public_key(&owner), hex::encode(new_key.public_key()));
        assert_eq!(owner_status(&owner), "active");
    }

    async fn did_login_status(owner: &RegisteredOwner) -> u16 {
        did_login(
            owner,
            |nonce| serde_json::json!({ "signature": sign_hex(&owner.key, nonce) }),
        )
        .await
        .0
    }

    async fn did_login(
        owner: &RegisteredOwner,
        proof: impl Fn(&str) -> serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let app = actix_web::test::init_service(
            actix_web::App::new().app_data(owner.state.clone()).service(
                web::scope("/api/v1")
                    .service(auth_challenge)
                    .service(auth_verify)
                    .service(session_key),
            ),
        )
        .await;
        let challenge_req = actix_web::test::TestRequest::post()
            .uri("/api/v1/identity/auth/challenge")
            .set_json(serde_json::json!({ "did": owner.did }))
            .to_request();
        let challenge: serde_json::Value =
            actix_web::test::call_and_read_body_json(&app, challenge_req).await;
        let nonce = challenge["data"]["challenge"].as_str().unwrap().to_string();
        let mut body = proof(&nonce);
        body["did"] = serde_json::json!(owner.did);
        body["challenge"] = serde_json::json!(nonce);
        let verify_req = actix_web::test::TestRequest::post()
            .uri("/api/v1/identity/auth/verify")
            .set_json(body)
            .to_request();
        let response = actix_web::test::call_service(&app, verify_req).await;
        let status = response.status().as_u16();
        let bytes = actix_web::test::read_body(response).await;
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn session_claims(response: &serde_json::Value) -> serde_json::Value {
        let token = response["data"]["session_token"].as_str().unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn published_session_key(state: &web::Data<AppState>) -> (u16, serde_json::Value) {
        let app = actix_web::test::init_service(
            actix_web::App::new()
                .app_data(state.clone())
                .service(web::scope("/api/v1").service(session_key)),
        )
        .await;
        let request = actix_web::test::TestRequest::get()
            .uri("/api/v1/identity/auth/session-key")
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        let status = response.status().as_u16();
        let bytes = actix_web::test::read_body(response).await;
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[actix_web::test]
    async fn session_token_verifies_against_the_published_key() {
        let owner = registered_owner();
        let (status, response) = did_login(
            &owner,
            |nonce| serde_json::json!({ "signature": sign_hex(&owner.key, nonce) }),
        )
        .await;
        assert_eq!(status, 200);
        let token = response["data"]["session_token"].as_str().unwrap();
        let (key_status, key) = published_session_key(&owner.state).await;
        assert_eq!(key_status, 200);
        assert_eq!(key["data"]["alg"], "ML-DSA-65");

        let parts: Vec<&str> = token.split('.').collect();
        let decode = |part: &str| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, part).unwrap()
        };
        let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        assert_eq!(header["alg"], "ML-DSA-65");
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let public_key = key["data"]["public_key"].as_str().unwrap();
        assert!(crate::signature::verify_signature(
            crate::identity::signing::SigningAlgorithm::MlDsa65,
            public_key,
            signing_input.as_bytes(),
            &hex::encode(decode(parts[2])),
        ));
        let forged_input = signing_input.replacen('.', "x.", 1);
        assert!(!crate::signature::verify_signature(
            crate::identity::signing::SigningAlgorithm::MlDsa65,
            public_key,
            forged_input.as_bytes(),
            &hex::encode(decode(parts[2])),
        ));
    }

    #[actix_web::test]
    async fn node_without_session_key_refuses_to_issue_tokens() {
        let owner = registered_owner();
        let keyless = RegisteredOwner {
            state: web::Data::new(AppState::test_default()),
            ..owner
        };
        get_channel_store(&keyless.state, "default")
            .unwrap()
            .write_identity(&identity_record(
                &keyless.did,
                &hex::encode(crate::identity::signing::SigningProvider::public_key(
                    &keyless.key,
                )),
                "active",
            ))
            .unwrap();
        let (status, response) = did_login(
            &keyless,
            |nonce| serde_json::json!({ "signature": sign_hex(&keyless.key, nonce) }),
        )
        .await;
        assert_eq!(status, 500, "{response}");
        assert!(response["data"]["session_token"].is_null());
        assert_eq!(published_session_key(&keyless.state).await.0, 500);
    }

    #[actix_web::test]
    async fn did_login_records_signed_device_factors() {
        let owner = registered_owner();
        let (status, response) = did_login(&owner, |nonce| {
            let message = format!("identity:login:{nonce}:pin,biometric");
            serde_json::json!({
                "signature": sign_hex(&owner.key, &message),
                "device_factors": ["pin", "biometric"],
            })
        })
        .await;
        assert_eq!(status, 200);
        let claims = session_claims(&response);
        assert_eq!(claims["verified_factors"], serde_json::json!(["key"]));
        assert_eq!(
            claims["device_factors"],
            serde_json::json!(["pin", "biometric"])
        );
    }

    #[actix_web::test]
    async fn did_login_without_factors_records_key_only() {
        let owner = registered_owner();
        let (status, response) = did_login(
            &owner,
            |nonce| serde_json::json!({ "signature": sign_hex(&owner.key, nonce) }),
        )
        .await;
        assert_eq!(status, 200);
        let claims = session_claims(&response);
        assert_eq!(claims["verified_factors"], serde_json::json!(["key"]));
        assert_eq!(claims["device_factors"], serde_json::json!([]));
    }

    #[actix_web::test]
    async fn did_login_rejects_factors_not_covered_by_signature() {
        let owner = registered_owner();
        let (status, _) = did_login(&owner, |nonce| {
            serde_json::json!({
                "signature": sign_hex(&owner.key, nonce),
                "device_factors": ["pin", "biometric"],
            })
        })
        .await;
        assert_eq!(status, 401);
    }

    #[actix_web::test]
    async fn did_login_rejects_repeated_factor() {
        let owner = registered_owner();
        let (status, response) = did_login(&owner, |nonce| {
            let message = format!("identity:login:{nonce}:pin,pin");
            serde_json::json!({
                "signature": sign_hex(&owner.key, &message),
                "device_factors": ["pin", "pin"],
            })
        })
        .await;
        assert_eq!(status, 400);
        assert_eq!(response["error"]["field"], "device_factors");
    }

    #[actix_web::test]
    async fn did_login_rejects_unknown_factor() {
        let owner = registered_owner();
        let (status, _) = did_login(&owner, |nonce| {
            serde_json::json!({
                "signature": sign_hex(&owner.key, nonce),
                "device_factors": ["retina"],
            })
        })
        .await;
        assert_eq!(status, 400);
    }

    #[actix_web::test]
    async fn did_login_succeeds_for_active_identity() {
        let owner = registered_owner();
        assert_eq!(did_login_status(&owner).await, 200);
    }

    #[actix_web::test]
    async fn did_login_rejects_revoked_identity() {
        let owner = registered_owner();
        let message = format!("identity:revoke:{}", owner.did);
        let body = serde_json::json!({ "signature": sign_hex(&owner.key, &message) });
        assert_eq!(post_owner_action(&owner, "revoke", body).await, 200);
        assert_eq!(did_login_status(&owner).await, 403);
    }
}
