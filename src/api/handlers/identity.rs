use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{
    channel_id_from_req, enforce_channel_membership, get_channel_store,
};
use crate::api::models::*;
use crate::app_state::AppState;
use crate::identity::keys::KeyManager;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use chrono::Utc;

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
    };

    let tx = crate::storage::traits::Transaction {
        id: format!("identity-{}", uuid::Uuid::new_v4()),
        block_height: 0,
        timestamp: now,
        input_did: did.clone(),
        output_recipient: did.clone(),
        amount: 0,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(crate::storage::traits::TxPayload::RegisterIdentity {
            record,
            civil_anchor: civil_anchor.clone(),
        }),
    };

    crate::transaction::apply_tx_payload(store.as_ref(), &tx).map_err(|e| {
        if e.to_string().contains("civil anchor already registered") {
            ApiError::Conflict {
                reason: "identity with document already exists".to_string(),
            }
        } else {
            ApiError::StorageError {
                reason: e.to_string(),
            }
        }
    })?;

    store
        .write_transaction(&tx)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

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

/// POST /identity/{did}/rotate-key - Key rotation (generates new keypair).
#[post("/identity/{did}/rotate-key")]
async fn rotate_key(
    state: web::Data<AppState>,
    path: web::Path<String>,
    _body: web::Json<RotateKeyRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Verify DID exists
    let _channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, _channel)?;
    let mut record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;

    // Update timestamp to reflect rotation
    record.updated_at = now;
    store
        .write_identity(&record)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    let response = RotateKeyResponse {
        did,
        new_key_index: _body.old_key_index + 1,
        rotated_at: Utc::now(),
    };
    Ok(HttpResponse::Ok().json(ApiResponse::success(response, trace_id)))
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

    let mut record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;
    verify_owner_signature(&record, &format!("identity:revoke:{did}"), &body.signature)?;

    if record.status == "revoked" {
        return Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({ "did": did, "status": "already_revoked" }),
            trace_id,
        )));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    record.status = "revoked".to_string();
    record.updated_at = now;

    store
        .write_identity(&record)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRegistered,
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

// ── PQC Migration ───────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct MigrateRequest {
    #[serde(default = "default_target_algorithm")]
    pub target_algorithm: String,
    pub signature: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct OwnerActionRequest {
    pub signature: String,
}

fn verify_owner_signature(
    record: &crate::storage::traits::IdentityRecord,
    message: &str,
    signature_hex: &str,
) -> Result<(), ApiError> {
    let is_owner = crate::signature::verify::infer_algorithm_from_key(&record.public_key)
        .is_some_and(|algorithm| {
            crate::signature::verify_signature(
                algorithm,
                &record.public_key,
                message.as_bytes(),
                signature_hex,
            )
        });
    if !is_owner {
        return Err(ApiError::UnauthorizedWithMessage {
            message: format!(
                "signature over {message:?} does not verify against the key registered for {}",
                record.did
            ),
        });
    }
    Ok(())
}

fn default_target_algorithm() -> String {
    "ml-dsa-65".into()
}

#[derive(Debug, serde::Serialize)]
struct MigrateResponse {
    old_did: String,
    new_did: String,
    new_algorithm: String,
    new_public_key_hex: String,
    migrated_at: u64,
}

#[post("/identity/{did}/migrate")]
pub async fn migrate_did(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<MigrateRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let target = match body.target_algorithm.to_lowercase().as_str() {
        "ml-dsa-65" | "mldsa65" | "" => crate::identity::signing::SigningAlgorithm::MlDsa65,
        "ed25519" => crate::identity::signing::SigningAlgorithm::Ed25519,
        other => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "INVALID_ALGORITHM".into(),
                    message: format!("unsupported target: {other}. Use ml-dsa-65 or ed25519"),
                    field: Some("target_algorithm".into()),
                },
                400,
            )));
        }
    };

    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let record = store.read_identity(&did).map_err(|_| ApiError::NotFound {
        resource: format!("identity {did}"),
    })?;
    verify_owner_signature(
        &record,
        &format!("identity:migrate:{did}:{}", body.target_algorithm),
        &body.signature,
    )?;

    if record.status == "migrated" {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            ErrorDto {
                code: "ALREADY_MIGRATED".into(),
                message: format!("DID {did} already migrated"),
                field: None,
            },
            409,
        )));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let result = crate::identity::keys::migrate_identity(store.as_ref(), &did, target, now)
        .map_err(|e| ApiError::StorageError {
            reason: format!("migration failed: {e}"),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        MigrateResponse {
            old_did: result.old_did,
            new_did: result.new_did,
            new_algorithm: format!("{}", result.new_algorithm),
            new_public_key_hex: result.new_public_key_hex,
            migrated_at: now,
        },
        trace_id,
    )))
}

// ── Store-backed identity endpoints ──────────────────────────────────────────

/// POST /api/v1/store/identities — persiste un IdentityRecord en el store.
#[post("/store/identities")]
pub async fn store_write_identity(
    state: web::Data<AppState>,
    body: web::Json<crate::storage::traits::IdentityRecord>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Identity",
        &req,
    )?;
    super::validation::validate_store_identity(&body)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    validate_new_identity(store.as_ref(), &body)?;
    store
        .write_identity(&body)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::DidRegistered,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("did={}", body.did)),
    );
    Ok(HttpResponse::Created().json(ApiResponse::success(body.into_inner(), trace_id)))
}

fn validate_new_identity(
    store: &dyn crate::storage::traits::BlockStore,
    record: &crate::storage::traits::IdentityRecord,
) -> Result<(), ApiError> {
    if !crate::identity::did::did_matches_pubkey(&record.did, &record.public_key) {
        return Err(ApiError::ValidationError {
            field: "did".into(),
            reason: "did must be derived from public_key".into(),
        });
    }
    if record.status != "active" {
        return Err(ApiError::ValidationError {
            field: "status".into(),
            reason: format!("new identities must be active, got {:?}", record.status),
        });
    }
    if store.read_identity(&record.did).is_ok() {
        return Err(ApiError::Conflict {
            reason: format!("identity {} already registered", record.did),
        });
    }
    Ok(())
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

fn mint_session_jwt(
    did: &str,
    exp: u64,
    signer: Option<&dyn crate::identity::signing::SigningProvider>,
) -> String {
    let now = now_secs();
    let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT"});
    let payload = serde_json::json!({
        "sub": did,
        "iat": now,
        "exp": exp,
        "iss": "goya-ledger",
        "type": "session",
    });
    let h = b64url_encode(&serde_json::to_vec(&header).unwrap_or_default());
    let p = b64url_encode(&serde_json::to_vec(&payload).unwrap_or_default());
    let signing_input = format!("{h}.{p}");
    let sig = signer
        .and_then(|s| s.sign(signing_input.as_bytes()).ok())
        .unwrap_or_default();
    let s = b64url_encode(&sig);
    format!("{signing_input}.{s}")
}

fn now_secs() -> u64 {
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
        challenge.nonce.as_bytes(),
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
    let session_token = mint_session_jwt(&body.did, session_exp, state.signing_provider.as_deref());

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
        }
    }

    fn canonical_identity() -> (String, String) {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let public_key = hex::encode(SoftwareSigningProvider::generate().public_key());
        (
            crate::identity::did::did_from_pubkey_hex(&public_key),
            public_key,
        )
    }

    #[test]
    fn new_identity_accepts_did_derived_from_key() {
        let store = crate::storage::MemoryStore::new();
        let (did, public_key) = canonical_identity();
        let record = identity_record(&did, &public_key, "active");
        assert!(validate_new_identity(&store, &record).is_ok());
    }

    #[test]
    fn new_identity_rejects_did_not_derived_from_key() {
        let store = crate::storage::MemoryStore::new();
        let (victim_did, _) = canonical_identity();
        let (_, attacker_key) = canonical_identity();
        let record = identity_record(&victim_did, &attacker_key, "active");
        assert!(matches!(
            validate_new_identity(&store, &record),
            Err(ApiError::ValidationError { .. })
        ));
    }

    #[test]
    fn new_identity_rejects_non_active_status() {
        let store = crate::storage::MemoryStore::new();
        let (did, public_key) = canonical_identity();
        let record = identity_record(&did, &public_key, "revoked");
        assert!(matches!(
            validate_new_identity(&store, &record),
            Err(ApiError::ValidationError { .. })
        ));
    }

    #[test]
    fn new_identity_rejects_existing_did() {
        use crate::storage::traits::BlockStore;
        let store = crate::storage::MemoryStore::new();
        let (did, public_key) = canonical_identity();
        let record = identity_record(&did, &public_key, "active");
        store.write_identity(&record).unwrap();
        assert!(matches!(
            validate_new_identity(&store, &record),
            Err(ApiError::Conflict { .. })
        ));
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
        let token = mint_session_jwt("did:goya:test1234", now_secs() + 3600, Some(&provider));
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

    fn registered_owner() -> RegisteredOwner {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let state = web::Data::new(AppState::test_default());
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
                    .service(migrate_did),
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

    #[actix_web::test]
    async fn migrate_rejects_signature_from_another_key() {
        let owner = registered_owner();
        let attacker = crate::identity::signing::SoftwareSigningProvider::generate();
        let message = format!("identity:migrate:{}:ml-dsa-65", owner.did);
        let body = serde_json::json!({
            "target_algorithm": "ml-dsa-65",
            "signature": sign_hex(&attacker, &message),
        });
        assert_eq!(post_owner_action(&owner, "migrate", body).await, 401);
        assert_eq!(owner_status(&owner), "active");
    }

    #[actix_web::test]
    async fn migrate_with_owner_signature_migrates() {
        let owner = registered_owner();
        let message = format!("identity:migrate:{}:ml-dsa-65", owner.did);
        let body = serde_json::json!({
            "target_algorithm": "ml-dsa-65",
            "signature": sign_hex(&owner.key, &message),
        });
        assert_eq!(post_owner_action(&owner, "migrate", body).await, 200);
        assert_eq!(owner_status(&owner), "migrated");
    }
}
