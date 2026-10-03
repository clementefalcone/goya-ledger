//! Alias registry endpoints — zero-knowledge alias system.
//!
//! The node stores only SHA3-256 commitments, never plaintext aliases.
//! Clients compute commitments and encrypted aliases locally.
//!
//! Endpoints:
//! - POST /alias/register — register an alias commitment
//! - POST /alias/resolve — resolve commitment to DID
//! - POST /alias/revoke  — revoke an alias (15-day cooldown)

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::app_state::AppState;
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{BiometricEvidence, SignatureLevel};
use crate::storage::traits::AliasEntry;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// 15-day cooldown in seconds before a revoked alias can be re-registered.
const REVOKE_COOLDOWN_SECS: u64 = 15 * 24 * 60 * 60;

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Request types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AliasRegisterRequest {
    pub did: String,
    /// Ed25519 public key (hex, 64 chars = 32 bytes).
    pub public_key: String,
    /// SHA3-256 commitment: hex(SHA3-256(salt || alias)), 64 hex chars.
    pub commitment: String,
    /// Deterministic salt: hex, 32 chars (16 bytes).
    pub salt: String,
    /// AES-256-GCM encrypted alias (hex). Opaque to the node.
    pub encrypted_alias: String,
    /// Signature over the register payload (hex).
    pub signature: String,
    #[serde(default)]
    pub signature_level: SignatureLevel,
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

#[derive(Deserialize)]
pub struct AliasResolveRequest {
    /// SHA3-256 commitment to look up.
    pub commitment: String,
}

#[derive(Deserialize)]
pub struct AliasRevokeRequest {
    pub did: String,
    /// Ed25519 public key (hex, 64 chars = 32 bytes).
    pub public_key: String,
    pub commitment: String,
    /// Signature over the revoke payload (hex).
    pub signature: String,
    #[serde(default)]
    pub signature_level: SignatureLevel,
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /api/v1/alias/register
#[post("/alias/register")]
pub async fn alias_register(
    state: web::Data<AppState>,
    body: web::Json<AliasRegisterRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate commitment format: 64 hex chars (32 bytes SHA3-256)
    if body.commitment.len() != 64 || hex::decode(&body.commitment).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_COMMITMENT", "commitment must be 64 hex characters"),
            400,
        )));
    }

    // Validate salt format: 32 hex chars (16 bytes)
    if body.salt.len() != 32 || hex::decode(&body.salt).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_SALT", "salt must be 32 hex characters"),
            400,
        )));
    }

    // Validate FES/FEA constraints
    if let Err(e) = crate::signature::validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("VALIDATION", &e.to_string()),
            400,
        )));
    }

    if !crate::identity::did::did_matches_pubkey(&body.did, &body.public_key) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("SIGNER_MISMATCH", "public_key does not derive the DID"),
            401,
        )));
    }
    // Verify signature over register payload
    let base_payload = format!("alias:register:{}", body.commitment);
    let register_msg = match body.signature_level {
        SignatureLevel::Simple => base_payload,
        _ => format!(
            "{}:{}",
            base_payload,
            crate::signature::compute_biometrics_hash(&body.biometric_evidence)
        ),
    };
    if !crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        register_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    // Check if DID already has an active alias
    if let Ok(existing) = store.read_alias_by_did(&body.did) {
        if existing.status == "active" {
            return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
                err_dto(
                    "ALIAS_EXISTS",
                    "this DID already has an active alias; revoke it first",
                ),
                409,
            )));
        }
    }

    // Check if commitment already exists
    if let Ok(existing) = store.read_alias(&body.commitment) {
        if existing.status == "active" {
            return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
                err_dto("ALIAS_TAKEN", "this alias commitment is already registered"),
                409,
            )));
        }
        // Revoked — check cooldown
        if existing.status == "revoked" {
            if let Some(revoked_at) = existing.revoked_at {
                if now_secs() < revoked_at + REVOKE_COOLDOWN_SECS {
                    return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
                        err_dto(
                            "ALIAS_COOLDOWN",
                            "this alias is in a 15-day cooldown after revocation",
                        ),
                        409,
                    )));
                }
            }
        }
    }

    let entry = AliasEntry {
        commitment: body.commitment.clone(),
        did: body.did.clone(),
        salt: body.salt.clone(),
        encrypted_alias: body.encrypted_alias.clone(),
        registered_at: now_secs(),
        status: "active".to_string(),
        revoked_at: None,
        signature_level: body.signature_level,
        signature_algorithm: body.signature_algorithm,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_alias(&entry)
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "commitment": body.commitment,
            "did": body.did,
        }),
        trace,
    )))
}

/// POST /api/v1/alias/resolve
#[post("/alias/resolve")]
pub async fn alias_resolve(
    state: web::Data<AppState>,
    body: web::Json<AliasResolveRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    match store.read_alias(&body.commitment) {
        Ok(entry) if entry.status == "active" => {
            // Extract address from DID (did:goya:<address>)
            let address = entry
                .did
                .strip_prefix("did:goya:")
                .unwrap_or(&entry.did)
                .to_string();
            Ok(HttpResponse::Ok().json(ApiResponse::success(
                serde_json::json!({
                    "did": entry.did,
                    "address": address,
                }),
                trace,
            )))
        }
        Ok(entry) if entry.status == "revoked" => Ok(HttpResponse::Gone().json(
            ApiResponse::<()>::error(err_dto("ALIAS_REVOKED", "this alias has been revoked"), 410),
        )),
        _ => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "alias not found"),
            404,
        ))),
    }
}

/// GET /api/v1/alias/by-did/{did}
#[get("/alias/by-did/{did}")]
pub async fn alias_by_did(
    state: web::Data<AppState>,
    did: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    match store.read_alias_by_did(&did) {
        Ok(entry) if entry.status == "active" => Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({
                "commitment": entry.commitment,
                "did": entry.did,
                "encrypted_alias": entry.encrypted_alias,
                "registered_at": entry.registered_at,
            }),
            trace,
        ))),
        Ok(entry) if entry.status == "revoked" => Ok(HttpResponse::Gone().json(
            ApiResponse::<()>::error(err_dto("ALIAS_REVOKED", "this alias has been revoked"), 410),
        )),
        _ => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "no alias found for this DID"),
            404,
        ))),
    }
}

/// POST /api/v1/alias/revoke
#[post("/alias/revoke")]
pub async fn alias_revoke(
    state: web::Data<AppState>,
    body: web::Json<AliasRevokeRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Read the existing alias
    let entry = match store.read_alias(&body.commitment) {
        Ok(e) => e,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", "alias not found"),
                404,
            )));
        }
    };

    // Only the owner can revoke
    if entry.did != body.did {
        return Ok(HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            err_dto("FORBIDDEN", "only the alias owner can revoke it"),
            403,
        )));
    }

    if entry.status == "revoked" {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto("ALREADY_REVOKED", "this alias is already revoked"),
            409,
        )));
    }

    // Validate FES/FEA + verify signature
    if !body
        .signature_level
        .algorithm_satisfies(body.signature_algorithm)
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "ALGORITHM_MISMATCH",
                &format!(
                    "signature level {} requires ML-DSA-65, got {}",
                    body.signature_level, body.signature_algorithm
                ),
            ),
            400,
        )));
    }
    if body.signature_level.requires_biometric() && body.biometric_evidence.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "BIOMETRIC_REQUIRED",
                &format!(
                    "signature level {} requires biometric evidence",
                    body.signature_level
                ),
            ),
            400,
        )));
    }
    for evidence in &body.biometric_evidence {
        if let Err(e) = evidence.validate() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_BIOMETRIC", &e.to_string()),
                400,
            )));
        }
    }
    if let Err(msg) =
        crate::signature::validate_public_key(body.signature_algorithm, &body.public_key)
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_PUBLIC_KEY", &msg),
            400,
        )));
    }
    if !crate::identity::did::did_matches_pubkey(&body.did, &body.public_key) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("SIGNER_MISMATCH", "public_key does not derive the DID"),
            401,
        )));
    }
    let base_payload = format!("alias:revoke:{}", body.commitment);
    let revoke_msg = match body.signature_level {
        SignatureLevel::Simple => base_payload,
        _ => format!(
            "{}:{}",
            base_payload,
            crate::signature::compute_biometrics_hash(&body.biometric_evidence)
        ),
    };
    if !crate::signature::verify_signature(
        body.signature_algorithm,
        &body.public_key,
        revoke_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    // Mark as revoked
    let revoked = AliasEntry {
        status: "revoked".to_string(),
        revoked_at: Some(now_secs()),
        ..entry
    };
    store
        .write_alias(&revoked)
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "commitment": body.commitment,
            "status": "revoked",
        }),
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    fn make_app_data() -> web::Data<AppState> {
        web::Data::new(AppState::test_default())
    }

    fn dummy_sig() -> String {
        "aa".repeat(32)
    }

    #[actix_web::test]
    async fn now_secs_returns_reasonable_value() {
        let t = now_secs();
        assert!(t > 1_700_000_000);
    }

    // ── register: input validation ──────────────────────────────────

    #[actix_web::test]
    async fn register_rejects_short_commitment() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(alias_register)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/alias/register")
            .set_json(serde_json::json!({
                "did": "did:goya:test",
                "public_key": "aa".repeat(32),
                "commitment": "tooshort",
                "salt": "bb".repeat(16),
                "encrypted_alias": "ciphertext",
                "signature": dummy_sig(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_COMMITMENT");
    }

    #[actix_web::test]
    async fn register_rejects_invalid_salt() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(alias_register)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/alias/register")
            .set_json(serde_json::json!({
                "did": "did:goya:test",
                "public_key": "aa".repeat(32),
                "commitment": "cc".repeat(32),
                "salt": "short",
                "encrypted_alias": "ciphertext",
                "signature": dummy_sig(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_SALT");
    }

    // ── resolve: not found ──────────────────────────────────────────

    #[actix_web::test]
    async fn resolve_returns_404_for_unknown() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(alias_resolve)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/alias/resolve")
            .set_json(serde_json::json!({
                "commitment": "dd".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "NOT_FOUND");
    }

    // ── by-did: not found ───────────────────────────────────────────

    #[actix_web::test]
    async fn by_did_returns_404_for_unknown() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(alias_by_did)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/alias/by-did/did:goya:ghost")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ── revoke: not found ───────────────────────────────────────────

    #[actix_web::test]
    async fn revoke_returns_404_for_unknown() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(alias_revoke)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/alias/revoke")
            .set_json(serde_json::json!({
                "did": "did:goya:test",
                "public_key": "aa".repeat(32),
                "commitment": "ee".repeat(32),
                "signature": dummy_sig(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    fn ed25519_identity() -> (String, crate::identity::signing::SoftwareSigningProvider) {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let key = SoftwareSigningProvider::generate();
        let did = crate::identity::did::did_from_pubkey_hex(&hex::encode(key.public_key()));
        (did, key)
    }

    fn signed_alias_body(
        did: &str,
        key: &crate::identity::signing::SoftwareSigningProvider,
        action: &str,
        commitment: &str,
    ) -> serde_json::Value {
        use crate::identity::signing::SigningProvider;
        let message = format!("alias:{action}:{commitment}");
        serde_json::json!({
            "did": did,
            "public_key": hex::encode(key.public_key()),
            "commitment": commitment,
            "salt": "bb".repeat(16),
            "encrypted_alias": "ciphertext",
            "signature": hex::encode(key.sign(message.as_bytes()).unwrap()),
            "signature_algorithm": "Ed25519",
        })
    }

    async fn post_alias(
        state: &web::Data<AppState>,
        action: &str,
        body: serde_json::Value,
    ) -> actix_web::http::StatusCode {
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(alias_register)
                    .service(alias_revoke),
            ),
        )
        .await;
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/alias/{action}"))
            .set_json(body)
            .to_request();
        test::call_service(&app, req).await.status()
    }

    #[actix_web::test]
    async fn register_accepts_owner_key() {
        let state = make_app_data();
        let (did, key) = ed25519_identity();
        let body = signed_alias_body(&did, &key, "register", &"cc".repeat(32));
        assert_eq!(post_alias(&state, "register", body).await, 200);
    }

    #[actix_web::test]
    async fn register_rejects_key_not_bound_to_did() {
        let state = make_app_data();
        let (victim_did, _) = ed25519_identity();
        let (_, attacker) = ed25519_identity();
        let body = signed_alias_body(&victim_did, &attacker, "register", &"cc".repeat(32));
        assert_eq!(post_alias(&state, "register", body).await, 401);
    }

    #[actix_web::test]
    async fn revoke_rejects_key_not_bound_to_did() {
        let state = make_app_data();
        let (owner_did, owner_key) = ed25519_identity();
        let commitment = "cc".repeat(32);
        let register = signed_alias_body(&owner_did, &owner_key, "register", &commitment);
        assert_eq!(post_alias(&state, "register", register).await, 200);

        let (_, attacker) = ed25519_identity();
        let revoke = signed_alias_body(&owner_did, &attacker, "revoke", &commitment);
        assert_eq!(post_alias(&state, "revoke", revoke).await, 401);
    }
}
