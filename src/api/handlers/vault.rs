//! Vault endpoints — encrypted wallet backup storage.
//!
//! The node stores encrypted wallet blobs keyed by DID. The wallet content
//! is opaque — the node never parses or decrypts it.
//!
//! Recovery: when `VAULT_RECOVERY_SECRET` is set, clients can supply a
//! `recovery_key` (client-derived via KDF) during store. The node computes
//! a blind index via HMAC-SHA3-256 (NIST SP 800-185) and stores the mapping
//! `blind_index → DID`. Recovery looks up the DID and returns the encrypted wallet.

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::app_state::AppState;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_RECOVERY_ATTEMPTS: u32 = 5;
const RECOVERY_WINDOW: Duration = Duration::from_secs(300);

/// Per-IP rate limiter for vault recovery attempts (brute-force protection).
pub struct RecoveryRateLimiter {
    attempts: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RecoveryRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt from `ip`. Returns `false` when the limit is exceeded.
    pub fn check(&self, ip: &str) -> bool {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match map.get_mut(ip) {
            Some((count, window_start)) => {
                match now.duration_since(*window_start) > RECOVERY_WINDOW {
                    true => {
                        *count = 1;
                        *window_start = now;
                        true
                    }
                    false => match *count >= MAX_RECOVERY_ATTEMPTS {
                        true => false,
                        false => {
                            *count += 1;
                            true
                        }
                    },
                }
            }
            None => {
                map.insert(ip.to_string(), (1, now));
                true
            }
        }
    }
}

impl Default for RecoveryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Fire-and-forget vault audit entry.
fn emit_vault_audit(state: &AppState, operation: &str, did: &str, trace: &str, req: &HttpRequest) {
    state.audit_store.as_ref().inspect(|store| {
        let entry = crate::audit::AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: crate::audit::AuditAction::VaultOperation,
            method: req.method().to_string(),
            path: req.path().to_string(),
            org_id: req
                .headers()
                .get("X-Org-Id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
            source_ip: req
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_default(),
            status_code: 200,
            trace_id: trace.to_string(),
            duration_ms: 0,
            metadata: Some(serde_json::json!({ "operation": operation, "did": did }).to_string()),
            previous_hash: String::new(),
            entry_hash: String::new(),
        };
        store.append(&entry).ok();
    });
}

fn err_dto(msg: &str) -> ErrorDto {
    ErrorDto {
        code: "VAULT_ERROR".to_string(),
        message: msg.to_string(),
        field: None,
    }
}

/// Compute the blind index for a recovery key using HMAC-SHA3-256.
fn blind_index(secret: &[u8], recovery_key: &[u8]) -> Result<String, String> {
    let hash = pqc_crypto_module::api::hmac_sha3_256(secret, recovery_key)
        .map_err(|e| format!("crypto error: {e}"))?;
    Ok(hash.to_hex())
}

#[derive(Deserialize)]
pub struct VaultStoreRequest {
    pub did: String,
    pub encrypted_wallet: serde_json::Value,
    /// Client-derived recovery key (hex, 64 chars = 32 bytes). Optional.
    pub recovery_key: Option<String>,
    pub public_key: String,
    pub signature: String,
}

pub fn vault_store_message(
    did: &str,
    encrypted_wallet: &serde_json::Value,
    recovery_key: Option<&str>,
) -> String {
    format!(
        "vault:store:{did}:{}:{encrypted_wallet}",
        recovery_key.unwrap_or("")
    )
}

fn key_owns_vault_did(
    store: &dyn crate::storage::traits::BlockStore,
    did: &str,
    public_key_hex: &str,
) -> bool {
    let owner_did = did.replacen("did:goya:bio:", "did:goya:", 1);
    crate::identity::operations::key_controls_did(store, &owner_did, public_key_hex)
}

#[derive(Deserialize)]
pub struct VaultRecoverRequest {
    /// Client-derived recovery key (hex, 64 chars = 32 bytes).
    pub recovery_key: String,
}

/// POST /api/v1/vault/store — store an encrypted wallet backup
#[post("/vault/store")]
pub async fn vault_store(
    state: web::Data<AppState>,
    body: web::Json<VaultStoreRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    if body.did.is_empty() {
        return Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(err_dto("did is required"), 400)));
    }

    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if !key_owns_vault_did(store.as_ref(), &body.did, &body.public_key) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto(&format!("public_key does not own vault {}", body.did)),
            401,
        )));
    }
    let message = vault_store_message(
        &body.did,
        &body.encrypted_wallet,
        body.recovery_key.as_deref(),
    );
    if !crate::identity::operations::is_signed_by(&body.public_key, &message, &body.signature) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto(&format!(
                "signature over {message:?} does not verify against public_key"
            )),
            401,
        )));
    }

    store
        .write_vault(&body.did, &body.encrypted_wallet)
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    // If recovery_key is provided and VAULT_RECOVERY_SECRET is configured,
    // store the blind index → DID mapping.
    if let Some(ref recovery_key_hex) = body.recovery_key {
        if let Some(ref secret) = state.vault_recovery_secret {
            // Validate: must be exactly 64 hex chars (32 bytes)
            if recovery_key_hex.len() != 64 || hex::decode(recovery_key_hex).is_err() {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_dto("recovery_key must be exactly 64 hex characters (32 bytes)"),
                    400,
                )));
            }

            let recovery_key_bytes = hex::decode(recovery_key_hex).unwrap_or_default();
            let idx = blind_index(secret, &recovery_key_bytes).map_err(|e| {
                crate::api::errors::ApiError::StorageError {
                    reason: e.to_string(),
                }
            })?;

            store.write_vault_recovery(&idx, &body.did).map_err(|e| {
                crate::api::errors::ApiError::StorageError {
                    reason: e.to_string(),
                }
            })?;
        }
        // If VAULT_RECOVERY_SECRET is not set, silently ignore recovery_key
    }

    emit_vault_audit(&state, "store", &body.did, &trace, &req);

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "did": body.did }),
        trace,
    )))
}

/// GET /api/v1/vault/{did} — retrieve an encrypted wallet backup
#[get("/vault/{did}")]
pub async fn vault_get(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let did_raw = path.into_inner();
    let did = urlencoding::decode(&did_raw)
        .unwrap_or_default()
        .to_string();

    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    match store.read_vault(&did) {
        Ok(encrypted_wallet) => {
            emit_vault_audit(&state, "get", &did, &trace, &req);
            Ok(HttpResponse::Ok().json(ApiResponse::success(
                serde_json::json!({
                    "did": did,
                    "encrypted_wallet": encrypted_wallet,
                }),
                trace,
            )))
        }
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("vault entry not found"),
            404,
        ))),
    }
}

/// POST /api/v1/vault/recover — recover wallet by client-derived recovery key
#[post("/vault/recover")]
pub async fn vault_recover(
    state: web::Data<AppState>,
    body: web::Json<VaultRecoverRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    // Rate limit recovery attempts per IP
    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    match state.vault_rate_limiter.check(&ip) {
        true => {}
        false => return Err(crate::api::errors::ApiError::RateLimited),
    }

    // Require VAULT_RECOVERY_SECRET
    let secret = state.vault_recovery_secret.as_ref().ok_or_else(|| {
        crate::api::errors::ApiError::InternalError {
            reason: "vault recovery not configured".into(),
        }
    })?;

    // Validate recovery_key format: exactly 64 hex chars (32 bytes)
    let recovery_key_bytes = hex::decode(&body.recovery_key).map_err(|_| {
        crate::api::errors::ApiError::ValidationError {
            field: "recovery_key".into(),
            reason: "recovery_key must be exactly 64 hex characters (32 bytes)".into(),
        }
    })?;
    match recovery_key_bytes.len() {
        32 => {}
        _ => {
            return Err(crate::api::errors::ApiError::ValidationError {
                field: "recovery_key".into(),
                reason: "recovery_key must be exactly 64 hex characters (32 bytes)".into(),
            });
        }
    }

    let idx = blind_index(secret, &recovery_key_bytes).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        }
    })?;

    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Look up DID from blind index
    let did = match store.read_vault_by_recovery(&idx) {
        Ok(did) => did,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("no vault entry found for this recovery key"),
                404,
            )));
        }
    };

    // Fetch the encrypted wallet by DID
    match store.read_vault(&did) {
        Ok(encrypted_wallet) => {
            emit_vault_audit(&state, "recover", &did, &trace, &req);
            Ok(HttpResponse::Ok().json(ApiResponse::success(
                serde_json::json!({
                    "did": did,
                    "encrypted_wallet": encrypted_wallet,
                }),
                trace,
            )))
        }
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("vault entry not found for recovered DID"),
            404,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};

    struct Wallet {
        key: SoftwareSigningProvider,
        public_key: String,
        did: String,
    }

    fn new_wallet() -> Wallet {
        let key = SoftwareSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = format!(
            "did:goya:{}",
            crate::identity::operations::wallet_address_of(&public_key).unwrap()
        );
        Wallet {
            key,
            public_key,
            did,
        }
    }

    fn store_body(
        signer: &Wallet,
        did: &str,
        encrypted_wallet: serde_json::Value,
        recovery_key: Option<&str>,
    ) -> serde_json::Value {
        let message = vault_store_message(did, &encrypted_wallet, recovery_key);
        serde_json::json!({
            "did": did,
            "encrypted_wallet": encrypted_wallet,
            "recovery_key": recovery_key,
            "public_key": signer.public_key,
            "signature": hex::encode(signer.key.sign(message.as_bytes()).unwrap()),
        })
    }

    async fn call(
        state: &web::Data<AppState>,
        request: actix_web::test::TestRequest,
    ) -> actix_web::dev::ServiceResponse {
        let app = actix_web::test::init_service(
            actix_web::App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(vault_store)
                    .service(vault_get),
            ),
        )
        .await;
        actix_web::test::call_service(&app, request.to_request()).await
    }

    async fn store(state: &web::Data<AppState>, body: serde_json::Value) -> u16 {
        let request = actix_web::test::TestRequest::post()
            .uri("/api/v1/vault/store")
            .set_json(body);
        call(state, request).await.status().as_u16()
    }

    async fn stored_wallet(state: &web::Data<AppState>, did: &str) -> serde_json::Value {
        let uri = format!("/api/v1/vault/{}", urlencoding::encode(did));
        let request = actix_web::test::TestRequest::get().uri(&uri);
        let body: serde_json::Value =
            actix_web::test::read_body_json(call(state, request).await).await;
        body["data"]["encrypted_wallet"].clone()
    }

    #[actix_web::test]
    async fn owner_stores_and_replaces_its_wallet_backup() {
        let state = web::Data::new(AppState::test_default());
        let owner = new_wallet();
        let first = serde_json::json!({ "address": "a", "nonce": "1" });
        let second = serde_json::json!({ "address": "a", "nonce": "2" });
        assert_eq!(
            store(&state, store_body(&owner, &owner.did, first, None)).await,
            200
        );
        assert_eq!(
            store(&state, store_body(&owner, &owner.did, second.clone(), None)).await,
            200
        );
        assert_eq!(stored_wallet(&state, &owner.did).await, second);
    }

    #[actix_web::test]
    async fn stranger_cannot_overwrite_a_wallet_backup() {
        let state = web::Data::new(AppState::test_default());
        let owner = new_wallet();
        let stranger = new_wallet();
        let original = serde_json::json!({ "nonce": "1" });
        assert_eq!(
            store(
                &state,
                store_body(&owner, &owner.did, original.clone(), None)
            )
            .await,
            200
        );
        let hijack = store_body(
            &stranger,
            &owner.did,
            serde_json::json!({ "nonce": "evil" }),
            None,
        );
        assert_eq!(store(&state, hijack).await, 401);
        assert_eq!(stored_wallet(&state, &owner.did).await, original);
    }

    #[actix_web::test]
    async fn signature_covers_the_wallet_and_recovery_key() {
        let state = web::Data::new(AppState::test_default());
        let owner = new_wallet();
        let signed = store_body(
            &owner,
            &owner.did,
            serde_json::json!({ "nonce": "1" }),
            None,
        );
        let mut swapped_wallet = signed.clone();
        swapped_wallet["encrypted_wallet"] = serde_json::json!({ "nonce": "evil" });
        assert_eq!(store(&state, swapped_wallet).await, 401);
        let mut added_recovery = signed;
        added_recovery["recovery_key"] = serde_json::json!("ab".repeat(32));
        assert_eq!(store(&state, added_recovery).await, 401);
    }

    #[actix_web::test]
    async fn unsigned_store_is_rejected() {
        let state = web::Data::new(AppState::test_default());
        let owner = new_wallet();
        let body = serde_json::json!({ "did": owner.did, "encrypted_wallet": { "nonce": "1" } });
        assert_eq!(store(&state, body).await, 400);
    }

    #[actix_web::test]
    async fn biometric_backup_belongs_to_the_wallet_key() {
        let state = web::Data::new(AppState::test_default());
        let owner = new_wallet();
        let stranger = new_wallet();
        let bio_did = owner.did.replacen("did:goya:", "did:goya:bio:", 1);
        let sealed = serde_json::json!({ "credential_id": "c", "iv": "i", "ct": "x" });
        assert_eq!(
            store(
                &state,
                store_body(&stranger, &bio_did, sealed.clone(), None)
            )
            .await,
            401
        );
        assert_eq!(
            store(&state, store_body(&owner, &bio_did, sealed, None)).await,
            200
        );
        assert_eq!(
            store(
                &state,
                store_body(&owner, &bio_did, serde_json::Value::Null, None)
            )
            .await,
            200
        );
    }

    #[actix_web::test]
    async fn canonical_did_backup_needs_the_key_that_derives_it() {
        let state = web::Data::new(AppState::test_default());
        let owner = new_wallet();
        let canonical_did = crate::identity::did::did_from_pubkey_hex(&owner.public_key);
        let wallet = serde_json::json!({ "nonce": "1" });
        assert_eq!(
            store(
                &state,
                store_body(&new_wallet(), &canonical_did, wallet.clone(), None)
            )
            .await,
            401
        );
        assert_eq!(
            store(&state, store_body(&owner, &canonical_did, wallet, None)).await,
            200
        );
    }

    #[test]
    fn blind_index_is_deterministic() {
        let a = blind_index(b"secret", b"recovery").unwrap();
        let b = blind_index(b"secret", b"recovery").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex
    }

    #[test]
    fn blind_index_different_secrets_differ() {
        let a = blind_index(b"secret1", b"recovery").unwrap();
        let b = blind_index(b"secret2", b"recovery").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn recovery_rate_limiter_allows_under_threshold() {
        let limiter = RecoveryRateLimiter::new();
        (0..MAX_RECOVERY_ATTEMPTS).for_each(|_| assert!(limiter.check("10.0.0.1")));
    }

    #[test]
    fn recovery_rate_limiter_blocks_after_threshold() {
        let limiter = RecoveryRateLimiter::new();
        (0..MAX_RECOVERY_ATTEMPTS).for_each(|_| {
            let _ = limiter.check("10.0.0.2");
        });
        assert!(!limiter.check("10.0.0.2"));
    }

    #[test]
    fn recovery_rate_limiter_independent_per_ip() {
        let limiter = RecoveryRateLimiter::new();
        (0..MAX_RECOVERY_ATTEMPTS).for_each(|_| {
            let _ = limiter.check("10.0.0.3");
        });
        assert!(limiter.check("10.0.0.4")); // Different IP still allowed
        assert!(!limiter.check("10.0.0.3")); // Original IP blocked
    }
}
