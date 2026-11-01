use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::{
    channel_id_from_req, enforce_channel_membership, get_channel_store,
};
use crate::api::handlers::identity::{commit_ledger_op, identity_op_error};
use crate::app_state::AppState;
use crate::identity::credential_ops::{self, RevokeRequest};
use crate::identity::operations::Change;
use crate::storage::traits::{Credential, TxPayload};
use actix_web::{get, post, web, HttpRequest, HttpResponse};

#[derive(Debug, serde::Deserialize)]
pub struct IssueCredentialRequest {
    #[serde(flatten)]
    pub credential: Credential,
    pub issuer_public_key: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct RevokeCredentialRequest {
    pub revoked_at: u64,
    pub issuer_public_key: String,
    pub signature: String,
}

fn emit_credential_audit(
    state: &AppState,
    req: &HttpRequest,
    action: crate::audit::AuditAction,
    id: &str,
) {
    crate::audit::emit_if_present(
        &state.audit_store,
        action,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("credential_id={id}")),
    );
}

/// POST /api/v1/store/credentials — records a credential signed by its issuer.
#[post("/store/credentials")]
pub async fn store_write_credential(
    state: web::Data<AppState>,
    body: web::Json<IssueCredentialRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let IssueCredentialRequest {
        credential,
        issuer_public_key,
    } = body.into_inner();
    super::validation::validate_store_credential(&credential)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, channel, &req)?;
    let store = get_channel_store(&state, channel)?;

    if store.read_identity(&credential.issuer_did).is_err() {
        return Err(ApiError::ValidationError {
            field: "issuer_did".to_string(),
            reason: format!(
                "issuer DID '{}' not found — register identity before issuing credentials",
                credential.issuer_did
            ),
        });
    }
    let change = credential_ops::check_issue(store.as_ref(), &credential, &issuer_public_key)
        .map_err(identity_op_error)?;
    if change == Change::AlreadyApplied {
        return Err(ApiError::Conflict {
            reason: format!("credential {} already recorded", credential.id),
        });
    }
    commit_ledger_op(
        &state,
        store.as_ref(),
        channel,
        &credential.issuer_did,
        TxPayload::IssueCredential {
            credential: Box::new(credential.clone()),
            issuer_public_key,
        },
    )?;
    emit_credential_audit(
        &state,
        &req,
        crate::audit::AuditAction::CredentialStored,
        &credential.id,
    );
    Ok(HttpResponse::Created().json(ApiResponse::success(credential, trace_id)))
}

/// POST /api/v1/store/credentials/{cred_id}/revoke — revokes a credential with its issuer's signature.
#[post("/store/credentials/{cred_id}/revoke")]
pub async fn store_revoke_credential(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RevokeCredentialRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, channel, &req)?;
    let store = get_channel_store(&state, channel)?;
    let request = RevokeRequest {
        id: &id,
        revoked_at: body.revoked_at,
        issuer_public_key: &body.issuer_public_key,
        signature: &body.signature,
    };
    let change =
        credential_ops::check_revoke(store.as_ref(), &request).map_err(identity_op_error)?;
    if change == Change::Write {
        let issuer_did = store
            .read_credential(&id)
            .map_err(|e| ApiError::StorageError {
                reason: format!("credential {id} unreadable: {e}"),
            })?
            .issuer_did;
        commit_ledger_op(
            &state,
            store.as_ref(),
            channel,
            &issuer_did,
            TxPayload::RevokeCredential {
                id: id.clone(),
                revoked_at: body.revoked_at,
                issuer_public_key: body.issuer_public_key.clone(),
                signature: body.signature.clone(),
            },
        )?;
        emit_credential_audit(
            &state,
            &req,
            crate::audit::AuditAction::CredentialRevoked,
            &id,
        );
    }
    let credential = store
        .read_credential(&id)
        .map_err(|e| ApiError::StorageError {
            reason: format!("credential {id} unreadable: {e}"),
        })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(credential, trace_id)))
}

/// GET /api/v1/store/credentials/{cred_id} — lee un Credential del store.
#[get("/store/credentials/{cred_id}")]
pub async fn store_get_credential(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let cred_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    match store.read_credential(&cred_id) {
        Ok(cred) => Ok(HttpResponse::Ok().json(ApiResponse::success(cred, trace_id))),
        Err(_) => Err(ApiError::NotFound {
            resource: format!("credential {cred_id}"),
        }),
    }
}

/// GET /api/v1/store/credentials/by-subject/{subject_did}
#[get("/store/credentials/by-subject/{subject_did}")]
pub async fn store_get_credentials_by_subject(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let subject_did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let creds = store
        .credentials_by_subject_did(&subject_did)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(creds, trace_id)))
}

/// GET /api/v1/store/credentials/by-issuer/{issuer_did}
#[get("/store/credentials/by-issuer/{issuer_did}")]
pub async fn store_get_credentials_by_issuer(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let issuer_did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let creds =
        store
            .credentials_by_issuer_did(&issuer_did)
            .map_err(|e| ApiError::StorageError {
                reason: e.to_string(),
            })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(creds, trace_id)))
}

/// GET /api/v1/store/credentials?page=1&limit=20 — list credentials (paginated).
#[get("/store/credentials")]
pub async fn store_list_credentials(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<crate::api::pagination::PaginationParams>,
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let all = store
        .list_credentials()
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    let total = all.len();
    let page: Vec<_> = all
        .into_iter()
        .skip(query.offset())
        .take(query.limit())
        .collect();
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        crate::api::pagination::PaginatedResponse::new(page, total, &query),
        trace_id,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    fn make_app_data() -> web::Data<AppState> {
        web::Data::new(AppState::test_default())
    }

    #[actix_web::test]
    async fn store_credential_handlers_are_public() {
        let _ = (store_write_credential, store_get_credential);
    }

    // ── store_get_credential: not found ─────────────────────────────

    #[actix_web::test]
    async fn store_get_returns_404() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(store_get_credential)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/store/credentials/ghost")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};

    struct Issuer {
        key: SoftwareSigningProvider,
        public_key: String,
        did: String,
    }

    fn registered_issuer(state: &AppState) -> Issuer {
        let key = SoftwareSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        get_channel_store(state, "default")
            .unwrap()
            .write_identity(&crate::storage::traits::IdentityRecord {
                did: did.clone(),
                public_key: public_key.clone(),
                created_at: 1,
                updated_at: 1,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            })
            .unwrap();
        Issuer {
            key,
            public_key,
            did,
        }
    }

    fn sign(issuer: &Issuer, message: &str) -> String {
        hex::encode(issuer.key.sign(message.as_bytes()).unwrap())
    }

    fn issue_body(issuer: &Issuer) -> serde_json::Value {
        let mut credential = Credential {
            id: "cred-1".to_string(),
            issuer_did: issuer.did.clone(),
            subject_did: "did:goya:subject".to_string(),
            cred_type: "consent".to_string(),
            issued_at: 100,
            expires_at: 0,
            revoked_at: None,
            claims: serde_json::Value::Null,
            signature: String::new(),
            status: "active".to_string(),
            claims_commitment: Some("ab".repeat(32)),
            claims_salt: None,
        };
        credential.signature = sign(issuer, &credential_ops::issue_message(&credential));
        let mut body = serde_json::to_value(credential).unwrap();
        body["issuer_public_key"] = issuer.public_key.clone().into();
        body
    }

    macro_rules! post {
        ($app:expr, $uri:expr, $body:expr) => {{
            let req = test::TestRequest::post()
                .uri($uri)
                .set_json($body)
                .to_request();
            test::call_service($app, req).await.status().as_u16()
        }};
    }

    #[actix_web::test]
    async fn issuer_signed_credential_is_recorded_and_queued_for_the_chain() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::scope("/api/v1").service(store_write_credential)),
        )
        .await;
        let issuer = registered_issuer(&state);
        assert_eq!(
            post!(&app, "/api/v1/store/credentials", issue_body(&issuer)),
            201
        );
        let pool = state.tx_pool.lock().unwrap();
        assert!(pool
            .all()
            .iter()
            .any(|tx| matches!(&tx.payload, Some(TxPayload::IssueCredential { credential, .. }) if credential.id == "cred-1")));
    }

    #[actix_web::test]
    async fn credential_without_a_valid_issuer_signature_is_refused() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::scope("/api/v1").service(store_write_credential)),
        )
        .await;
        let issuer = registered_issuer(&state);
        let mut body = issue_body(&issuer);
        body["subject_did"] = "did:goya:someone-else".into();
        assert_eq!(post!(&app, "/api/v1/store/credentials", body), 401);
        let store = get_channel_store(&state, "default").unwrap();
        assert!(store.read_credential("cred-1").is_err());
    }

    #[actix_web::test]
    async fn credential_with_personal_claims_is_refused() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(web::scope("/api/v1").service(store_write_credential)),
        )
        .await;
        let issuer = registered_issuer(&state);
        let mut body = issue_body(&issuer);
        body["claims"] = serde_json::json!({ "rut": "11111111-1" });
        assert_eq!(post!(&app, "/api/v1/store/credentials", body), 400);
    }

    #[actix_web::test]
    async fn only_the_issuer_can_revoke_a_credential() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(store_write_credential)
                    .service(store_revoke_credential),
            ),
        )
        .await;
        let issuer = registered_issuer(&state);
        assert_eq!(
            post!(&app, "/api/v1/store/credentials", issue_body(&issuer)),
            201
        );
        let stranger = registered_issuer(&state);
        let revoke = |by: &Issuer| {
            serde_json::json!({
                "revoked_at": 200,
                "issuer_public_key": by.public_key,
                "signature": sign(by, &credential_ops::revoke_message("cred-1", 200)),
            })
        };
        let uri = "/api/v1/store/credentials/cred-1/revoke";
        assert_eq!(post!(&app, uri, revoke(&stranger)), 401);
        assert_eq!(post!(&app, uri, revoke(&issuer)), 200);
        let store = get_channel_store(&state, "default").unwrap();
        assert_eq!(store.read_credential("cred-1").unwrap().status, "revoked");
    }
}
