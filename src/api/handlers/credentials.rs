use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::{
    channel_id_from_req, enforce_channel_membership, get_channel_store,
};
use crate::app_state::AppState;
use actix_web::{get, post, web, HttpRequest, HttpResponse};

// ── Store-backed credential endpoints ────────────────────────────────────────

/// POST /api/v1/store/credentials — persiste un Credential en el store.
#[post("/store/credentials")]
pub async fn store_write_credential(
    state: web::Data<AppState>,
    body: web::Json<crate::storage::traits::Credential>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    super::validation::validate_store_credential(&body)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;

    // Validate issuer DID exists
    if store.read_identity(&body.issuer_did).is_err() {
        return Err(ApiError::ValidationError {
            field: "issuer_did".to_string(),
            reason: format!(
                "issuer DID '{}' not found — register identity before issuing credentials",
                body.issuer_did
            ),
        });
    }

    store
        .write_credential(&body)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::CredentialStored,
        req.headers()
            .get("X-Org-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown"),
        Some(format!("credential_id={}", body.id)),
    );
    Ok(HttpResponse::Created().json(ApiResponse::success(body.into_inner(), trace_id)))
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
}
