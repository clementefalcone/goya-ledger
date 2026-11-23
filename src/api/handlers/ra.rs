//! Registration Authority (RA) API handlers — Ley 19.799 Art. 15.

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use crate::identity::ra::{Jurisdiction, ProofingMethod, RaStore};
use actix_web::{get, post, web, HttpResponse};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn get_ra(state: &AppState) -> Result<&Arc<RaStore>, Box<HttpResponse>> {
    state.ra_store.as_ref().ok_or_else(|| {
        Box::new(
            HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                err_dto("RA_UNAVAILABLE", "Registration Authority is not configured"),
                503,
            )),
        )
    })
}

#[derive(Deserialize)]
pub struct ProofRequest {
    pub did: String,
    pub rut: String,
    pub legal_name: String,
    #[serde(default = "default_method")]
    pub method: ProofingMethod,
}

fn default_method() -> ProofingMethod {
    ProofingMethod::InPerson
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub officer_did: String,
}

#[derive(Deserialize)]
pub struct RejectRequest {
    pub officer_did: String,
    pub reason: String,
}

/// Submit an identity proofing request.
#[post("/identity/proof")]
pub async fn submit_proof(
    state: web::Data<AppState>,
    body: web::Json<ProofRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let ra = match get_ra(&state) {
        Ok(r) => r,
        Err(resp) => return Ok(*resp),
    };

    match ra.submit(
        body.did.clone(),
        body.rut.clone(),
        body.legal_name.clone(),
        body.method,
        now_secs(),
    ) {
        Ok(proofing) => Ok(HttpResponse::Created().json(ApiResponse::success(proofing, trace))),
        Err(msg) => Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(err_dto("PROOF_ERROR", &msg), 400))),
    }
}

/// Approve a pending proofing request (RA officer action).
#[post("/identity/proof/{did}/approve")]
pub async fn approve_proof(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ApproveRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let did = path.into_inner();
    let ra = match get_ra(&state) {
        Ok(r) => r,
        Err(resp) => return Ok(*resp),
    };

    match ra.approve(&did, &body.officer_did, now_secs()) {
        Ok(proofing) => Ok(HttpResponse::Ok().json(ApiResponse::success(proofing, trace))),
        Err(msg) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("APPROVE_ERROR", &msg),
            400,
        ))),
    }
}

/// Reject a pending proofing request (RA officer action).
#[post("/identity/proof/{did}/reject")]
pub async fn reject_proof(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RejectRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let did = path.into_inner();
    let ra = match get_ra(&state) {
        Ok(r) => r,
        Err(resp) => return Ok(*resp),
    };

    match ra.reject(&did, &body.officer_did, &body.reason, now_secs()) {
        Ok(proofing) => Ok(HttpResponse::Ok().json(ApiResponse::success(proofing, trace))),
        Err(msg) => Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(err_dto("REJECT_ERROR", &msg), 400))),
    }
}

/// Get proofing status for a DID.
#[get("/identity/proof/{did}")]
pub async fn get_proof_status(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let did = path.into_inner();
    let ra = match get_ra(&state) {
        Ok(r) => r,
        Err(resp) => return Ok(*resp),
    };

    match ra.get(&did) {
        Some(proofing) => Ok(HttpResponse::Ok().json(ApiResponse::success(proofing, trace))),
        None => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "no proofing request found for this DID"),
            404,
        ))),
    }
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub did: String,
    pub national_id: String,
    pub legal_name: String,
    #[serde(default = "default_jurisdiction")]
    pub jurisdiction: Jurisdiction,
}

fn default_jurisdiction() -> Jurisdiction {
    Jurisdiction::Eu
}

#[post("/identity/verify")]
pub async fn verify_identity(
    state: web::Data<AppState>,
    body: web::Json<VerifyRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let ra = match get_ra(&state) {
        Ok(r) => r.clone(),
        Err(resp) => return Ok(*resp),
    };
    let verifier = match &state.identity_verifier {
        Some(v) => v.clone(),
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto(
                        "VERIFIER_UNAVAILABLE",
                        "identity verification provider not configured",
                    ),
                    503,
                )),
            );
        }
    };

    let did = body.did.clone();
    let national_id = body.national_id.clone();
    let legal_name = body.legal_name.clone();
    let jurisdiction = body.jurisdiction;

    let result = web::block(move || {
        ra.submit_and_verify(
            did,
            national_id,
            legal_name,
            jurisdiction,
            now_secs(),
            verifier.as_ref(),
        )
    })
    .await
    .map_err(|e| crate::api::errors::ApiError::StorageError {
        reason: format!("verification task failed: {e}"),
    })?;

    match result {
        Ok((proofing, vr)) => {
            let resp = serde_json::json!({
                "proofing": proofing,
                "verification": vr,
            });
            Ok(HttpResponse::Ok().json(ApiResponse::success(resp, trace)))
        }
        Err(msg) => Ok(HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error(err_dto("VERIFY_ERROR", &msg), 400))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use actix_web::{test, web, App};

    fn make_ra_state() -> web::Data<AppState> {
        let mut state = AppState::test_default();
        state.ra_store = Some(Arc::new(RaStore::new()));
        state.identity_verifier = Some(Arc::new(crate::identity::ra::SimulatedIdentityVerifier));
        web::Data::new(state)
    }

    macro_rules! ra_app {
        ($state:expr) => {
            test::init_service(
                App::new().app_data($state).service(
                    web::scope("/api/v1")
                        .service(submit_proof)
                        .service(approve_proof)
                        .service(reject_proof)
                        .service(get_proof_status)
                        .service(verify_identity),
                ),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn e2e_submit_approve_flow() {
        let state = make_ra_state();
        let app = ra_app!(state);

        // Submit
        let req = test::TestRequest::post()
            .uri("/api/v1/identity/proof")
            .set_json(serde_json::json!({
                "did": "did:goya:subscriber1",
                "rut": "12.345.678-5",
                "legal_name": "Juan Pérez",
                "method": "in_person",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["status"], "pending");
        assert_eq!(body["data"]["rut"], "12345678-5");

        // Approve
        let req = test::TestRequest::post()
            .uri("/api/v1/identity/proof/did:goya:subscriber1/approve")
            .set_json(serde_json::json!({
                "officer_did": "did:goya:officer",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["status"], "verified");
        assert_eq!(body["data"]["resolved_by"], "did:goya:officer");

        // Check status
        let req = test::TestRequest::get()
            .uri("/api/v1/identity/proof/did:goya:subscriber1")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["status"], "verified");
    }

    #[actix_web::test]
    async fn e2e_submit_reject_flow() {
        let state = make_ra_state();
        let app = ra_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/proof")
            .set_json(serde_json::json!({
                "did": "did:goya:sub2",
                "rut": "11111111-1",
                "legal_name": "María López",
            }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/proof/did:goya:sub2/reject")
            .set_json(serde_json::json!({
                "officer_did": "did:goya:officer",
                "reason": "document expired",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["status"], "rejected");
        assert_eq!(body["data"]["rejection_reason"], "document expired");
    }

    #[actix_web::test]
    async fn e2e_invalid_rut_rejected() {
        let state = make_ra_state();
        let app = ra_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/proof")
            .set_json(serde_json::json!({
                "did": "did:goya:sub3",
                "rut": "12345678-0",
                "legal_name": "Bad RUT",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "PROOF_ERROR");
    }

    #[actix_web::test]
    async fn e2e_404_unknown_did() {
        let state = make_ra_state();
        let app = ra_app!(state);

        let req = test::TestRequest::get()
            .uri("/api/v1/identity/proof/did:goya:unknown")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn e2e_503_when_ra_not_configured() {
        let state = web::Data::new(AppState::test_default());
        let app = ra_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/proof")
            .set_json(serde_json::json!({
                "did": "did:goya:sub",
                "rut": "12345678-5",
                "legal_name": "Test",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn e2e_verify_identity_success() {
        let state = make_ra_state();
        let app = ra_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/verify")
            .set_json(serde_json::json!({
                "did": "did:goya:verified1",
                "national_id": "12345678-5",
                "legal_name": "Juan Pérez",
                "jurisdiction": "chile",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verification"]["verified"], true);
        assert_eq!(body["data"]["verification"]["provider_name"], "simulated");
        assert_eq!(body["data"]["proofing"]["status"], "verified");
    }

    #[actix_web::test]
    async fn e2e_verify_identity_invalid_id_stays_pending() {
        let state = make_ra_state();
        let app = ra_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/verify")
            .set_json(serde_json::json!({
                "did": "did:goya:failed1",
                "national_id": "00000000-0",
                "legal_name": "Bad ID",
                "jurisdiction": "chile",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verification"]["verified"], false);
        assert_eq!(body["data"]["proofing"]["status"], "pending");
    }

    #[actix_web::test]
    async fn e2e_verify_identity_eu_jurisdiction() {
        let state = make_ra_state();
        let app = ra_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/identity/verify")
            .set_json(serde_json::json!({
                "did": "did:goya:euuser1",
                "national_id": "DE-1234567890",
                "legal_name": "Hans Mueller",
                "jurisdiction": "eu",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verification"]["verified"], true);
        assert_eq!(body["data"]["proofing"]["loa"], "substantial");
    }
}
