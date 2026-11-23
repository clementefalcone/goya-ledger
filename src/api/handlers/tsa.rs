//! TSA (Time Stamping Authority) API handlers — RFC 3161.

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use crate::tsa::{TimeStampRequest, TsaProvider};
use actix_web::{get, post, web, HttpResponse};
use std::sync::Arc;

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn get_tsa(state: &AppState) -> Result<&Arc<TsaProvider>, Box<HttpResponse>> {
    state.tsa_provider.as_ref().ok_or_else(|| {
        Box::new(
            HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                err_dto("TSA_UNAVAILABLE", "TSA service is not configured"),
                503,
            )),
        )
    })
}

/// Request a timestamp token for a content hash.
#[post("/tsa/timestamp")]
pub async fn request_timestamp(
    state: web::Data<AppState>,
    body: web::Json<TimeStampRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    let tsa = match get_tsa(&state) {
        Ok(t) => t,
        Err(resp) => return Ok(*resp),
    };

    let resp = tsa.issue(&body);

    if resp.status != 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("TSA_REJECTED", &resp.status_string),
            400,
        )));
    }

    if let Some(token) = &resp.token {
        crate::audit::emit_if_present(
            &state.audit_store,
            crate::audit::AuditAction::TimestampIssued,
            "",
            Some(format!("serial={}", token.tst_info.serial_number)),
        );
    }

    Ok(HttpResponse::Created().json(ApiResponse::success(resp.token, trace)))
}

/// Get TSA policy information.
#[get("/tsa/policy")]
pub async fn tsa_policy(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    let tsa = match get_tsa(&state) {
        Ok(t) => t,
        Err(resp) => return Ok(*resp),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(tsa.policy_info(), trace)))
}

/// Request a DER-encoded RFC 3161 TimeStampResp (binary).
#[post("/tsa/timestamp/der")]
pub async fn request_timestamp_der(
    state: web::Data<AppState>,
    body: web::Json<TimeStampRequest>,
) -> ApiResult<HttpResponse> {
    let tsa = match get_tsa(&state) {
        Ok(t) => t,
        Err(resp) => return Ok(*resp),
    };

    match tsa.issue_der(&body) {
        Ok(der) => {
            crate::audit::emit_if_present(
                &state.audit_store,
                crate::audit::AuditAction::TimestampIssued,
                "",
                Some("format=der".to_string()),
            );
            Ok(HttpResponse::Created()
                .content_type("application/timestamp-reply")
                .body(der))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("TSA_REJECTED", &e.to_string()),
            400,
        ))),
    }
}

/// Verify a timestamp token's signature.
#[post("/tsa/verify")]
pub async fn verify_timestamp(
    body: web::Json<crate::tsa::TimeStampToken>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let valid = crate::tsa::verify_token(&body);

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "valid": valid,
            "serial_number": body.tst_info.serial_number,
            "gen_time": body.tst_info.gen_time,
            "message_imprint": body.tst_info.message_imprint,
            "tsa_name": body.tst_info.tsa_name,
            "signature_algorithm": body.signature_algorithm,
        }),
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::identity::signing::SoftwareSigningProvider;
    use actix_web::{test, web, App};

    fn make_tsa_state() -> web::Data<AppState> {
        let mut state = AppState::test_default();
        let signer = Arc::new(SoftwareSigningProvider::generate());
        state.tsa_provider = Some(Arc::new(TsaProvider::new(
            signer,
            "did:goya:tsa-test".to_string(),
        )));
        web::Data::new(state)
    }

    fn valid_imprint() -> String {
        use crate::crypto::hasher::{hash_with, HashAlgorithm};
        hex::encode(hash_with(HashAlgorithm::Sha256, b"test data"))
    }

    macro_rules! tsa_app {
        ($state:expr) => {
            test::init_service(
                App::new().app_data($state).service(
                    web::scope("/api/v1")
                        .service(request_timestamp)
                        .service(request_timestamp_der)
                        .service(tsa_policy)
                        .service(verify_timestamp),
                ),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn e2e_request_timestamp_and_verify() {
        let state = make_tsa_state();
        let app = tsa_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp")
            .set_json(serde_json::json!({
                "message_imprint": valid_imprint(),
                "nonce": 42,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let token = &body["data"];
        assert_eq!(token["tst_info"]["version"], 1);
        assert_eq!(token["tst_info"]["nonce"], 42);
        assert!(!token["signature"].as_str().unwrap().is_empty());

        // Verify the token
        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/verify")
            .set_json(&body["data"])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let verify_body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(verify_body["data"]["valid"], true);
    }

    #[actix_web::test]
    async fn e2e_policy_endpoint() {
        let state = make_tsa_state();
        let app = tsa_app!(state);

        let req = test::TestRequest::get()
            .uri("/api/v1/tsa/policy")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["policy_oid"], crate::tsa::TSA_POLICY_OID);
    }

    #[actix_web::test]
    async fn e2e_rejects_invalid_imprint() {
        let state = make_tsa_state();
        let app = tsa_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp")
            .set_json(serde_json::json!({
                "message_imprint": "tooshort",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_503_when_tsa_not_configured() {
        let state = web::Data::new(AppState::test_default());
        let app = tsa_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp")
            .set_json(serde_json::json!({
                "message_imprint": valid_imprint(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn e2e_request_timestamp_der() {
        let state = make_tsa_state();
        let app = tsa_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp/der")
            .set_json(serde_json::json!({
                "message_imprint": valid_imprint(),
                "nonce": 77,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/timestamp-reply"
        );
        let body = test::read_body(resp).await;
        assert_eq!(body[0], 0x30, "DER must start with SEQUENCE");
        assert!(body.len() > 50);
    }

    #[actix_web::test]
    async fn e2e_tampered_token_fails_verify() {
        let state = make_tsa_state();
        let app = tsa_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp")
            .set_json(serde_json::json!({
                "message_imprint": valid_imprint(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let mut token = body["data"].clone();
        token["tst_info"]["serial_number"] = serde_json::json!(999999);

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/verify")
            .set_json(&token)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let verify_body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(verify_body["data"]["valid"], false);
    }

    #[actix_web::test]
    async fn e2e_timestamp_emits_audit_event() {
        let state = make_tsa_state();
        let app = tsa_app!(state.clone());

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp")
            .set_json(serde_json::json!({
                "message_imprint": valid_imprint(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let audit = state
            .audit_store
            .as_ref()
            .unwrap()
            .query(
                None,
                None,
                None,
                Some(&crate::audit::AuditAction::TimestampIssued),
                100,
            )
            .unwrap();
        assert!(!audit.is_empty(), "TimestampIssued event must be emitted");
        assert!(audit[0].metadata.as_deref().unwrap().contains("serial="));
    }

    #[actix_web::test]
    async fn e2e_timestamp_der_emits_audit_event() {
        let state = make_tsa_state();
        let app = tsa_app!(state.clone());

        let req = test::TestRequest::post()
            .uri("/api/v1/tsa/timestamp/der")
            .set_json(serde_json::json!({
                "message_imprint": valid_imprint(),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let audit = state
            .audit_store
            .as_ref()
            .unwrap()
            .query(
                None,
                None,
                None,
                Some(&crate::audit::AuditAction::TimestampIssued),
                100,
            )
            .unwrap();
        assert!(!audit.is_empty());
        assert!(audit[0].metadata.as_deref().unwrap().contains("format=der"));
    }
}
