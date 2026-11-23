//! OCSP responder API handlers — RFC 6960 semantics.

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use crate::msp::ocsp::{OcspRequest, OcspResponder};
use crate::msp::ocsp_der::encode_ocsp_response_der;
use actix_web::{get, post, web, HttpResponse};
use std::sync::Arc;

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn get_ocsp(state: &AppState) -> Result<&Arc<OcspResponder>, Box<HttpResponse>> {
    state.ocsp_responder.as_ref().ok_or_else(|| {
        Box::new(
            HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                err_dto("OCSP_UNAVAILABLE", "OCSP responder is not configured"),
                503,
            )),
        )
    })
}

/// Query certificate status via OCSP.
#[post("/ocsp/query")]
pub async fn ocsp_query(
    state: web::Data<AppState>,
    body: web::Json<OcspRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let ocsp = match get_ocsp(&state) {
        Ok(o) => o,
        Err(resp) => return Ok(*resp),
    };
    let crl_store = match state.crl_store.as_ref() {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("CRL_UNAVAILABLE", "CRL store is not configured"),
                    503,
                )),
            );
        }
    };

    let resp = ocsp.query(&body, crl_store.as_ref());

    if resp.response_status != 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "OCSP_ERROR",
                &format!("response_status: {}", resp.response_status),
            ),
            400,
        )));
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(resp, trace)))
}

/// Direct certificate status lookup by MSP ID and serial.
#[get("/ocsp/status/{msp_id}/{serial}")]
pub async fn ocsp_status(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let (msp_id, serial) = path.into_inner();
    let ocsp = match get_ocsp(&state) {
        Ok(o) => o,
        Err(resp) => return Ok(*resp),
    };
    let crl_store = match state.crl_store.as_ref() {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("CRL_UNAVAILABLE", "CRL store is not configured"),
                    503,
                )),
            );
        }
    };

    let req = OcspRequest {
        msp_id,
        serial,
        nonce: None,
    };
    let resp = ocsp.query(&req, crl_store.as_ref());

    if resp.response_status != 0 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "OCSP_ERROR",
                &format!("response_status: {}", resp.response_status),
            ),
            400,
        )));
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(resp, trace)))
}

/// Query certificate status and return DER-encoded OCSPResponse (RFC 6960).
#[post("/ocsp/query/der")]
pub async fn ocsp_query_der(
    state: web::Data<AppState>,
    body: web::Json<OcspRequest>,
) -> ApiResult<HttpResponse> {
    let ocsp = match get_ocsp(&state) {
        Ok(o) => o,
        Err(resp) => return Ok(*resp),
    };
    let crl_store = match state.crl_store.as_ref() {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("CRL_UNAVAILABLE", "CRL store is not configured"),
                    503,
                )),
            );
        }
    };

    let resp = ocsp.query(&body, crl_store.as_ref());

    let signer = match state.signing_provider.as_ref() {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("SIGNER_UNAVAILABLE", "Signing provider is not configured"),
                    503,
                )),
            );
        }
    };

    match encode_ocsp_response_der(&resp, signer.as_ref()) {
        Ok(der) => Ok(HttpResponse::Ok()
            .content_type("application/ocsp-response")
            .body(der)),
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                err_dto("OCSP_DER_ERROR", &e.to_string()),
                500,
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::identity::signing::SoftwareSigningProvider;
    use crate::msp::{CrlStore, MemoryCrlStore};
    use actix_web::{test, web, App};

    fn make_ocsp_state(revoked_serials: &[&str]) -> web::Data<AppState> {
        let mut state = AppState::test_default();
        let signer = Arc::new(SoftwareSigningProvider::generate());
        state.ocsp_responder = Some(Arc::new(OcspResponder::new(
            signer.clone(),
            "did:goya:ocsp-test".into(),
        )));
        state.signing_provider = Some(signer);
        let crl = Arc::new(MemoryCrlStore::new());
        let serials: Vec<String> = revoked_serials.iter().map(|s| s.to_string()).collect();
        crl.write_crl("msp1", &serials).unwrap();
        state.crl_store = Some(crl);
        web::Data::new(state)
    }

    macro_rules! ocsp_app {
        ($state:expr) => {
            test::init_service(
                App::new().app_data($state).service(
                    web::scope("/api/v1")
                        .service(ocsp_query)
                        .service(ocsp_status),
                ),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn e2e_query_good() {
        let state = make_ocsp_state(&[]);
        let app = ocsp_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/ocsp/query")
            .set_json(serde_json::json!({
                "msp_id": "msp1",
                "serial": hex::encode([1u8; 8]),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["response"]["status"], "good");
    }

    #[actix_web::test]
    async fn e2e_query_revoked() {
        let serial = hex::encode([2u8; 8]);
        let state = make_ocsp_state(&[&serial]);
        let app = ocsp_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/ocsp/query")
            .set_json(serde_json::json!({
                "msp_id": "msp1",
                "serial": serial,
                "nonce": 42,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["response"]["status"], "revoked");
        assert_eq!(body["data"]["nonce"], 42);
    }

    #[actix_web::test]
    async fn e2e_status_endpoint() {
        let state = make_ocsp_state(&[]);
        let app = ocsp_app!(state);
        let serial = hex::encode([1u8; 8]);

        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/ocsp/status/msp1/{serial}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["response"]["status"], "good");
    }

    #[actix_web::test]
    async fn e2e_503_when_not_configured() {
        let state = web::Data::new(AppState::test_default());
        let app = ocsp_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/ocsp/query")
            .set_json(serde_json::json!({
                "msp_id": "msp1",
                "serial": hex::encode([1u8; 8]),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn e2e_bad_request_empty_serial() {
        let state = make_ocsp_state(&[]);
        let app = ocsp_app!(state);

        let req = test::TestRequest::post()
            .uri("/api/v1/ocsp/query")
            .set_json(serde_json::json!({
                "msp_id": "msp1",
                "serial": "",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_query_der_returns_binary() {
        let state = make_ocsp_state(&[]);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(ocsp_query_der)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/ocsp/query/der")
            .set_json(serde_json::json!({
                "msp_id": "msp1",
                "serial": hex::encode([1u8; 8]),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("application/ocsp-response"));
        let body = test::read_body(resp).await;
        assert_eq!(body[0], 0x30, "DER must start with SEQUENCE tag");
    }
}
