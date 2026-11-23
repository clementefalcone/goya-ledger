//! Trust Service List (TSL) API handler — ETSI TS 119 612.

use crate::api::errors::{ApiResponse, ApiResult};
use crate::tsl;
use actix_web::{get, web, HttpResponse};
use std::time::{SystemTime, UNIX_EPOCH};

/// Get the Trust Service List for this node.
#[get("/tsl")]
pub async fn get_tsl(state: web::Data<crate::app_state::AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let node_signing_algorithm = state
        .signing_provider
        .as_ref()
        .map(|provider| provider.algorithm());
    let list = tsl::build_tsl(now, node_signing_algorithm);
    Ok(HttpResponse::Ok().json(ApiResponse::success(list, trace)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn e2e_get_tsl() {
        let state = web::Data::new(AppState::test_default());
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(get_tsl)),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/v1/tsl").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["operator"], "Goya Ledger");
        assert_eq!(body["data"]["services"].as_array().unwrap().len(), 5);
    }
}
