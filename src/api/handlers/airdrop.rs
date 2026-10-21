//! Airdrop endpoints — tracking, statistics, eligibility, history, tiers.
//!
//! Endpoints:
//! - GET  /airdrop/tracking/{address}    — get node tracking info
//! - GET  /airdrop/statistics            — get airdrop statistics
//! - GET  /airdrop/eligible              — list eligible nodes
//! - GET  /airdrop/eligibility/{address} — get eligibility info without claiming
//! - GET  /airdrop/history               — get claim history
//! - GET  /airdrop/tiers                 — get available tiers

use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::app_state::AppState;
use actix_web::{get, web, HttpResponse};

/// GET /api/v1/airdrop/tracking/{address}
#[get("/airdrop/tracking/{address}")]
pub async fn get_node_tracking(
    state: web::Data<AppState>,
    address: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let tracking = state
        .airdrop_manager
        .get_node_tracking(&address)
        .ok_or(ApiError::NotFound {
            resource: format!("node_tracking:{address}"),
        })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(tracking, trace)))
}

/// GET /api/v1/airdrop/statistics
#[get("/airdrop/statistics")]
pub async fn get_airdrop_statistics(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let stats = state.airdrop_manager.get_statistics();
    Ok(HttpResponse::Ok().json(ApiResponse::success(stats, trace)))
}

/// GET /api/v1/airdrop/eligible
#[get("/airdrop/eligible")]
pub async fn get_eligible_nodes(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let nodes = state.airdrop_manager.get_eligible_nodes();
    Ok(HttpResponse::Ok().json(ApiResponse::success(nodes, trace)))
}

/// GET /api/v1/airdrop/eligibility/{address}
#[get("/airdrop/eligibility/{address}")]
pub async fn get_eligibility_info(
    state: web::Data<AppState>,
    address: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let info = state
        .airdrop_manager
        .get_eligibility_info(&address)
        .ok_or(ApiError::NotFound {
            resource: format!("node_tracking:{address}"),
        })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(info, trace)))
}

/// GET /api/v1/airdrop/history
#[get("/airdrop/history")]
pub async fn get_claim_history(
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let limit = query.get("limit").and_then(|s| s.parse::<u64>().ok());
    let node_address = query.get("node_address").map(|s| s.as_str());
    let history = state.airdrop_manager.get_claim_history(limit, node_address);
    Ok(HttpResponse::Ok().json(ApiResponse::success(history, trace)))
}

/// GET /api/v1/airdrop/tiers
#[get("/airdrop/tiers")]
pub async fn get_airdrop_tiers(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let tiers = state.airdrop_manager.get_tiers();
    Ok(HttpResponse::Ok().json(ApiResponse::success(tiers, trace)))
}
