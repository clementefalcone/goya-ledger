//! Staking endpoints — validator registration, unstaking, and queries.
//!
//! Endpoints:
//! - GET  /staking/validators         — list active validators
//! - GET  /staking/validator/{address} — get validator info
//! - GET  /staking/my-stake/{address}  — get own stake info

use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::app_state::AppState;
use actix_web::{get, web, HttpResponse};

/// GET /api/v1/staking/validators
#[get("/staking/validators")]
pub async fn get_validators(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let validators = state.staking_manager.get_active_validators();
    Ok(HttpResponse::Ok().json(ApiResponse::success(validators, trace)))
}

/// GET /api/v1/staking/validator/{address}
#[get("/staking/validator/{address}")]
pub async fn get_validator(
    state: web::Data<AppState>,
    address: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    match state.staking_manager.get_validator(&address) {
        Some(validator) => Ok(HttpResponse::Ok().json(ApiResponse::success(validator, trace))),
        None => Err(ApiError::NotFound {
            resource: format!("validator:{address}"),
        }),
    }
}

/// GET /api/v1/staking/my-stake/{address}
#[get("/staking/my-stake/{address}")]
pub async fn get_my_stake(
    state: web::Data<AppState>,
    address: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    match state.staking_manager.get_validator(&address) {
        Some(validator) => Ok(HttpResponse::Ok().json(ApiResponse::success(validator, trace))),
        None => Err(ApiError::NotFound {
            resource: format!("stake:{address}"),
        }),
    }
}
