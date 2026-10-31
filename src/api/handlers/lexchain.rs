use actix_web::{get, post, web, HttpRequest, HttpResponse};

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult};
use crate::app_state::AppState;
use crate::lexchain::engine;
use crate::lexchain::types::{DeployRequest, LexContract, SignRequest, WebhookEvent};

fn fire_webhook(contract: &LexContract, event: &str) {
    let Some(ref url) = contract.definition.webhook_url else {
        return;
    };
    let payload = WebhookEvent {
        contract_id: contract.id.clone(),
        event: event.to_string(),
        state: contract.state,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let url = url.clone();
    tokio::spawn(async move {
        if let Err(e) = post_webhook(&url, &payload).await {
            log::warn!("webhook for contract {}: {e}", payload.contract_id);
        }
    });
}

async fn post_webhook(raw_url: &str, payload: &WebhookEvent) -> Result<(), String> {
    use crate::lexchain::webhook::{resolve_public_address, validate_webhook_url};
    let url = validate_webhook_url(raw_url)?;
    let address = resolve_public_address(&url).await?;
    let host = url.host_str().unwrap_or_default().to_string();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, address)
        .build()
        .map_err(|e| format!("webhook client for {raw_url}: {e}"))?;
    client
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("POST {raw_url}: {e}"))?;
    Ok(())
}

#[post("/lexchain/deploy")]
async fn deploy_contract(
    state: web::Data<AppState>,
    body: web::Json<DeployRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Deploy",
        &req,
    )?;
    let trace_id = uuid::Uuid::new_v4().to_string();

    let contract =
        engine::deploy_request(&state.lexchain_store, body.into_inner()).map_err(|e| {
            ApiError::ValidationError {
                field: "contract".into(),
                reason: e.to_string(),
            }
        })?;

    fire_webhook(&contract, "deployed");
    Ok(HttpResponse::Created().json(ApiResponse::success(contract, trace_id)))
}

#[post("/lexchain/{id}/sign")]
async fn sign_contract(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Sign",
        &req,
    )?;
    let contract_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let mut contract =
        engine::sign(&state.lexchain_store, &contract_id, &body).map_err(|e| match &e {
            engine::LexChainError::NotFound(_) => ApiError::NotFound {
                resource: format!("contract {contract_id}"),
            },
            _ => ApiError::ValidationError {
                field: "signature".into(),
                reason: e.to_string(),
            },
        })?;

    fire_webhook(&contract, "signed");

    if contract.all_signed() && contract.definition.require_notarization {
        if let Some(ref tsa) = state.tsa_provider {
            match engine::notarize(&state.lexchain_store, &contract_id, tsa) {
                Ok(notarized) => {
                    contract = notarized;
                    fire_webhook(&contract, "notarized");
                }
                Err(e) => log::warn!("auto-notarization failed: {e}"),
            }
        }
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(contract, trace_id)))
}

#[get("/lexchain/{id}")]
async fn get_contract(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Query",
        &req,
    )?;
    let contract_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let contract = state
        .lexchain_store
        .get(&contract_id)
        .ok_or_else(|| ApiError::NotFound {
            resource: format!("contract {contract_id}"),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(contract, trace_id)))
}

#[get("/lexchain")]
async fn list_contracts(state: web::Data<AppState>, req: HttpRequest) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Query",
        &req,
    )?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let contracts = state.lexchain_store.list();
    Ok(HttpResponse::Ok().json(ApiResponse::success(contracts, trace_id)))
}

#[get("/lexchain/templates")]
async fn list_templates(state: web::Data<AppState>, req: HttpRequest) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "lexchain/Query",
        &req,
    )?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let templates = state.lexchain_store.list_templates();
    Ok(HttpResponse::Ok().json(ApiResponse::success(templates, trace_id)))
}
