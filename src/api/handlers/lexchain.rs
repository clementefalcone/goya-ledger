use actix_web::{get, post, web, HttpResponse};

use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::identity::{commit_ledger_op, now_secs};
use crate::api::handlers::oid4vci::SIGNED_REQUEST_FRESHNESS_SECS;
use crate::app_state::AppState;
use crate::identity::operations::is_signed_by;
use crate::lexchain::engine;
use crate::lexchain::types::{DeployRequest, LexContract, SignRequest, WebhookEvent};
use crate::storage::traits::TxPayload;

const LEXCHAIN_CHANNEL: &str = "default";

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
) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();

    let contract = engine::draft_request(&state.lexchain_store, body.into_inner())
        .and_then(|contract| {
            engine::check_deploy(state.lexchain_store.backend(), &contract)?;
            Ok(contract)
        })
        .map_err(|e| ApiError::ValidationError {
            field: "contract".into(),
            reason: e.to_string(),
        })?;
    commit_ledger_op(
        &state,
        state.lexchain_store.backend(),
        LEXCHAIN_CHANNEL,
        &contract.id,
        TxPayload::DeployContract {
            contract: Box::new(contract.public_view()),
        },
    )?;
    state
        .lexchain_store
        .save(contract.clone())
        .map_err(|e| ApiError::StorageError {
            reason: format!(
                "terms of contract {} not kept on this node: {e}",
                contract.id
            ),
        })?;

    fire_webhook(&contract, "deployed");
    Ok(HttpResponse::Created().json(ApiResponse::success(contract, trace_id)))
}

#[post("/lexchain/{id}/sign")]
async fn sign_contract(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<SignRequest>,
) -> ApiResult<HttpResponse> {
    let contract_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();

    let envelope = engine::prepare_signature(&state.lexchain_store, &contract_id, &body).map_err(
        |e| match &e {
            engine::LexChainError::NotFound(_) => ApiError::NotFound {
                resource: format!("contract {contract_id}"),
            },
            _ => ApiError::ValidationError {
                field: "signature".into(),
                reason: e.to_string(),
            },
        },
    )?;
    commit_ledger_op(
        &state,
        state.lexchain_store.backend(),
        LEXCHAIN_CHANNEL,
        &envelope.signer.clone(),
        TxPayload::SignContract {
            contract_id: contract_id.clone(),
            envelope: Box::new(envelope),
        },
    )?;
    let mut contract =
        state
            .lexchain_store
            .get(&contract_id)
            .ok_or_else(|| ApiError::NotFound {
                resource: format!("contract {contract_id}"),
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

pub fn read_message(contract_id: &str, issued_at: u64) -> String {
    format!("lexchain:read:{contract_id}:{issued_at}")
}

#[derive(serde::Deserialize)]
pub struct PartyReadQuery {
    did: String,
    issued_at: u64,
    signature: String,
}

fn is_party_read(
    state: &AppState,
    contract: &LexContract,
    query: &PartyReadQuery,
) -> Result<bool, ApiError> {
    if contract.party_by_did(&query.did).is_none() {
        return Ok(false);
    }
    if now_secs().abs_diff(query.issued_at) > SIGNED_REQUEST_FRESHNESS_SECS {
        return Err(ApiError::UnauthorizedWithMessage {
            message: format!(
                "issued_at {} is more than {SIGNED_REQUEST_FRESHNESS_SECS} s from now",
                query.issued_at
            ),
        });
    }
    let public_key = state
        .lexchain_store
        .backend()
        .read_identity(&query.did)
        .map_err(|_| ApiError::UnauthorizedWithMessage {
            message: format!("{} is not a registered DID", query.did),
        })?
        .public_key;
    Ok(is_signed_by(
        &public_key,
        &read_message(&contract.id, query.issued_at),
        &query.signature,
    ))
}

#[get("/lexchain/{id}")]
async fn get_contract(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: Option<web::Query<PartyReadQuery>>,
) -> ApiResult<HttpResponse> {
    let contract_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let contract = state
        .lexchain_store
        .get(&contract_id)
        .ok_or_else(|| ApiError::NotFound {
            resource: format!("contract {contract_id}"),
        })?;
    let Some(query) = query else {
        return Ok(HttpResponse::Ok().json(ApiResponse::success(contract.public_view(), trace_id)));
    };
    if !is_party_read(&state, &contract, &query)? {
        return Err(ApiError::UnauthorizedWithMessage {
            message: format!(
                "only a party of {contract_id} signing lexchain:read:{contract_id}:{{issued_at}} reads its terms"
            ),
        });
    }
    Ok(HttpResponse::Ok().json(ApiResponse::success(contract, trace_id)))
}

#[get("/lexchain")]
async fn list_contracts(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let contracts: Vec<LexContract> = state
        .lexchain_store
        .list()
        .iter()
        .map(LexContract::public_view)
        .collect();
    Ok(HttpResponse::Ok().json(ApiResponse::success(contracts, trace_id)))
}

#[get("/lexchain/templates")]
async fn list_templates(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let templates = state.lexchain_store.list_templates();
    Ok(HttpResponse::Ok().json(ApiResponse::success(templates, trace_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
    use actix_web::{test, App};

    #[actix_web::test]
    async fn deploy_and_signature_are_queued_for_the_chain() {
        let state = web::Data::new(AppState::test_default());
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(deploy_contract)
                .service(sign_contract)
                .service(get_contract),
        )
        .await;
        let alice = SoftwareSigningProvider::generate();
        let public_key = hex::encode(alice.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        state
            .lexchain_store
            .backend()
            .write_identity(&crate::storage::traits::IdentityRecord {
                did: did.clone(),
                public_key: public_key.clone(),
                created_at: 0,
                updated_at: 0,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            })
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/lexchain/deploy")
            .set_json(serde_json::json!({
                "type": "nda",
                "parties": [{ "role": "discloser", "did": did, "signature_level": "simple" }],
                "payload": { "terms": "keep it quiet" },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let contract_id = body["data"]["id"].as_str().unwrap().to_string();
        let content_hash = body["data"]["content_hash"].as_str().unwrap().to_string();

        let signature = alice
            .sign(format!("fes:{did}:{content_hash}").as_bytes())
            .unwrap();
        let req = test::TestRequest::post()
            .uri(&format!("/lexchain/{contract_id}/sign"))
            .set_json(serde_json::json!({
                "did": did, "public_key": public_key, "signature": hex::encode(signature),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let queued: Vec<&str> = state
            .tx_pool
            .lock()
            .unwrap()
            .all()
            .iter()
            .filter_map(|tx| match &tx.payload {
                Some(TxPayload::DeployContract { contract }) => {
                    assert_eq!(contract.definition.payload, serde_json::Value::Null);
                    assert!(contract.payload_salt.is_none());
                    Some("deploy")
                }
                Some(TxPayload::SignContract { .. }) => Some("sign"),
                _ => None,
            })
            .collect();
        assert_eq!(queued, ["deploy", "sign"]);

        let read = |did: &str, key: &SoftwareSigningProvider| {
            let issued_at = now_secs();
            let signature = key
                .sign(read_message(&contract_id, issued_at).as_bytes())
                .unwrap();
            test::TestRequest::get()
                .uri(&format!(
                    "/lexchain/{contract_id}?did={did}&issued_at={issued_at}&signature={}",
                    hex::encode(signature)
                ))
                .to_request()
        };
        let public: serde_json::Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::get()
                .uri(&format!("/lexchain/{contract_id}"))
                .to_request(),
        )
        .await;
        assert_eq!(
            public["data"]["definition"]["payload"],
            serde_json::Value::Null
        );
        let party: serde_json::Value =
            test::call_and_read_body_json(&app, read(&did, &alice)).await;
        assert_eq!(
            party["data"]["definition"]["payload"]["terms"],
            "keep it quiet"
        );
        let impostor = SoftwareSigningProvider::generate();
        let resp = test::call_service(&app, read(&did, &impostor)).await;
        assert_eq!(resp.status(), 401);
    }
}
