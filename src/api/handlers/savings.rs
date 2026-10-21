use actix_web::{post, web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::get_channel_store;
use crate::api::handlers::transactions::{admit_signed_transaction, now_secs, SignedOperation};
use crate::app_state::AppState;
use crate::storage::traits::{Transaction, TxPayload};

#[derive(Debug, Deserialize)]
pub struct SavingsLockRequest {
    pub did: String,
    pub amount: u64,
    pub unlock_at: u64,
    pub nonce: u64,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SavingsReleaseRequest {
    pub did: String,
    pub lock_id: String,
    pub nonce: u64,
    pub signature: String,
}

fn vault_address(lock_id: &str) -> String {
    format!("savings:{lock_id}")
}

fn pending_transaction(
    input_did: &str,
    output_recipient: String,
    amount: u64,
    payload: TxPayload,
) -> Transaction {
    Transaction {
        id: uuid::Uuid::new_v4().to_string(),
        block_height: 0,
        timestamp: now_secs(),
        input_did: input_did.to_string(),
        output_recipient,
        amount,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(payload),
    }
}

#[post("/savings/lock")]
pub async fn lock_savings(
    state: web::Data<AppState>,
    req: web::Json<SavingsLockRequest>,
    http_req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &http_req,
    )?;
    if req.amount == 0 {
        return Err(ApiError::ValidationError {
            field: "amount".to_string(),
            reason: "amount must be greater than 0".to_string(),
        });
    }
    let now = now_secs();
    if req.unlock_at <= now {
        return Err(ApiError::ValidationError {
            field: "unlock_at".to_string(),
            reason: format!("unlock_at {} is not after node time {now}", req.unlock_at),
        });
    }
    let mut tx = pending_transaction(
        &req.did,
        String::new(),
        req.amount,
        TxPayload::SavingsLock {
            unlock_at: req.unlock_at,
            nonce: req.nonce,
        },
    );
    tx.output_recipient = vault_address(&tx.id);
    let operation = SignedOperation {
        signer: &req.did,
        message: format!(
            "savings_lock:{}:{}:{}:{}",
            req.did, req.amount, req.unlock_at, req.nonce
        ),
        signature: &req.signature,
        nonce: req.nonce,
    };
    let tx = admit_signed_transaction(&state, operation, tx)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Created().json(ApiResponse::success(tx, trace_id)))
}

#[post("/savings/release")]
pub async fn release_savings(
    state: web::Data<AppState>,
    req: web::Json<SavingsReleaseRequest>,
    http_req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &http_req,
    )?;
    let store = get_channel_store(&state, "default")?;
    let lock = store
        .read_transaction(&req.lock_id)
        .map_err(|e| ApiError::NotFound {
            resource: format!("savings lock {}: {e}", req.lock_id),
        })?;
    let Some(TxPayload::SavingsLock { unlock_at, .. }) = lock.payload else {
        return Err(ApiError::NotFound {
            resource: format!("savings lock {}: transaction is not a lock", req.lock_id),
        });
    };
    if lock.input_did != req.did {
        return Err(ApiError::Forbidden {
            reason: format!("savings lock {} belongs to {}", req.lock_id, lock.input_did),
        });
    }
    let now = now_secs();
    if now < unlock_at {
        return Err(ApiError::Forbidden {
            reason: format!(
                "savings lock {} is locked until {unlock_at}, node time is {now}",
                req.lock_id
            ),
        });
    }
    let vault = vault_address(&req.lock_id);
    let locked = store
        .calculate_balance(&vault)
        .map_err(|e| ApiError::StorageError {
            reason: format!("balance of {vault}: {e}"),
        })?;
    if locked == 0 {
        return Err(ApiError::Conflict {
            reason: format!("savings lock {} was already released", req.lock_id),
        });
    }
    let tx = pending_transaction(
        &vault,
        req.did.clone(),
        locked,
        TxPayload::SavingsRelease {
            owner: req.did.clone(),
            lock_id: req.lock_id.clone(),
            nonce: req.nonce,
        },
    );
    let operation = SignedOperation {
        signer: &req.did,
        message: format!("savings_release:{}:{}:{}", req.did, req.lock_id, req.nonce),
        signature: &req.signature,
        nonce: req.nonce,
    };
    let tx = admit_signed_transaction(&state, operation, tx)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Created().json(ApiResponse::success(tx, trace_id)))
}
