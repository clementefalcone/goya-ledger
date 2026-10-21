use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SavingsStatus {
    Pending,
    Locked,
    Unlockable,
    Released,
}

#[derive(Debug, Serialize)]
pub struct SavingsEntry {
    pub lock_id: String,
    pub amount: u64,
    pub locked_amount: u64,
    pub unlock_at: u64,
    pub locked_at: u64,
    pub status: SavingsStatus,
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

fn savings_entry(lock: &Transaction, locked_amount: u64, is_pending: bool) -> Option<SavingsEntry> {
    let Some(TxPayload::SavingsLock { unlock_at, .. }) = lock.payload else {
        return None;
    };
    let status = match (is_pending, locked_amount, now_secs() >= unlock_at) {
        (true, _, _) => SavingsStatus::Pending,
        (false, 0, _) => SavingsStatus::Released,
        (false, _, true) => SavingsStatus::Unlockable,
        (false, _, false) => SavingsStatus::Locked,
    };
    Some(SavingsEntry {
        lock_id: lock.id.clone(),
        amount: lock.amount,
        locked_amount,
        unlock_at,
        locked_at: lock.timestamp,
        status,
    })
}

#[get("/savings/{did}")]
pub async fn list_savings(
    state: web::Data<AppState>,
    did: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let store = get_channel_store(&state, "default")?;
    let owned_by_did = |tx: &&Transaction| tx.input_did == did.as_str();
    let mut entries = store
        .transactions_for_address(&did)
        .map_err(|e| ApiError::StorageError {
            reason: format!("transactions of {did}: {e}"),
        })?
        .iter()
        .filter(owned_by_did)
        .filter_map(|lock| {
            let locked = store.calculate_balance(&vault_address(&lock.id)).ok()?;
            savings_entry(lock, locked, false)
        })
        .collect::<Vec<_>>();
    let pending = state
        .tx_pool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .all()
        .iter()
        .filter(owned_by_did)
        .filter_map(|lock| savings_entry(lock, lock.amount, true))
        .collect::<Vec<_>>();
    entries.extend(pending);
    let trace_id = uuid::Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok().json(ApiResponse::success(entries, trace_id)))
}
