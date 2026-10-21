//! POST /transactions and GET /mempool (gateway envelope).

use actix_web::{get, post, web, HttpRequest, HttpResponse};

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::{
    channel_id_from_req, enforce_channel_membership, get_channel_store,
};
use crate::api::models::CreateTransactionRequest;
use crate::app_state::AppState;
use crate::storage::traits::{BlockStore, Transaction, TxPayload};

use super::validation::validate_store_transaction;

const MINT_ACCOUNT: &str = "0";

pub(crate) struct SignedOperation<'a> {
    pub signer: &'a str,
    pub message: String,
    pub signature: &'a str,
    pub nonce: u64,
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn verify_account_signature(
    store: &dyn BlockStore,
    did: &str,
    message: &str,
    signature: &str,
) -> Result<(), ApiError> {
    let identity = store.read_identity(did).map_err(|e| ApiError::NotFound {
        resource: format!("identity {did}: {e}"),
    })?;
    if identity.status != "active" {
        return Err(ApiError::Forbidden {
            reason: format!("identity {did} is {}", identity.status),
        });
    }
    let algorithm = crate::signature::verify::infer_algorithm_from_key(&identity.public_key)
        .ok_or_else(|| ApiError::UnauthorizedWithMessage {
            message: format!("identity {did} has no usable public key"),
        })?;
    if !crate::signature::verify_signature(
        algorithm,
        &identity.public_key,
        message.as_bytes(),
        signature,
    ) {
        return Err(ApiError::UnauthorizedWithMessage {
            message: format!("{algorithm} signature over \"{message}\" does not verify for {did}"),
        });
    }
    Ok(())
}

fn committed_nonce(store: &dyn BlockStore, author: &str) -> u64 {
    store
        .transactions_for_address(author)
        .unwrap_or_default()
        .iter()
        .filter(|tx| tx.signed_author() == Some(author))
        .count() as u64
}

fn pending_nonce(pool: &crate::transaction::mempool::TransactionPool, author: &str) -> u64 {
    pool.all()
        .iter()
        .filter(|tx| tx.signed_author() == Some(author))
        .count() as u64
}

pub(crate) fn account_nonce(state: &AppState, author: &str) -> Result<u64, ApiError> {
    let store = get_channel_store(state, "default")?;
    let pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
    Ok(committed_nonce(store.as_ref(), author) + pending_nonce(&pool, author))
}

pub(crate) fn admit_signed_transaction(
    state: &AppState,
    operation: SignedOperation,
    tx: Transaction,
) -> Result<Transaction, ApiError> {
    let store = get_channel_store(state, "default")?;
    verify_account_signature(
        store.as_ref(),
        operation.signer,
        &operation.message,
        operation.signature,
    )?;
    let author = tx
        .signed_author()
        .ok_or_else(|| ApiError::InternalError {
            reason: format!("transaction {} carries no signed payload", tx.id),
        })?
        .to_string();
    let spendable = match tx.input_did.as_str() {
        MINT_ACCOUNT => u64::MAX,
        sender => store
            .calculate_balance(sender)
            .map_err(|e| ApiError::StorageError {
                reason: format!("balance of {sender}: {e}"),
            })?,
    };
    let committed = committed_nonce(store.as_ref(), &author);
    let mut pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
    let expected = committed + pending_nonce(&pool, &author);
    if operation.nonce != expected {
        return Err(ApiError::Conflict {
            reason: format!(
                "nonce {} rejected for {author}: expected {expected}",
                operation.nonce
            ),
        });
    }
    pool.add_checked(tx.clone(), spendable)
        .map_err(|reason| ApiError::ValidationError {
            field: "amount".to_string(),
            reason,
        })?;
    Ok(tx)
}

fn mint_signer(from: &str) -> Result<String, ApiError> {
    match from {
        MINT_ACCOUNT => std::env::var("NOTA_ISSUER_DID").map_err(|_| ApiError::Forbidden {
            reason: "minting from \"0\" is disabled: NOTA_ISSUER_DID is not configured".to_string(),
        }),
        sender => Ok(sender.to_string()),
    }
}

pub(crate) fn admit_transfer(
    state: &AppState,
    req: &CreateTransactionRequest,
) -> Result<Transaction, ApiError> {
    if req.amount == 0 {
        return Err(ApiError::ValidationError {
            field: "amount".to_string(),
            reason: "amount must be greater than 0".to_string(),
        });
    }
    if req.from == req.to {
        return Err(ApiError::ValidationError {
            field: "to".to_string(),
            reason: format!("sender and recipient are both {}", req.from),
        });
    }
    let signer = mint_signer(&req.from)?;
    let tx = Transaction {
        id: uuid::Uuid::new_v4().to_string(),
        block_height: 0,
        timestamp: now_secs(),
        input_did: req.from.clone(),
        output_recipient: req.to.clone(),
        amount: req.amount,
        state: "pending".to_string(),
        fee: 0,
        payload: Some(TxPayload::SignedTransfer { nonce: req.nonce }),
    };
    let operation = SignedOperation {
        signer: &signer,
        message: format!(
            "transfer:{}:{}:{}:{}",
            req.from, req.to, req.amount, req.nonce
        ),
        signature: &req.signature,
        nonce: req.nonce,
    };
    admit_signed_transaction(state, operation, tx)
}

fn billing_error(message: String) -> ApiError {
    match message.contains("Límite de transacciones alcanzado") {
        true => ApiError::PaymentRequired { message },
        false => ApiError::UnauthorizedWithMessage { message },
    }
}

/// POST /api/v1/transactions — validates and enqueues in the transaction pool.
#[post("/transactions")]
pub async fn create_transaction(
    state: web::Data<AppState>,
    req: web::Json<CreateTransactionRequest>,
    http_req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &http_req,
    )?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let api_key = http_req
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    if let Some(key) = &api_key {
        state
            .billing_manager
            .try_record_transaction(key)
            .map_err(billing_error)?;
    }

    let tx = admit_transfer(&state, &req)?;

    let body = ApiResponse::success(tx, trace_id);
    Ok(HttpResponse::Created().json(body))
}

// ── Store-backed transaction endpoints ───────────────────────────────────────

/// POST /api/v1/store/transactions — persiste una transacción en el store.
#[post("/store/transactions")]
pub async fn store_write_transaction(
    state: web::Data<AppState>,
    body: web::Json<crate::storage::traits::Transaction>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    validate_store_transaction(&body)?;
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    store
        .write_transaction(&body)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    Ok(HttpResponse::Created().json(ApiResponse::success_with_code(
        body.into_inner(),
        201,
        trace_id,
    )))
}

/// GET /api/v1/store/transactions/{tx_id} — lee una transacción del store.
#[get("/store/transactions/{tx_id}")]
pub async fn store_get_transaction(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let tx_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    match store.read_transaction(&tx_id) {
        Ok(tx) => Ok(HttpResponse::Ok().json(ApiResponse::success(tx, trace_id))),
        Err(_) => Err(ApiError::NotFound {
            resource: format!("transaction {tx_id}"),
        }),
    }
}

/// GET /api/v1/store/blocks/{height}/transactions — lista txs de un bloque por altura.
#[get("/store/blocks/{height}/transactions")]
pub async fn store_get_transactions_by_block(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let height = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let _channel = channel_id_from_req(&req);
    enforce_channel_membership(&state, _channel, &req)?;
    let store = get_channel_store(&state, _channel)?;
    let txs = store
        .transactions_by_block_height(height)
        .map_err(|e| ApiError::StorageError {
            reason: e.to_string(),
        })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(txs, trace_id)))
}

/// GET /api/v1/tx/{tx_id} — query a committed transaction by ID (any node).
///
/// Simplified endpoint without channel membership enforcement — intended for
/// cross-node tx verification in the DLT demo.
#[get("/tx/{tx_id}")]
pub async fn get_tx_by_id(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let tx_id = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    // Try the default channel store.
    let store = get_channel_store(&state, "default")?;
    match store.read_transaction(&tx_id) {
        Ok(tx) => Ok(HttpResponse::Ok().json(ApiResponse::success(tx, trace_id))),
        Err(_) => Err(ApiError::NotFound {
            resource: format!("transaction {tx_id}"),
        }),
    }
}

/// GET /api/v1/mempool — transacciones pendientes.
#[get("/mempool")]
pub async fn get_mempool(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();

    // Read from new TransactionPool
    let pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
    let transactions = pool.all().to_vec();
    drop(pool);

    #[derive(serde::Serialize)]
    struct PoolResponse {
        count: usize,
        transactions: Vec<crate::storage::traits::Transaction>,
    }
    let data = PoolResponse {
        count: transactions.len(),
        transactions,
    };
    let body = ApiResponse::success(data, trace_id);
    Ok(HttpResponse::Ok().json(body))
}
