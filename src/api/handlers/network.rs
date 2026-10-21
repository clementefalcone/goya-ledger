//! Network endpoints — peers, sync, and mining.
//!
//! Endpoints:
//! - GET  /peers                   — list connected peers
//! - POST /peers/{address}/connect — connect to a peer
//! - POST /sync                    — sync blockchain with all peers
//! - POST /mine                    — mine a new block

use std::sync::atomic::{AtomicBool, Ordering};

use crate::api::errors::{enforce_acl, ApiError, ApiResponse, ApiResult};
use crate::app_state::AppState;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

/// Guard to prevent concurrent mining requests from queueing up.
static MINING_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// GET /api/v1/peers
#[get("/peers")]
pub async fn get_peers(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    let node = state.node.as_ref().ok_or(ApiError::InternalError {
        reason: "P2P node not available".to_string(),
    })?;

    let peers: Vec<String> = {
        let peers_guard = node.peers.lock().unwrap_or_else(|e| e.into_inner());
        peers_guard.iter().cloned().collect()
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(peers, trace)))
}

/// POST /api/v1/peers/{address}/connect
#[post("/peers/{address}/connect")]
pub async fn connect_peer(
    state: web::Data<AppState>,
    address: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Admin",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();

    let node = state.node.as_ref().ok_or(ApiError::InternalError {
        reason: "P2P node not available".to_string(),
    })?;

    let node_clone = node.clone();
    let address_str = address.clone();

    match node_clone.connect_to_peer(&address_str).await {
        Ok(_) => Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({ "connected_to": address.as_str() }),
            trace,
        ))),
        Err(e) => {
            let msg = format!("Error connecting to {address}: {e}");
            if e.to_string().contains("Network ID mismatch") {
                Err(ApiError::ValidationError {
                    field: "address".to_string(),
                    reason: msg,
                })
            } else {
                Err(ApiError::InternalError { reason: msg })
            }
        }
    }
}

/// POST /api/v1/sync
#[post("/sync")]
pub async fn sync_blockchain(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Admin",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();

    let node = state.node.as_ref().ok_or(ApiError::InternalError {
        reason: "P2P node not available".to_string(),
    })?;

    let node_clone = node.clone();
    actix_web::rt::spawn(async move {
        let _ = node_clone.sync_with_all_peers().await;
    });

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "status": "sync_started" }),
        trace,
    )))
}

#[derive(Deserialize)]
pub struct MineBlockRequest {
    #[serde(default)]
    pub max_transactions: Option<usize>,
}

#[derive(Serialize)]
struct MineResponse {
    hash: String,
    reward: u64,
    transactions_count: usize,
}

/// POST /api/v1/mine
#[post("/mine")]
pub async fn mine_block(
    state: web::Data<AppState>,
    body: web::Json<MineBlockRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    // Reject concurrent mine requests
    if MINING_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::ValidationError {
            field: "mining".to_string(),
            reason: "mining already in progress — try again shortly".to_string(),
        });
    }
    struct MiningGuard;
    impl Drop for MiningGuard {
        fn drop(&mut self) {
            MINING_IN_PROGRESS.store(false, Ordering::SeqCst);
        }
    }
    let _guard = MiningGuard;

    enforce_acl(
        state.acl_provider.as_deref(),
        state.policy_store.as_deref(),
        "peer/Propose",
        &req,
    )?;
    let trace = uuid::Uuid::new_v4().to_string();

    let mining_service = state
        .mining_service
        .as_ref()
        .ok_or(ApiError::InternalError {
            reason: "MiningService not available".to_string(),
        })?;

    // Drain pending transactions from pool
    let max_txs = body.max_transactions.unwrap_or(10);
    let pool_txs = {
        let mut pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
        pool.drain_for_block(max_txs)
    };

    let height = mining_service
        .mine_block("auto-miner", pool_txs)
        .map_err(|e| ApiError::InternalError {
            reason: format!("Mining error: {e}"),
        })?;

    let reward = {
        let econ = state
            .economics_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::tokenomics::economics::capped_block_reward(
            econ.height.saturating_sub(1),
            econ.total_minted,
        )
    };

    // P2P broadcast via ordered block
    if let Some(node) = &state.node {
        if let Ok(store_map) = state.store.read() {
            if let Some(store) = store_map.get("default") {
                if let Ok(block) = store.read_block(height) {
                    let node_clone = node.clone();
                    tokio::spawn(async move {
                        node_clone.broadcast_ordered_block(&block).await;
                    });
                }
            }
        }
    }

    let tx_count = if let Ok(store_map) = state.store.read() {
        if let Some(store) = store_map.get("default") {
            store
                .read_block(height)
                .map(|b| b.transactions.len())
                .unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::BlockMined,
        "auto-miner",
        Some(format!("height={height}")),
    );

    Ok(HttpResponse::Created().json(ApiResponse::success(
        MineResponse {
            hash: format!("block-{height}"),
            reward,
            transactions_count: tx_count,
        },
        trace,
    )))
}
