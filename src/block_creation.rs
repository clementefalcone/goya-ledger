use crate::api::errors::ApiError;
use crate::api::handlers::transactions::admit_transfer;
use crate::api::models::CreateBlockRequest;
use crate::app_state::AppState;
use crate::storage::traits::Transaction;

fn withdraw_from_pool(state: &AppState, admitted: Vec<Transaction>) -> Vec<Transaction> {
    let mut pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
    admitted
        .into_iter()
        .filter(|tx| pool.remove(&tx.id))
        .collect()
}

pub fn try_create_block(state: &AppState, req: &CreateBlockRequest) -> Result<String, ApiError> {
    let mining_service = state
        .mining_service
        .as_ref()
        .ok_or_else(|| ApiError::InternalError {
            reason: "MiningService not available".to_string(),
        })?;

    let mut admitted = Vec::new();
    for tx_req in &req.transactions {
        match admit_transfer(state, tx_req) {
            Ok(tx) => admitted.push(tx),
            Err(e) => {
                withdraw_from_pool(state, admitted);
                return Err(e);
            }
        }
    }

    let txs = withdraw_from_pool(state, admitted);
    let height = mining_service
        .mine_block("auto-miner", txs)
        .map_err(|reason| ApiError::InternalError { reason })?;
    Ok(format!("block-{height}"))
}
