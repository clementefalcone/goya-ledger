use actix_web::{get, web, HttpResponse};

use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::get_channel_store;
use crate::api::models::{ChainInfoResponse, ChainVerifyResponse};
use crate::app_state::AppState;
use crate::mining::block_hash;
use crate::storage::traits::BlockStore;

/// Hex-encode a 32-byte hash.
pub(crate) fn hex_hash(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

/// GET /api/v1/chain/verify — walk the chain and verify parent_hash linkage.
#[get("/verify")]
pub async fn verify_chain(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let store = get_channel_store(&state, "default")?;
    let height = store.get_latest_height().unwrap_or(0);
    let has_genesis = store.block_exists(0).unwrap_or(false);
    let block_count = if has_genesis {
        (height + 1) as usize
    } else {
        0
    };

    if block_count == 0 {
        let data = ChainVerifyResponse {
            valid: true,
            block_count: 0,
            first_invalid_height: None,
        };
        return Ok(HttpResponse::Ok().json(ApiResponse::success(data, trace_id)));
    }

    let first_invalid_height = first_unlinked_height(store.as_ref(), height)?;

    let data = ChainVerifyResponse {
        valid: first_invalid_height.is_none(),
        block_count,
        first_invalid_height,
    };
    let body = ApiResponse::success(data, trace_id);
    Ok(HttpResponse::Ok().json(body))
}

fn first_unlinked_height(store: &dyn BlockStore, height: u64) -> ApiResult<Option<u64>> {
    let genesis = store.read_block(0).map_err(|e| ApiError::StorageError {
        reason: e.to_string(),
    })?;
    let mut prev_hash = block_hash(&genesis);
    for h in 1..=height {
        match store.read_block(h) {
            Ok(block) if block.parent_hash == prev_hash => prev_hash = block_hash(&block),
            _ => return Ok(Some(h)),
        }
    }
    Ok(None)
}

/// GET /api/v1/chain/info — chain metadata from BlockStore with real latest block hash.
#[get("/info")]
pub async fn get_blockchain_info(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace_id = uuid::Uuid::new_v4().to_string();
    let store = get_channel_store(&state, "default")?;
    let height = store.get_latest_height().unwrap_or(0);
    let has_genesis = store.block_exists(0).unwrap_or(false);
    let block_count = if has_genesis {
        (height + 1) as usize
    } else {
        0
    };

    let latest_block_hash = if has_genesis {
        match store.read_block(height) {
            Ok(block) => hex_hash(&block_hash(&block)),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    let data = ChainInfoResponse {
        block_count,
        latest_block_hash,
        is_valid: true,
    };
    let body = ApiResponse::success(data, trace_id);
    Ok(HttpResponse::Ok().json(body))
}

#[cfg(test)]
mod tests {
    use super::{first_unlinked_height, get_blockchain_info, verify_chain};
    use crate::storage::traits::BlockStore;

    #[test]
    fn chain_gateway_handlers_are_public() {
        let _ = (verify_chain, get_blockchain_info);
    }

    fn mined_chain(length: u64, forged_height: Option<u64>) -> crate::storage::MemoryStore {
        let store = crate::storage::MemoryStore::new();
        let mut parent_hash = [0u8; 32];
        for height in 0..length {
            let block = crate::storage::traits::Block {
                height,
                timestamp: 1_000 + height,
                parent_hash,
                merkle_root: [height as u8; 32],
                transactions: vec![format!("tx-{height}")],
                proposer: "v0".into(),
                signature: vec![1u8; 64],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: None,
                transaction_data: vec![],
            };
            parent_hash = crate::mining::block_hash(&block);
            let stored = match forged_height {
                Some(forged) if forged == height => crate::storage::traits::Block {
                    transactions: vec!["forged".into()],
                    ..block
                },
                _ => block,
            };
            store.write_block(&stored).unwrap();
        }
        store
    }

    #[test]
    fn chain_linked_by_the_mining_hash_verifies() {
        let store = mined_chain(5, None);

        assert_eq!(first_unlinked_height(&store, 4).unwrap(), None);
    }

    #[test]
    fn altered_block_breaks_the_link_to_its_child() {
        let store = mined_chain(5, Some(2));

        assert_eq!(first_unlinked_height(&store, 4).unwrap(), Some(3));
    }
}
