//! Mining service backed by BlockStore.
//!
//! Encapsulates block creation, reward calculation, and persistence
//! using the new storage layer. Replaces `Blockchain::mine_block_with_reward`.

use crate::crypto::hasher::{hash, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use crate::ordering::block_hash_for_signing;
use crate::storage::traits::{Block, BlockStore, Transaction};
use crate::tokenomics::economics::EconomicsState;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the mining service.
#[derive(Debug, Clone)]
pub struct MiningConfig {
    pub base_reward: u64,
    pub halving_interval: u64,
    pub burn_percentage: u64,
    pub miner_fee_share: u64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            base_reward: 50,
            halving_interval: 210_000,
            burn_percentage: 80,
            miner_fee_share: 20,
        }
    }
}

/// Mining service that creates blocks and writes them to BlockStore.
pub struct MiningService {
    store: Arc<dyn BlockStore>,
    config: MiningConfig,
    signer: Option<Arc<dyn SigningProvider>>,
    secondary_signer: Option<Arc<dyn SigningProvider>>,
    economics: Option<Arc<Mutex<EconomicsState>>>,
}

impl MiningService {
    pub fn new(store: Arc<dyn BlockStore>, config: MiningConfig) -> Self {
        Self {
            store,
            config,
            signer: None,
            secondary_signer: None,
            economics: None,
        }
    }

    pub fn with_economics(mut self, economics: Arc<Mutex<EconomicsState>>) -> Self {
        self.economics = Some(economics);
        self
    }

    /// Attach a signing provider for block signatures.
    pub fn with_signer(mut self, signer: Arc<dyn SigningProvider>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Attach a secondary signing provider for dual signatures (PQC migration).
    pub fn with_secondary_signer(mut self, signer: Arc<dyn SigningProvider>) -> Self {
        self.secondary_signer = Some(signer);
        self
    }

    /// Mine a new block with the given transactions and miner reward.
    ///
    /// Returns the block height on success.
    pub fn mine_block(
        &self,
        miner_address: &str,
        transactions: Vec<Transaction>,
    ) -> Result<u64, String> {
        let latest_height = self.store.get_latest_height().unwrap_or(0);
        let new_height = if self.store.block_exists(0).unwrap_or(false) {
            latest_height + 1
        } else {
            0
        };

        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum();
        let (reward, proposer_fees) = if let Some(ref econ) = self.economics {
            let mut state = econ.lock().unwrap_or_else(|e| e.into_inner());
            let (new_state, fee_split, reward) = crate::tokenomics::economics::process_block(
                &state,
                transactions.len() as u64,
                total_fees,
            );
            *state = new_state;
            (reward, fee_split.proposer)
        } else {
            (self.calculate_reward(new_height), 0)
        };
        let total_reward = reward + proposer_fees;

        // Build coinbase transaction
        let coinbase = Transaction {
            id: format!("coinbase-{new_height}"),
            block_height: new_height,
            timestamp: now(),
            input_did: "coinbase".to_string(),
            output_recipient: miner_address.to_string(),
            amount: total_reward,
            state: "confirmed".to_string(),
            fee: 0,
            payload: None,
        };

        let parent_hash = parent_hash_at(self.store.as_ref(), new_height)?;

        // Collect all tx IDs
        let mut all_tx_ids = vec![coinbase.id.clone()];
        all_tx_ids.extend(transactions.iter().map(|tx| tx.id.clone()));

        let mut all_tx_data = vec![coinbase.clone()];
        all_tx_data.extend(transactions.iter().cloned());

        let merkle_root = transactions_merkle_root(&all_tx_data);

        let mut block = Block {
            height: new_height,
            timestamp: now(),
            parent_hash,
            merkle_root,
            transactions: all_tx_ids,
            proposer: miner_address.to_string(),
            signature: Vec::new(),
            signature_algorithm: SigningAlgorithm::default(),
            endorsements: Vec::new(),
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: HashAlgorithm::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: all_tx_data,
        };

        let signing_hash = block_hash_for_signing(&block);

        if let Some(ref signer) = self.signer {
            if let Ok(sig) = signer.sign(&signing_hash) {
                block.signature = sig;
                block.signature_algorithm = signer.algorithm();
            }
        }

        if let Some(ref secondary) = self.secondary_signer {
            if let Ok(sig) = secondary.sign(&signing_hash) {
                block.secondary_signature = Some(sig);
                block.secondary_signature_algorithm = Some(secondary.algorithm());
            }
        }

        // Write block and transactions
        self.store
            .write_block(&block)
            .map_err(|e| format!("failed to write block: {e}"))?;

        // Write coinbase tx
        self.store
            .write_transaction(&coinbase)
            .map_err(|e| format!("failed to write coinbase tx: {e}"))?;

        for mut tx in transactions {
            tx.block_height = new_height;
            tx.state = "confirmed".to_string();
            if let Err(e) = crate::transaction::apply_tx_payload(self.store.as_ref(), &tx) {
                log::warn!("tx {} payload rejected: {e}", tx.id);
                tx.state = "invalid_payload".to_string();
            }
            self.store
                .write_transaction(&tx)
                .map_err(|e| format!("failed to write tx: {e}"))?;
        }

        Ok(new_height)
    }

    /// Calculate mining reward with halving schedule.
    fn calculate_reward(&self, height: u64) -> u64 {
        let halvings = height / self.config.halving_interval;
        self.config.base_reward >> halvings.min(64)
    }
}

/// Compute SHA-256 hash of a block (for parent_hash linkage).
pub fn block_hash(block: &Block) -> [u8; 32] {
    let data = format!(
        "{}:{}:{:?}:{:?}:{:?}",
        block.height, block.timestamp, block.parent_hash, block.transactions, block.merkle_root
    );
    hash(data.as_bytes())
}

pub fn parent_hash_at(store: &dyn BlockStore, height: u64) -> Result<[u8; 32], String> {
    let parent_height = match height.checked_sub(1) {
        Some(parent_height) => parent_height,
        None => return Ok([0u8; 32]),
    };
    let parent_exists = store
        .block_exists(parent_height)
        .map_err(|e| format!("failed to check parent block {parent_height}: {e}"))?;
    if !parent_exists {
        return Ok([0u8; 32]);
    }
    store
        .read_block(parent_height)
        .map(|parent| block_hash(&parent))
        .map_err(|e| format!("failed to read parent block {parent_height}: {e}"))
}

const MERKLE_LEAF_PREFIX: u8 = 0x00;
const MERKLE_NODE_PREFIX: u8 = 0x01;

pub fn transactions_merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| {
            let encoded = serde_json::to_vec(tx).expect("Transaction always serializes to JSON");
            hash(&[&[MERKLE_LEAF_PREFIX], encoded.as_slice()].concat())
        })
        .collect();
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                hash(&[&[MERKLE_NODE_PREFIX], pair[0].as_slice(), right.as_slice()].concat())
            })
            .collect();
    }
    level[0]
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;

    #[test]
    fn mine_genesis_block() {
        let store = Arc::new(MemoryStore::new());
        let service = MiningService::new(store.clone(), MiningConfig::default());

        let height = service.mine_block("miner1", vec![]).unwrap();
        assert_eq!(height, 0);

        let block = store.read_block(0).unwrap();
        assert_eq!(block.proposer, "miner1");
        assert_eq!(block.transactions.len(), 1); // coinbase only
    }

    #[test]
    fn mine_second_block_links_parent() {
        let store = Arc::new(MemoryStore::new());
        let service = MiningService::new(store.clone(), MiningConfig::default());

        service.mine_block("miner1", vec![]).unwrap();
        service.mine_block("miner1", vec![]).unwrap();

        let block1 = store.read_block(1).unwrap();
        let block0 = store.read_block(0).unwrap();
        assert_eq!(block1.parent_hash, block_hash(&block0));
    }

    fn notarization_tx(content_hash: &str) -> Transaction {
        Transaction {
            id: "notarize:abc".to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: "did:goya:signer".to_string(),
            output_recipient: content_hash.to_string(),
            amount: 0,
            state: format!("{{\"content_hash\":\"{content_hash}\"}}"),
            fee: 0,
            payload: None,
        }
    }

    #[test]
    fn mined_block_merkle_root_commits_to_transaction_content() {
        let store = Arc::new(MemoryStore::new());
        let service = MiningService::new(store.clone(), MiningConfig::default());
        service
            .mine_block("miner1", vec![notarization_tx(&"a".repeat(64))])
            .unwrap();

        let block = store.read_block(0).unwrap();
        assert_eq!(
            block.merkle_root,
            transactions_merkle_root(&block.transaction_data)
        );

        let mut tampered = block.transaction_data.clone();
        tampered[1].state = format!("{{\"content_hash\":\"{}\"}}", "b".repeat(64));
        assert_ne!(block.merkle_root, transactions_merkle_root(&tampered));
    }

    #[test]
    fn block_hash_changes_when_merkle_root_changes() {
        let store = Arc::new(MemoryStore::new());
        let service = MiningService::new(store.clone(), MiningConfig::default());
        service.mine_block("miner1", vec![]).unwrap();
        let block = store.read_block(0).unwrap();

        let mut tampered = block.clone();
        tampered.merkle_root[0] ^= 0xff;
        assert_ne!(block_hash(&block), block_hash(&tampered));
    }

    #[test]
    fn merkle_root_depends_on_transaction_order() {
        let first = notarization_tx(&"a".repeat(64));
        let second = notarization_tx(&"b".repeat(64));
        assert_ne!(
            transactions_merkle_root(&[first.clone(), second.clone()]),
            transactions_merkle_root(&[second, first])
        );
    }

    #[test]
    fn mining_reward_halves() {
        let store = Arc::new(MemoryStore::new());
        let config = MiningConfig {
            halving_interval: 10,
            ..Default::default()
        };
        let service = MiningService::new(store, config);

        assert_eq!(service.calculate_reward(0), 50);
        assert_eq!(service.calculate_reward(9), 50);
        assert_eq!(service.calculate_reward(10), 25);
        assert_eq!(service.calculate_reward(20), 12);
    }

    #[test]
    fn mine_block_with_transactions() {
        let store = Arc::new(MemoryStore::new());
        let service = MiningService::new(store.clone(), MiningConfig::default());

        let tx = Transaction {
            id: "tx-1".to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: "alice".to_string(),
            output_recipient: "bob".to_string(),
            amount: 10,
            state: "pending".to_string(),
            fee: 0,
            payload: None,
        };

        let height = service.mine_block("miner1", vec![tx]).unwrap();
        assert_eq!(height, 0);

        let block = store.read_block(0).unwrap();
        assert_eq!(block.transactions.len(), 2); // coinbase + tx-1

        // Verify transaction was persisted with confirmed state
        let stored_tx = store.read_transaction("tx-1").unwrap();
        assert_eq!(stored_tx.state, "confirmed");
        assert_eq!(stored_tx.block_height, 0);
    }

    #[test]
    fn mine_block_with_dual_signature() {
        use crate::identity::signing::{MlDsaSigningProvider, SoftwareSigningProvider};

        let store = Arc::new(MemoryStore::new());
        let primary: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
        let secondary: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

        let service = MiningService::new(store.clone(), MiningConfig::default())
            .with_signer(primary)
            .with_secondary_signer(secondary);

        service.mine_block("miner1", vec![]).unwrap();
        let block = store.read_block(0).unwrap();

        assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(block.signature.len(), 64);
        assert_eq!(
            block.secondary_signature_algorithm,
            Some(SigningAlgorithm::MlDsa65)
        );
        assert_eq!(block.secondary_signature.as_ref().unwrap().len(), 3309);
    }
}
