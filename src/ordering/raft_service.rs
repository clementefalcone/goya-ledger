use std::sync::{Arc, Mutex};

use crate::identity::signing::SigningProvider;
use crate::ordering::raft_node::{RaftError, RaftNode};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{Block, Transaction};

/// Ordering service backed by a Raft cluster.
///
/// Wraps a [`RaftNode`] and translates `submit_tx` / `cut_block` into
/// raft propose + committed-entry draining.
pub struct RaftOrderingService {
    pub(crate) raft_node: Arc<Mutex<RaftNode>>,
    pub max_batch_size: usize,
    #[allow(dead_code)]
    pub batch_timeout_ms: u64,
    signing_key: Option<pqc_crypto_module::legacy::ed25519::SigningKey>,
    signing_provider: Option<Arc<dyn SigningProvider>>,
}

impl RaftOrderingService {
    pub fn new(
        id: u64,
        peers: Vec<u64>,
        max_batch_size: usize,
        batch_timeout_ms: u64,
    ) -> Result<Self, RaftError> {
        let node = RaftNode::new(id, peers)?;
        Ok(Self {
            raft_node: Arc::new(Mutex::new(node)),
            max_batch_size,
            batch_timeout_ms,
            signing_key: None,
            signing_provider: None,
        })
    }

    /// Create a persistent Raft ordering service that recovers state from disk.
    pub fn new_persistent(
        id: u64,
        peers: Vec<u64>,
        max_batch_size: usize,
        batch_timeout_ms: u64,
        raft_db_path: &std::path::Path,
    ) -> Result<Self, RaftError> {
        let node = RaftNode::new_persistent(id, peers, raft_db_path)?;
        Ok(Self {
            raft_node: Arc::new(Mutex::new(node)),
            max_batch_size,
            batch_timeout_ms,
            signing_key: None,
            signing_provider: None,
        })
    }

    #[allow(dead_code)]
    /// Create from a shared `RaftNode` — used when the tick loop and P2P
    /// handler share the same node instance.
    pub fn from_shared(
        raft_node: Arc<Mutex<RaftNode>>,
        max_batch_size: usize,
        batch_timeout_ms: u64,
    ) -> Self {
        Self {
            raft_node,
            max_batch_size,
            batch_timeout_ms,
            signing_key: None,
            signing_provider: None,
        }
    }

    #[allow(dead_code)]
    /// Attach an Ed25519 signing key so `cut_block` signs each block.
    pub fn with_signing_key(mut self, key: pqc_crypto_module::legacy::ed25519::SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Attach a pluggable signing provider (Ed25519 or ML-DSA-65).
    pub fn with_signing_provider(mut self, provider: Arc<dyn SigningProvider>) -> Self {
        self.signing_provider = Some(provider);
        self
    }

    /// Serialize the transaction and propose it through Raft.
    ///
    /// After proposing, drives the Raft state machine forward so the entry
    /// can be committed before the caller calls `cut_block`. Without this,
    /// the async tick loop might not have run yet and `cut_block` would
    /// return `None`.
    pub fn submit_tx(&self, tx: &Transaction) -> StorageResult<()> {
        let data = serde_json::to_vec(tx)
            .map_err(|e| crate::storage::errors::StorageError::SerializationError(e.to_string()))?;
        let mut node = self.raft_node.lock().unwrap_or_else(|e| e.into_inner());
        node.propose(data)
            .map_err(|e| crate::storage::errors::StorageError::SerializationError(e.to_string()))?;
        // Drive Raft forward so the entry gets committed synchronously.
        // For a single-node or quorum-ready cluster, one advance cycle suffices.
        for _ in 0..5 {
            node.tick();
            node.advance();
            if !node.committed_entries.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Number of committed entries not yet consumed by `cut_block`.
    pub fn pending_count(&self) -> usize {
        self.raft_node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .committed_entries
            .len()
    }

    /// Drain committed entries, deserialize transactions, and cut a block.
    /// Returns `None` if no committed entries with transaction data are available.
    pub fn cut_block(&self, height: u64, proposer: &str) -> StorageResult<Option<Block>> {
        let mut node = self.raft_node.lock().unwrap_or_else(|e| e.into_inner());
        if node.committed_entries.is_empty() {
            return Ok(None);
        }

        // Drain entries, collecting up to max_batch_size valid TXs.
        // Skip raft internal entries (empty data / non-TX).
        let mut tx_data: Vec<Transaction> = Vec::new();
        while !node.committed_entries.is_empty() && tx_data.len() < self.max_batch_size {
            let entry = node.committed_entries.remove(0);
            if entry.data.is_empty() {
                continue;
            }
            if let Ok(tx) = serde_json::from_slice::<Transaction>(&entry.data) {
                tx_data.push(tx);
            }
        }

        if tx_data.is_empty() {
            return Ok(None);
        }

        let tx_ids: Vec<String> = tx_data.iter().map(|tx| tx.id.clone()).collect();

        let mut block = Block {
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            parent_hash: [0u8; 32],
            merkle_root: crate::mining::transactions_merkle_root(&tx_data),
            transactions: tx_ids,
            proposer: proposer.to_string(),
            signature: vec![0u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            embedded_entries: Vec::new(),
            transaction_data: tx_data,
        };

        if let Some(provider) = &self.signing_provider {
            super::sign_block_with_provider(&mut block, provider.as_ref());
        } else if let Some(key) = &self.signing_key {
            super::sign_block(&mut block, key);
        }

        Ok(Some(block))
    }
}

impl super::OrderingBackend for RaftOrderingService {
    fn submit_tx(&self, tx: &Transaction) -> StorageResult<()> {
        self.submit_tx(tx)
    }

    fn cut_block(&self, height: u64, proposer: &str) -> StorageResult<Option<Block>> {
        self.cut_block(height, proposer)
    }

    fn pending_count(&self) -> usize {
        self.pending_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(id: &str) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: "did:goya:alice".to_string(),
            output_recipient: "did:goya:bob".to_string(),
            amount: 1,
            state: "pending".to_string(),
            fee: 0,
            payload: None,
        }
    }

    /// Elect the single-node raft so it can accept proposals.
    fn elect(svc: &RaftOrderingService) {
        let mut node = svc.raft_node.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..20 {
            node.tick();
            node.advance();
            if node.is_leader() {
                return;
            }
        }
        panic!("node did not become leader");
    }

    #[test]
    fn submit_three_txs_cut_block_returns_three() {
        let svc = RaftOrderingService::new(1, vec![1], 100, 2000).unwrap();
        elect(&svc);

        for i in 1..=3 {
            svc.submit_tx(&make_tx(&format!("tx{i}"))).unwrap();
        }

        // Advance raft to commit the proposals.
        {
            let mut node = svc.raft_node.lock().unwrap_or_else(|e| e.into_inner());
            node.advance();
        }

        let block = svc
            .cut_block(1, "orderer")
            .unwrap()
            .expect("expected a block");
        assert_eq!(block.height, 1);
        assert_eq!(block.proposer, "orderer");
        assert_eq!(block.transactions, vec!["tx1", "tx2", "tx3"]);
    }

    #[test]
    fn cut_block_returns_none_when_empty() {
        let svc = RaftOrderingService::new(1, vec![1], 100, 2000).unwrap();
        assert!(svc.cut_block(1, "orderer").unwrap().is_none());
    }

    #[test]
    fn cut_block_respects_max_batch_size() {
        let svc = RaftOrderingService::new(1, vec![1], 2, 2000).unwrap();
        elect(&svc);

        for i in 1..=5 {
            svc.submit_tx(&make_tx(&format!("tx{i}"))).unwrap();
        }

        {
            let mut node = svc.raft_node.lock().unwrap_or_else(|e| e.into_inner());
            node.advance();
        }

        let b1 = svc.cut_block(1, "orderer").unwrap().expect("block 1");
        assert_eq!(b1.transactions.len(), 2);

        let b2 = svc.cut_block(2, "orderer").unwrap().expect("block 2");
        assert_eq!(b2.transactions.len(), 2);

        let b3 = svc.cut_block(3, "orderer").unwrap().expect("block 3");
        assert_eq!(b3.transactions.len(), 1);

        assert!(svc.cut_block(4, "orderer").unwrap().is_none());
    }
}
