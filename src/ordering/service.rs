use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::identity::signing::SigningProvider;
use crate::metrics::MetricsCollector;
use crate::storage::{
    errors::StorageResult,
    traits::{Block, BlockStore, Transaction},
};

/// Collects endorsed transactions and cuts them into ordered blocks.
pub struct OrderingService {
    pub(crate) pending_txs: Mutex<VecDeque<Transaction>>,
    pub max_batch_size: usize,
    #[allow(dead_code)]
    pub batch_timeout_ms: u64,
    metrics: Option<Arc<MetricsCollector>>,
    signing_key: Option<pqc_crypto_module::legacy::ed25519::SigningKey>,
    signing_provider: Option<Arc<dyn SigningProvider>>,
}

impl Default for OrderingService {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderingService {
    /// Create a new `OrderingService` reading config from env:
    /// - `ORDERING_BATCH_SIZE` (default 100)
    /// - `ORDERING_BATCH_TIMEOUT_MS` (default 2000)
    pub fn new() -> Self {
        let max_batch_size = std::env::var("ORDERING_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let batch_timeout_ms = std::env::var("ORDERING_BATCH_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2000);

        Self::with_config(max_batch_size, batch_timeout_ms)
    }

    pub fn with_config(max_batch_size: usize, batch_timeout_ms: u64) -> Self {
        Self {
            pending_txs: Mutex::new(VecDeque::new()),
            max_batch_size,
            batch_timeout_ms,
            metrics: None,
            signing_key: None,
            signing_provider: None,
        }
    }

    #[allow(dead_code)]
    /// Attach a metrics collector so `cut_block` increments `ordering_blocks_cut_total`.
    pub fn with_metrics(mut self, metrics: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    #[allow(dead_code)]
    /// Attach an Ed25519 signing key so `cut_block` signs each block.
    pub fn with_signing_key(mut self, key: pqc_crypto_module::legacy::ed25519::SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Attach a pluggable signing provider (Ed25519 or ML-DSA-65).
    /// When set, `cut_block` signs both the proposer and orderer fields.
    pub fn with_signing_provider(mut self, provider: Arc<dyn SigningProvider>) -> Self {
        self.signing_provider = Some(provider);
        self
    }

    /// Enqueue a transaction for the next ordered block.
    pub fn submit_tx(&self, tx: Transaction) -> StorageResult<()> {
        self.pending_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(tx);
        Ok(())
    }

    #[allow(dead_code)]
    /// Enqueue an endorsed transaction for the next ordered block.
    ///
    /// Extracts the inner `Transaction` from the proposal and enqueues it.
    /// For MVP the endorsement metadata is validated by the Gateway before
    /// calling this method; a future version should carry the full
    /// `EndorsedTransaction` through to the block so committer peers can
    /// re-validate endorsements.
    pub fn submit_endorsed_tx(
        &self,
        etx: crate::transaction::endorsed::EndorsedTransaction,
    ) -> StorageResult<()> {
        self.pending_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(etx.proposal.tx);
        Ok(())
    }

    /// Number of transactions currently waiting to be ordered.
    pub fn pending_count(&self) -> usize {
        self.pending_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Drain up to `max_batch_size` transactions and create an ordered `Block`.
    /// Returns `None` if the pending queue is empty.
    pub fn cut_block(
        &self,
        height: u64,
        parent_hash: [u8; 32],
        proposer: &str,
    ) -> StorageResult<Option<Block>> {
        let mut queue = self.pending_txs.lock().unwrap_or_else(|e| e.into_inner());
        if queue.is_empty() {
            return Ok(None);
        }

        let count = queue.len().min(self.max_batch_size);
        let drained: Vec<Transaction> = queue.drain(..count).collect();
        let tx_ids: Vec<String> = drained.iter().map(|tx| tx.id.clone()).collect();

        let mut block = Block {
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            parent_hash,
            merkle_root: crate::mining::transactions_merkle_root(&drained),
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
            transaction_data: drained,
        };

        if let Some(provider) = &self.signing_provider {
            super::sign_block_with_provider(&mut block, provider.as_ref());
        } else if let Some(key) = &self.signing_key {
            super::sign_block(&mut block, key);
        }

        if let Some(m) = &self.metrics {
            m.record_ordering_block_cut();
        }
        Ok(Some(block))
    }
}

#[allow(dead_code)]
/// Continuously drain pending transactions into ordered blocks on a timer.
///
/// Launched via `tokio::spawn` in `main.rs` when `role == Orderer || PeerAndOrderer`.
/// The height counter is local to this loop; a future phase can derive it from the store.
pub async fn run_batch_loop(service: Arc<OrderingService>, store: Arc<dyn BlockStore>) {
    let timeout = tokio::time::Duration::from_millis(service.batch_timeout_ms);
    let mut height: u64 = store.get_latest_height().unwrap_or(0) + 1;

    loop {
        tokio::time::sleep(timeout).await;
        let parent_hash = match crate::mining::parent_hash_at(store.as_ref(), height) {
            Ok(parent_hash) => parent_hash,
            Err(e) => {
                eprintln!("ordering: cannot cut block {height}: {e}");
                continue;
            }
        };
        match service.cut_block(height, parent_hash, "orderer") {
            Ok(Some(block)) => {
                height += 1;
                if let Err(e) = store.write_block(&block) {
                    eprintln!("ordering: failed to write block {}: {e}", block.height);
                }
            }
            Ok(None) => {} // No pending txs — nothing to do.
            Err(e) => eprintln!("ordering: cut_block error: {e}"),
        }
    }
}

impl super::OrderingBackend for OrderingService {
    fn submit_tx(&self, tx: &Transaction) -> StorageResult<()> {
        self.submit_tx(tx.clone())
    }

    fn cut_block(
        &self,
        height: u64,
        parent_hash: [u8; 32],
        proposer: &str,
    ) -> StorageResult<Option<Block>> {
        self.cut_block(height, parent_hash, proposer)
    }

    fn pending_count(&self) -> usize {
        self.pending_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_service_with_defaults() {
        let svc = OrderingService::with_config(100, 2000);
        assert_eq!(svc.max_batch_size, 100);
        assert_eq!(svc.batch_timeout_ms, 2000);
        assert_eq!(
            svc.pending_txs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
    }

    #[test]
    fn respects_custom_config() {
        let svc = OrderingService::with_config(50, 500);
        assert_eq!(svc.max_batch_size, 50);
        assert_eq!(svc.batch_timeout_ms, 500);
    }

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

    #[test]
    fn submit_three_txs_pending_count_is_three() {
        let svc = OrderingService::with_config(100, 2000);
        svc.submit_tx(make_tx("tx1")).unwrap();
        svc.submit_tx(make_tx("tx2")).unwrap();
        svc.submit_tx(make_tx("tx3")).unwrap();
        assert_eq!(svc.pending_count(), 3);
    }

    #[tokio::test]
    async fn batch_loop_cuts_block_after_timeout() {
        use crate::storage::{traits::BlockStore, MemoryStore};

        let svc = Arc::new(OrderingService::with_config(100, 50)); // 50ms timeout
        let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());

        svc.submit_tx(make_tx("tx1")).unwrap();

        let svc2 = svc.clone();
        let store2 = store.clone();
        let handle = tokio::spawn(super::run_batch_loop(svc2, store2));

        // Wait long enough for at least one cut (>50ms).
        tokio::time::sleep(tokio::time::Duration::from_millis(120)).await;
        handle.abort();

        // Block should be persisted in the store.
        let block = store.read_block(1).unwrap();
        assert_eq!(block.transactions, vec!["tx1"]);
    }

    #[test]
    fn cut_block_batches_up_to_max_size() {
        let svc = OrderingService::with_config(3, 2000);
        for i in 0..5 {
            svc.submit_tx(make_tx(&format!("tx{i}"))).unwrap();
        }

        // First cut: 3 txs
        let b1 = svc.cut_block(1, [0u8; 32], "orderer1").unwrap().unwrap();
        assert_eq!(b1.transactions.len(), 3);
        assert_eq!(b1.height, 1);
        assert_eq!(b1.proposer, "orderer1");

        // Second cut: remaining 2 txs
        let b2 = svc.cut_block(2, [0u8; 32], "orderer1").unwrap().unwrap();
        assert_eq!(b2.transactions.len(), 2);

        // Queue now empty
        assert!(svc.cut_block(3, [0u8; 32], "orderer1").unwrap().is_none());
    }

    #[test]
    fn cut_block_merkle_root_commits_to_transaction_content() {
        let svc = OrderingService::with_config(10, 2000);
        svc.submit_tx(make_tx("tx1")).unwrap();
        let block = svc.cut_block(1, [0u8; 32], "orderer1").unwrap().unwrap();
        assert_eq!(
            block.merkle_root,
            crate::mining::transactions_merkle_root(&block.transaction_data)
        );
        assert_ne!(block.merkle_root, [0u8; 32]);
    }
}
