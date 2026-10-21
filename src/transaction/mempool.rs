//! Transaction mempool backed by `storage::Transaction`.
//!
//! Replaces the legacy `models::Mempool` with the same API surface
//! but using the new storage types. Includes double-spend prevention.

use crate::storage::traits::Transaction;

/// Pool of pending transactions awaiting inclusion in a block.
#[derive(Debug, Clone)]
pub struct TransactionPool {
    transactions: Vec<Transaction>,
    max_size: usize,
}

impl TransactionPool {
    pub fn new() -> Self {
        let max_size = std::env::var("MEMPOOL_MAX_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);
        Self {
            transactions: Vec::new(),
            max_size,
        }
    }

    /// Create a pool with a specific capacity (for testing).
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            transactions: Vec::new(),
            max_size,
        }
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Add a transaction to the pool. Rejects duplicates and full pool.
    pub fn add(&mut self, tx: Transaction) -> Result<(), String> {
        if tx.amount > 0 {
            return Err(format!(
                "transaction {} moves {} without a balance check; use add_checked",
                tx.id, tx.amount
            ));
        }
        if self.transactions.len() >= self.max_size {
            return Err("Mempool full".to_string());
        }
        if self.transactions.iter().any(|t| t.id == tx.id) {
            return Err("Transaction already in mempool".to_string());
        }
        self.transactions.push(tx);
        Ok(())
    }

    /// Add a transaction with balance validation.
    /// Rejects if sender's pending spend + new amount exceeds available balance.
    pub fn add_checked(&mut self, tx: Transaction, sender_balance: u64) -> Result<(), String> {
        if self.transactions.len() >= self.max_size {
            return Err("Mempool full".to_string());
        }
        if self.transactions.iter().any(|t| t.id == tx.id) {
            return Err("Transaction already in mempool".to_string());
        }

        // Double-spend check: sum all pending amounts from the same sender
        let pending_spent: u64 = self
            .transactions
            .iter()
            .filter(|t| t.input_did == tx.input_did)
            .map(|t| t.amount)
            .sum();

        let total_required = pending_spent.saturating_add(tx.amount);
        if total_required > sender_balance {
            return Err(format!(
                "Double-spend: pending {pending_spent} + new {} = {total_required} exceeds balance {sender_balance}",
                tx.amount
            ));
        }

        self.transactions.push(tx);
        Ok(())
    }

    /// Drain up to `max` transactions for block inclusion.
    pub fn drain_for_block(&mut self, max: usize) -> Vec<Transaction> {
        let count = max.min(self.transactions.len());
        self.transactions.drain(..count).collect()
    }

    /// Remove a transaction by ID. Returns true if found.
    pub fn remove(&mut self, tx_id: &str) -> bool {
        if let Some(pos) = self.transactions.iter().position(|t| t.id == tx_id) {
            self.transactions.remove(pos);
            true
        } else {
            false
        }
    }

    /// View all pending transactions without removing them.
    pub fn all(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx(id: &str, from: &str, to: &str, amount: u64) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: 0,
            timestamp: 1000,
            input_did: from.to_string(),
            output_recipient: to.to_string(),
            amount,
            state: "pending".to_string(),
            fee: 0,
            payload: None,
        }
    }

    #[test]
    fn add_and_drain() {
        let mut pool = TransactionPool::new();
        pool.add(sample_tx("tx1", "alice", "bob", 0)).unwrap();
        pool.add(sample_tx("tx2", "bob", "carol", 0)).unwrap();
        assert_eq!(pool.len(), 2);

        let batch = pool.drain_for_block(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn unchecked_add_rejects_value_transfers() {
        let mut pool = TransactionPool::new();
        assert!(pool.add(sample_tx("tx1", "alice", "bob", 1)).is_err());
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_duplicate() {
        let mut pool = TransactionPool::new();
        pool.add(sample_tx("tx1", "alice", "bob", 0)).unwrap();
        assert!(pool.add(sample_tx("tx1", "alice", "bob", 0)).is_err());
    }

    #[test]
    fn remove_by_id() {
        let mut pool = TransactionPool::new();
        pool.add(sample_tx("tx1", "alice", "bob", 0)).unwrap();
        assert!(pool.remove("tx1"));
        assert!(pool.is_empty());
        assert!(!pool.remove("tx1"));
    }

    #[test]
    fn rejects_when_full() {
        let mut pool = TransactionPool {
            transactions: Vec::new(),
            max_size: 1,
        };
        pool.add(sample_tx("tx1", "a", "b", 0)).unwrap();
        assert!(pool.add(sample_tx("tx2", "a", "b", 0)).is_err());
    }

    #[test]
    fn add_checked_allows_within_balance() {
        let mut pool = TransactionPool::new();
        pool.add_checked(sample_tx("tx1", "alice", "bob", 50), 100)
            .unwrap();
        pool.add_checked(sample_tx("tx2", "alice", "carol", 30), 100)
            .unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn add_checked_rejects_double_spend() {
        let mut pool = TransactionPool::new();
        pool.add_checked(sample_tx("tx1", "alice", "bob", 80), 100)
            .unwrap();
        let result = pool.add_checked(sample_tx("tx2", "alice", "carol", 30), 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Double-spend"));
    }

    #[test]
    fn with_custom_max_size() {
        let mut pool = TransactionPool::with_max_size(2);
        pool.add(sample_tx("tx1", "a", "b", 0)).unwrap();
        pool.add(sample_tx("tx2", "a", "b", 0)).unwrap();
        assert!(pool.add(sample_tx("tx3", "a", "b", 0)).is_err());
        assert_eq!(pool.max_size(), 2);
    }

    #[test]
    fn add_checked_different_senders_independent() {
        let mut pool = TransactionPool::new();
        pool.add_checked(sample_tx("tx1", "alice", "bob", 80), 100)
            .unwrap();
        pool.add_checked(sample_tx("tx2", "bob", "carol", 90), 100)
            .unwrap();
        assert_eq!(pool.len(), 2);
    }
}
