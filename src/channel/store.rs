//! Channel-isolated storage — partitions world state and block store per channel.
//!
//! Each channel gets its own independent ledger, ensuring data isolation
//! between channels (Hyperledger Fabric compatible). Channels share the same
//! physical storage backend but use key prefixing for logical separation.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::Block;
use crate::storage::world_state::{MemoryWorldState, VersionedValue, WorldState};

/// Channel-scoped store providing isolated block and world state per channel.
pub struct ChannelStore {
    /// Per-channel world states.
    world_states: Mutex<HashMap<String, MemoryWorldState>>,
    /// Per-channel block heights (latest).
    block_heights: Mutex<HashMap<String, u64>>,
    /// Per-channel block history.
    blocks: Mutex<HashMap<String, Vec<Block>>>,
}

impl ChannelStore {
    pub fn new() -> Self {
        Self {
            world_states: Mutex::new(HashMap::new()),
            block_heights: Mutex::new(HashMap::new()),
            blocks: Mutex::new(HashMap::new()),
        }
    }

    /// Initialize a new channel with empty state.
    pub fn create_channel(&self, channel_id: &str) -> StorageResult<()> {
        let mut ws = self.world_states.lock().unwrap_or_else(|e| e.into_inner());
        if ws.contains_key(channel_id) {
            return Err(StorageError::KeyNotFound(format!(
                "channel '{channel_id}' already exists"
            )));
        }
        ws.insert(channel_id.to_string(), MemoryWorldState::new());
        self.block_heights
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(channel_id.to_string(), 0);
        self.blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(channel_id.to_string(), Vec::new());
        Ok(())
    }

    /// Get the world state for a channel (read a key).
    pub fn get_state(&self, channel_id: &str, key: &str) -> StorageResult<Option<VersionedValue>> {
        let ws = self.world_states.lock().unwrap_or_else(|e| e.into_inner());
        let state = ws
            .get(channel_id)
            .ok_or_else(|| StorageError::KeyNotFound(format!("channel '{channel_id}'")))?;
        state.get(key)
    }

    /// Write to a channel's world state.
    pub fn put_state(&self, channel_id: &str, key: &str, value: &[u8]) -> StorageResult<u64> {
        let ws = self.world_states.lock().unwrap_or_else(|e| e.into_inner());
        let state = ws
            .get(channel_id)
            .ok_or_else(|| StorageError::KeyNotFound(format!("channel '{channel_id}'")))?;
        state.put(key, value)
    }

    /// Write a block to a channel's ledger.
    pub fn write_block(&self, channel_id: &str, block: &Block) -> StorageResult<()> {
        let mut blocks = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        let chain = blocks
            .get_mut(channel_id)
            .ok_or_else(|| StorageError::KeyNotFound(format!("channel '{channel_id}'")))?;
        chain.push(block.clone());

        let mut heights = self.block_heights.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = heights.get_mut(channel_id) {
            *h = block.height;
        }
        Ok(())
    }

    /// Get the latest block height for a channel.
    pub fn get_height(&self, channel_id: &str) -> StorageResult<u64> {
        self.block_heights
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(channel_id)
            .copied()
            .ok_or_else(|| StorageError::KeyNotFound(format!("channel '{channel_id}'")))
    }

    /// Get a block by height from a channel.
    pub fn get_block(&self, channel_id: &str, height: u64) -> StorageResult<Option<Block>> {
        let blocks = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        let chain = blocks
            .get(channel_id)
            .ok_or_else(|| StorageError::KeyNotFound(format!("channel '{channel_id}'")))?;
        Ok(chain.iter().find(|b| b.height == height).cloned())
    }

    /// Number of blocks in a channel.
    pub fn block_count(&self, channel_id: &str) -> StorageResult<usize> {
        let blocks = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        let chain = blocks
            .get(channel_id)
            .ok_or_else(|| StorageError::KeyNotFound(format!("channel '{channel_id}'")))?;
        Ok(chain.len())
    }

    /// List all channel IDs.
    pub fn list_channels(&self) -> Vec<String> {
        self.world_states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Whether a channel exists.
    pub fn has_channel(&self, channel_id: &str) -> bool {
        self.world_states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(channel_id)
    }
}

impl Default for ChannelStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(height: u64) -> Block {
        Block {
            height,
            timestamp: 1000 + height,
            parent_hash: [0u8; 32],
            merkle_root: [height as u8; 32],
            transactions: vec![format!("tx_{height}")],
            proposer: "proposer".into(),
            signature: vec![1u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        }
    }

    // --- channel creation ---

    #[test]
    fn create_and_check_channel() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        assert!(store.has_channel("ch1"));
        assert!(!store.has_channel("ch2"));
    }

    #[test]
    fn create_duplicate_channel_fails() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        assert!(store.create_channel("ch1").is_err());
    }

    #[test]
    fn list_channels() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        store.create_channel("ch2").unwrap();
        let mut channels = store.list_channels();
        channels.sort();
        assert_eq!(channels, vec!["ch1", "ch2"]);
    }

    // --- state isolation ---

    #[test]
    fn state_isolated_between_channels() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        store.create_channel("ch2").unwrap();

        // Write to ch1.
        store.put_state("ch1", "asset", b"belongs_to_ch1").unwrap();

        // ch1 has the key.
        let val = store.get_state("ch1", "asset").unwrap().unwrap();
        assert_eq!(val.data, b"belongs_to_ch1");

        // ch2 does NOT have the key.
        assert!(store.get_state("ch2", "asset").unwrap().is_none());
    }

    #[test]
    fn same_key_different_values_per_channel() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        store.create_channel("ch2").unwrap();

        store.put_state("ch1", "balance", b"100").unwrap();
        store.put_state("ch2", "balance", b"999").unwrap();

        assert_eq!(
            store.get_state("ch1", "balance").unwrap().unwrap().data,
            b"100"
        );
        assert_eq!(
            store.get_state("ch2", "balance").unwrap().unwrap().data,
            b"999"
        );
    }

    #[test]
    fn state_on_unknown_channel_fails() {
        let store = ChannelStore::new();
        assert!(store.get_state("nonexistent", "key").is_err());
        assert!(store.put_state("nonexistent", "key", b"val").is_err());
    }

    // --- block isolation ---

    #[test]
    fn blocks_isolated_between_channels() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        store.create_channel("ch2").unwrap();

        store.write_block("ch1", &make_block(1)).unwrap();
        store.write_block("ch1", &make_block(2)).unwrap();
        store.write_block("ch2", &make_block(1)).unwrap();

        assert_eq!(store.block_count("ch1").unwrap(), 2);
        assert_eq!(store.block_count("ch2").unwrap(), 1);
        assert_eq!(store.get_height("ch1").unwrap(), 2);
        assert_eq!(store.get_height("ch2").unwrap(), 1);
    }

    #[test]
    fn get_block_by_height() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        store.write_block("ch1", &make_block(0)).unwrap();
        store.write_block("ch1", &make_block(1)).unwrap();

        let block = store.get_block("ch1", 1).unwrap().unwrap();
        assert_eq!(block.height, 1);
        assert!(store.get_block("ch1", 99).unwrap().is_none());
    }

    #[test]
    fn blocks_on_unknown_channel_fails() {
        let store = ChannelStore::new();
        assert!(store.write_block("nope", &make_block(0)).is_err());
        assert!(store.get_height("nope").is_err());
    }

    // --- versioning per channel ---

    #[test]
    fn versions_independent_per_channel() {
        let store = ChannelStore::new();
        store.create_channel("ch1").unwrap();
        store.create_channel("ch2").unwrap();

        // Write same key to both channels multiple times.
        store.put_state("ch1", "k", b"a").unwrap(); // v1
        store.put_state("ch1", "k", b"b").unwrap(); // v2
        store.put_state("ch2", "k", b"x").unwrap(); // v1

        assert_eq!(store.get_state("ch1", "k").unwrap().unwrap().version, 2);
        assert_eq!(store.get_state("ch2", "k").unwrap().unwrap().version, 1);
    }

    // --- stress ---

    #[test]
    fn stress_10_channels_100_keys_each() {
        let store = ChannelStore::new();
        for ch in 0..10 {
            let ch_id = format!("ch_{ch}");
            store.create_channel(&ch_id).unwrap();
            for k in 0..100 {
                store
                    .put_state(
                        &ch_id,
                        &format!("key_{k}"),
                        format!("val_{ch}_{k}").as_bytes(),
                    )
                    .unwrap();
            }
        }

        // Verify isolation.
        for ch in 0..10 {
            let ch_id = format!("ch_{ch}");
            for k in 0..100 {
                let val = store
                    .get_state(&ch_id, &format!("key_{k}"))
                    .unwrap()
                    .unwrap();
                let expected = format!("val_{ch}_{k}");
                assert_eq!(val.data, expected.as_bytes());
            }
        }
    }
}
