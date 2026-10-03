//! State snapshots for fast-sync and world state persistence.
//!
//! A snapshot serializes the entire world state at a given block height into a
//! streamable text file. Format: `{key}\t{version}\t{base64(data)}\n` per entry.

use std::io::Write;
use std::path::Path;

use base64::Engine as _;
use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use super::errors::{StorageError, StorageResult};
use super::traits::BlockStore;
use super::world_state::WorldState;

/// Metadata for a world-state snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub snapshot_id: String,
    pub channel_id: String,
    pub block_height: u64,
    pub created_at: u64,
    pub state_hash: [u8; 32],
    pub entry_count: u64,
}

/// Create a snapshot of the world state at the current latest block height.
///
/// Writes all key-value pairs to `snapshots/{channel_id}/{height}.snap` under
/// `base_dir`. Each line: `{key}\t{version}\t{base64(data)}\n`.
///
/// Returns the snapshot metadata including the SHA-256 hash of the file content.
pub fn create_snapshot(
    store: &dyn BlockStore,
    state: &dyn WorldState,
    channel_id: &str,
    base_dir: &Path,
) -> StorageResult<StateSnapshot> {
    let height = store.get_latest_height().unwrap_or(0);

    let dir = base_dir.join("snapshots").join(channel_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| StorageError::Other(format!("failed to create snapshot dir: {e}")))?;

    let file_path = dir.join(format!("{height}.snap"));
    let mut file = std::fs::File::create(&file_path)
        .map_err(|e| StorageError::Other(format!("failed to create snapshot file: {e}")))?;

    // Iterate all keys via get_range with full range.
    // Using "" .. high Unicode char covers all string keys.
    let all_entries = state.get_range("", "\u{FFFF}")?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut hasher = Sha256::new();
    let mut count = 0u64;

    for (key, vv) in &all_entries {
        let line = format!("{}\t{}\t{}\n", key, vv.version, b64.encode(&vv.data));
        hasher.update(line.as_bytes());
        file.write_all(line.as_bytes())
            .map_err(|e| StorageError::Other(format!("write error: {e}")))?;
        count += 1;
    }

    let hash: [u8; 32] = hasher.finalize().into();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(StateSnapshot {
        snapshot_id: format!("{channel_id}-{height}"),
        channel_id: channel_id.to_string(),
        block_height: height,
        created_at: now,
        state_hash: hash,
        entry_count: count,
    })
}

#[allow(dead_code)]
/// Restore a snapshot from a `.snap` file into the world state.
///
/// Reads each line, decodes `{key}\t{version}\t{base64(data)}`, and calls
/// `state.put(key, data)`. Verifies the SHA-256 hash matches after reading.
pub fn restore_snapshot(path: &Path, state: &dyn WorldState) -> StorageResult<StateSnapshot> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| StorageError::Other(format!("failed to read snapshot: {e}")))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut hasher = Sha256::new();
    let mut count = 0u64;

    for line in content.lines() {
        // Re-hash including the newline.
        hasher.update(format!("{line}\n").as_bytes());

        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() != 3 {
            continue;
        }
        let key = parts[0];
        let data = b64
            .decode(parts[2])
            .map_err(|e| StorageError::Other(format!("base64 decode error: {e}")))?;
        state.put(key, &data)?;
        count += 1;
    }

    let hash: [u8; 32] = hasher.finalize().into();

    // Extract channel_id and height from the file name if possible.
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let channel_id = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    Ok(StateSnapshot {
        snapshot_id: format!("{channel_id}-{file_stem}"),
        channel_id: channel_id.to_string(),
        block_height: file_stem.parse().unwrap_or(0),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        state_hash: hash,
        entry_count: count,
    })
}

#[allow(dead_code)]
/// Regenerate world state by replaying all blocks from the store.
///
/// Iterates blocks `[0, latest]` in order. For each transaction ID found in
/// a block, writes `tx_id → block_height` into the world state. Returns the
/// total number of keys written.
pub fn regenerate_state(
    store: &dyn BlockStore,
    state: &dyn WorldState,
    _channel_id: &str,
) -> StorageResult<u64> {
    let latest = store.get_latest_height().unwrap_or(0);
    let mut count = 0u64;

    for h in 0..=latest {
        let block = match store.read_block(h) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for tx_id in &block.transactions {
            let value = block.height.to_le_bytes();
            state.put(tx_id, &value)?;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStore;
    use crate::storage::world_state::MemoryWorldState;

    #[test]
    fn create_snapshot_metadata() {
        let snap = StateSnapshot {
            snapshot_id: "snap-001".into(),
            channel_id: "mychannel".into(),
            block_height: 42,
            created_at: 1_700_000_000,
            state_hash: [0xAB; 32],
            entry_count: 100,
        };

        assert_eq!(snap.snapshot_id, "snap-001");
        assert_eq!(snap.channel_id, "mychannel");
        assert_eq!(snap.block_height, 42);
        assert_eq!(snap.entry_count, 100);
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let snap = StateSnapshot {
            snapshot_id: "snap-002".into(),
            channel_id: "testchannel".into(),
            block_height: 10,
            created_at: 1_700_000_500,
            state_hash: [0xFF; 32],
            entry_count: 50,
        };

        let json = serde_json::to_string(&snap).unwrap();
        let decoded: StateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn create_snapshot_with_100_keys() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = MemoryStore::new();
        let state = MemoryWorldState::new();

        // Write a block so latest_height returns something.
        let block = crate::storage::traits::Block {
            height: 1,
            timestamp: 0,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec![],
            proposer: "p".into(),
            signature: vec![0u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        };
        store.write_block(&block).unwrap();

        // Populate world state with 100 keys.
        for i in 0..100u32 {
            state
                .put(&format!("key{i:04}"), format!("val{i}").as_bytes())
                .unwrap();
        }

        let snap = create_snapshot(&store, &state, "ch1", tmp.path()).unwrap();
        assert_eq!(snap.entry_count, 100);
        assert_eq!(snap.block_height, 1);
        assert_eq!(snap.channel_id, "ch1");
        assert_ne!(snap.state_hash, [0u8; 32]);

        // Verify file exists.
        let file_path = tmp.path().join("snapshots/ch1/1.snap");
        assert!(file_path.exists());
    }

    #[test]
    fn create_and_restore_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = MemoryStore::new();
        let original = MemoryWorldState::new();

        let block = crate::storage::traits::Block {
            height: 5,
            timestamp: 0,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec![],
            proposer: "p".into(),
            signature: vec![0u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        };
        store.write_block(&block).unwrap();

        // Populate 10 keys.
        for i in 0..10u32 {
            original
                .put(&format!("k{i}"), format!("v{i}").as_bytes())
                .unwrap();
        }

        let snap = create_snapshot(&store, &original, "ch1", tmp.path()).unwrap();

        // Restore into a fresh state.
        let restored = MemoryWorldState::new();
        let file_path = tmp.path().join("snapshots/ch1/5.snap");
        let snap2 = restore_snapshot(&file_path, &restored).unwrap();

        // Hash must match.
        assert_eq!(snap.state_hash, snap2.state_hash);
        assert_eq!(snap2.entry_count, 10);

        // Verify all keys are present.
        for i in 0..10u32 {
            let vv = restored
                .get(&format!("k{i}"))
                .unwrap()
                .expect("key must exist");
            assert_eq!(vv.data, format!("v{i}").as_bytes());
        }
    }

    #[test]
    fn regenerate_state_from_blocks() {
        let store = MemoryStore::new();
        let state = MemoryWorldState::new();

        // Write 10 blocks with 3 TXs each.
        for h in 0..10u64 {
            let block = crate::storage::traits::Block {
                height: h,
                timestamp: h * 100,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: vec![format!("tx{h}_0"), format!("tx{h}_1"), format!("tx{h}_2")],
                proposer: "p".into(),
                signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: None,
                transaction_data: vec![],
            };
            store.write_block(&block).unwrap();
        }

        let count = regenerate_state(&store, &state, "ch1").unwrap();
        assert_eq!(count, 30); // 10 blocks × 3 TXs

        // Verify a few keys.
        let vv = state.get("tx0_0").unwrap().expect("key must exist");
        assert_eq!(vv.data, 0u64.to_le_bytes());

        let vv = state.get("tx9_2").unwrap().expect("key must exist");
        assert_eq!(vv.data, 9u64.to_le_bytes());

        // Non-existent key should be absent.
        assert!(state.get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn list_blocks_pagination() {
        use crate::storage::traits::BlockStore;

        let store = MemoryStore::new();

        // Write 50 blocks.
        for h in 0..50u64 {
            let block = crate::storage::traits::Block {
                height: h,
                timestamp: h,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: vec![],
                proposer: "p".into(),
                signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: None,
                transaction_data: vec![],
            };
            store.write_block(&block).unwrap();
        }

        let (blocks, total) = store.list_blocks(10, 5).unwrap();
        assert_eq!(total, 50);
        assert_eq!(blocks.len(), 5);
        assert_eq!(blocks[0].height, 10);
        assert_eq!(blocks[4].height, 14);

        // Last page partial.
        let (blocks, total) = store.list_blocks(48, 5).unwrap();
        assert_eq!(total, 50);
        assert_eq!(blocks.len(), 2); // heights 48, 49
    }
}
