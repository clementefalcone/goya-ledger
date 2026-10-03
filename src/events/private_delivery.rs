//! Block delivery with authorized private data.
//!
//! `BlockWithPrivateData` bundles a committed block with the private data
//! from collections the requesting org is a member of.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::storage::traits::Block;

/// A committed block bundled with the caller's authorized private data.
///
/// `private_data` is keyed by collection name; each entry is a list of
/// `(key, value)` pairs from that collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockWithPrivateData {
    pub block: Block,
    pub private_data: HashMap<String, Vec<(String, Vec<u8>)>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_block() -> Block {
        Block {
            height: 3,
            timestamp: 500,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec!["tx1".into()],
            proposer: "peer0".into(),
            signature: vec![0u8; 64],
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

    #[test]
    fn serde_roundtrip() {
        let mut private_data = HashMap::new();
        private_data.insert(
            "secret_collection".to_string(),
            vec![
                ("key1".to_string(), b"value1".to_vec()),
                ("key2".to_string(), b"value2".to_vec()),
            ],
        );

        let bwpd = BlockWithPrivateData {
            block: test_block(),
            private_data,
        };

        let json = serde_json::to_string(&bwpd).unwrap();
        let decoded: BlockWithPrivateData = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.block.height, 3);
        assert_eq!(decoded.private_data.len(), 1);
        let entries = decoded.private_data.get("secret_collection").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "key1");
        assert_eq!(entries[0].1, b"value1");
    }

    #[test]
    fn empty_private_data() {
        let bwpd = BlockWithPrivateData {
            block: test_block(),
            private_data: HashMap::new(),
        };

        let json = serde_json::to_string(&bwpd).unwrap();
        let decoded: BlockWithPrivateData = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.private_data.len(), 0);
        assert_eq!(decoded.block.height, 3);
    }
}
