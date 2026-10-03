//! Filtered block delivery — privacy-preserving block summaries.
//!
//! `FilteredBlock` strips payload, rwset, and endorsements from a block,
//! exposing only transaction IDs and validation codes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single transaction summary within a filtered block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteredTx {
    pub tx_id: String,
    pub validation_code: String,
    pub chaincode_id: Option<String>,
}

/// A privacy-preserving summary of a committed block.
///
/// Contains only metadata and per-transaction validation status —
/// no payload, rwset, or endorsement data is included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteredBlock {
    pub channel_id: String,
    pub height: u64,
    pub tx_summaries: Vec<FilteredTx>,
}

/// Convert a storage [`Block`] into a [`FilteredBlock`].
///
/// `validations` maps `tx_id → validation_code` (e.g. "VALID", "MVCC_READ_CONFLICT").
/// Transactions not present in `validations` get code `"UNKNOWN"`.
pub fn to_filtered_block(
    block: &crate::storage::traits::Block,
    channel_id: &str,
    validations: &HashMap<String, String>,
) -> FilteredBlock {
    let tx_summaries = block
        .transactions
        .iter()
        .map(|tx_id| FilteredTx {
            tx_id: tx_id.clone(),
            validation_code: validations
                .get(tx_id)
                .cloned()
                .unwrap_or_else(|| "UNKNOWN".to_string()),
            chaincode_id: None,
        })
        .collect();

    FilteredBlock {
        channel_id: channel_id.to_string(),
        height: block.height,
        tx_summaries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::traits::Block;

    fn test_block() -> Block {
        Block {
            height: 5,
            timestamp: 1000,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec!["tx1".into(), "tx2".into(), "tx3".into()],
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
    fn filtered_block_omits_sensitive_data() {
        let block = test_block();
        let mut validations = HashMap::new();
        validations.insert("tx1".into(), "VALID".into());
        validations.insert("tx2".into(), "VALID".into());
        validations.insert("tx3".into(), "MVCC_READ_CONFLICT".into());

        let fb = to_filtered_block(&block, "mychannel", &validations);

        assert_eq!(fb.channel_id, "mychannel");
        assert_eq!(fb.height, 5);
        assert_eq!(fb.tx_summaries.len(), 3);

        // No payload, signature, endorsements — just IDs + codes
        let json = serde_json::to_string(&fb).unwrap();
        assert!(!json.contains("parent_hash"));
        assert!(!json.contains("merkle_root"));
        assert!(!json.contains("signature"));
        assert!(!json.contains("endorsements"));
    }

    #[test]
    fn to_filtered_block_maps_validation_codes() {
        let block = test_block();
        let mut validations = HashMap::new();
        validations.insert("tx1".into(), "VALID".into());
        validations.insert("tx2".into(), "VALID".into());
        validations.insert("tx3".into(), "MVCC_READ_CONFLICT".into());

        let fb = to_filtered_block(&block, "ch1", &validations);

        assert_eq!(fb.tx_summaries[0].validation_code, "VALID");
        assert_eq!(fb.tx_summaries[1].validation_code, "VALID");
        assert_eq!(fb.tx_summaries[2].validation_code, "MVCC_READ_CONFLICT");
    }

    #[test]
    fn missing_validation_defaults_to_unknown() {
        let block = test_block();
        let validations = HashMap::new(); // no entries

        let fb = to_filtered_block(&block, "ch1", &validations);

        for tx in &fb.tx_summaries {
            assert_eq!(tx.validation_code, "UNKNOWN");
        }
    }

    #[test]
    fn filtered_block_serde_roundtrip() {
        let fb = FilteredBlock {
            channel_id: "ch1".into(),
            height: 10,
            tx_summaries: vec![
                FilteredTx {
                    tx_id: "t1".into(),
                    validation_code: "VALID".into(),
                    chaincode_id: Some("basic".into()),
                },
                FilteredTx {
                    tx_id: "t2".into(),
                    validation_code: "PHANTOM_READ".into(),
                    chaincode_id: None,
                },
            ],
        };

        let json = serde_json::to_string(&fb).unwrap();
        let decoded: FilteredBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, decoded);
    }
}
