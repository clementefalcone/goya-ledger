//! Genesis block creation for new channels.

use crate::channel::config::ChannelConfig;
use crate::private_data::sha256;
use crate::storage::traits::Block;

/// Create the genesis block for a new channel.
///
/// The block has height 0, `parent_hash = [0u8; 32]`, and `proposer = "genesis"`.
/// `transactions` contains a single entry: the JSON-serialized `ChannelConfig`.
/// `merkle_root` is the SHA-256 of that JSON payload.
/// `signature` is zeroed — genesis blocks are not signed by a key.
pub fn create_genesis_block(channel_id: &str, config: &ChannelConfig) -> Block {
    let config_json = serde_json::to_string(config).unwrap_or_else(|_| "{}".to_string());

    let merkle_root = sha256(config_json.as_bytes());

    Block {
        height: 0,
        timestamp: 0,
        parent_hash: [0u8; 32],
        merkle_root,
        transactions: vec![config_json],
        proposer: format!("genesis:{channel_id}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::config::ChannelConfig;
    use crate::endorsement::policy::EndorsementPolicy;

    fn sample_config() -> ChannelConfig {
        ChannelConfig {
            version: 0,
            member_orgs: vec!["org1".to_string(), "org2".to_string()],
            orderer_orgs: vec!["orderer".to_string()],
            endorsement_policy: EndorsementPolicy::AnyOf(vec!["org1".to_string()]),
            ..ChannelConfig::default()
        }
    }

    #[test]
    fn genesis_block_has_correct_fields() {
        let cfg = sample_config();
        let block = create_genesis_block("ch1", &cfg);

        assert_eq!(block.height, 0);
        assert_eq!(block.parent_hash, [0u8; 32]);
        assert_eq!(block.proposer, "genesis:ch1");
        assert_eq!(block.signature, [0u8; 64]);
        assert_eq!(block.endorsements.len(), 0);
        assert_eq!(block.transactions.len(), 1);
    }

    #[test]
    fn genesis_block_transaction_deserializes_to_config() {
        let cfg = sample_config();
        let block = create_genesis_block("ch1", &cfg);

        let restored: ChannelConfig =
            serde_json::from_str(&block.transactions[0]).expect("deserialize");
        assert_eq!(restored, cfg);
    }

    #[test]
    fn genesis_block_merkle_root_matches_config_hash() {
        let cfg = sample_config();
        let block = create_genesis_block("ch1", &cfg);

        let config_json = serde_json::to_string(&cfg).unwrap();
        let expected_root = sha256(config_json.as_bytes());
        assert_eq!(block.merkle_root, expected_root);
    }

    #[test]
    fn genesis_block_is_identical_on_every_node() {
        let cfg = ChannelConfig::default();
        let first = create_genesis_block("default", &cfg);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = create_genesis_block("default", &cfg);
        assert_eq!(
            crate::mining::block_hash(&first),
            crate::mining::block_hash(&second)
        );
    }
}
