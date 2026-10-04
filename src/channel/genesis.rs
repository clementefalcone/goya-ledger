//! Genesis block creation for new channels.

use crate::channel::config::ChannelConfig;
use crate::private_data::sha256;
use crate::storage::traits::Block;

const NETWORK_GENESIS_TIMESTAMPS: [(&str, u64); 1] = [("mainnet", 1_790_258_251)];

pub fn network_genesis_timestamp(network_id: &str) -> u64 {
    NETWORK_GENESIS_TIMESTAMPS
        .iter()
        .find(|(known_network, _)| *known_network == network_id)
        .map_or(0, |(_, timestamp)| *timestamp)
}

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
    fn mainnet_default_genesis_matches_the_production_chain() {
        let genesis = Block {
            timestamp: network_genesis_timestamp("mainnet"),
            ..create_genesis_block("default", &ChannelConfig::default())
        };
        assert_eq!(
            hex::encode(crate::mining::block_hash(&genesis)),
            "0e1eec13edd44cb64447c1466e19612c17e91c1e6d5990f253dce26806942e6d"
        );
    }

    #[test]
    fn unknown_networks_start_at_timestamp_zero() {
        assert_eq!(network_genesis_timestamp("testnet"), 0);
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
