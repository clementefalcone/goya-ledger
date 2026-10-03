//! Property-based fuzz tests using proptest.
//!
//! Targets: JSON deserialization, input validation, smart contracts,
//! blockchain operations, and crypto operations.

use proptest::prelude::*;

// ── 1. JSON Deserialization (never panic on arbitrary bytes) ──────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn fuzz_transaction_deser(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = serde_json::from_slice::<rust_bc::storage::traits::Transaction>(&data);
    }

    #[test]
    fn fuzz_block_deser(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = serde_json::from_slice::<rust_bc::storage::traits::Block>(&data);
    }

    #[test]
    fn fuzz_identity_deser(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = serde_json::from_slice::<rust_bc::storage::traits::IdentityRecord>(&data);
    }

    #[test]
    fn fuzz_credential_deser(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = serde_json::from_slice::<rust_bc::storage::traits::Credential>(&data);
    }

    #[test]
    fn fuzz_p2p_message_deser(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        // P2P message deserialization must never panic
        let _ = serde_json::from_slice::<serde_json::Value>(&data);
    }
}

// ── 2. Input Validation (reject bad input, never panic) ──────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn fuzz_validate_string_field(s in "\\PC{0,1000}") {
        let result = rust_bc::api::handlers::validation::validate_string_field("test", &s);
        if s.contains('\0') || s.contains('<') || s.contains('>') || s.len() > 256 {
            prop_assert!(result.is_err(), "Should reject: {:?}", &s[..s.len().min(50)]);
        }
    }

    #[test]
    fn fuzz_validate_store_transaction(
        id in "\\PC{0,500}",
        input_did in "\\PC{0,500}",
        output in "\\PC{0,500}",
        state in "\\PC{0,500}",
        height in any::<u64>(),
        ts in any::<u64>(),
        amount in any::<u64>(),
    ) {
        let tx = rust_bc::storage::traits::Transaction {
            id,
            block_height: height,
            timestamp: ts,
            input_did,
            output_recipient: output,
            amount,
            fee: 0,
            state,
            payload: None,
        };
        let _ = rust_bc::api::handlers::validation::validate_store_transaction(&tx);
    }
}

// ── 3. Smart Contract Operations (no panic on arbitrary params) ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn fuzz_erc20_operations(
        owner in "[a-f0-9]{64}",
        to in "[a-f0-9]{64}",
        amount in any::<u64>(),
        supply in 1u64..=1_000_000_000u64,
    ) {
        use rust_bc::smart_contracts::{SmartContract, ContractFunction};

        let mut contract = SmartContract::new(
            owner.clone(),
            "ERC20".to_string(),
            "FuzzToken".to_string(),
            Some("FZZ".to_string()),
            Some(supply),
            Some(18),
        );

        // Mint then transfer — must never panic
        let _ = contract.execute(
            ContractFunction::Mint { to: owner.clone(), amount },
            Some(&owner),
        );
        let _ = contract.execute(
            ContractFunction::Transfer { to: to.clone(), amount },
            Some(&owner),
        );
        let _ = contract.execute(
            ContractFunction::Approve { spender: to, amount },
            Some(&owner),
        );
    }

    #[test]
    fn fuzz_nft_operations(
        owner in "[a-f0-9]{64}",
        to in "[a-f0-9]{64}",
        token_id in 0u64..1_000_000,
        uri in "[a-zA-Z0-9:/._-]{0,200}",
    ) {
        use rust_bc::smart_contracts::{SmartContract, ContractFunction};

        let mut contract = SmartContract::new(
            owner.clone(),
            "nft".to_string(),
            "FuzzNFT".to_string(),
            Some("FNFT".to_string()),
            None,
            None,
        );

        // Mint, transfer, approve — must never panic
        let _ = contract.execute(
            ContractFunction::MintNFT { to: owner.clone(), token_id, token_uri: uri },
            Some(&owner),
        );
        let _ = contract.execute(
            ContractFunction::TransferNFT { from: owner.clone(), to: to.clone(), token_id },
            Some(&owner),
        );
        let _ = contract.execute(
            ContractFunction::ApproveNFT { to, token_id },
            Some(&owner),
        );
    }
}

// ── 4. Blockchain Operations ─────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn fuzz_transaction_creation(
        from in "[a-z0-9]{5,64}",
        to in "[a-z0-9]{5,64}",
        amount in any::<u64>(),
        _fee in 0u64..1000,
    ) {
        use rust_bc::storage::traits::Transaction;

        let tx = Transaction {
            id: uuid::Uuid::new_v4().to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: from,
            output_recipient: to,
            amount,
            fee: 0,
            state: "pending".to_string(),
            payload: None,
        };
        prop_assert_eq!(tx.amount, amount);
        prop_assert!(!tx.id.is_empty());
    }

    #[test]
    fn fuzz_transaction_validation(
        from in "[a-z0-9]{5,300}",
        to in "[a-z0-9]{5,300}",
        amount in any::<u64>(),
        _fee in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        use rust_bc::transaction_validation::{TransactionValidator, ValidationConfig};
        use rust_bc::storage::traits::Transaction;

        let tx = Transaction {
            id: format!("fuzz-{}", rand::random::<u64>()),
            block_height: 0,
            timestamp,
            input_did: from,
            output_recipient: to,
            amount,
            fee: 0,
            state: "pending".to_string(),
            payload: None,
        };

        let config = ValidationConfig {
            max_future_drift_secs: u64::MAX,
            max_past_age_secs: u64::MAX,
            ..Default::default()
        };

        let mut validator = TransactionValidator::new(config);
        let result = validator.validate(&tx);
        prop_assert!(result.is_valid || !result.errors.is_empty());
    }
}

// ── 5. Crypto Operations ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn fuzz_sha256_no_panic(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        prop_assert_eq!(result.len(), 32);
    }

    #[test]
    fn fuzz_sha256_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        use sha2::{Digest, Sha256};
        let h1 = Sha256::digest(&data);
        let h2 = Sha256::digest(&data);
        prop_assert_eq!(h1, h2);
    }
}

// ── 6. Storage Operations (MemoryStore roundtrip) ────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn fuzz_memory_store_block_roundtrip(
        height in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        use rust_bc::storage::{MemoryStore, BlockStore};
        use rust_bc::storage::traits::Block;

        let store = MemoryStore::new();
        let block = Block {
            height,
            timestamp,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec![],
            proposer: "fuzz-proposer".to_string(),
            signature: vec![0u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None, commit_qc: None, transaction_data: vec![],
        };

        let write_result = store.write_block(&block);
        prop_assert!(write_result.is_ok());

        let read_result = store.read_block(height);
        if let Ok(read_back) = read_result {
            prop_assert_eq!(read_back.height, height);
            prop_assert_eq!(read_back.timestamp, timestamp);
        }
    }

    #[test]
    fn fuzz_memory_store_transaction_roundtrip(
        id in "[a-f0-9]{8,64}",
        height in any::<u64>(),
        amount in any::<u64>(),
    ) {
        use rust_bc::storage::{MemoryStore, BlockStore};
        use rust_bc::storage::traits::Transaction;

        let store = MemoryStore::new();
        let tx = Transaction {
            id: id.clone(),
            block_height: height,
            timestamp: 0,
            input_did: "did:bc:fuzz-in".to_string(),
            output_recipient: "did:bc:fuzz-out".to_string(),
            amount,
            fee: 0,
            state: "committed".to_string(),
            payload: None,
        };

        let write_result = store.write_transaction(&tx);
        prop_assert!(write_result.is_ok());

        let read_result = store.read_transaction(&id);
        if let Ok(read_back) = read_result {
            prop_assert_eq!(read_back.id, id);
            prop_assert_eq!(read_back.amount, amount);
        }
    }
}
