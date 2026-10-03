//! Property-based fuzz tests for critical parsers and validators.
//!
//! Uses proptest to generate adversarial inputs that unit tests miss.
//! These tests exercise deserialization, validation, and state transitions
//! with randomized data to catch panics, overflows, and logic errors.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    // ── Block deserialization ────────────────────────────────────────────────

    proptest! {
        /// Arbitrary JSON should never panic the block deserializer.
        #[test]
        fn block_deser_never_panics(data in "\\PC{0,500}") {
            let _ = serde_json::from_str::<crate::storage::traits::Block>(&data);
        }

        /// Arbitrary bytes as block fields should not panic.
        #[test]
        fn block_with_arbitrary_fields(
            height in any::<u64>(),
            timestamp in any::<u64>(),
            proposer in "[a-z0-9]{0,64}",
            tx_count in 0usize..20,
        ) {
            let txs: Vec<String> = (0..tx_count).map(|i| format!("tx-{i}")).collect();
            let block = crate::storage::traits::Block {
                height,
                timestamp,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: txs,
                proposer,
                signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None, commit_qc: None, embedded_entries: Vec::new(), transaction_data: vec![],
            };
            // Serialize and deserialize roundtrip must not panic
            let json = serde_json::to_string(&block).unwrap();
            let back: crate::storage::traits::Block = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back.height, height);
            prop_assert_eq!(back.timestamp, timestamp);
        }
    }

    // ── ISO 20022 validation ─────────────────────────────────────────────────

    proptest! {
        /// Arbitrary strings in ISO 20022 fields should not panic the validator.
        #[test]
        fn pacs008_never_panics(
            msg_id in "\\PC{0,200}",
            date in "\\PC{0,30}",
            amount in any::<u64>(),
            currency in "[A-Z]{0,5}",
            debtor_name in "\\PC{0,200}",
            creditor_name in "\\PC{0,200}",
            country in "[A-Z]{0,4}",
        ) {
            use crate::compliance::iso20022::*;
            let msg = Pacs008 {
                message_id: msg_id,
                creation_date: date,
                settlement_amount: CurrencyAmount { amount, currency: currency.clone() },
                debtor: Party {
                    name: debtor_name,
                    country: country.clone(),
                    account_iban: None,
                    bic: Some("TESTBIC1".into()),
                },
                creditor: Party {
                    name: creditor_name,
                    country,
                    account_iban: None,
                    bic: Some("TESTBIC2".into()),
                },
                debtor_agent_bic: "TESTBIC1".into(),
                creditor_agent_bic: "TESTBIC2".into(),
                remittance_info: None,
            };
            // Must not panic regardless of input
            let _ = validate_pacs008(&msg);
        }
    }

    // ── Oracle price submission ──────────────────────────────────────────────

    proptest! {
        /// Arbitrary oracle submissions should not panic the registry.
        #[test]
        fn oracle_submit_never_panics(
            oracle_id in "[a-z0-9-]{1,32}",
            symbol in "[A-Z/]{1,10}",
            price in any::<u64>(),
            confidence in 0u8..=100u8,
        ) {
            let mut registry = crate::oracle_system::OracleRegistry::new(66, 5000);
            let _ = registry.register_oracle(oracle_id.clone());
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let sig = crate::oracle_system::OracleRegistry::generate_signature(&oracle_id, price, ts);
            let _ = registry.submit_price_report(
                &oracle_id,
                symbol,
                price,
                ts,
                sig,
                confidence,
            );
        }

        /// Aggregation with arbitrary prices should not panic or overflow.
        #[test]
        fn oracle_aggregate_never_panics(
            prices in prop::collection::vec(1u64..u64::MAX, 1..10),
        ) {
            let mut registry = crate::oracle_system::OracleRegistry::new(66, 5000);
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            for (i, price) in prices.iter().enumerate() {
                let id = format!("oracle-{i}");
                let _ = registry.register_oracle(id.clone());
                let sig = crate::oracle_system::OracleRegistry::generate_signature(&id, *price, ts);
                let _ = registry.submit_price_report(
                    &id,
                    "TEST".into(),
                    *price,
                    ts,
                    sig,
                    95,
                );
            }
            let _ = registry.aggregate_reports("TEST", ts);
        }
    }

    // ── Credential parsing ───────────────────────────────────────────────────

    proptest! {
        /// Arbitrary JSON should never panic the credential deserializer.
        #[test]
        fn credential_deser_never_panics(data in "\\PC{0,500}") {
            let _ = serde_json::from_str::<crate::storage::traits::Credential>(&data);
        }

        #[test]
        fn credential_full_roundtrip(
            id in "[a-z0-9-]{1,64}",
            issuer in "[a-z0-9:]{1,64}",
            subject in "[a-z0-9:]{1,64}",
            cred_type in "[A-Za-z]{1,32}",
            issued_at in any::<u64>(),
            expires_at in any::<u64>(),
            has_revoked in any::<bool>(),
            sig_hex in "[a-f0-9]{128}",
            status in prop_oneof![Just("active"), Just("revoked"), Just("suspended")],
        ) {
            let revoked_at = if has_revoked { Some(expires_at.wrapping_add(1)) } else { None };
            let cred = crate::storage::traits::Credential {
                id: id.clone(),
                issuer_did: issuer.clone(),
                subject_did: subject.clone(),
                cred_type: cred_type.clone(),
                claims: serde_json::json!({"eidas_level": "high"}),
                issued_at,
                expires_at,
                revoked_at,
                signature: sig_hex.clone(),
                status: status.to_string(),
                claims_commitment: None,
                claims_salt: None,
            };
            let json = serde_json::to_string(&cred).unwrap();
            let back: crate::storage::traits::Credential = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&back.id, &id);
            prop_assert_eq!(&back.issuer_did, &issuer);
            prop_assert_eq!(&back.subject_did, &subject);
            prop_assert_eq!(&back.cred_type, &cred_type);
            prop_assert_eq!(back.issued_at, issued_at);
            prop_assert_eq!(back.expires_at, expires_at);
            prop_assert_eq!(back.revoked_at, revoked_at);
            prop_assert_eq!(&back.signature, &sig_hex);
            prop_assert_eq!(&back.status, status);
            prop_assert_eq!(back.claims.get("eidas_level").and_then(|v| v.as_str()), Some("high"));
        }
    }

    // ── Block full roundtrip ─────────────────────────────────────────────────

    fn arb_signing_algorithm() -> impl Strategy<Value = crate::identity::signing::SigningAlgorithm>
    {
        prop_oneof![
            Just(crate::identity::signing::SigningAlgorithm::Ed25519),
            Just(crate::identity::signing::SigningAlgorithm::MlDsa65),
            Just(crate::identity::signing::SigningAlgorithm::SlhDsa128s),
            Just(crate::identity::signing::SigningAlgorithm::EcdsaP256),
        ]
    }

    fn arb_hash_algorithm() -> impl Strategy<Value = crate::crypto::hasher::HashAlgorithm> {
        prop_oneof![
            Just(crate::crypto::hasher::HashAlgorithm::Sha256),
            Just(crate::crypto::hasher::HashAlgorithm::Sha3_256),
        ]
    }

    proptest! {
        #[test]
        fn block_full_roundtrip(
            height in any::<u64>(),
            timestamp in any::<u64>(),
            parent_hash in any::<[u8; 32]>(),
            merkle_root in any::<[u8; 32]>(),
            proposer in "[a-z0-9:]{1,64}",
            sig_len in prop_oneof![Just(64usize), Just(3309usize)],
            sig_algo in arb_signing_algorithm(),
            hash_algo in arb_hash_algorithm(),
            tx_count in 0usize..10,
            endorsement_count in 0usize..3,
            entry_count in 0usize..3,
            has_secondary in any::<bool>(),
            has_orderer in any::<bool>(),
        ) {
            let txs: Vec<String> = (0..tx_count).map(|i| format!("tx-{i}")).collect();
            let signature = vec![0xAB; sig_len];

            let endorsements: Vec<_> = (0..endorsement_count).map(|i| {
                crate::endorsement::types::Endorsement {
                    signer_did: format!("did:goya:endorser{i}"),
                    org_id: format!("org-{i}"),
                    signature: vec![0xCC; 64],
                    signature_algorithm: crate::identity::signing::SigningAlgorithm::Ed25519,
                    payload_hash: [i as u8; 32],
                    timestamp: 1000 + i as u64,
                }
            }).collect();

            let entries: Vec<_> = (0..entry_count).map(|i| {
                crate::storage::traits::NotarizationEntry {
                    signer_proof: None,
                    id: format!("entry-{i}"),
                    content_hash: "a".repeat(64),
                    signer: format!("did:goya:noter{i}"),
                    metadata: None,
                    notarized_at: 2000 + i as u64,
                    block_height: height,
                    signature: "b".repeat(128),
                    public_key: "aa".repeat(32),
                    cades_der: None,
                    signature_algorithm: sig_algo,
                    signature_level: crate::signature::SignatureLevel::Simple,
                    biometric_evidence: vec![],
                }
            }).collect();

            let secondary_signature = if has_secondary { Some(vec![0xDD; 3309]) } else { None };
            let secondary_signature_algorithm = if has_secondary {
                Some(crate::identity::signing::SigningAlgorithm::MlDsa65)
            } else { None };
            let orderer_signature = if has_orderer { Some(vec![0xEE; 64]) } else { None };

            let block = crate::storage::traits::Block {
                height,
                timestamp,
                parent_hash,
                merkle_root,
                transactions: txs.clone(),
                proposer: proposer.clone(),
                signature: signature.clone(),
                signature_algorithm: sig_algo,
                endorsements: endorsements.clone(),
                secondary_signature: secondary_signature.clone(),
                secondary_signature_algorithm,
                hash_algorithm: hash_algo,
                orderer_signature: orderer_signature.clone(),
                commit_qc: None,
                embedded_entries: entries.clone(),
                transaction_data: vec![],
            };

            let json = serde_json::to_string(&block).unwrap();
            let back: crate::storage::traits::Block = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(back.height, height);
            prop_assert_eq!(back.timestamp, timestamp);
            prop_assert_eq!(back.parent_hash, parent_hash);
            prop_assert_eq!(back.merkle_root, merkle_root);
            prop_assert_eq!(back.transactions, txs);
            prop_assert_eq!(&back.proposer, &proposer);
            prop_assert_eq!(&back.signature, &signature);
            prop_assert_eq!(back.signature_algorithm, sig_algo);
            prop_assert_eq!(back.hash_algorithm, hash_algo);
            prop_assert_eq!(&back.secondary_signature, &secondary_signature);
            prop_assert_eq!(back.secondary_signature_algorithm, secondary_signature_algorithm);
            prop_assert_eq!(&back.orderer_signature, &orderer_signature);
            prop_assert_eq!(back.endorsements.len(), endorsement_count);
            prop_assert_eq!(back.embedded_entries.len(), entry_count);
            prop_assert!(back.commit_qc.is_none());

            let bytes = serde_json::to_vec(&block).unwrap();
            let back2: crate::storage::traits::Block = serde_json::from_slice(&bytes).unwrap();
            prop_assert_eq!(back2.height, height);
            prop_assert_eq!(&back2.signature, &back.signature);
        }
    }

    // ── Transaction full roundtrip ──────────────────────────────────────────

    proptest! {
        #[test]
        fn transaction_full_roundtrip(
            id in "[a-z0-9-]{1,64}",
            block_height in any::<u64>(),
            timestamp in any::<u64>(),
            input_did in "[a-z0-9:]{1,64}",
            output_recipient in "[a-z0-9:]{1,64}",
            amount in any::<u64>(),
            state in prop_oneof![Just("pending"), Just("confirmed"), Just("failed")],
        ) {
            let tx = crate::storage::traits::Transaction {
                id: id.clone(),
                block_height,
                timestamp,
                input_did: input_did.clone(),
                output_recipient: output_recipient.clone(),
                amount,
                state: state.to_string(),
                fee: 0,
                payload: None,
            };

            let json = serde_json::to_string(&tx).unwrap();
            let back: crate::storage::traits::Transaction = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(&back.id, &id);
            prop_assert_eq!(back.block_height, block_height);
            prop_assert_eq!(back.timestamp, timestamp);
            prop_assert_eq!(&back.input_did, &input_did);
            prop_assert_eq!(&back.output_recipient, &output_recipient);
            prop_assert_eq!(back.amount, amount);
            prop_assert_eq!(&back.state, state);
        }
    }

    // ── IdentityRecord full roundtrip ───────────────────────────────────────

    proptest! {
        #[test]
        fn identity_record_full_roundtrip(
            did in "did:goya:[a-f0-9]{16}",
            public_key in "[a-f0-9]{64}",
            created_at in any::<u64>(),
            updated_at in any::<u64>(),
            status in prop_oneof![Just("active"), Just("revoked"), Just("migrated")],
            has_migrated_from in any::<bool>(),
        ) {
            let migrated_from = if has_migrated_from {
                Some("did:goya:oldkey12345678".to_string())
            } else { None };

            let record = crate::storage::traits::IdentityRecord {
                did: did.clone(),
                public_key: public_key.clone(),
                created_at,
                updated_at,
                status: status.to_string(),
                migrated_from: migrated_from.clone(),
                signature_algorithm: None,
                civil_anchor: None,
            };

            let json = serde_json::to_string(&record).unwrap();
            let back: crate::storage::traits::IdentityRecord = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(&back.did, &did);
            prop_assert_eq!(&back.public_key, &public_key);
            prop_assert_eq!(back.created_at, created_at);
            prop_assert_eq!(back.updated_at, updated_at);
            prop_assert_eq!(&back.status, status);
            prop_assert_eq!(back.migrated_from, migrated_from);
        }
    }

    // ── Block JSON idempotency ──────────────────────────────────────────────

    proptest! {
        #[test]
        fn block_double_roundtrip_is_idempotent(
            height in any::<u64>(),
            proposer in "[a-z0-9]{1,32}",
            sig_algo in arb_signing_algorithm(),
        ) {
            let block = crate::storage::traits::Block {
                height,
                timestamp: 0,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: vec!["tx-0".into()],
                proposer,
                signature: vec![0xFF; 64],
                signature_algorithm: sig_algo,
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: None,
                embedded_entries: vec![],
                transaction_data: vec![],
            };

            let json1 = serde_json::to_string(&block).unwrap();
            let mid: crate::storage::traits::Block = serde_json::from_str(&json1).unwrap();
            let json2 = serde_json::to_string(&mid).unwrap();

            prop_assert_eq!(&json1, &json2);
        }
    }

    // ── Signature consistency ────────────────────────────────────────────────

    proptest! {
        /// Arbitrary signature sizes should never panic the consistency checker.
        #[test]
        fn signature_consistency_never_panics(
            sig_len in 0usize..10000,
            algo_idx in 0u8..2,
        ) {
            use crate::identity::signing::SigningAlgorithm;
            let algo = if algo_idx == 0 {
                SigningAlgorithm::Ed25519
            } else {
                SigningAlgorithm::MlDsa65
            };
            let sig = vec![0xAA; sig_len];
            let _ = crate::identity::pqc_policy::validate_signature_consistency(
                algo, &sig, "fuzz-test",
            );
        }
    }

    // ── Signature size ↔ algorithm cross-validation ───────────────────────────

    proptest! {
        #[test]
        fn correct_sig_size_passes_consistency(
            sig_algo in arb_signing_algorithm(),
        ) {
            use crate::identity::pqc_policy::validate_signature_consistency;

            let expected_len = match sig_algo {
                crate::identity::signing::SigningAlgorithm::Ed25519 => 64,
                crate::identity::signing::SigningAlgorithm::MlDsa65 => 3309,
                crate::identity::signing::SigningAlgorithm::SlhDsa128s => 7856,
                crate::identity::signing::SigningAlgorithm::Rsa => 256,
                crate::identity::signing::SigningAlgorithm::EcdsaP256 => 64,
            };
            let sig = vec![0xAA; expected_len];
            prop_assert!(validate_signature_consistency(sig_algo, &sig, "proptest").is_ok());
        }

        #[test]
        fn wrong_sig_size_fails_consistency(
            sig_algo in arb_signing_algorithm(),
            delta in 1usize..100,
            add in any::<bool>(),
        ) {
            use crate::identity::pqc_policy::validate_signature_consistency;

            let expected_len = match sig_algo {
                crate::identity::signing::SigningAlgorithm::Ed25519 => 64,
                crate::identity::signing::SigningAlgorithm::MlDsa65 => 3309,
                crate::identity::signing::SigningAlgorithm::SlhDsa128s => 7856,
                crate::identity::signing::SigningAlgorithm::Rsa => 256,
                crate::identity::signing::SigningAlgorithm::EcdsaP256 => 64,
            };
            let wrong_len = if add { expected_len + delta } else { expected_len.saturating_sub(delta) };
            prop_assume!(wrong_len != expected_len);
            let sig = vec![0xBB; wrong_len];
            prop_assert!(validate_signature_consistency(sig_algo, &sig, "proptest").is_err());
        }
    }

    // ── Legacy JSON (missing default fields) deserializes correctly ──────────

    proptest! {
        #[test]
        fn block_missing_defaults_uses_sane_values(
            height in any::<u64>(),
            proposer in "[a-z0-9]{1,16}",
        ) {
            let zeros_32: Vec<u8> = vec![0u8; 32];
            let legacy_json = serde_json::json!({
                "height": height,
                "timestamp": 0,
                "parent_hash": zeros_32,
                "merkle_root": zeros_32,
                "transactions": [],
                "proposer": proposer,
                "signature": hex::encode(vec![0u8; 64]),
            });

            let block: crate::storage::traits::Block = serde_json::from_value(legacy_json).unwrap();
            prop_assert_eq!(block.signature_algorithm, crate::identity::signing::SigningAlgorithm::Ed25519);
            prop_assert_eq!(block.hash_algorithm, crate::crypto::hasher::HashAlgorithm::Sha256);
            prop_assert!(block.endorsements.is_empty());
            prop_assert!(block.secondary_signature.is_none());
            prop_assert!(block.orderer_signature.is_none());
            prop_assert!(block.commit_qc.is_none());
            prop_assert!(block.embedded_entries.is_empty());
        }
    }

    // ── Tampered JSON produces different values ─────────────────────────────

    proptest! {
        #[test]
        fn tampered_height_detected(
            height in 0u64..u64::MAX,
            proposer in "[a-z0-9]{1,16}",
        ) {
            let block = crate::storage::traits::Block {
                height,
                timestamp: 0,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: vec![],
                proposer,
                signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: None,
                embedded_entries: vec![],
                transaction_data: vec![],
            };

            let mut json: serde_json::Value = serde_json::to_value(&block).unwrap();
            let original_height = json["height"].as_u64().unwrap();
            json["height"] = serde_json::json!(original_height.wrapping_add(1));

            let tampered: crate::storage::traits::Block = serde_json::from_value(json).unwrap();
            prop_assert_ne!(tampered.height, height);
        }
    }

    // ── Signature algorithm roundtrip exhaustive ────────────────────────────

    proptest! {
        #[test]
        fn signing_algorithm_json_roundtrip(
            algo in arb_signing_algorithm(),
        ) {
            let json = serde_json::to_string(&algo).unwrap();
            let back: crate::identity::signing::SigningAlgorithm = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back, algo);
        }

        #[test]
        fn hash_algorithm_json_roundtrip(
            algo in arb_hash_algorithm(),
        ) {
            let json = serde_json::to_string(&algo).unwrap();
            let back: crate::crypto::hasher::HashAlgorithm = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back, algo);
        }
    }

    // ── Endorsement roundtrip (custom vec_hex + hash_hex) ─────────────────────

    proptest! {
        #[test]
        fn endorsement_roundtrip_all_algos(
            signer_did in "did:goya:[a-f0-9]{16}",
            org_id in "[a-z0-9]{1,16}",
            sig_bytes in prop::collection::vec(any::<u8>(), 0..=3309),
            algo in arb_signing_algorithm(),
            payload_hash in any::<[u8; 32]>(),
            timestamp in any::<u64>(),
        ) {
            let endorsement = crate::endorsement::types::Endorsement {
                signer_did: signer_did.clone(),
                org_id: org_id.clone(),
                signature: sig_bytes.clone(),
                signature_algorithm: algo,
                payload_hash,
                timestamp,
            };
            let json = serde_json::to_string(&endorsement).unwrap();
            let back: crate::endorsement::types::Endorsement = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back, endorsement);
        }
    }

    // ── vec_hex / opt_vec_hex edge cases ────────────────────────────────────

    proptest! {
        #[test]
        fn block_empty_signature_roundtrips(height in any::<u64>()) {
            let block = crate::storage::traits::Block {
                height,
                timestamp: 0,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: vec![],
                proposer: "p".into(),
                signature: vec![],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: Some(vec![]),
                secondary_signature_algorithm: Some(crate::identity::signing::SigningAlgorithm::MlDsa65),
                hash_algorithm: Default::default(),
                orderer_signature: Some(vec![]),
                commit_qc: None,
                embedded_entries: vec![],
                transaction_data: vec![],
            };
            let json = serde_json::to_string(&block).unwrap();
            let back: crate::storage::traits::Block = serde_json::from_str(&json).unwrap();
            prop_assert!(back.signature.is_empty());
            prop_assert_eq!(&back.secondary_signature, &Some(vec![]));
            prop_assert_eq!(&back.orderer_signature, &Some(vec![]));
        }
    }

    // ── Block with QuorumCertificate ────────────────────────────────────────

    proptest! {
        #[test]
        fn block_with_qc_roundtrip(
            height in any::<u64>(),
            round in any::<u64>(),
            block_hash in any::<[u8; 32]>(),
            voter_count in 1usize..5,
            phase_idx in 0u8..4,
        ) {
            use crate::consensus::bft::types::{BftPhase, QuorumCertificate, VoteMessage};

            let phase = match phase_idx {
                0 => BftPhase::Prepare,
                1 => BftPhase::PreCommit,
                2 => BftPhase::Commit,
                _ => BftPhase::Decide,
            };

            let votes: Vec<VoteMessage> = (0..voter_count).map(|i| {
                VoteMessage {
                    block_hash,
                    round,
                    phase,
                    voter_id: format!("did:goya:voter{i:016x}"),
                    signature: vec![0xAA; 64],
                }
            }).collect();

            let qc = QuorumCertificate::new(phase, block_hash, round, votes.clone()).unwrap();

            let block = crate::storage::traits::Block {
                height,
                timestamp: 0,
                parent_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                transactions: vec![],
                proposer: "leader".into(),
                signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                endorsements: vec![],
                secondary_signature: None,
                secondary_signature_algorithm: None,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: Some(qc),
                embedded_entries: vec![],
                transaction_data: vec![],
            };

            let json = serde_json::to_string(&block).unwrap();
            let back: crate::storage::traits::Block = serde_json::from_str(&json).unwrap();

            let back_qc = back.commit_qc.unwrap();
            prop_assert_eq!(back_qc.block_hash, block_hash);
            prop_assert_eq!(back_qc.round, round);
            prop_assert_eq!(back_qc.phase, phase);
            prop_assert_eq!(back_qc.votes.len(), voter_count);
            for (orig, deser) in votes.iter().zip(back_qc.votes.iter()) {
                prop_assert_eq!(&deser.voter_id, &orig.voter_id);
                prop_assert_eq!(&deser.signature, &orig.signature);
                prop_assert_eq!(deser.phase, orig.phase);
            }
        }
    }

    // ── NotarizationEntry with biometric evidence ───────────────────────────

    proptest! {
        #[test]
        fn notarization_entry_with_biometrics_roundtrip(
            signer in "did:goya:[a-f0-9]{16}",
            captured_at in any::<u64>(),
            has_device in any::<bool>(),
        ) {
            use crate::signature::{BiometricEvidence, BiometricType, SignatureLevel};

            let evidence = BiometricEvidence {
                evidence_type: BiometricType::Fingerprint,
                commitment: "a".repeat(64),
                captured_at,
                capture_device: if has_device { Some("Scanner-v3".into()) } else { None },
            };

            let entry = crate::storage::traits::NotarizationEntry {
                signer_proof: None,
                id: "test-entry".into(),
                content_hash: "b".repeat(64),
                signer: signer.clone(),
                metadata: Some(serde_json::json!({"doc": "contract.pdf"})),
                notarized_at: captured_at,
                block_height: 42,
                signature: "c".repeat(128),
                public_key: "aa".repeat(1952),
                cades_der: None,
                signature_algorithm: crate::identity::signing::SigningAlgorithm::MlDsa65,
                signature_level: SignatureLevel::Advanced,
                biometric_evidence: vec![evidence],
            };

            let json = serde_json::to_string(&entry).unwrap();
            let back: crate::storage::traits::NotarizationEntry = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back, entry);
        }
    }

    // ── Transaction conflict detection ───────────────────────────────────────

    proptest! {
        /// Arbitrary transaction batches should not panic the scheduler.
        #[test]
        fn schedule_batch_never_panics(
            tx_count in 0usize..50,
            key_count in 1usize..10,
        ) {
            use crate::transaction::parallel::{schedule_batch, TxWithRwSet};
            use crate::transaction::rwset::{KVRead, KVWrite, ReadWriteSet};

            let keys: Vec<String> = (0..key_count).map(|i| format!("key-{i}")).collect();

            let txs: Vec<TxWithRwSet> = (0..tx_count).map(|i| {
                let read_key = &keys[i % key_count];
                let write_key = &keys[(i + 1) % key_count];
                TxWithRwSet {
                    index: i,
                    tx_id: format!("tx-{i}"),
                    rwset: ReadWriteSet {
                        reads: vec![KVRead { key: read_key.clone(), version: 1 }],
                        writes: vec![KVWrite { key: write_key.clone(), value: vec![1] }],
                    },
                }
            }).collect();

            let schedule = schedule_batch(&txs);
            // Invariant: all transactions must appear in exactly one wave
            let total_in_waves: usize = schedule.waves.iter().map(|w| w.tx_indices.len()).sum();
            prop_assert_eq!(total_in_waves, tx_count);
        }
    }
}
