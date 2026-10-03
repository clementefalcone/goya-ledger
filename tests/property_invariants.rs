//! Property-based invariant tests using proptest.
//!
//! Validates fundamental cryptographic and consensus invariants that
//! must hold for ALL inputs, not just specific test vectors.

use proptest::prelude::*;

use rust_bc::consensus::equivocation::EquivocationDetector;
use rust_bc::crypto::hasher::{hash_with, HashAlgorithm};
use rust_bc::identity::pqc_policy::validate_signature_consistency;
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::storage::traits::Block;

// ═══════════════════════════════════════════════════════════════════
// 1. Tampering any signed payload invalidates signature
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn tampering_payload_invalidates_mldsa_signature(
        data in proptest::collection::vec(any::<u8>(), 1..256),
        flip_pos in 0usize..256,
    ) {
        let signer = MlDsaSigningProvider::generate();
        let sig = signer.sign(&data).unwrap();

        // Verify original
        prop_assert!(signer.verify(&data, &sig).unwrap());

        // Tamper one byte
        let mut tampered = data.clone();
        let pos = flip_pos % tampered.len();
        tampered[pos] ^= 0xff;

        // Tampered must fail
        prop_assert!(!signer.verify(&tampered, &sig).unwrap());
    }
}

proptest! {
    #[test]
    fn tampering_payload_invalidates_ed25519_signature(
        data in proptest::collection::vec(any::<u8>(), 1..256),
        flip_pos in 0usize..256,
    ) {
        let signer = SoftwareSigningProvider::generate();
        let sig = signer.sign(&data).unwrap();

        prop_assert!(signer.verify(&data, &sig).unwrap());

        let mut tampered = data.clone();
        let pos = flip_pos % tampered.len();
        tampered[pos] ^= 0xff;

        prop_assert!(!signer.verify(&tampered, &sig).unwrap());
    }
}

// ═══════════════════════════════════════════════════════════════════
// 2. Same proposer cannot have two blocks at same position
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn equivocation_always_detected_for_conflicting_blocks(
        height in 0u64..1000,
        slot in 0u64..1000,
        hash_a in any::<[u8; 32]>(),
        hash_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(hash_a != hash_b);

        let mut det = EquivocationDetector::new();
        det.check_proposal(height, slot, "proposer", hash_a, &[1u8; 64], SigningAlgorithm::MlDsa65);
        let result = det.check_proposal(height, slot, "proposer", hash_b, &[2u8; 64], SigningAlgorithm::MlDsa65);

        prop_assert!(result.is_some(), "equivocation must always be detected");
        prop_assert!(det.is_penalized("proposer"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3. Duplicate messages do not change state
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn duplicate_proposal_is_idempotent(
        height in 0u64..1000,
        hash in any::<[u8; 32]>(),
    ) {
        let mut det = EquivocationDetector::new();
        let r1 = det.check_proposal(height, height, "dup", hash, &[1u8; 64], SigningAlgorithm::MlDsa65);
        let r2 = det.check_proposal(height, height, "dup", hash, &[1u8; 64], SigningAlgorithm::MlDsa65);

        prop_assert!(r1.is_none());
        prop_assert!(r2.is_none());
        prop_assert!(!det.is_penalized("dup"));
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. Hash changes if block content changes
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn hash_changes_with_different_input(
        data_a in proptest::collection::vec(any::<u8>(), 1..512),
        data_b in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(data_a != data_b);

        let h_a = hash_with(HashAlgorithm::Sha3_256, &data_a);
        let h_b = hash_with(HashAlgorithm::Sha3_256, &data_b);
        prop_assert_ne!(h_a, h_b, "different inputs must produce different hashes");
    }
}

// ═══════════════════════════════════════════════════════════════════
// 5. Serialization roundtrip preserves PQC metadata
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn block_serde_roundtrip_preserves_pqc_metadata(
        height in 0u64..10000,
        algo in prop_oneof![Just(SigningAlgorithm::Ed25519), Just(SigningAlgorithm::MlDsa65)],
        hash_algo in prop_oneof![Just(HashAlgorithm::Sha256), Just(HashAlgorithm::Sha3_256)],
    ) {
        let block = Block {
            height,
            timestamp: height * 6,
            parent_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            transactions: vec![],
            proposer: "prop".to_string(),
            signature: vec![42u8; if algo == SigningAlgorithm::Ed25519 { 64 } else { 3309 }],
            signature_algorithm: algo,
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: hash_algo,
            orderer_signature: None, commit_qc: None, transaction_data: vec![],
        };

        let json = serde_json::to_string(&block).unwrap();
        let decoded: Block = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(decoded.signature_algorithm, algo);
        prop_assert_eq!(decoded.hash_algorithm, hash_algo);
        prop_assert_eq!(decoded.height, height);
        prop_assert_eq!(decoded.signature.len(), block.signature.len());
    }
}

// ═══════════════════════════════════════════════════════════════════
// 6. Strict PQC mode never accepts classical-only
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn signature_consistency_catches_all_mismatches(
        sig_len in 0usize..10000,
    ) {
        prop_assume!(sig_len != 64 && sig_len != 3309);

        let sig = vec![42u8; sig_len];

        // Neither Ed25519 (expects 64) nor MlDsa65 (expects 3309) should accept
        let r1 = validate_signature_consistency(SigningAlgorithm::Ed25519, &sig, "test");
        let r2 = validate_signature_consistency(SigningAlgorithm::MlDsa65, &sig, "test");

        prop_assert!(r1.is_err(), "Ed25519 must reject {sig_len}-byte sig");
        prop_assert!(r2.is_err(), "MlDsa65 must reject {sig_len}-byte sig");
    }
}
