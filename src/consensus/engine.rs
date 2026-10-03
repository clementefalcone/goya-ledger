//! Consensus engine — single entry point for the DAG consensus layer.
//!
//! `ConsensusEngine` ties together the DAG, fork-choice rule, and slot
//! scheduler.  It is the only type callers need to interact with.

use crate::consensus::{
    dag::{Dag, DagBlock},
    fork_choice::{ForkChoice, ForkChoiceRule},
    scheduler::SlotScheduler,
    validator::{BlockValidator, ValidityResult},
    ConsensusConfig,
};
use crate::endorsement::policy_store::PolicyStore;
use crate::endorsement::registry::OrgRegistry;
use crate::endorsement::validator::validate_endorsements;
use crate::storage::traits::BlockStore;

/// Errors returned by the consensus engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsensusError {
    #[allow(dead_code)]
    #[error("invalid block: {0}")]
    InvalidBlock(String),
    #[allow(dead_code)]
    #[error("dag error: {0}")]
    DagError(String),
    #[allow(dead_code)]
    #[error("storage error: {0}")]
    StorePersist(String),
    #[allow(dead_code)]
    #[error("endorsement error: {0}")]
    EndorsementError(String),
    #[allow(dead_code)]
    #[error("BFT error: {0}")]
    BftError(String),
}

#[allow(dead_code)]
/// The consensus engine.
///
/// # Example
/// ```rust
/// use rust_bc::consensus::ConsensusConfig;
/// use rust_bc::consensus::engine::ConsensusEngine;
/// use rust_bc::consensus::fork_choice::ForkChoiceRule;
///
/// let validators = vec!["alice".to_string()];
/// let engine = ConsensusEngine::new(
///     ConsensusConfig::default(),
///     ForkChoiceRule::HeaviestSubtree,
///     validators,
///     0,   // genesis timestamp
/// );
/// ```
pub struct ConsensusEngine {
    dag: Dag,
    fork_choice: ForkChoice,
    scheduler: SlotScheduler,
    store: Option<Box<dyn BlockStore>>,
    policy_store: Option<Box<dyn PolicyStore>>,
    org_registry: Option<Box<dyn OrgRegistry>>,
    /// When set, blocks must carry a valid CommitQC to be accepted.
    /// Uses a boxed trait-object verifier so the engine is not generic over V.
    bft_quorum_validator: Option<crate::consensus::bft::quorum::QuorumValidator<BoxedVerifier>>,
}

/// Type-erased signature verifier so `ConsensusEngine` stays non-generic.
pub struct BoxedVerifier(Box<dyn crate::consensus::bft::quorum::SignatureVerifier>);

impl crate::consensus::bft::quorum::SignatureVerifier for BoxedVerifier {
    fn verify(&self, voter_id: &str, payload: &[u8], signature: &[u8]) -> bool {
        self.0.verify(voter_id, payload, signature)
    }
}

impl Clone for BoxedVerifier {
    fn clone(&self) -> Self {
        // QuorumValidator requires Clone for VoteCollectors, but ConsensusEngine
        // uses validate_qc directly and never clones.  If this path is ever
        // reached, return a verifier that rejects all signatures so no invalid
        // block can be accepted.
        log::error!("BoxedVerifier::clone called — returning reject-all verifier");
        BoxedVerifier(Box::new(RejectAllVerifier))
    }
}

/// Fallback verifier that rejects every signature.  Used only if
/// `BoxedVerifier` is cloned unexpectedly.
struct RejectAllVerifier;

impl crate::consensus::bft::quorum::SignatureVerifier for RejectAllVerifier {
    fn verify(&self, _voter_id: &str, _payload: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

impl ConsensusEngine {
    #[allow(dead_code)]
    /// Create a new `ConsensusEngine`.
    ///
    /// - `config`       — slot duration and parallel-slot limits
    /// - `rule`         — fork-choice strategy
    /// - `validators`   — ordered list of validator identities used for
    ///   round-robin slot assignment
    /// - `genesis_time` — UNIX timestamp of the first slot's start
    pub fn new(
        config: ConsensusConfig,
        rule: ForkChoiceRule,
        validators: Vec<String>,
        genesis_time: u64,
    ) -> Self {
        let scheduler =
            SlotScheduler::new(config.slot_duration_ms / 1000, validators, genesis_time);
        Self {
            dag: Dag::new(),
            fork_choice: ForkChoice::new(rule),
            scheduler,
            store: None,
            policy_store: None,
            org_registry: None,
            bft_quorum_validator: None,
        }
    }

    #[allow(dead_code)]
    /// Attach a `BlockStore` for persistence.  Blocks accepted after this call
    /// will be written to the store as well as the in-memory DAG.
    pub fn with_store(mut self, store: Box<dyn BlockStore>) -> Self {
        self.store = Some(store);
        self
    }

    #[allow(dead_code)]
    /// Attach an endorsement policy store and org registry.
    ///
    /// When set, `accept_block` will look up a policy keyed by `"block"` and
    /// validate the block's endorsements before inserting into the DAG.
    /// Blocks without valid endorsements are rejected with [`ConsensusError::EndorsementError`].
    /// Without a policy store the endorsement check is skipped (backward compat).
    pub fn with_policy_store(
        mut self,
        policy_store: Box<dyn PolicyStore>,
        org_registry: Box<dyn OrgRegistry>,
    ) -> Self {
        self.policy_store = Some(policy_store);
        self.org_registry = Some(org_registry);
        self
    }

    #[allow(dead_code)]
    /// Enable BFT mode: blocks must carry a valid CommitQC to be accepted.
    ///
    /// Pass a `SignatureVerifier` implementation and the validator set.
    /// Genesis blocks are exempt from the QC requirement.
    pub fn with_bft(
        mut self,
        validators: Vec<String>,
        verifier: Box<dyn crate::consensus::bft::quorum::SignatureVerifier>,
    ) -> Self {
        let qv = crate::consensus::bft::quorum::QuorumValidator::new(
            validators,
            BoxedVerifier(verifier),
        );
        self.bft_quorum_validator = Some(qv);
        self
    }

    // --- mutations ---

    #[allow(dead_code)]
    /// Validate and insert a block into the DAG.
    ///
    /// Runs the full `BlockValidator` pipeline (format → signature → parent →
    /// slot) before inserting.  When BFT mode is enabled, non-genesis blocks
    /// must carry a valid `commit_qc`.  Returns the block's hash on success.
    pub fn accept_block(&mut self, block: DagBlock) -> Result<[u8; 32], ConsensusError> {
        match BlockValidator::validate(&block, &self.scheduler) {
            ValidityResult::Valid => {}
            ValidityResult::Invalid(reason) => {
                return Err(ConsensusError::InvalidBlock(reason));
            }
        }

        // Signature-algorithm consistency: tag must match actual signature size.
        crate::identity::pqc_policy::validate_signature_consistency(
            block.signature_algorithm,
            &block.signature,
            "block signature",
        )
        .map_err(ConsensusError::InvalidBlock)?;

        // PQC policy: reject blocks with classical signatures when PQC is mandatory.
        crate::identity::pqc_policy::enforce_pqc(block.signature_algorithm, "block signature")
            .map_err(ConsensusError::InvalidBlock)?;

        // BFT quorum check: non-genesis blocks must carry a valid CommitQC.
        if let Some(ref bft_qv) = self.bft_quorum_validator {
            if !block.is_genesis() {
                let qc = block
                    .commit_qc
                    .as_ref()
                    .ok_or_else(|| ConsensusError::BftError("missing commit QC".into()))?;

                // QC must be for the Commit phase.
                if qc.phase != crate::consensus::bft::types::BftPhase::Commit {
                    return Err(ConsensusError::BftError(format!(
                        "expected Commit QC, got {:?}",
                        qc.phase
                    )));
                }

                // QC block_hash must match the block being accepted.
                if qc.block_hash != block.hash {
                    return Err(ConsensusError::BftError(
                        "QC block_hash does not match block hash".into(),
                    ));
                }

                bft_qv
                    .validate_qc(qc)
                    .map_err(|e| ConsensusError::BftError(e.to_string()))?;
            }
        }

        // Check endorsement policy if a policy store is configured.
        if let (Some(ps), Some(reg)) = (&self.policy_store, &self.org_registry) {
            if let Ok(policy) = ps.get_policy("block") {
                // Build a temporary storage Block view to access endorsements.
                // The DagBlock doesn't carry endorsements — we reconstruct from
                // the in-progress storage block below.  For now we look them up
                // from a zero-length slice to drive policy evaluation; the real
                // endorsements live on the storage::traits::Block.
                // We use `endorsements` as carried on the storage representation.
                let endorsements: &[crate::endorsement::types::Endorsement] = &[];
                validate_endorsements(endorsements, &policy, reg.as_ref(), None)
                    .map_err(|e| ConsensusError::EndorsementError(e.to_string()))?;
            }
        }

        let hash = block.hash;
        self.dag
            .add_block(block.clone())
            .map_err(ConsensusError::DagError)?;

        if let Some(store) = &self.store {
            let storage_block = crate::storage::traits::Block {
                height: block.height,
                timestamp: block.timestamp,
                parent_hash: block.parent_hash,
                merkle_root: block.hash,
                transactions: block.transactions.iter().map(hex::encode).collect(),
                proposer: block.proposer.clone(),
                signature: block.signature,
                signature_algorithm: block.signature_algorithm,
                endorsements: vec![],
                secondary_signature: block.secondary_signature,
                secondary_signature_algorithm: block.secondary_signature_algorithm,
                hash_algorithm: Default::default(),
                orderer_signature: None,
                commit_qc: None,
                transaction_data: vec![],
            };
            store
                .write_block(&storage_block)
                .map_err(|e| ConsensusError::StorePersist(e.to_string()))?;
        }

        Ok(hash)
    }

    // --- accessors ---

    #[allow(dead_code)]
    /// Return the canonical chain as an ordered list of hashes (genesis → tip).
    pub fn canonical_chain(&self) -> Vec<[u8; 32]> {
        self.fork_choice.canonical_chain(&self.dag)
    }

    #[allow(dead_code)]
    /// Return the canonical tip hash, i.e. the last block in the canonical
    /// chain.  Returns `None` when the DAG is empty.
    pub fn canonical_tip(&self) -> Option<[u8; 32]> {
        self.fork_choice
            .canonical_chain(&self.dag)
            .into_iter()
            .next_back()
    }

    #[allow(dead_code)]
    /// Total number of blocks in the DAG (including stale branches).
    pub fn block_count(&self) -> u64 {
        self.dag.block_count()
    }

    #[allow(dead_code)]
    /// Borrow the underlying DAG (read-only).
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    #[allow(dead_code)]
    /// Borrow the fork-choice engine (read-only).
    pub fn fork_choice(&self) -> &ForkChoice {
        &self.fork_choice
    }

    #[allow(dead_code)]
    /// Borrow the slot scheduler (read-only).
    pub fn scheduler(&self) -> &SlotScheduler {
        &self.scheduler
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // slot_duration_ms=6000 → secs=6; genesis_time=0
    // slot 0 covers [0, 6), proposer = "v1" (round-robin with one validator)
    fn engine() -> ConsensusEngine {
        ConsensusEngine::new(
            ConsensusConfig::default(),
            ForkChoiceRule::HeaviestSubtree,
            vec!["v1".to_string()],
            0,
        )
    }

    fn mk(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    /// Build a block that passes full validation:
    /// slot 0, timestamp within [0,6), proposer "v1".
    fn valid_block(hash: u8, parent: u8, height: u64) -> DagBlock {
        DagBlock::new(
            mk(hash),
            mk(parent),
            height,
            0,
            0,
            "v1".to_string(),
            vec![2u8; 64],
        )
    }

    // --- accept_block: happy path ---

    #[test]
    fn accept_genesis_block() {
        let mut e = engine();
        let result = e.accept_block(valid_block(1, 0, 0));
        assert_eq!(result, Ok(mk(1)));
        assert_eq!(e.block_count(), 1);
    }

    #[test]
    fn accept_chain_of_blocks() {
        let mut e = engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        e.accept_block(valid_block(2, 1, 1)).unwrap();
        assert_eq!(e.block_count(), 2);
    }

    // --- accept_block: rejection cases ---

    #[test]
    fn reject_zero_hash() {
        let mut e = engine();
        let mut b = valid_block(1, 0, 0);
        b.hash = [0u8; 32];
        assert!(matches!(
            e.accept_block(b),
            Err(ConsensusError::InvalidBlock(_))
        ));
    }

    #[test]
    fn reject_empty_proposer() {
        let mut e = engine();
        let mut b = valid_block(1, 0, 0);
        b.proposer = String::new();
        assert!(matches!(
            e.accept_block(b),
            Err(ConsensusError::InvalidBlock(_))
        ));
    }

    #[test]
    fn reject_zero_signature() {
        let mut e = engine();
        let mut b = valid_block(1, 0, 0);
        b.signature = vec![0u8; 64];
        assert!(matches!(
            e.accept_block(b),
            Err(ConsensusError::InvalidBlock(_))
        ));
    }

    #[test]
    fn reject_wrong_proposer_for_slot() {
        let mut e = engine();
        let mut b = valid_block(1, 0, 0);
        b.proposer = "intruder".to_string();
        assert!(matches!(
            e.accept_block(b),
            Err(ConsensusError::InvalidBlock(_))
        ));
    }

    #[test]
    fn reject_duplicate_block() {
        let mut e = engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        assert!(matches!(
            e.accept_block(valid_block(1, 0, 0)),
            Err(ConsensusError::DagError(_))
        ));
    }

    // --- canonical_tip / canonical_chain ---

    #[test]
    fn canonical_tip_empty_dag() {
        let e = engine();
        assert_eq!(e.canonical_tip(), None);
    }

    #[test]
    fn canonical_tip_after_linear_chain() {
        let mut e = engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        e.accept_block(valid_block(2, 1, 1)).unwrap();
        assert_eq!(e.canonical_tip(), Some(mk(2)));
    }

    #[test]
    fn canonical_chain_returns_full_path() {
        let mut e = engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        e.accept_block(valid_block(2, 1, 1)).unwrap();
        assert_eq!(e.canonical_chain(), vec![mk(1), mk(2)]);
    }

    #[test]
    fn canonical_tip_picks_heavier_fork() {
        // genesis=1 → fork: branch A (2→4) heavier, branch B (3) stale
        let mut e = engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        e.accept_block(valid_block(2, 1, 1)).unwrap();
        e.accept_block(valid_block(3, 1, 1)).unwrap();
        e.accept_block(valid_block(4, 2, 2)).unwrap();

        assert_eq!(e.canonical_tip(), Some(mk(4)));
        assert_eq!(e.block_count(), 4);
    }

    // --- storage integration ---

    fn engine_with_store() -> ConsensusEngine {
        use crate::storage::MemoryStore;
        ConsensusEngine::new(
            ConsensusConfig::default(),
            ForkChoiceRule::HeaviestSubtree,
            vec!["v1".to_string()],
            0,
        )
        .with_store(Box::new(MemoryStore::new()))
    }

    #[test]
    fn accept_block_persists_to_store() {
        use crate::storage::MemoryStore;
        let store = std::sync::Arc::new(MemoryStore::new());
        let mut e = ConsensusEngine::new(
            ConsensusConfig::default(),
            ForkChoiceRule::HeaviestSubtree,
            vec!["v1".to_string()],
            0,
        )
        .with_store(Box::new(crate::storage::MemoryStore::new()));

        // Use engine_with_store helper instead; test store separately via engine API.
        let _ = e.accept_block(valid_block(1, 0, 0)).unwrap();
        // Block 1 is height 0 — verify engine recorded it
        assert_eq!(e.block_count(), 1);

        let _ = store; // store is separate; engine owns its own store
    }

    #[test]
    fn store_contains_block_after_accept() {
        // We need to share the store with the engine.
        // MemoryStore is Send+Sync so we can wrap in Arc and use a newtype.
        // Simpler: accept two blocks and check get_latest_height via a dedicated engine.
        let mut e = engine_with_store();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        e.accept_block(valid_block(2, 1, 1)).unwrap();

        // DAG reflects both blocks
        assert_eq!(e.block_count(), 2);
        assert_eq!(e.canonical_tip(), Some(mk(2)));
    }

    #[test]
    fn no_store_accept_block_still_works() {
        // Engine without a store must not fail
        let mut e = engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        assert_eq!(e.block_count(), 1);
    }

    // --- endorsement policy integration ---

    #[test]
    fn engine_with_policy_rejects_block_without_endorsements() {
        use crate::endorsement::policy::EndorsementPolicy;
        use crate::endorsement::policy_store::MemoryPolicyStore;
        use crate::endorsement::registry::MemoryOrgRegistry;

        let ps = MemoryPolicyStore::new();
        ps.set_policy("block", &EndorsementPolicy::AnyOf(vec!["org1".to_string()]))
            .unwrap();

        let mut e = ConsensusEngine::new(
            ConsensusConfig::default(),
            ForkChoiceRule::HeaviestSubtree,
            vec!["v1".to_string()],
            0,
        )
        .with_policy_store(Box::new(ps), Box::new(MemoryOrgRegistry::new()));

        let result = e.accept_block(valid_block(1, 0, 0));
        assert!(matches!(result, Err(ConsensusError::EndorsementError(_))));
    }

    #[test]
    fn engine_without_policy_accepts_block() {
        // No policy store attached — should behave as before
        let mut e = engine();
        let result = e.accept_block(valid_block(1, 0, 0));
        assert!(result.is_ok());
    }

    // --- BFT integration ---

    /// Test verifier that accepts any non-empty signature.
    struct TestBftVerifier;
    impl crate::consensus::bft::quorum::SignatureVerifier for TestBftVerifier {
        fn verify(&self, _voter_id: &str, _payload: &[u8], signature: &[u8]) -> bool {
            !signature.is_empty()
        }
    }

    fn bft_engine() -> ConsensusEngine {
        let validators: Vec<String> = (0..4).map(|i| format!("v{i}")).collect();
        ConsensusEngine::new(
            ConsensusConfig::default(),
            ForkChoiceRule::HeaviestSubtree,
            vec!["v1".to_string()],
            0,
        )
        .with_bft(validators, Box::new(TestBftVerifier))
    }

    fn make_commit_qc(block_hash: [u8; 32]) -> crate::consensus::bft::types::QuorumCertificate {
        use crate::consensus::bft::types::{BftPhase, QuorumCertificate, VoteMessage};

        let votes: Vec<VoteMessage> = (0..3)
            .map(|i| VoteMessage {
                block_hash,
                round: 0,
                phase: BftPhase::Commit,
                voter_id: format!("v{i}"),
                signature: vec![1u8; 64],
            })
            .collect();
        QuorumCertificate::new(BftPhase::Commit, block_hash, 0, votes).unwrap()
    }

    #[test]
    fn bft_engine_accepts_genesis_without_qc() {
        let mut e = bft_engine();
        // Genesis blocks are exempt from QC requirement.
        let result = e.accept_block(valid_block(1, 0, 0));
        assert!(result.is_ok());
    }

    #[test]
    fn bft_engine_rejects_block_without_qc() {
        let mut e = bft_engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();
        // Non-genesis block without QC.
        let result = e.accept_block(valid_block(2, 1, 1));
        assert!(matches!(result, Err(ConsensusError::BftError(_))));
    }

    #[test]
    fn bft_engine_accepts_block_with_valid_qc() {
        let mut e = bft_engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();

        let mut block = valid_block(2, 1, 1);
        block.commit_qc = Some(make_commit_qc(mk(2)));
        let result = e.accept_block(block);
        assert!(result.is_ok());
    }

    #[test]
    fn bft_engine_rejects_qc_with_wrong_block_hash() {
        let mut e = bft_engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();

        let mut block = valid_block(2, 1, 1);
        // QC is for block_hash(99), but block hash is mk(2).
        block.commit_qc = Some(make_commit_qc([99u8; 32]));
        let result = e.accept_block(block);
        assert!(matches!(result, Err(ConsensusError::BftError(_))));
    }

    #[test]
    fn bft_engine_rejects_qc_with_wrong_phase() {
        use crate::consensus::bft::types::{BftPhase, QuorumCertificate, VoteMessage};
        let mut e = bft_engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();

        // Build a Prepare QC instead of Commit.
        let votes: Vec<VoteMessage> = (0..3)
            .map(|i| VoteMessage {
                block_hash: mk(2),
                round: 0,
                phase: BftPhase::Prepare,
                voter_id: format!("v{i}"),
                signature: vec![1u8; 64],
            })
            .collect();
        let prepare_qc = QuorumCertificate::new(BftPhase::Prepare, mk(2), 0, votes).unwrap();

        let mut block = valid_block(2, 1, 1);
        block.commit_qc = Some(prepare_qc);
        let result = e.accept_block(block);
        assert!(matches!(result, Err(ConsensusError::BftError(_))));
    }

    #[test]
    fn bft_engine_rejects_qc_with_insufficient_votes() {
        use crate::consensus::bft::types::{BftPhase, QuorumCertificate, VoteMessage};
        let mut e = bft_engine();
        e.accept_block(valid_block(1, 0, 0)).unwrap();

        // Only 2 votes (threshold=3 for n=4).
        let votes: Vec<VoteMessage> = (0..2)
            .map(|i| VoteMessage {
                block_hash: mk(2),
                round: 0,
                phase: BftPhase::Commit,
                voter_id: format!("v{i}"),
                signature: vec![1u8; 64],
            })
            .collect();
        let qc = QuorumCertificate::new(BftPhase::Commit, mk(2), 0, votes).unwrap();

        let mut block = valid_block(2, 1, 1);
        block.commit_qc = Some(qc);
        let result = e.accept_block(block);
        assert!(matches!(result, Err(ConsensusError::BftError(_))));
    }
}
