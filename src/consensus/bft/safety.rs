//! HotStuff safety rules — locking, vote monotonicity, ancestry checks.
//!
//! Invariant: **two finalized blocks are never conflicting** — for any pair
//! of committed blocks A and B, A is an ancestor of B or B of A.
//!
//! Lock lifecycle (mapped to our 3-phase + Decide flow):
//! - `high_qc`   updated on PrepareQC  (one-chain)
//! - `locked_qc`  updated on PreCommitQC (two-chain — THE LOCK)
//! - finalization on CommitQC → Decide   (three-chain)
//!
//! Locking at PreCommitQC (not PrepareQC) preserves liveness: a lone
//! PrepareQC without PreCommitQC means the quorum has not confirmed
//! awareness of the prepare, so locking there could stall the chain
//! after a single timeout.

#[cfg(test)]
use super::types::BftPhase;
use super::types::QuorumCertificate;

// ── Ancestry ────────────────────────────────────────────────────────────────

/// Returns true if `ancestor` is an ancestor of (or equal to) `descendant`
/// in the block chain.
pub trait AncestryChecker: Send + Sync {
    fn is_ancestor(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool;
}

/// Permissive checker — always returns true.
/// Used ONLY in tests or during bootstrap before the block store is available.
#[derive(Clone)]
pub struct AlwaysExtends;

impl AncestryChecker for AlwaysExtends {
    fn is_ancestor(&self, _ancestor: &[u8; 32], _descendant: &[u8; 32]) -> bool {
        true
    }
}

/// Production ancestry checker backed by the block store.
///
/// Maintains a `hash → (height, parent_hash)` index for O(1) lookup
/// instead of scanning the entire chain. The index is built incrementally:
/// new blocks are indexed on demand when a hash miss occurs.
///
/// Fail-closed: returns false on missing/corrupt data.
pub struct ChainAncestryChecker {
    store: std::sync::Arc<dyn crate::storage::traits::BlockStore>,
    index: std::sync::Mutex<BlockIndex>,
}

struct BlockIndex {
    hash_to_info: std::collections::HashMap<[u8; 32], BlockInfo>,
    indexed_up_to: Option<u64>,
}

#[derive(Clone)]
struct BlockInfo {
    height: u64,
    parent_hash: [u8; 32],
}

impl ChainAncestryChecker {
    pub fn new(store: std::sync::Arc<dyn crate::storage::traits::BlockStore>) -> Self {
        Self {
            store,
            index: std::sync::Mutex::new(BlockIndex {
                hash_to_info: std::collections::HashMap::new(),
                indexed_up_to: None,
            }),
        }
    }

    fn refresh_index(&self, idx: &mut BlockIndex) {
        let latest = match self.store.get_latest_height() {
            Ok(h) => h,
            Err(_) => return,
        };
        let start = idx.indexed_up_to.map_or(0, |h| h + 1);
        for h in start..=latest {
            if let Ok(block) = self.store.read_block(h) {
                let bh = crate::mining::block_hash(&block);
                idx.hash_to_info.insert(
                    bh,
                    BlockInfo {
                        height: h,
                        parent_hash: block.parent_hash,
                    },
                );
            }
        }
        idx.indexed_up_to = Some(latest);
    }

    fn lookup(&self, idx: &BlockIndex, hash: &[u8; 32]) -> Option<BlockInfo> {
        idx.hash_to_info.get(hash).cloned()
    }
}

impl AncestryChecker for ChainAncestryChecker {
    fn is_ancestor(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool {
        if ancestor == descendant {
            return true;
        }

        let mut idx = match self.index.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        // Try lookup; refresh on miss.
        if self.lookup(&idx, ancestor).is_none() || self.lookup(&idx, descendant).is_none() {
            self.refresh_index(&mut idx);
        }

        let anc_info = match self.lookup(&idx, ancestor) {
            Some(i) => i,
            None => return false,
        };
        let desc_info = match self.lookup(&idx, descendant) {
            Some(i) => i,
            None => return false,
        };

        // Height check: ancestor can't be deeper than descendant.
        if anc_info.height > desc_info.height {
            return false;
        }

        // Walk parent chain from descendant towards ancestor using index only.
        let mut current_hash = desc_info.parent_hash;
        let mut remaining = desc_info.height - anc_info.height;
        while remaining > 0 {
            if current_hash == *ancestor {
                return true;
            }
            match self.lookup(&idx, &current_hash) {
                Some(info) => {
                    current_hash = info.parent_hash;
                    remaining -= 1;
                }
                None => return false,
            }
        }

        current_hash == *ancestor
    }
}

// ── Safety errors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyError {
    RoundNotMonotonic {
        proposal: u64,
        last_voted: u64,
    },
    LockedConflict {
        justify_round: Option<u64>,
        lock_round: u64,
    },
}

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoundNotMonotonic {
                proposal,
                last_voted,
            } => write!(
                f,
                "round {proposal} <= last voted round {last_voted}"
            ),
            Self::LockedConflict {
                justify_round,
                lock_round,
            } => write!(
                f,
                "locked at round {lock_round}, justify_qc round {:?} does not supersede and proposal does not extend lock",
                justify_round
            ),
        }
    }
}

// ── Safety state ────────────────────────────────────────────────────────────

/// Per-validator safety state that persists across rounds.
#[derive(Default)]
pub struct SafetyState {
    /// Highest PrepareQC seen. Leaders include this as `justify_qc`.
    high_qc: Option<QuorumCertificate>,
    /// Highest PreCommitQC seen — the lock.
    locked_qc: Option<QuorumCertificate>,
    /// Highest round in which this validator cast a Prepare vote.
    last_voted_round: Option<u64>,
}

impl SafetyState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn high_qc(&self) -> Option<&QuorumCertificate> {
        self.high_qc.as_ref()
    }

    pub fn locked_qc(&self) -> Option<&QuorumCertificate> {
        self.locked_qc.as_ref()
    }

    pub fn last_voted_round(&self) -> Option<u64> {
        self.last_voted_round
    }

    /// Check whether it is safe to vote for a proposal in `proposal_round`.
    ///
    /// # Rules (HotStuff-derived)
    ///
    /// 1. **Monotonicity**: `proposal_round > last_voted_round`
    /// 2. **Lock check** — one of:
    ///   - No lock exists (early rounds)
    ///   - Proposal *extends* the locked block (ancestry verification)
    ///   - `justify_qc.round > locked_qc.round` AND the proposal extends
    ///     the justify_qc's certified block (safe unlock)
    ///
    /// Rule 2c requires the proposal to be coherent with the justify_qc's
    /// block, preventing a Byzantine leader from attaching a valid QC to
    /// an unrelated sibling.
    pub fn safe_to_vote(
        &self,
        proposal_round: u64,
        proposal_block_hash: &[u8; 32],
        justify_qc: Option<&QuorumCertificate>,
        ancestry: &dyn AncestryChecker,
    ) -> Result<(), SafetyError> {
        // 1. Monotonicity — prevents equivocation across rounds.
        if let Some(last) = self.last_voted_round {
            if proposal_round <= last {
                return Err(SafetyError::RoundNotMonotonic {
                    proposal: proposal_round,
                    last_voted: last,
                });
            }
        }

        // 2. Lock check.
        let lock = match &self.locked_qc {
            None => return Ok(()),
            Some(qc) => qc,
        };

        // 2b. Safety: proposal extends the locked block directly.
        if ancestry.is_ancestor(&lock.block_hash, proposal_block_hash) {
            return Ok(());
        }

        // 2c. Liveness: justify_qc with strictly higher round supersedes lock,
        //     BUT the proposal must extend the justify_qc's certified block.
        //     A higher QC attached to an unrelated sibling is not sufficient.
        if let Some(jqc) = justify_qc {
            if jqc.round > lock.round && ancestry.is_ancestor(&jqc.block_hash, proposal_block_hash)
            {
                return Ok(());
            }
        }

        Err(SafetyError::LockedConflict {
            justify_round: justify_qc.map(|q| q.round),
            lock_round: lock.round,
        })
    }

    /// Record that we voted Prepare in `round`.
    pub fn record_vote(&mut self, round: u64) {
        self.last_voted_round = Some(self.last_voted_round.map_or(round, |prev| prev.max(round)));
    }

    /// Update `high_qc` on PrepareQC. Only updates if strictly higher round.
    pub fn update_high_qc(&mut self, qc: &QuorumCertificate) {
        if self.high_qc.as_ref().is_none_or(|h| qc.round > h.round) {
            self.high_qc = Some(qc.clone());
        }
    }

    /// Update `locked_qc` on PreCommitQC — THE LOCK.
    /// Only updates if strictly higher round.
    pub fn update_locked_qc(&mut self, qc: &QuorumCertificate) {
        if self.locked_qc.as_ref().is_none_or(|l| qc.round > l.round) {
            self.locked_qc = Some(qc.clone());
        }
    }
}

// ── Test utilities ──────────────────────────────────────────────────────────

/// Chain-aware ancestry checker for tests.
/// Tracks `block_hash → parent_hash` and walks the chain.
#[cfg(test)]
pub mod test_util {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct MockAncestry {
        parents: HashMap<[u8; 32], [u8; 32]>,
    }

    impl MockAncestry {
        pub fn new() -> Self {
            Self {
                parents: HashMap::new(),
            }
        }

        /// Register `child` as having `parent` as its parent.
        pub fn add_block(&mut self, child: [u8; 32], parent: [u8; 32]) {
            self.parents.insert(child, parent);
        }
    }

    impl AncestryChecker for MockAncestry {
        fn is_ancestor(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool {
            if ancestor == descendant {
                return true;
            }
            let mut current = *descendant;
            for _ in 0..1000 {
                match self.parents.get(&current) {
                    Some(parent) => {
                        if parent == ancestor {
                            return true;
                        }
                        current = *parent;
                    }
                    None => return false,
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::MockAncestry;
    use super::*;

    fn block_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    fn make_qc(phase: BftPhase, hash_id: u8, round: u64) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash(hash_id),
            round,
            phase,
            votes: vec![],
        }
    }

    fn chain_abc() -> MockAncestry {
        // genesis(0x00) ← A(0xAA) ← B(0xBB) ← C(0xCC)
        //                         ← D(0xDD) (sibling of B, same parent A)
        let mut m = MockAncestry::new();
        m.add_block(block_hash(0xAA), block_hash(0x00));
        m.add_block(block_hash(0xBB), block_hash(0xAA));
        m.add_block(block_hash(0xCC), block_hash(0xBB));
        m.add_block(block_hash(0xDD), block_hash(0xAA)); // sibling of B
        m
    }

    // ── Monotonicity ────────────────────────────────────────────────

    #[test]
    fn rejects_vote_in_same_round() {
        let mut s = SafetyState::new();
        s.record_vote(5);
        let r = s.safe_to_vote(5, &block_hash(1), None, &AlwaysExtends);
        assert!(matches!(
            r,
            Err(SafetyError::RoundNotMonotonic {
                proposal: 5,
                last_voted: 5
            })
        ));
    }

    #[test]
    fn rejects_vote_in_earlier_round() {
        let mut s = SafetyState::new();
        s.record_vote(5);
        let r = s.safe_to_vote(3, &block_hash(1), None, &AlwaysExtends);
        assert!(matches!(r, Err(SafetyError::RoundNotMonotonic { .. })));
    }

    #[test]
    fn accepts_vote_in_higher_round() {
        let mut s = SafetyState::new();
        s.record_vote(5);
        assert!(s
            .safe_to_vote(6, &block_hash(1), None, &AlwaysExtends)
            .is_ok());
    }

    #[test]
    fn accepts_first_vote_ever() {
        let s = SafetyState::new();
        assert!(s
            .safe_to_vote(0, &block_hash(1), None, &AlwaysExtends)
            .is_ok());
    }

    // ── No lock ─────────────────────────────────────────────────────

    #[test]
    fn no_lock_accepts_anything() {
        let s = SafetyState::new();
        assert!(s
            .safe_to_vote(0, &block_hash(0xFF), None, &AlwaysExtends)
            .is_ok());
    }

    // ── Lock + ancestry ─────────────────────────────────────────────

    #[test]
    fn locked_accepts_descendant() {
        let mut s = SafetyState::new();
        // Locked on A
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 0));
        let chain = chain_abc();
        // B is child of A → safe
        assert!(s.safe_to_vote(1, &block_hash(0xBB), None, &chain).is_ok());
        // C is grandchild of A → safe
        assert!(s.safe_to_vote(2, &block_hash(0xCC), None, &chain).is_ok());
    }

    #[test]
    fn locked_rejects_sibling() {
        let mut s = SafetyState::new();
        // Locked on B (child of A)
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xBB, 0));
        let chain = chain_abc();
        // D is sibling of B (same parent A) — NOT a descendant of B → reject
        let r = s.safe_to_vote(1, &block_hash(0xDD), None, &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    #[test]
    fn locked_rejects_unrelated_block() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 0));
        let chain = chain_abc();
        // 0xFF not in chain at all
        let r = s.safe_to_vote(1, &block_hash(0xFF), None, &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    // ── Lock + justify_qc (safe unlock) ─────────────────────────────

    #[test]
    fn higher_justify_qc_unlocks() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        let chain = chain_abc();
        // justify_qc.round=6 > lock.round=5 → unlock, accept even unrelated block
        let jqc = make_qc(BftPhase::Prepare, 0xFF, 6);
        assert!(s
            .safe_to_vote(7, &block_hash(0xFF), Some(&jqc), &chain)
            .is_ok());
    }

    #[test]
    fn equal_justify_qc_does_not_unlock() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        let chain = chain_abc();
        // justify_qc.round=5 == lock.round=5 → does NOT unlock
        let jqc = make_qc(BftPhase::Prepare, 0xFF, 5);
        let r = s.safe_to_vote(6, &block_hash(0xFF), Some(&jqc), &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    #[test]
    fn lower_justify_qc_does_not_unlock() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        let chain = chain_abc();
        // justify_qc.round=3 < lock.round=5 → stale, does not unlock
        let jqc = make_qc(BftPhase::Prepare, 0xFF, 3);
        let r = s.safe_to_vote(6, &block_hash(0xFF), Some(&jqc), &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    // ── high_qc / locked_qc updates ─────────────────────────────────

    #[test]
    fn high_qc_only_increases() {
        let mut s = SafetyState::new();
        s.update_high_qc(&make_qc(BftPhase::Prepare, 0xAA, 5));
        assert_eq!(s.high_qc().unwrap().round, 5);

        s.update_high_qc(&make_qc(BftPhase::Prepare, 0xBB, 3));
        assert_eq!(s.high_qc().unwrap().round, 5); // unchanged

        s.update_high_qc(&make_qc(BftPhase::Prepare, 0xCC, 7));
        assert_eq!(s.high_qc().unwrap().round, 7); // updated
    }

    #[test]
    fn locked_qc_only_increases() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        assert_eq!(s.locked_qc().unwrap().round, 5);

        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xBB, 3));
        assert_eq!(s.locked_qc().unwrap().round, 5); // unchanged

        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xCC, 7));
        assert_eq!(s.locked_qc().unwrap().round, 7); // updated
    }

    // ── MockAncestry ────────────────────────────────────────────────

    #[test]
    fn ancestry_reflexive() {
        let chain = chain_abc();
        assert!(chain.is_ancestor(&block_hash(0xAA), &block_hash(0xAA)));
    }

    #[test]
    fn ancestry_direct_parent() {
        let chain = chain_abc();
        assert!(chain.is_ancestor(&block_hash(0xAA), &block_hash(0xBB)));
    }

    #[test]
    fn ancestry_grandparent() {
        let chain = chain_abc();
        assert!(chain.is_ancestor(&block_hash(0xAA), &block_hash(0xCC)));
    }

    #[test]
    fn ancestry_not_reverse() {
        let chain = chain_abc();
        assert!(!chain.is_ancestor(&block_hash(0xCC), &block_hash(0xAA)));
    }

    #[test]
    fn ancestry_sibling_not_ancestor() {
        let chain = chain_abc();
        assert!(!chain.is_ancestor(&block_hash(0xBB), &block_hash(0xDD)));
        assert!(!chain.is_ancestor(&block_hash(0xDD), &block_hash(0xBB)));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Integration tests with real MemoryStore + ChainAncestryChecker
    // ═══════════════════════════════════════════════════════════════════

    use crate::storage::memory::MemoryStore;
    use crate::storage::traits::{Block, BlockStore};
    use std::sync::Arc;

    fn make_block(height: u64, parent_hash: [u8; 32]) -> Block {
        Block {
            height,
            timestamp: 1000 + height,
            parent_hash,
            merkle_root: [0u8; 32],
            transactions: vec![format!("tx-{height}")],
            proposer: "test".into(),
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

    fn store_with_chain() -> (Arc<MemoryStore>, [u8; 32], [u8; 32], [u8; 32]) {
        // Build: genesis(0) ← A(1) ← C(2)
        //                   ← B(1') sibling of A (would have same height but different hash)
        // Since MemoryStore keys by height, we store B at height 3 to avoid collision.
        let store = Arc::new(MemoryStore::new());

        let genesis = make_block(0, [0u8; 32]);
        store.write_block(&genesis).unwrap();
        let genesis_hash = crate::mining::block_hash(&genesis);

        let block_a = make_block(1, genesis_hash);
        store.write_block(&block_a).unwrap();
        let hash_a = crate::mining::block_hash(&block_a);

        let block_c = make_block(2, hash_a);
        store.write_block(&block_c).unwrap();
        let hash_c = crate::mining::block_hash(&block_c);

        // B: sibling of A — same parent (genesis) but at height 3
        let block_b = make_block(3, genesis_hash);
        store.write_block(&block_b).unwrap();
        let hash_b = crate::mining::block_hash(&block_b);

        (store, hash_a, hash_b, hash_c)
    }

    #[test]
    fn chain_checker_parent_is_ancestor() {
        let (store, hash_a, _, hash_c) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        assert!(checker.is_ancestor(&hash_a, &hash_c)); // A ← C
    }

    #[test]
    fn chain_checker_reflexive() {
        let (store, hash_a, _, _) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        assert!(checker.is_ancestor(&hash_a, &hash_a));
    }

    #[test]
    fn chain_checker_sibling_not_ancestor() {
        let (store, _, hash_b, hash_c) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        // B and C are siblings (both have genesis as ancestor, but not each other)
        assert!(!checker.is_ancestor(&hash_b, &hash_c));
        assert!(!checker.is_ancestor(&hash_c, &hash_b));
    }

    #[test]
    fn chain_checker_not_reverse() {
        let (store, hash_a, _, hash_c) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        assert!(!checker.is_ancestor(&hash_c, &hash_a));
    }

    #[test]
    fn chain_checker_unknown_hash_fails_closed() {
        let (store, _, _, _) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        assert!(!checker.is_ancestor(&[0xFFu8; 32], &[0xEEu8; 32]));
    }

    // ── Integration: SafetyState + ChainAncestryChecker ─────────────

    #[test]
    fn real_chain_lock_rejects_sibling() {
        let (store, hash_a, hash_b, _) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        let mut safety = SafetyState::new();
        // Lock on A.
        safety.update_locked_qc(&make_qc(BftPhase::PreCommit, 0, 0)); // dummy hash
                                                                      // Override with real hash for the test.
        safety.locked_qc.as_mut().unwrap().block_hash = hash_a;

        let r = safety.safe_to_vote(1, &hash_b, None, &checker);
        assert!(
            matches!(r, Err(SafetyError::LockedConflict { .. })),
            "sibling B must be rejected when locked on A"
        );
    }

    #[test]
    fn real_chain_lock_accepts_child() {
        let (store, hash_a, _, hash_c) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        let mut safety = SafetyState::new();
        safety.update_locked_qc(&make_qc(BftPhase::PreCommit, 0, 0));
        safety.locked_qc.as_mut().unwrap().block_hash = hash_a;

        let r = safety.safe_to_vote(1, &hash_c, None, &checker);
        assert!(r.is_ok(), "child C of A must be accepted when locked on A");
    }

    #[test]
    fn real_chain_higher_qc_with_unrelated_proposal_rejected() {
        let (store, hash_a, hash_b, _) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        let mut safety = SafetyState::new();
        safety.update_locked_qc(&make_qc(BftPhase::PreCommit, 0, 0));
        safety.locked_qc.as_mut().unwrap().block_hash = hash_a;

        // justify_qc has higher round but certifies A — proposal B doesn't extend A.
        let mut jqc = make_qc(BftPhase::Prepare, 0, 5);
        jqc.block_hash = hash_a;
        let r = safety.safe_to_vote(6, &hash_b, Some(&jqc), &checker);
        assert!(
            matches!(r, Err(SafetyError::LockedConflict { .. })),
            "higher QC for A + proposal B (sibling) must be rejected"
        );
    }

    #[test]
    fn real_chain_higher_qc_with_descendant_proposal_accepted() {
        let (store, hash_a, _, hash_c) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        let mut safety = SafetyState::new();
        safety.update_locked_qc(&make_qc(BftPhase::PreCommit, 0, 0));
        safety.locked_qc.as_mut().unwrap().block_hash = hash_a;

        // justify_qc certifies A, proposal C extends A → OK.
        let mut jqc = make_qc(BftPhase::Prepare, 0, 5);
        jqc.block_hash = hash_a;
        let r = safety.safe_to_vote(6, &hash_c, Some(&jqc), &checker);
        assert!(
            r.is_ok(),
            "higher QC for A + proposal C (child of A) must be accepted"
        );
    }

    #[test]
    fn real_chain_missing_block_fails_closed() {
        let store = Arc::new(MemoryStore::new());
        // Only genesis — no other blocks.
        let genesis = make_block(0, [0u8; 32]);
        store.write_block(&genesis).unwrap();

        let checker = ChainAncestryChecker::new(store);
        let mut safety = SafetyState::new();
        safety.update_locked_qc(&make_qc(BftPhase::PreCommit, 0, 0));

        // Lock hash doesn't correspond to any block in store → fail closed.
        let r = safety.safe_to_vote(1, &[0xAAu8; 32], None, &checker);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Randomized comparison: optimized ChainAncestryChecker vs brute-force
    // ═══════════════════════════════════════════════════════════════════

    fn brute_force_is_ancestor(
        store: &dyn BlockStore,
        ancestor: &[u8; 32],
        descendant: &[u8; 32],
    ) -> bool {
        if ancestor == descendant {
            return true;
        }
        let latest = match store.get_latest_height() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut desc_height = None;
        for h in (0..=latest).rev() {
            if let Ok(block) = store.read_block(h) {
                if crate::mining::block_hash(&block) == *descendant {
                    desc_height = Some(h);
                    break;
                }
            }
        }
        let start = match desc_height {
            Some(h) => h,
            None => return false,
        };
        let mut cur = match store.read_block(start) {
            Ok(b) => b.parent_hash,
            Err(_) => return false,
        };
        for h in (0..start).rev() {
            if cur == *ancestor {
                return true;
            }
            match store.read_block(h) {
                Ok(block) => {
                    if crate::mining::block_hash(&block) != cur {
                        return false;
                    }
                    cur = block.parent_hash;
                }
                Err(_) => return false,
            }
        }
        cur == *ancestor
    }

    /// Build a linear chain (one block per height, sequential parents).
    /// This matches the BlockStore's height-keyed semantics used in production.
    fn build_linear_chain(seed: u64, depth: u64) -> (Arc<MemoryStore>, Vec<[u8; 32]>) {
        let store = Arc::new(MemoryStore::new());
        let mut all_hashes = Vec::new();

        let genesis = make_block(0, [0u8; 32]);
        store.write_block(&genesis).unwrap();
        let genesis_hash = crate::mining::block_hash(&genesis);
        all_hashes.push(genesis_hash);

        let mut tip = genesis_hash;
        for h in 1..=depth {
            let mut b = make_block(h, tip);
            b.timestamp = 1000 + h + (seed.wrapping_mul(h)) % 500;
            store.write_block(&b).unwrap();
            let bh = crate::mining::block_hash(&b);
            all_hashes.push(bh);
            tip = bh;
        }
        (store, all_hashes)
    }

    #[test]
    fn optimized_matches_brute_force_on_linear_chains() {
        for seed in 0..50u64 {
            let (store, hashes) = build_linear_chain(seed, 10);
            let checker = ChainAncestryChecker::new(store.clone());

            for a in &hashes {
                for d in &hashes {
                    let optimized = checker.is_ancestor(a, d);
                    let reference = brute_force_is_ancestor(store.as_ref(), a, d);
                    assert_eq!(
                        optimized, reference,
                        "seed={seed}: is_ancestor({:02x}..., {:02x}...) optimized={optimized} reference={reference}",
                        a[0], d[0]
                    );
                }
            }
        }
    }

    #[test]
    fn optimized_superset_of_brute_force_on_forked_store() {
        // When forks exist (blocks at non-sequential heights), the optimized
        // checker is strictly better: it finds correct ancestry that the old
        // height-based walker incorrectly rejects (fail-closed). Verify that
        // the optimized checker never returns false when the reference returns
        // true (no regressions).
        let (store, hash_a, hash_b, hash_c) = store_with_chain();
        let checker = ChainAncestryChecker::new(store.clone());
        let hashes = [hash_a, hash_b, hash_c];

        for a in &hashes {
            for d in &hashes {
                let optimized = checker.is_ancestor(a, d);
                let reference = brute_force_is_ancestor(store.as_ref(), a, d);
                if reference {
                    assert!(
                        optimized,
                        "optimized must be >= reference: ref=true but opt=false"
                    );
                }
            }
        }
    }

    #[test]
    fn optimized_height_shortcut_works() {
        let store = Arc::new(MemoryStore::new());
        let genesis = make_block(0, [0u8; 32]);
        store.write_block(&genesis).unwrap();
        let gh = crate::mining::block_hash(&genesis);

        let b1 = make_block(1, gh);
        store.write_block(&b1).unwrap();
        let h1 = crate::mining::block_hash(&b1);

        let b2 = make_block(2, h1);
        store.write_block(&b2).unwrap();
        let h2 = crate::mining::block_hash(&b2);

        let checker = ChainAncestryChecker::new(store);
        // Higher block can't be ancestor of lower block
        assert!(!checker.is_ancestor(&h2, &h1));
        assert!(!checker.is_ancestor(&h2, &gh));
        // But lower is ancestor of higher
        assert!(checker.is_ancestor(&gh, &h2));
        assert!(checker.is_ancestor(&h1, &h2));
    }

    #[test]
    fn optimized_incremental_index_after_new_blocks() {
        let store = Arc::new(MemoryStore::new());
        let genesis = make_block(0, [0u8; 32]);
        store.write_block(&genesis).unwrap();
        let gh = crate::mining::block_hash(&genesis);

        let b1 = make_block(1, gh);
        store.write_block(&b1).unwrap();
        let h1 = crate::mining::block_hash(&b1);

        let checker = ChainAncestryChecker::new(store.clone());
        assert!(checker.is_ancestor(&gh, &h1));

        // Add a new block AFTER checker was created
        let b2 = make_block(2, h1);
        store.write_block(&b2).unwrap();
        let h2 = crate::mining::block_hash(&b2);

        // Index refreshes on miss → still works
        assert!(checker.is_ancestor(&gh, &h2));
        assert!(checker.is_ancestor(&h1, &h2));
        assert!(!checker.is_ancestor(&h2, &h1));
    }

    #[test]
    fn real_chain_byzantine_leader_forged_qc_with_sibling_rejected() {
        let (store, hash_a, hash_b, _) = store_with_chain();
        let checker = ChainAncestryChecker::new(store);
        let mut safety = SafetyState::new();
        safety.update_locked_qc(&make_qc(BftPhase::PreCommit, 0, 0));
        safety.locked_qc.as_mut().unwrap().block_hash = hash_a;

        // Byzantine leader forges a QC that certifies B at round 5.
        // Proposal is also for B. justify_qc.round > lock.round.
        // But B doesn't extend A (sibling). Since we now also require
        // ancestry.is_ancestor(jqc.block_hash=B, proposal=B), this is
        // reflexively true. HOWEVER the ancestry check in rule 2b
        // (lock.block_hash=A → proposal=B) already failed.
        // And rule 2c requires ancestry(jqc.block_hash=B, proposal=B)
        // which is true, but jqc.round(5) > lock.round(0) is also true.
        // So this WOULD pass rule 2c... and that's actually correct
        // per HotStuff: if the Byzantine leader managed to get a valid QC
        // at round 5 for B, it means a quorum voted for B, which means
        // the locked nodes must have unlocked. The forge would require
        // real signatures from a quorum.
        //
        // With AcceptAllVerifier, the forged QC passes. With real crypto,
        // the forge would fail signature verification. This test documents
        // that safety ultimately relies on QC signature verification.
        let mut forged_jqc = make_qc(BftPhase::Prepare, 0, 5);
        forged_jqc.block_hash = hash_b;
        let r = safety.safe_to_vote(6, &hash_b, Some(&forged_jqc), &checker);
        // This passes because the forged QC satisfies both conditions:
        // jqc.round(5) > lock.round(0) AND ancestry(B, B) is true.
        // Safety relies on QC verification happening BEFORE safe_to_vote.
        assert!(
            r.is_ok(),
            "forged QC passes safe_to_vote — QC verification must happen upstream"
        );
    }
}
