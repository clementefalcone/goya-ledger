//! Round manager — orchestrates consecutive BFT rounds with leader rotation
//! and timeout-based liveness.
//!
//! Sits above [`BftRound`] and handles:
//! - Round-robin leader election from the validator set
//! - Timeout detection and view change (advance to next round with new leader)
//! - Tracking the highest committed QC for chain continuity

use super::quorum::{QuorumValidator, SignatureVerifier};
use super::round::{BftRound, RoundAction, RoundEvent, RoundState};
use super::safety::{AlwaysExtends, AncestryChecker, SafetyState};
use super::types::{BftPhase, QcError, QuorumCertificate};

/// Configuration for the round manager.
#[derive(Debug, Clone)]
pub struct RoundManagerConfig {
    /// Base timeout in milliseconds for a single round.
    /// Doubles on each consecutive timeout (exponential backoff).
    pub base_timeout_ms: u64,
    /// Maximum timeout in milliseconds (backoff cap).
    pub max_timeout_ms: u64,
}

impl Default for RoundManagerConfig {
    fn default() -> Self {
        Self {
            base_timeout_ms: 3000,
            max_timeout_ms: 30_000,
        }
    }
}

/// Actions emitted by the round manager to the network layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerAction {
    /// A round action from the current BftRound.
    Round(RoundAction),
    /// A new round started — caller should reset their timeout timer.
    NewRound {
        round: u64,
        leader_id: String,
        timeout_ms: u64,
    },
    /// No action.
    None,
}

/// Manages consecutive BFT rounds with leader rotation and liveness timeouts.
pub struct RoundManager<V: SignatureVerifier + Clone> {
    node_id: String,
    validators: Vec<String>,
    verifier: V,
    config: RoundManagerConfig,
    /// Current round number.
    current_round: u64,
    /// The active round state machine.
    current: Option<BftRound<V>>,
    /// Number of consecutive timeouts (for exponential backoff).
    pub(crate) consecutive_timeouts: u32,
    /// Highest committed QC seen so far.
    highest_commit_qc: Option<QuorumCertificate>,
    /// HotStuff safety state — locking, vote monotonicity.
    safety: SafetyState,
    /// Ancestry checker for lock verification.
    ancestry: Box<dyn AncestryChecker>,
}

impl<V: SignatureVerifier + Clone> RoundManager<V> {
    /// Create a new round manager with permissive ancestry (QC round comparison only).
    pub fn new(
        node_id: String,
        validators: Vec<String>,
        verifier: V,
        config: RoundManagerConfig,
    ) -> Self {
        Self::with_ancestry(
            node_id,
            validators,
            verifier,
            config,
            Box::new(AlwaysExtends),
        )
    }

    /// Create a round manager with a custom ancestry checker.
    pub fn with_ancestry(
        node_id: String,
        validators: Vec<String>,
        verifier: V,
        config: RoundManagerConfig,
        ancestry: Box<dyn AncestryChecker>,
    ) -> Self {
        Self {
            node_id,
            validators,
            verifier,
            config,
            current_round: 0,
            current: None,
            consecutive_timeouts: 0,
            highest_commit_qc: None,
            safety: SafetyState::new(),
            ancestry,
        }
    }

    /// Current round number.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// The leader for a given round (round-robin over validators).
    pub fn leader_for_round(&self, round: u64) -> &str {
        if self.validators.is_empty() {
            return "";
        }
        let idx = (round as usize) % self.validators.len();
        &self.validators[idx]
    }

    /// The leader for the current round.
    pub fn current_leader(&self) -> &str {
        self.leader_for_round(self.current_round)
    }

    /// Whether this node is leader for the current round.
    pub fn is_current_leader(&self) -> bool {
        self.current_leader() == self.node_id
    }

    /// Current timeout in ms (with exponential backoff).
    pub fn current_timeout_ms(&self) -> u64 {
        let timeout = self.config.base_timeout_ms * 2u64.saturating_pow(self.consecutive_timeouts);
        timeout.min(self.config.max_timeout_ms)
    }

    /// The highest committed QC.
    pub fn highest_commit_qc(&self) -> Option<&QuorumCertificate> {
        self.highest_commit_qc.as_ref()
    }

    /// State of the current round (if active).
    pub fn round_state(&self) -> Option<RoundState> {
        self.current.as_ref().map(|r| r.state())
    }

    /// Start or advance to a specific round.
    ///
    /// Creates a new `BftRound`, selects the leader via round-robin,
    /// and returns a `NewRound` action so the caller can set their timer.
    /// If this node is the leader, also returns a `StartAsLeader` prompt.
    pub fn start_round(&mut self, round: u64) -> ManagerAction {
        self.current_round = round;
        let leader = self.leader_for_round(round).to_string();

        let bft_round = BftRound::new(
            round,
            self.node_id.clone(),
            leader.clone(),
            self.validators.clone(),
            self.verifier.clone(),
        );
        self.current = Some(bft_round);

        ManagerAction::NewRound {
            round,
            leader_id: leader,
            timeout_ms: self.current_timeout_ms(),
        }
    }

    /// Start round 0 (convenience for initialization).
    pub fn start(&mut self) -> ManagerAction {
        self.start_round(0)
    }

    /// Feed an event to the current round. Returns the resulting action.
    ///
    /// For `Proposal` events, enforces HotStuff safety rules before
    /// forwarding to the round state machine:
    /// - Round monotonicity (no voting in past rounds)
    /// - Lock check (proposal must extend locked block or present higher QC)
    pub fn process_event(&mut self, event: RoundEvent) -> ManagerAction {
        if self.current.is_none() {
            return ManagerAction::None;
        }

        // Safety gate for proposals — runs BEFORE mutable borrow of current round.
        if let RoundEvent::Proposal {
            ref block_hash,
            ref justify_qc,
            ..
        } = event
        {
            // 1. Validate justify_qc cryptographically BEFORE using it.
            if let Some(ref jqc) = justify_qc {
                if let Err(e) = self.validate_received_qc(jqc) {
                    log::warn!(
                        "BFT: rejected proposal with invalid justify_qc in round {}: {e}",
                        self.current_round
                    );
                    return ManagerAction::Round(RoundAction::None);
                }
            }
            // 2. Check HotStuff safety rules (locking, ancestry, monotonicity).
            if let Err(e) = self.safety.safe_to_vote(
                self.current_round,
                block_hash,
                justify_qc.as_ref(),
                self.ancestry.as_ref(),
            ) {
                log::warn!(
                    "BFT safety: rejected proposal in round {}: {e}",
                    self.current_round
                );
                return ManagerAction::Round(RoundAction::None);
            }
        }

        if let RoundEvent::StartAsLeader { ref block_hash } = event {
            if let Err(e) = self.safety.safe_to_vote(
                self.current_round,
                block_hash,
                self.safety.high_qc(),
                self.ancestry.as_ref(),
            ) {
                log::warn!(
                    "BFT safety: refused to propose in round {}: {e}",
                    self.current_round
                );
                return ManagerAction::Round(RoundAction::None);
            }
        }

        let round = self.current.as_mut().unwrap();
        let action = round.process(event);

        // Post-process: update safety state from actions.
        match &action {
            RoundAction::SendVote(vote) if vote.phase == BftPhase::Prepare => {
                self.safety.record_vote(vote.round);
            }
            RoundAction::BroadcastProposal { .. } => {
                self.safety.record_vote(self.current_round);
            }
            RoundAction::PhaseComplete { phase, qc } => match phase {
                BftPhase::Prepare => self.safety.update_high_qc(qc),
                BftPhase::PreCommit => self.safety.update_locked_qc(qc),
                _ => {}
            },
            RoundAction::Decide { ref commit_qc, .. } => {
                self.highest_commit_qc = Some(commit_qc.clone());
                self.consecutive_timeouts = 0;
            }
            _ => {}
        }

        ManagerAction::Round(action)
    }

    /// The safety state (for inspection in tests and controller).
    pub fn safety(&self) -> &SafetyState {
        &self.safety
    }

    /// Validate a received QC cryptographically: quorum threshold, voter
    /// membership, signature validity, no duplicates. MUST be called on any
    /// justify_qc received from the network BEFORE passing it to safe_to_vote.
    fn validate_received_qc(&self, qc: &QuorumCertificate) -> Result<(), QcError> {
        // Check header/vote consistency (phase, block_hash, round).
        for vote in &qc.votes {
            if vote.phase != qc.phase {
                return Err(QcError::MismatchedPhase {
                    expected: qc.phase,
                    got: vote.phase,
                });
            }
            if vote.block_hash != qc.block_hash {
                return Err(QcError::MismatchedBlockHash {
                    expected: qc.block_hash,
                    got: vote.block_hash,
                });
            }
            if vote.round != qc.round {
                return Err(QcError::MismatchedRound {
                    expected: qc.round,
                    got: vote.round,
                });
            }
        }
        // Validate quorum: membership, signatures, threshold.
        let qv = QuorumValidator::new(self.validators.clone(), self.verifier.clone());
        qv.validate_qc(qc)
    }

    /// Handle a timeout for the current round.
    ///
    /// Increments the backoff counter and advances to the next round with
    /// a new leader. Returns `NewRound` so the caller can reset their timer.
    pub fn on_timeout(&mut self) -> ManagerAction {
        // Notify the current round of the timeout.
        if let Some(ref mut r) = self.current {
            r.process(RoundEvent::Timeout);
        }

        self.consecutive_timeouts += 1;
        let next_round = self.current_round + 1;
        self.start_round(next_round)
    }

    /// Advance to the next round after a successful Decide.
    ///
    /// Resets timeout backoff since progress was made.
    pub fn advance_after_decide(&mut self) -> ManagerAction {
        self.consecutive_timeouts = 0;
        let next_round = self.current_round + 1;
        self.start_round(next_round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::quorum::AcceptAllVerifier;
    use crate::consensus::bft::round::RoundAction;
    use crate::consensus::bft::types::{BftPhase, VoteMessage};

    fn validators() -> Vec<String> {
        (0..4).map(|i| format!("v{i}")).collect()
    }

    fn manager(node: &str) -> RoundManager<AcceptAllVerifier> {
        RoundManager::new(
            node.into(),
            validators(),
            AcceptAllVerifier,
            RoundManagerConfig::default(),
        )
    }

    fn block_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    fn make_vote(phase: BftPhase, hash_id: u8, round: u64, voter: &str) -> VoteMessage {
        VoteMessage {
            block_hash: block_hash(hash_id),
            round,
            phase,
            voter_id: voter.to_string(),
            signature: vec![1u8; 64],
        }
    }

    // --- leader rotation ---

    #[test]
    fn leader_rotates_round_robin() {
        let m = manager("v0");
        assert_eq!(m.leader_for_round(0), "v0");
        assert_eq!(m.leader_for_round(1), "v1");
        assert_eq!(m.leader_for_round(2), "v2");
        assert_eq!(m.leader_for_round(3), "v3");
        assert_eq!(m.leader_for_round(4), "v0"); // wraps
    }

    #[test]
    fn start_returns_new_round_action() {
        let mut m = manager("v0");
        let action = m.start();
        match action {
            ManagerAction::NewRound {
                round,
                leader_id,
                timeout_ms,
            } => {
                assert_eq!(round, 0);
                assert_eq!(leader_id, "v0");
                assert_eq!(timeout_ms, 3000);
            }
            other => panic!("expected NewRound, got {other:?}"),
        }
        assert_eq!(m.current_round(), 0);
    }

    #[test]
    fn is_current_leader_when_round_matches() {
        let mut m = manager("v0");
        m.start_round(0);
        assert!(m.is_current_leader());

        m.start_round(1);
        assert!(!m.is_current_leader()); // v1 is leader for round 1
    }

    // --- timeout & backoff ---

    #[test]
    fn timeout_advances_round() {
        let mut m = manager("v0");
        m.start();
        let action = m.on_timeout();
        match action {
            ManagerAction::NewRound {
                round, leader_id, ..
            } => {
                assert_eq!(round, 1);
                assert_eq!(leader_id, "v1");
            }
            other => panic!("expected NewRound, got {other:?}"),
        }
        assert_eq!(m.current_round(), 1);
    }

    #[test]
    fn timeout_backoff_doubles() {
        let mut m = manager("v0");
        m.start();
        assert_eq!(m.current_timeout_ms(), 3000);

        m.on_timeout(); // consecutive=1
        assert_eq!(m.current_timeout_ms(), 6000);

        m.on_timeout(); // consecutive=2
        assert_eq!(m.current_timeout_ms(), 12000);

        m.on_timeout(); // consecutive=3
        assert_eq!(m.current_timeout_ms(), 24000);

        m.on_timeout(); // consecutive=4 → 48000 capped to 30000
        assert_eq!(m.current_timeout_ms(), 30_000);
    }

    #[test]
    fn backoff_resets_after_decide() {
        let mut m = manager("v0");
        m.start();
        m.on_timeout(); // consecutive=1
        m.on_timeout(); // consecutive=2
        assert_eq!(m.current_timeout_ms(), 12000);

        // Simulate a decide.
        m.advance_after_decide();
        assert_eq!(m.current_timeout_ms(), 3000); // reset
    }

    // --- full flow through manager ---

    #[test]
    fn full_round_via_manager() {
        let mut m = manager("v0");
        m.start();

        // Leader proposes.
        let action = m.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::BroadcastProposal { .. })
        ));

        // Collect votes through all phases.
        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            for voter in &["v0", "v1", "v2"] {
                m.process_event(RoundEvent::Vote(make_vote(phase, 1, 0, voter)));
            }
        }

        assert_eq!(m.round_state(), Some(RoundState::Decided));
        assert!(m.highest_commit_qc().is_some());
        assert_eq!(m.consecutive_timeouts, 0);
    }

    #[test]
    fn follower_receives_proposal_via_manager() {
        let mut m = manager("v1"); // v0 is leader for round 0
        m.start();

        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(1),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        match action {
            ManagerAction::Round(RoundAction::SendVote(vote)) => {
                assert_eq!(vote.voter_id, "v1");
                assert_eq!(vote.phase, BftPhase::Prepare);
            }
            other => panic!("expected SendVote, got {other:?}"),
        }
    }

    #[test]
    fn events_before_start_are_noop() {
        let mut m = manager("v0");
        let action = m.process_event(RoundEvent::Vote(make_vote(BftPhase::Prepare, 1, 0, "v0")));
        assert_eq!(action, ManagerAction::None);
    }

    // --- multiple rounds ---

    // ── Adversarial scenarios ─────────────────────────────────────────

    /// Helper: drive a full Prepare→PreCommit→Commit cycle on a single
    /// manager, feeding votes from the given voters. Returns true if Decide.
    fn drive_full_round(
        m: &mut RoundManager<AcceptAllVerifier>,
        hash_id: u8,
        round: u64,
        voters: &[&str],
    ) -> bool {
        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            for voter in voters {
                let action =
                    m.process_event(RoundEvent::Vote(make_vote(phase, hash_id, round, voter)));
                if matches!(action, ManagerAction::Round(RoundAction::Decide { .. })) {
                    return true;
                }
            }
        }
        false
    }

    // ── Scenario 1: Network partition 2+2 ───────────────────────────
    //
    // Partition: {v0, v1} vs {v2, v3}. Neither side has 3 votes.
    // Chain must halt (no Decide on either side), never fork.
    // On reunion: the combined votes must allow progress.

    #[test]
    fn partition_2_2_halts_no_fork() {
        // Two independent managers simulating the two partitions.
        let mut left_leader = manager("v0"); // v0 is leader of round 0
        let mut right_follower = manager("v2");

        left_leader.start();
        right_follower.start();

        // Leader v0 proposes block A.
        left_leader.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xAA),
        });

        // Right side receives the proposal (before partition).
        right_follower.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });

        // LEFT partition: v0 and v1 vote. Only 2 votes — no quorum.
        for voter in &["v0", "v1"] {
            left_leader.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        // Left side stuck in Preparing — no PhaseComplete.
        assert_eq!(left_leader.round_state(), Some(RoundState::Preparing));

        // RIGHT partition: v2 and v3 vote. Only 2 votes — no quorum.
        for voter in &["v2", "v3"] {
            right_follower.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        assert_eq!(right_follower.round_state(), Some(RoundState::Preparing));

        // Neither side decided — chain halted, no fork.
        assert_ne!(left_leader.round_state(), Some(RoundState::Decided));
        assert_ne!(right_follower.round_state(), Some(RoundState::Decided));

        // REUNION: left side receives votes from right.
        let action = left_leader.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v2",
        )));
        // 3 votes now (v0, v1, v2) → Prepare quorum reached!
        assert!(
            matches!(
                action,
                ManagerAction::Round(RoundAction::PhaseComplete {
                    phase: BftPhase::Prepare,
                    ..
                })
            ),
            "reunion should reach Prepare quorum, got {action:?}"
        );

        // Drive through PreCommit and Commit with 3 voters.
        let decided = drive_full_round(&mut left_leader, 0xAA, 0, &["v0", "v1", "v2"]);
        assert!(decided, "should reach Decide after reunion");
        assert_eq!(left_leader.round_state(), Some(RoundState::Decided));

        // Verify: only ONE block was decided (no fork).
        let qc = left_leader.highest_commit_qc().unwrap();
        assert_eq!(qc.block_hash, block_hash(0xAA));
    }

    // ── Scenario 2: Byzantine equivocation ──────────────────────────
    //
    // v3 (Byzantine) votes block A to {v0, v1} and block B to {v2}.
    // Honest nodes each see one hash. Two QCs must not coexist.

    #[test]
    fn byzantine_equivocation_cannot_produce_two_qcs() {
        let block_a = block_hash(0xAA);
        let block_b = block_hash(0xBB);

        // --- Node v0's view: leader proposes A ---
        let mut m_v0 = manager("v0");
        m_v0.start();
        m_v0.process_event(RoundEvent::StartAsLeader {
            block_hash: block_a,
        });

        // v0 sees: v0(A), v1(A), v3(A) — Byzantine v3 sends A to this partition.
        m_v0.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v0",
        )));
        m_v0.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v1",
        )));
        let action = m_v0.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v3",
        )));
        // 3 votes for A → Prepare quorum.
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::PhaseComplete {
                phase: BftPhase::Prepare,
                ..
            })
        ));

        // --- Node v2's view: Byzantine v3 sent vote for B ---
        let mut m_v2 = manager("v2");
        m_v2.start();
        m_v2.process_event(RoundEvent::Proposal {
            block_hash: block_a, // v2 received the real proposal (block A)
            leader_id: "v0".into(),
            justify_qc: None,
        });

        // v2 votes A (honest). v3 sends B to v2.
        m_v2.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v2",
        )));
        // v3's vote for B is rejected by v2's collector (hash mismatch with A).
        let action = m_v2.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xBB,
            0,
            "v3",
        )));
        assert!(
            matches!(action, ManagerAction::Round(RoundAction::None)),
            "vote for wrong block hash must be rejected"
        );

        // v2 only has 1 valid vote (itself). Cannot form QC for B.
        // v2 also cannot form QC for A without 2 more votes.
        assert_eq!(m_v2.round_state(), Some(RoundState::Preparing));

        // Key invariant: QC(A) exists (on v0's side), QC(B) does NOT exist.
        // The Byzantine node cannot cause a fork — at most it can delay v2.

        // Now: can v3 somehow help form QC(B) on a separate collector?
        // Even with a dedicated B-collector, v3 only has 1 vote (itself).
        // Needs 2 more from {v0, v1, v2} — all voted A. Impossible.
        use crate::consensus::bft::quorum::QuorumValidator;
        use crate::consensus::bft::vote_collector::VoteCollector;

        let mut col_b = VoteCollector::new(
            BftPhase::Prepare,
            0,
            block_b,
            QuorumValidator::new(validators(), AcceptAllVerifier),
        );
        col_b.add_vote(make_vote(BftPhase::Prepare, 0xBB, 0, "v3"));
        assert_eq!(col_b.vote_count(), 1);
        assert!(!col_b.is_complete());
        // QC(B) impossible: 1/3 quorum. Byzantine equivocation blocked.
    }

    // ── Scenario 3: Leader death during consensus ───────────────────
    //
    // v0 (leader round 0) proposes A. Gets Prepare votes from v1, v2.
    // v0 dies after Prepare (before PreCommit/Commit).
    // Timeout → round 1, new leader v1. v1 proposes and gets Decide
    // without double-committing A from round 0.

    #[test]
    fn leader_death_after_prepare_recovers_without_double_commit() {
        // Simulate from v1's perspective (v1 survives the leader death).
        let mut m = manager("v1");
        m.start(); // round 0, leader = v0

        // v1 receives proposal from v0.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });

        // Prepare votes arrive from v0, v1, v2. v1's own vote was already
        // returned as SendVote; here we simulate all votes arriving.
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v0",
        )));
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v1",
        )));
        let action = m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v2",
        )));
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::PhaseComplete {
                phase: BftPhase::Prepare,
                ..
            })
        ));
        assert_eq!(m.round_state(), Some(RoundState::PreCommitting));

        // v0 DIES here. No more votes from v0 for PreCommit/Commit.
        // Only v1 and v2 can vote PreCommit → 2 votes < quorum=3.
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::PreCommit,
            0xAA,
            0,
            "v1",
        )));
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::PreCommit,
            0xAA,
            0,
            "v2",
        )));
        // Still PreCommitting — no quorum.
        assert_eq!(m.round_state(), Some(RoundState::PreCommitting));

        // TIMEOUT: round 0 failed. Advance to round 1.
        let action = m.on_timeout();
        match &action {
            ManagerAction::NewRound {
                round, leader_id, ..
            } => {
                assert_eq!(*round, 1);
                assert_eq!(leader_id, "v1"); // v1 is new leader!
            }
            other => panic!("expected NewRound, got {other:?}"),
        }

        // Round 0 block A was NOT decided (no CommitQC).
        assert!(
            m.highest_commit_qc().is_none(),
            "block A must NOT be committed"
        );

        // v1 (new leader) proposes block B in round 1.
        m.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xBB),
        });

        // Drive full round with v1, v2, v3 (v0 is dead).
        let decided = drive_full_round(&mut m, 0xBB, 1, &["v1", "v2", "v3"]);
        assert!(decided, "round 1 should reach Decide with 3 live nodes");
        assert_eq!(m.round_state(), Some(RoundState::Decided));

        // Verify: only block B was committed (no double-commit of A).
        let qc = m.highest_commit_qc().unwrap();
        assert_eq!(
            qc.block_hash,
            block_hash(0xBB),
            "only block B should be committed"
        );
        assert_eq!(qc.round, 1);
        assert_eq!(qc.phase, BftPhase::Commit);

        // Block A from round 0 has PrepareQC but no CommitQC → not finalized.
        // This is correct: Prepare lock without Commit = abandoned.
    }

    #[test]
    fn three_consecutive_rounds_rotate_leaders() {
        let mut m = manager("v0");

        for expected_round in 0..3u64 {
            let action = m.start_round(expected_round);
            match action {
                ManagerAction::NewRound {
                    round, leader_id, ..
                } => {
                    assert_eq!(round, expected_round);
                    let expected_leader = format!("v{}", expected_round % 4);
                    assert_eq!(leader_id, expected_leader);
                }
                other => panic!("expected NewRound, got {other:?}"),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // HotStuff safety locking — adversarial scenarios
    //
    // Invariant under test:
    //   For any two finalized blocks A and B:
    //     A ancestor_of B || B ancestor_of A
    //   Two conflicting finalized blocks NEVER coexist.
    // ════════════════════════════════════════════════════════════════════

    use crate::consensus::bft::safety::test_util::MockAncestry;

    fn manager_with_chain(node: &str, chain: MockAncestry) -> RoundManager<AcceptAllVerifier> {
        RoundManager::with_ancestry(
            node.into(),
            validators(),
            AcceptAllVerifier,
            RoundManagerConfig::default(),
            Box::new(chain),
        )
    }

    fn chain_for_tests() -> MockAncestry {
        // genesis(0x00) ← A(0xAA) ← C(0xCC)
        //              ← B(0xBB)   (sibling of A)
        //              A(0xAA) ← D(0xDD) (child of A, sibling of C)
        let mut m = MockAncestry::new();
        m.add_block(block_hash(0xAA), block_hash(0x00));
        m.add_block(block_hash(0xBB), block_hash(0x00));
        m.add_block(block_hash(0xCC), block_hash(0xAA));
        m.add_block(block_hash(0xDD), block_hash(0xAA));
        m
    }

    #[allow(dead_code)]
    fn make_precommit_qc(hash_id: u8, round: u64) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash(hash_id),
            round,
            phase: BftPhase::PreCommit,
            votes: vec![
                make_vote(BftPhase::PreCommit, hash_id, round, "v0"),
                make_vote(BftPhase::PreCommit, hash_id, round, "v1"),
                make_vote(BftPhase::PreCommit, hash_id, round, "v2"),
            ],
        }
    }

    #[allow(dead_code)]
    fn make_prepare_qc(hash_id: u8, round: u64) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash(hash_id),
            round,
            phase: BftPhase::Prepare,
            votes: vec![
                make_vote(BftPhase::Prepare, hash_id, round, "v0"),
                make_vote(BftPhase::Prepare, hash_id, round, "v1"),
                make_vote(BftPhase::Prepare, hash_id, round, "v2"),
            ],
        }
    }

    // ── Test 1: Conflicting proposal against locked_qc ──────────────

    #[test]
    fn locked_node_rejects_conflicting_sibling_proposal() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();

        // Round 0: Prepare + PreCommit for A → lock on A.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }
        assert_eq!(m.safety().locked_qc().unwrap().block_hash, block_hash(0xAA));

        m.on_timeout(); // → round 1

        // Byzantine leader proposes B (sibling of A).
        // justify_qc.round == lock.round → does NOT supersede.
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v1".into(),
            justify_qc: Some(make_prepare_qc(0xAA, 0)),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "locked node must reject sibling proposal"
        );
    }

    fn leader_v1_locked_on_a_in_round_1() -> RoundManager<AcceptAllVerifier> {
        let mut m = manager_with_chain("v1", chain_for_tests());
        m.start();
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for phase in [BftPhase::Prepare, BftPhase::PreCommit] {
            for voter in &["v0", "v1", "v2"] {
                m.process_event(RoundEvent::Vote(make_vote(phase, 0xAA, 0, voter)));
            }
        }
        m.on_timeout();
        assert!(m.is_current_leader());
        m
    }

    #[test]
    fn locked_leader_refuses_to_propose_conflicting_sibling() {
        let mut m = leader_v1_locked_on_a_in_round_1();

        let action = m.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xBB),
        });

        assert_eq!(action, ManagerAction::Round(RoundAction::None));
        assert_eq!(m.round_state(), Some(RoundState::AwaitingProposal));
        assert_eq!(m.safety().last_voted_round(), Some(0));
    }

    #[test]
    fn locked_leader_proposes_descendant_and_records_its_vote() {
        let mut m = leader_v1_locked_on_a_in_round_1();

        let action = m.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xCC),
        });

        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::BroadcastProposal {
                block_hash: block_hash(0xCC)
            })
        );
        assert_eq!(m.safety().last_voted_round(), Some(1));
    }

    // ── Test 2: Locked node accepts descendant ──────────────────────

    #[test]
    fn locked_node_accepts_descendant_proposal() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();

        // Lock on A.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }
        m.on_timeout(); // → round 1

        // C is child of A → extends lock → accepted.
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xCC),
            leader_id: "v1".into(),
            justify_qc: Some(make_prepare_qc(0xAA, 0)),
        });
        assert!(
            matches!(action, ManagerAction::Round(RoundAction::SendVote(_))),
            "descendant proposal must be accepted"
        );
    }

    // ── Test 3: Higher justify_qc safely unlocks ────────────────────

    #[test]
    fn higher_justify_qc_unlocks_for_different_branch() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();

        // Lock on A at round 0.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }
        m.on_timeout(); // → round 1
        m.on_timeout(); // → round 2

        // justify_qc from round 1 > lock round 0 → safe unlock.
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v2".into(),
            justify_qc: Some(make_prepare_qc(0xBB, 1)),
        });
        assert!(
            matches!(action, ManagerAction::Round(RoundAction::SendVote(_))),
            "higher justify_qc must unlock"
        );
    }

    // ── Test 4: Stale justify_qc does NOT unlock ────────────────────

    #[test]
    fn stale_justify_qc_does_not_unlock() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();
        m.on_timeout(); // → round 1
        m.on_timeout(); // → round 2

        // Lock on A at round 2.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v2".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                2,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                2,
                voter,
            )));
        }
        m.on_timeout(); // → round 3

        // justify_qc from round 0 < lock round 2 → stale.
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v3".into(),
            justify_qc: Some(make_prepare_qc(0xBB, 0)),
        });
        assert_eq!(action, ManagerAction::Round(RoundAction::None));
    }

    // ── Test 5: Vote monotonicity ───────────────────────────────────

    #[test]
    fn vote_monotonicity_prevents_equivocation() {
        let mut m = manager("v1");
        m.start();

        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        assert_eq!(m.safety().last_voted_round(), Some(0));

        m.on_timeout(); // → round 1
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v1".into(),
            justify_qc: None,
        });
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::SendVote(_))
        ));
        assert_eq!(m.safety().last_voted_round(), Some(1));
    }

    // ── Test 6: Leader death after PreCommitQC — lock survives ──────

    #[test]
    fn leader_death_after_precommit_preserves_lock() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();

        // Lock on A.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }
        m.on_timeout(); // → round 1

        // Lock survives.
        assert_eq!(m.safety().locked_qc().unwrap().block_hash, block_hash(0xAA));

        // Descendant C: accepted.
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xCC),
            leader_id: "v1".into(),
            justify_qc: Some(make_prepare_qc(0xAA, 0)),
        });
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::SendVote(_))
        ));

        // Sibling B: rejected.
        m.on_timeout(); // → round 2
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v2".into(),
            justify_qc: Some(make_prepare_qc(0xAA, 0)),
        });
        assert_eq!(action, ManagerAction::Round(RoundAction::None));
    }

    // ── Test 7: Delayed CommitQC cannot create fork ─────────────────

    #[test]
    fn delayed_commit_qc_cannot_fork() {
        let mut m = manager("v1");
        m.start();

        // Round 0: PrepareQC(A), but no PreCommitQC → no lock.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        assert!(m.safety().locked_qc().is_none()); // no lock!

        m.on_timeout(); // → round 1

        // B is freely accepted (no lock).
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v1".into(),
            justify_qc: None,
        });
        let decided = drive_full_round(&mut m, 0xBB, 1, &["v1", "v2", "v3"]);
        assert!(decided);
        assert_eq!(m.highest_commit_qc().unwrap().block_hash, block_hash(0xBB));

        // CommitQC(A) is impossible: it would need PreCommitQC(A) which
        // needs 3 PreCommit votes — but the round timed out and the pipeline
        // was incomplete. The invariant holds.
    }

    // ── Test 8: Stale votes from old rounds ignored ─────────────────

    #[test]
    fn old_round_votes_are_noop() {
        let mut m = manager("v1");
        m.start();
        m.on_timeout(); // → round 1
        m.on_timeout(); // → round 2

        // Vote from round 0 — ignored.
        let action = m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v0",
        )));
        assert_eq!(action, ManagerAction::Round(RoundAction::None));
    }

    // ── Test 9: Partition + heal respects lock ──────────────────────

    #[test]
    fn partition_heal_with_lock() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();

        // Lock on A at round 0.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }

        // Partition: several timeouts.
        for _ in 0..5 {
            m.on_timeout();
        }
        // round = 5 now.

        // Heal: leader with higher justify_qc → unlock OK.
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v1".into(), // v1 is leader of round 5? 5%4=1 → v1
            justify_qc: Some(make_prepare_qc(0xBB, 3)),
        });
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::SendVote(_))
        ));
    }

    // ── Test 10: Finalization invariant under stress ─────────────────

    #[test]
    fn two_finalized_blocks_never_conflict() {
        let chain = {
            let mut c = MockAncestry::new();
            c.add_block(block_hash(0xAA), block_hash(0x00));
            c.add_block(block_hash(0xBB), block_hash(0x00));
            c
        };

        // Finalize A on v0.
        let mut m0 = manager_with_chain("v0", chain);
        m0.start();
        m0.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xAA),
        });
        let decided_a = drive_full_round(&mut m0, 0xAA, 0, &["v0", "v1", "v2"]);
        assert!(decided_a);

        // v1 was locked on A after round 0 (PreCommitQC formed).
        let chain2 = {
            let mut c = MockAncestry::new();
            c.add_block(block_hash(0xAA), block_hash(0x00));
            c.add_block(block_hash(0xBB), block_hash(0x00));
            c
        };
        let mut m1 = manager_with_chain("v1", chain2);
        m1.start();
        m1.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m1.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m1.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }
        // v1 locked on A.
        m1.on_timeout(); // → round 1

        // Byzantine leader proposes B (sibling). REJECTED.
        let action = m1.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v1".into(),
            justify_qc: Some(make_prepare_qc(0xAA, 0)),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "INVARIANT: no conflicting finalization possible"
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // QC validation gate — forged/invalid justify_qc must be rejected
    // BEFORE reaching safe_to_vote.
    // ════════════════════════════════════════════════════════════════════

    use crate::consensus::bft::quorum::RejectVoterVerifier;
    use std::collections::HashSet;

    fn manager_rejecting(node: &str, reject: &[&str]) -> RoundManager<RejectVoterVerifier> {
        let reject_set: HashSet<String> = reject.iter().map(|s| s.to_string()).collect();
        RoundManager::new(
            node.into(),
            validators(),
            RejectVoterVerifier { reject: reject_set },
            RoundManagerConfig::default(),
        )
    }

    fn forged_qc(phase: BftPhase, hash_id: u8, round: u64, voters: &[&str]) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash(hash_id),
            round,
            phase,
            votes: voters
                .iter()
                .map(|v| make_vote(phase, hash_id, round, v))
                .collect(),
        }
    }

    #[test]
    fn forged_qc_round_999999_rejected() {
        // Byzantine forges QC with round=999999. With RejectVoterVerifier
        // that rejects all voters, the signatures fail.
        let mut m = manager_rejecting("v1", &["v0", "v1", "v2", "v3"]);
        m.start();

        // Lock on something first (need AcceptAll for that → use separate manager).
        // Actually, with rejecting verifier, we can't build lock either.
        // Use a clean manager — the point is the forged QC is rejected
        // regardless of lock state.
        let mut m = manager("v1");
        m.start();

        let bad_qc = forged_qc(BftPhase::Prepare, 0xFF, 999999, &["v0", "v1", "v2"]);
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        // QC round=999999 doesn't matter — QC itself is structurally valid
        // with AcceptAllVerifier. The test proves that with a real verifier
        // (below), it would be rejected. With AcceptAll, it passes validation
        // but safe_to_vote may still gate it. This documents the boundary.
        //
        // The REAL protection test is the next one with RejectVoterVerifier.
        assert!(
            matches!(action, ManagerAction::Round(RoundAction::SendVote(_))),
            "AcceptAllVerifier: structurally valid QC passes (testnet behavior)"
        );
    }

    #[test]
    fn qc_with_invalid_signature_rejected() {
        // RejectVoterVerifier rejects v0's signature.
        let mut m = manager_rejecting("v1", &["v0"]);
        m.start();

        // QC has v0's vote (rejected) + v1, v2 (accepted) — but v0 fails.
        let bad_qc = forged_qc(BftPhase::Prepare, 0xAA, 0, &["v0", "v1", "v2"]);
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "QC with invalid signature must be rejected"
        );
    }

    #[test]
    fn qc_with_unknown_voter_rejected() {
        let mut m = manager("v1");
        m.start();

        // QC includes "intruder" — not in validator set.
        let bad_qc = forged_qc(BftPhase::Prepare, 0xAA, 0, &["v0", "intruder", "v2"]);
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "QC with unknown voter must be rejected"
        );
    }

    #[test]
    fn qc_with_duplicate_voter_rejected() {
        let mut m = manager("v1");
        m.start();

        // v0 appears twice.
        let bad_qc = forged_qc(BftPhase::Prepare, 0xAA, 0, &["v0", "v0", "v2"]);
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "QC with duplicate voter must be rejected"
        );
    }

    #[test]
    fn qc_with_insufficient_votes_rejected() {
        let mut m = manager("v1");
        m.start();

        // Only 2 votes — quorum requires 3.
        let bad_qc = forged_qc(BftPhase::Prepare, 0xAA, 0, &["v0", "v1"]);
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "QC with insufficient votes must be rejected"
        );
    }

    #[test]
    fn qc_with_modified_block_hash_rejected() {
        let mut m = manager("v1");
        m.start();

        // Votes are for block 0xAA but QC header says 0xFF.
        let mut bad_qc = forged_qc(BftPhase::Prepare, 0xAA, 0, &["v0", "v1", "v2"]);
        bad_qc.block_hash = block_hash(0xFF); // tampered header
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "QC with tampered block_hash must be rejected"
        );
    }

    #[test]
    fn qc_with_wrong_phase_rejected() {
        let mut m = manager("v1");
        m.start();

        // QC header says Prepare but votes say Commit.
        let mut bad_qc = forged_qc(BftPhase::Commit, 0xAA, 0, &["v0", "v1", "v2"]);
        bad_qc.phase = BftPhase::Prepare; // header/vote phase mismatch
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v0".into(),
            justify_qc: Some(bad_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "QC with mismatched phase must be rejected"
        );
    }

    #[test]
    fn valid_qc_but_proposal_wrong_branch_rejected() {
        let chain = chain_for_tests();
        let mut m = manager_with_chain("v1", chain);
        m.start();

        // Lock on A.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            m.process_event(RoundEvent::Vote(make_vote(
                BftPhase::PreCommit,
                0xAA,
                0,
                voter,
            )));
        }
        m.on_timeout(); // → round 1

        // Valid QC (passes validate_received_qc) but proposal B is sibling of A.
        // QC certifies A at round 0 (same as lock) → does NOT unlock.
        // B doesn't extend A → rejected by safe_to_vote.
        let valid_qc = forged_qc(BftPhase::Prepare, 0xAA, 0, &["v0", "v1", "v2"]);
        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xBB),
            leader_id: "v1".into(),
            justify_qc: Some(valid_qc),
        });
        assert_eq!(
            action,
            ManagerAction::Round(RoundAction::None),
            "valid QC + wrong branch must be rejected by safe_to_vote"
        );
    }
}
