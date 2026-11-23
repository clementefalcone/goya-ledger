//! BFT round state machine — drives a single consensus round through
//! HotStuff phases: Propose → Prepare → PreCommit → Commit → Decide.
//!
//! The state machine is event-driven and synchronous: callers feed events
//! (proposals, votes, timeouts) and receive actions (broadcast, send vote,
//! commit block) to execute externally.

use super::quorum::{QuorumValidator, SignatureVerifier};
use super::types::{BftPhase, QuorumCertificate, VoteMessage};
use super::vote_collector::{VoteCollector, VoteResult};

/// Events fed into the round state machine.
#[derive(Debug, Clone)]
pub enum RoundEvent {
    /// This node is the leader and should propose a block.
    StartAsLeader { block_hash: [u8; 32] },
    /// Received a block proposal from the round leader.
    Proposal {
        block_hash: [u8; 32],
        leader_id: String,
        /// The QC the leader includes to justify the proposal (its `high_qc`).
        /// Followers use this in `safe_to_vote` to decide whether to unlock.
        justify_qc: Option<QuorumCertificate>,
    },
    /// Received a vote from a validator.
    Vote(VoteMessage),
    /// Timeout: the current phase took too long.
    Timeout,
}

/// Actions the caller must execute after processing an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundAction {
    /// Broadcast a block proposal to all validators.
    BroadcastProposal { block_hash: [u8; 32] },
    /// Send our vote to the leader (or broadcast, depending on protocol variant).
    SendVote(VoteMessage),
    /// A QC was formed for a phase — advance to the next phase.
    PhaseComplete {
        phase: BftPhase,
        qc: QuorumCertificate,
    },
    /// Block is decided (CommitQC formed) — finalize and commit.
    Decide {
        block_hash: [u8; 32],
        round: u64,
        commit_qc: QuorumCertificate,
    },
    /// No action needed.
    None,
}

/// Internal state of the round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundState {
    /// Waiting for a proposal (either to create one as leader or receive one).
    AwaitingProposal,
    /// Collecting Prepare votes.
    Preparing,
    /// Collecting PreCommit votes (PrepareQC already formed).
    PreCommitting,
    /// Collecting Commit votes (PreCommitQC already formed).
    Committing,
    /// Block decided — terminal state.
    Decided,
    /// Round failed (timeout or error) — terminal state.
    Failed,
}

/// Helper: create an unsigned vote stub for this node.
/// The caller must sign it before sending over the network.
fn make_vote(phase: BftPhase, block_hash: [u8; 32], round: u64, node_id: &str) -> VoteMessage {
    VoteMessage {
        block_hash,
        round,
        phase,
        voter_id: node_id.to_string(),
        signature: Vec::new(),
    }
}

/// A single BFT consensus round.
///
/// Manages phase transitions for one `(round, block_hash)`. A new `BftRound`
/// is created for each consensus round. The caller is responsible for leader
/// election and networking — this struct only tracks state + vote collection.
pub struct BftRound<V: SignatureVerifier> {
    round: u64,
    node_id: String,
    leader_id: String,
    state: RoundState,
    block_hash: Option<[u8; 32]>,
    prepare_qc: Option<QuorumCertificate>,
    precommit_qc: Option<QuorumCertificate>,
    commit_qc: Option<QuorumCertificate>,
    prepare_collector: Option<VoteCollector<V>>,
    precommit_collector: Option<VoteCollector<V>>,
    commit_collector: Option<VoteCollector<V>>,
    deferred_votes: Vec<VoteMessage>,
    validators: Vec<String>,
    verifier: V,
}

const VOTING_PHASES: [BftPhase; 3] = [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit];

fn phase_position(phase: BftPhase) -> Option<usize> {
    VOTING_PHASES.iter().position(|p| *p == phase)
}

impl<V: SignatureVerifier + Clone> BftRound<V> {
    /// Create a new round.
    ///
    /// - `round` — round number
    /// - `node_id` — this node's validator identity
    /// - `leader_id` — the designated leader for this round
    /// - `validators` — full validator set
    /// - `verifier` — signature verification backend (cloned per collector)
    pub fn new(
        round: u64,
        node_id: String,
        leader_id: String,
        validators: Vec<String>,
        verifier: V,
    ) -> Self {
        Self {
            round,
            node_id,
            leader_id,
            state: RoundState::AwaitingProposal,
            block_hash: None,
            prepare_qc: None,
            precommit_qc: None,
            commit_qc: None,
            prepare_collector: None,
            precommit_collector: None,
            commit_collector: None,
            deferred_votes: Vec::new(),
            validators,
            verifier,
        }
    }

    /// Current round number.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Current state.
    pub fn state(&self) -> RoundState {
        self.state
    }

    /// Whether this node is the leader.
    pub fn is_leader(&self) -> bool {
        self.node_id == self.leader_id
    }

    /// Block hash under vote.
    pub fn block_hash(&self) -> Option<[u8; 32]> {
        self.block_hash
    }

    /// PrepareQC if formed.
    pub fn prepare_qc(&self) -> Option<&QuorumCertificate> {
        self.prepare_qc.as_ref()
    }

    /// PreCommitQC if formed.
    pub fn precommit_qc(&self) -> Option<&QuorumCertificate> {
        self.precommit_qc.as_ref()
    }

    /// CommitQC if formed.
    pub fn commit_qc(&self) -> Option<&QuorumCertificate> {
        self.commit_qc.as_ref()
    }

    /// Process an event and return the action to take.
    pub fn process(&mut self, event: RoundEvent) -> RoundAction {
        match event {
            RoundEvent::StartAsLeader { block_hash } => self.handle_start_as_leader(block_hash),
            RoundEvent::Proposal {
                block_hash,
                leader_id,
                ..
            } => self.handle_proposal(block_hash, &leader_id),
            RoundEvent::Vote(vote) => self.handle_vote(vote),
            RoundEvent::Timeout => self.handle_timeout(),
        }
    }

    fn handle_start_as_leader(&mut self, block_hash: [u8; 32]) -> RoundAction {
        if self.state != RoundState::AwaitingProposal || !self.is_leader() {
            return RoundAction::None;
        }

        self.block_hash = Some(block_hash);
        self.state = RoundState::Preparing;
        self.ensure_collector(BftPhase::Prepare, block_hash);

        RoundAction::BroadcastProposal { block_hash }
    }

    fn handle_proposal(&mut self, block_hash: [u8; 32], leader_id: &str) -> RoundAction {
        if self.state != RoundState::AwaitingProposal || leader_id != self.leader_id {
            return RoundAction::None;
        }

        self.block_hash = Some(block_hash);
        self.state = RoundState::Preparing;
        self.ensure_collector(BftPhase::Prepare, block_hash);

        RoundAction::SendVote(make_vote(
            BftPhase::Prepare,
            block_hash,
            self.round,
            &self.node_id,
        ))
    }

    fn handle_vote(&mut self, vote: VoteMessage) -> RoundAction {
        let (Some(bh), Some(current)) = (self.block_hash, self.collecting_phase()) else {
            return RoundAction::None;
        };
        if phase_position(vote.phase) > phase_position(current) {
            self.defer_vote(vote);
            return RoundAction::None;
        }
        self.on_vote(current, vote, bh)
    }

    fn collecting_phase(&self) -> Option<BftPhase> {
        match self.state {
            RoundState::Preparing => Some(BftPhase::Prepare),
            RoundState::PreCommitting => Some(BftPhase::PreCommit),
            RoundState::Committing => Some(BftPhase::Commit),
            _ => None,
        }
    }

    fn defer_vote(&mut self, vote: VoteMessage) {
        let is_known_voter = self.validators.contains(&vote.voter_id);
        let is_duplicate = self
            .deferred_votes
            .iter()
            .any(|d| d.phase == vote.phase && d.voter_id == vote.voter_id);
        if vote.round == self.round && is_known_voter && !is_duplicate {
            self.deferred_votes.push(vote);
        }
    }

    pub fn take_ready_votes(&mut self) -> Vec<VoteMessage> {
        let Some(current) = self.collecting_phase() else {
            return Vec::new();
        };
        let (ready, later) = std::mem::take(&mut self.deferred_votes)
            .into_iter()
            .partition(|vote| vote.phase == current);
        self.deferred_votes = later;
        ready
    }

    fn on_vote(&mut self, phase: BftPhase, vote: VoteMessage, bh: [u8; 32]) -> RoundAction {
        self.ensure_collector(phase, bh);
        let collector = match phase {
            BftPhase::Prepare => self.prepare_collector.as_mut(),
            BftPhase::PreCommit => self.precommit_collector.as_mut(),
            BftPhase::Commit => self.commit_collector.as_mut(),
            BftPhase::Decide => return RoundAction::None,
        };
        let c = match collector {
            Some(c) => c,
            None => return RoundAction::None,
        };

        match c.add_vote(vote) {
            VoteResult::QuorumReached { qc } => self.advance_phase(phase, qc, bh),
            _ => RoundAction::None,
        }
    }

    fn advance_phase(
        &mut self,
        completed_phase: BftPhase,
        qc: QuorumCertificate,
        bh: [u8; 32],
    ) -> RoundAction {
        match completed_phase {
            BftPhase::Prepare => {
                self.prepare_qc = Some(qc.clone());
                self.state = RoundState::PreCommitting;
                self.ensure_collector(BftPhase::PreCommit, bh);
                RoundAction::PhaseComplete {
                    phase: BftPhase::Prepare,
                    qc,
                }
            }
            BftPhase::PreCommit => {
                self.precommit_qc = Some(qc.clone());
                self.state = RoundState::Committing;
                self.ensure_collector(BftPhase::Commit, bh);
                RoundAction::PhaseComplete {
                    phase: BftPhase::PreCommit,
                    qc,
                }
            }
            BftPhase::Commit => {
                self.commit_qc = Some(qc.clone());
                self.state = RoundState::Decided;
                RoundAction::Decide {
                    block_hash: bh,
                    round: self.round,
                    commit_qc: qc,
                }
            }
            BftPhase::Decide => RoundAction::None,
        }
    }

    fn handle_timeout(&mut self) -> RoundAction {
        if self.state != RoundState::Decided && self.state != RoundState::Failed {
            self.state = RoundState::Failed;
        }
        RoundAction::None
    }

    fn ensure_collector(&mut self, phase: BftPhase, bh: [u8; 32]) {
        let slot = match phase {
            BftPhase::Prepare => &mut self.prepare_collector,
            BftPhase::PreCommit => &mut self.precommit_collector,
            BftPhase::Commit => &mut self.commit_collector,
            BftPhase::Decide => return,
        };
        if slot.is_none() {
            let qv = QuorumValidator::new(self.validators.clone(), self.verifier.clone());
            *slot = Some(VoteCollector::new(phase, self.round, bh, qv));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::quorum::AcceptAllVerifier;

    fn validators() -> Vec<String> {
        (0..4).map(|i| format!("v{i}")).collect()
    }

    fn block_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    fn make_test_vote(phase: BftPhase, hash_id: u8, round: u64, voter: &str) -> VoteMessage {
        VoteMessage {
            block_hash: block_hash(hash_id),
            round,
            phase,
            voter_id: voter.to_string(),
            signature: vec![1u8; 64],
        }
    }

    fn leader_round(round: u64, leader: &str) -> BftRound<AcceptAllVerifier> {
        BftRound::new(
            round,
            leader.into(),
            leader.into(),
            validators(),
            AcceptAllVerifier,
        )
    }

    fn follower_round(round: u64, node: &str, leader: &str) -> BftRound<AcceptAllVerifier> {
        BftRound::new(
            round,
            node.into(),
            leader.into(),
            validators(),
            AcceptAllVerifier,
        )
    }

    // --- initial state ---

    #[test]
    fn initial_state_is_awaiting_proposal() {
        let r = leader_round(0, "v0");
        assert_eq!(r.state(), RoundState::AwaitingProposal);
        assert!(r.block_hash().is_none());
    }

    #[test]
    fn is_leader_correct() {
        let r = leader_round(0, "v0");
        assert!(r.is_leader());

        let r2 = follower_round(0, "v1", "v0");
        assert!(!r2.is_leader());
    }

    // --- leader flow ---

    #[test]
    fn leader_starts_and_broadcasts() {
        let mut r = leader_round(0, "v0");
        let action = r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        assert_eq!(
            action,
            RoundAction::BroadcastProposal {
                block_hash: block_hash(1)
            }
        );
        assert_eq!(r.state(), RoundState::Preparing);
        assert_eq!(r.block_hash(), Some(block_hash(1)));
    }

    #[test]
    fn non_leader_ignores_start_as_leader() {
        let mut r = follower_round(0, "v1", "v0");
        let action = r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        assert_eq!(action, RoundAction::None);
        assert_eq!(r.state(), RoundState::AwaitingProposal);
    }

    // --- follower flow ---

    #[test]
    fn follower_receives_proposal_and_votes() {
        let mut r = follower_round(0, "v1", "v0");
        let action = r.process(RoundEvent::Proposal {
            block_hash: block_hash(1),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        match action {
            RoundAction::SendVote(vote) => {
                assert_eq!(vote.phase, BftPhase::Prepare);
                assert_eq!(vote.block_hash, block_hash(1));
                assert_eq!(vote.voter_id, "v1");
            }
            other => panic!("expected SendVote, got {other:?}"),
        }
        assert_eq!(r.state(), RoundState::Preparing);
    }

    #[test]
    fn follower_ignores_proposal_from_wrong_leader() {
        let mut r = follower_round(0, "v1", "v0");
        let action = r.process(RoundEvent::Proposal {
            block_hash: block_hash(1),
            leader_id: "v2".into(),
            justify_qc: None,
        });
        assert_eq!(action, RoundAction::None);
    }

    // --- full round: Prepare → PreCommit → Commit → Decide ---

    #[test]
    fn full_round_reaches_decide() {
        let mut r = leader_round(0, "v0");

        // 1. Leader proposes.
        r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        assert_eq!(r.state(), RoundState::Preparing);

        // 2. Collect 3 Prepare votes (threshold=3 for n=4).
        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Prepare,
            1,
            0,
            "v0",
        )));
        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Prepare,
            1,
            0,
            "v1",
        )));
        let action = r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Prepare,
            1,
            0,
            "v2",
        )));
        assert!(matches!(
            action,
            RoundAction::PhaseComplete {
                phase: BftPhase::Prepare,
                ..
            }
        ));
        assert_eq!(r.state(), RoundState::PreCommitting);
        assert!(r.prepare_qc().is_some());

        // 3. Collect 3 PreCommit votes.
        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::PreCommit,
            1,
            0,
            "v0",
        )));
        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::PreCommit,
            1,
            0,
            "v1",
        )));
        let action = r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::PreCommit,
            1,
            0,
            "v2",
        )));
        assert!(matches!(
            action,
            RoundAction::PhaseComplete {
                phase: BftPhase::PreCommit,
                ..
            }
        ));
        assert_eq!(r.state(), RoundState::Committing);
        assert!(r.precommit_qc().is_some());

        // 4. Collect 3 Commit votes → Decide.
        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Commit,
            1,
            0,
            "v0",
        )));
        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Commit,
            1,
            0,
            "v1",
        )));
        let action = r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Commit,
            1,
            0,
            "v2",
        )));
        match action {
            RoundAction::Decide {
                block_hash: decided_hash,
                round,
                commit_qc,
            } => {
                assert_eq!(decided_hash, block_hash(1));
                assert_eq!(round, 0);
                assert_eq!(commit_qc.phase, BftPhase::Commit);
                assert_eq!(commit_qc.voter_count(), 3);
            }
            other => panic!("expected Decide, got {other:?}"),
        }
        assert_eq!(r.state(), RoundState::Decided);
        assert!(r.commit_qc().is_some());
    }

    // --- timeout ---

    #[test]
    fn timeout_during_prepare_fails_round() {
        let mut r = leader_round(0, "v0");
        r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        r.process(RoundEvent::Timeout);
        assert_eq!(r.state(), RoundState::Failed);
    }

    #[test]
    fn timeout_after_decide_is_noop() {
        let mut r = leader_round(0, "v0");
        r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        for voter in &["v0", "v1", "v2"] {
            r.process(RoundEvent::Vote(make_test_vote(
                BftPhase::Prepare,
                1,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            r.process(RoundEvent::Vote(make_test_vote(
                BftPhase::PreCommit,
                1,
                0,
                voter,
            )));
        }
        for voter in &["v0", "v1", "v2"] {
            r.process(RoundEvent::Vote(make_test_vote(
                BftPhase::Commit,
                1,
                0,
                voter,
            )));
        }
        assert_eq!(r.state(), RoundState::Decided);

        r.process(RoundEvent::Timeout);
        assert_eq!(r.state(), RoundState::Decided);
    }

    // --- edge cases ---

    #[test]
    fn votes_before_proposal_ignored() {
        let mut r = leader_round(0, "v0");
        let action = r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Prepare,
            1,
            0,
            "v1",
        )));
        assert_eq!(action, RoundAction::None);
    }

    #[test]
    fn wrong_phase_votes_ignored() {
        let mut r = leader_round(0, "v0");
        r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });

        // Commit vote during Prepare phase — routed to Commit collector, which
        // doesn't exist yet (state is Preparing), so it's a no-op.
        let action = r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::Commit,
            1,
            0,
            "v0",
        )));
        assert_eq!(action, RoundAction::None);
    }

    #[test]
    fn votes_for_a_later_phase_count_once_the_round_reaches_it() {
        let mut r = follower_round(0, "v1", "v0");
        r.process(RoundEvent::Proposal {
            block_hash: block_hash(1),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for voter in ["v2", "v3"] {
            r.process(RoundEvent::Vote(make_test_vote(
                BftPhase::PreCommit,
                1,
                0,
                voter,
            )));
        }
        for voter in ["v0", "v1", "v2"] {
            r.process(RoundEvent::Vote(make_test_vote(
                BftPhase::Prepare,
                1,
                0,
                voter,
            )));
        }
        assert_eq!(r.state(), RoundState::PreCommitting);

        r.process(RoundEvent::Vote(make_test_vote(
            BftPhase::PreCommit,
            1,
            0,
            "v1",
        )));
        let ready = r.take_ready_votes();
        assert_eq!(ready.len(), 2);
        let actions: Vec<RoundAction> = ready
            .into_iter()
            .map(|vote| r.process(RoundEvent::Vote(vote)))
            .collect();
        assert!(actions.iter().any(|a| matches!(
            a,
            RoundAction::PhaseComplete {
                phase: BftPhase::PreCommit,
                ..
            }
        )));
        assert_eq!(r.state(), RoundState::Committing);
    }

    #[test]
    fn deferred_votes_reject_strangers_other_rounds_and_duplicates() {
        let mut r = follower_round(0, "v1", "v0");
        r.process(RoundEvent::Proposal {
            block_hash: block_hash(1),
            leader_id: "v0".into(),
            justify_qc: None,
        });
        for vote in [
            make_test_vote(BftPhase::PreCommit, 1, 0, "mallory"),
            make_test_vote(BftPhase::PreCommit, 1, 7, "v2"),
            make_test_vote(BftPhase::PreCommit, 1, 0, "v2"),
            make_test_vote(BftPhase::PreCommit, 1, 0, "v2"),
        ] {
            r.process(RoundEvent::Vote(vote));
        }
        for voter in ["v0", "v1", "v2"] {
            r.process(RoundEvent::Vote(make_test_vote(
                BftPhase::Prepare,
                1,
                0,
                voter,
            )));
        }
        assert_eq!(r.take_ready_votes().len(), 1);
    }

    #[test]
    fn duplicate_start_as_leader_ignored() {
        let mut r = leader_round(0, "v0");
        r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        let action = r.process(RoundEvent::StartAsLeader {
            block_hash: block_hash(2),
        });
        assert_eq!(action, RoundAction::None);
        assert_eq!(r.block_hash(), Some(block_hash(1)));
    }
}
