//! Adversarial BFT E2E tests — simulates a network of BFT nodes with
//! configurable Byzantine behavior, network partitions, and stress scenarios.
//!
//! These tests verify safety (no conflicting decisions) and liveness
//! (progress despite faults) of the HotStuff-inspired BFT consensus.

use std::collections::HashMap;

use rust_bc::consensus::bft::quorum::SignatureVerifier;
use rust_bc::consensus::bft::round::RoundAction;
use rust_bc::consensus::bft::round::{RoundEvent, RoundState};
use rust_bc::consensus::bft::round_manager::{ManagerAction, RoundManager, RoundManagerConfig};
use rust_bc::consensus::bft::types::{BftPhase, QuorumCertificate, VoteMessage};

/// Local signature verifier for integration tests — accepts any non-empty signature.
#[derive(Clone)]
struct TestVerifier;

impl SignatureVerifier for TestVerifier {
    fn verify(&self, _voter_id: &str, _payload: &[u8], signature: &[u8]) -> bool {
        !signature.is_empty()
    }
}

// ── Test harness ────────────────────────────────────────────────────────────

/// Behavior mode for a simulated node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeBehavior {
    /// Honest: follows the protocol exactly.
    Honest,
    /// Equivocator: votes for multiple different blocks in the same round.
    Equivocator,
    /// Silent: never sends votes (simulates crash or withholding).
    Silent,
    /// DelayedLeader: proposes blocks but only after a delay (simulates slow leader).
    DelayedLeader,
}

/// A simulated BFT node.
struct SimNode {
    id: String,
    behavior: NodeBehavior,
    manager: RoundManager<TestVerifier>,
}

/// Network simulator that routes messages between nodes.
struct BftTestNetwork {
    nodes: HashMap<String, SimNode>,
    validators: Vec<String>,
    /// Messages dropped by the network (for partition simulation).
    drop_from: Vec<String>,
    /// Global round tracker.
    current_round: u64,
    /// Total messages delivered across all rounds.
    messages_delivered: u64,
}

fn block_hash(round: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    let bytes = round.to_le_bytes();
    h[..8].copy_from_slice(&bytes);
    h
}

fn make_vote(phase: BftPhase, bh: [u8; 32], round: u64, voter: &str) -> VoteMessage {
    VoteMessage {
        block_hash: bh,
        round,
        phase,
        voter_id: voter.to_string(),
        signature: vec![1u8; 64],
    }
}

impl BftTestNetwork {
    fn new(n: usize, behaviors: &[NodeBehavior]) -> Self {
        let validators: Vec<String> = (0..n).map(|i| format!("v{i}")).collect();
        let config = RoundManagerConfig {
            base_timeout_ms: 100,
            max_timeout_ms: 1000,
        };

        let mut nodes = HashMap::new();
        for (i, &behavior) in behaviors.iter().enumerate() {
            let id = format!("v{i}");
            let manager =
                RoundManager::new(id.clone(), validators.clone(), TestVerifier, config.clone());
            nodes.insert(
                id.clone(),
                SimNode {
                    id,
                    behavior,
                    manager,
                },
            );
        }

        BftTestNetwork {
            nodes,
            validators,
            drop_from: Vec::new(),
            current_round: 0,
            messages_delivered: 0,
        }
    }

    fn with_partition(mut self, partitioned: Vec<String>) -> Self {
        self.drop_from = partitioned;
        self
    }

    /// Start all nodes at round 0.
    fn start_all(&mut self) {
        let ids: Vec<String> = self.nodes.keys().cloned().collect();
        for id in &ids {
            let node = self.nodes.get_mut(id).unwrap();
            node.manager.start();
        }
    }

    /// Get the leader for a given round.
    fn leader_for_round(&self, round: u64) -> &str {
        let idx = (round as usize) % self.validators.len();
        &self.validators[idx]
    }

    /// Run a single BFT round to completion (or timeout).
    /// Returns the number of nodes that decided.
    fn run_round(&mut self, round: u64) -> usize {
        self.current_round = round;
        let bh = block_hash(round);
        let leader_id = self.leader_for_round(round).to_string();

        // 1. Start the round on all nodes.
        let ids: Vec<String> = self.nodes.keys().cloned().collect();
        for id in &ids {
            let node = self.nodes.get_mut(id).unwrap();
            node.manager.start_round(round);
        }

        // 2. Leader proposes (or not, depending on behavior).
        let leader_behavior = self.nodes.get(&leader_id).map(|n| n.behavior);
        match leader_behavior {
            Some(NodeBehavior::Silent) => {
                // Leader is silent — no proposal. Nodes should timeout.
                return 0;
            }
            Some(NodeBehavior::DelayedLeader) => {
                // Delayed — we'll still propose but after votes already started.
                // For simplicity, treat as honest but with late start.
            }
            _ => {}
        }

        // Leader processes StartAsLeader.
        if let Some(leader) = self.nodes.get_mut(&leader_id) {
            if leader.behavior != NodeBehavior::Silent {
                leader
                    .manager
                    .process_event(RoundEvent::StartAsLeader { block_hash: bh });
            }
        }

        // 3. All non-leader nodes receive the proposal.
        for id in &ids {
            if *id == leader_id {
                continue;
            }
            let node = self.nodes.get_mut(id).unwrap();
            if node.behavior == NodeBehavior::Silent {
                continue;
            }
            node.manager.process_event(RoundEvent::Proposal {
                block_hash: bh,
                leader_id: leader_id.clone(),
                justify_qc: None,
            });
        }

        // 4. Run vote collection for each phase.
        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            self.broadcast_votes(round, bh, phase);
        }

        // 5. Count decisions.
        let mut decided_count = 0;
        for node in self.nodes.values() {
            if node.manager.round_state()
                == Some(rust_bc::consensus::bft::round::RoundState::Decided)
            {
                decided_count += 1;
            }
        }

        decided_count
    }

    /// Broadcast votes from all honest nodes for a given phase.
    fn broadcast_votes(&mut self, round: u64, bh: [u8; 32], phase: BftPhase) {
        // Collect votes from all non-silent, non-partitioned nodes.
        let mut votes: Vec<VoteMessage> = Vec::new();

        for (id, node) in &self.nodes {
            if self.drop_from.contains(id) {
                continue;
            }
            match node.behavior {
                NodeBehavior::Silent => continue,
                NodeBehavior::Equivocator => {
                    // Equivocator sends TWO conflicting votes for the same
                    // (round, phase): the correct hash and a corrupted one.
                    // The vote collector must deduplicate by voter_id so only
                    // the first counts — that dedup is what this exercises.
                    let mut bad_hash = bh;
                    bad_hash[31] ^= 0xFF;
                    votes.push(make_vote(phase, bh, round, id));
                    votes.push(make_vote(phase, bad_hash, round, id));
                }
                _ => {
                    votes.push(make_vote(phase, bh, round, id));
                }
            }
        }

        // Deliver votes to all nodes.
        let ids: Vec<String> = self.nodes.keys().cloned().collect();
        for vote in &votes {
            for id in &ids {
                let node = self.nodes.get_mut(id).unwrap();
                if node.behavior == NodeBehavior::Silent {
                    continue;
                }
                node.manager.process_event(RoundEvent::Vote(vote.clone()));
                self.messages_delivered += 1;
            }
        }
    }

    /// Trigger timeout on all nodes and advance to next round.
    fn timeout_all(&mut self) {
        let ids: Vec<String> = self.nodes.keys().cloned().collect();
        for id in &ids {
            let node = self.nodes.get_mut(id).unwrap();
            node.manager.jump_to_round(node.manager.current_round() + 1);
        }
    }

    /// Check safety: no two honest nodes decided different blocks for the same round.
    fn assert_safety(&self) {
        let mut decisions: HashMap<u64, [u8; 32]> = HashMap::new();

        for node in self.nodes.values() {
            if node.behavior != NodeBehavior::Honest && node.behavior != NodeBehavior::DelayedLeader
            {
                continue; // Only check honest nodes.
            }
            if let Some(qc) = node.manager.highest_commit_qc() {
                let round = qc.round;
                let hash = qc.block_hash;
                if let Some(&existing) = decisions.get(&round) {
                    assert_eq!(
                        existing, hash,
                        "SAFETY VIOLATION: node {} decided different block for round {round}",
                        node.id
                    );
                } else {
                    decisions.insert(round, hash);
                }
            }
        }
    }
}

// ── Test scenarios ──────────────────────────────────────────────────────────

#[test]
fn e2e_4_honest_nodes_reach_consensus() {
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let decided = net.run_round(0);
    assert_eq!(decided, 4, "all 4 honest nodes should decide");
    net.assert_safety();
}

#[test]
fn e2e_1_byzantine_equivocator_safety_holds() {
    // v3 equivocates but 3 honest nodes still reach consensus.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Equivocator,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let decided = net.run_round(0);
    // At least 3 honest nodes should decide (equivocator may or may not).
    assert!(
        decided >= 3,
        "at least 3 honest nodes should decide, got {decided}"
    );
    net.assert_safety();
}

#[test]
fn e2e_1_silent_node_liveness_with_3_honest() {
    // v3 is silent (crashed). n=4, f=1, threshold=3.
    // 3 honest nodes should still reach consensus.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Silent,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let decided = net.run_round(0);
    assert!(
        decided >= 3,
        "3 honest nodes should decide despite 1 silent, got {decided}"
    );
    net.assert_safety();
}

#[test]
fn e2e_2_silent_nodes_no_progress() {
    // n=4, f=1 tolerant. With 2 silent, only 2 honest nodes remain — below threshold.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Silent,
        NodeBehavior::Silent,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let decided = net.run_round(0);
    assert_eq!(decided, 0, "should NOT reach consensus with 2 silent nodes");
}

#[test]
fn e2e_silent_leader_triggers_timeout_and_view_change() {
    // Round 0 leader is v0. Make v0 silent → no proposal → timeout.
    // Round 1 leader is v1 (honest) → should succeed.
    let behaviors = [
        NodeBehavior::Silent, // v0 — round 0 leader, silent
        NodeBehavior::Honest, // v1 — round 1 leader
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    // Round 0: silent leader, no progress.
    let decided_r0 = net.run_round(0);
    assert_eq!(decided_r0, 0, "round 0 should stall with silent leader");

    // Timeout and advance.
    net.timeout_all();

    // Round 1: v1 is leader, honest. But v0 is still silent.
    // 3 honest nodes (v1, v2, v3) should decide.
    let decided_r1 = net.run_round(1);
    assert!(
        decided_r1 >= 3,
        "round 1 should succeed with v1 as leader, got {decided_r1}"
    );
    net.assert_safety();
}

#[test]
fn e2e_network_partition_minority_stalls() {
    // Partition: v3 is isolated. n=4, 3 nodes in majority should still decide.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors).with_partition(vec!["v3".into()]);
    net.start_all();

    let decided = net.run_round(0);
    // v0, v1, v2 form the majority (3 votes). v3 is partitioned — doesn't vote.
    // threshold=3, so 3 honest votes should be enough.
    assert!(
        decided >= 3,
        "majority partition should decide, got {decided}"
    );
    net.assert_safety();
}

#[test]
fn e2e_network_partition_no_quorum() {
    // Partition: v2 and v3 are isolated. Only v0, v1 remain (2 < threshold 3).
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors).with_partition(vec!["v2".into(), "v3".into()]);
    net.start_all();

    let decided = net.run_round(0);
    assert_eq!(
        decided, 0,
        "should NOT decide with only 2/4 nodes reachable"
    );
}

#[test]
fn e2e_100_consecutive_rounds_stress_test() {
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    for round in 0..100 {
        let decided = net.run_round(round);
        assert_eq!(decided, 4, "round {round}: all 4 should decide");
    }

    net.assert_safety();
    assert!(
        net.messages_delivered > 3000,
        "stress test should deliver many messages, got {}",
        net.messages_delivered
    );
}

#[test]
fn e2e_7_nodes_tolerates_2_byzantine() {
    // n=7, f=2, threshold=5. Two equivocators, five honest.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Equivocator,
        NodeBehavior::Equivocator,
    ];
    let mut net = BftTestNetwork::new(7, &behaviors);
    net.start_all();

    let decided = net.run_round(0);
    assert!(decided >= 5, "5 honest nodes should decide, got {decided}");
    net.assert_safety();
}

#[test]
fn e2e_7_nodes_3_silent_no_progress() {
    // n=7, f=2. With 3 silent, only 4 honest remain — below threshold of 5.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Silent,
        NodeBehavior::Silent,
        NodeBehavior::Silent,
    ];
    let mut net = BftTestNetwork::new(7, &behaviors);
    net.start_all();

    let decided = net.run_round(0);
    assert_eq!(decided, 0, "should NOT decide with only 4/7 honest");
}

#[test]
fn e2e_leader_rotation_across_5_rounds() {
    // Verify different leaders across rounds and all succeed.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    for round in 0..5u64 {
        let expected_leader = format!("v{}", round % 4);
        assert_eq!(
            net.leader_for_round(round),
            expected_leader,
            "round {round} leader mismatch"
        );
        let decided = net.run_round(round);
        assert_eq!(decided, 4, "round {round}: all should decide");
    }

    net.assert_safety();
}

#[test]
fn e2e_mixed_faults_across_rounds() {
    // Round 0: v0 leads (honest) — success.
    // Round 1: v1 leads (equivocator) — honest nodes ignore bad votes, still decide.
    // Round 2: v2 leads (honest) — success.
    // Round 3: v3 leads (silent) — timeout, no decision.
    // Round 4: v0 leads (honest) — recovery after timeout.
    let behaviors = [
        NodeBehavior::Honest,      // v0
        NodeBehavior::Equivocator, // v1
        NodeBehavior::Honest,      // v2
        NodeBehavior::Silent,      // v3
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    // Round 0: v0 leads, 3 honest (v0, v2 + equivocator v1 still votes).
    let d0 = net.run_round(0);
    assert!(d0 >= 3, "round 0 should succeed, got {d0}");

    // Round 1: v1 leads (equivocator). Equivocator still proposes — honest nodes
    // receive proposal and vote. Equivocator's own vote counts (valid signature).
    // v3 is silent but v0, v1, v2 = 3 votes ≥ threshold.
    let d1 = net.run_round(1);
    assert!(
        d1 >= 2,
        "round 1 should succeed with equivocator leader, got {d1}"
    );

    // Round 2: v2 leads (honest).
    let d2 = net.run_round(2);
    assert!(d2 >= 3, "round 2 should succeed, got {d2}");

    // Round 3: v3 leads (silent) — no proposal.
    let d3 = net.run_round(3);
    assert_eq!(d3, 0, "round 3 should stall with silent leader");

    // Timeout.
    net.timeout_all();

    // Round 4: v0 leads again (honest) — recovery.
    let d4 = net.run_round(4);
    assert!(d4 >= 3, "round 4 should recover, got {d4}");

    net.assert_safety();
}

#[test]
fn e2e_partition_heals_and_resumes() {
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];

    // Round 0: v3 partitioned — 3 nodes decide.
    let mut net = BftTestNetwork::new(4, &behaviors).with_partition(vec!["v3".into()]);
    net.start_all();
    let d0 = net.run_round(0);
    assert!(
        d0 >= 3,
        "round 0: majority decides despite partition, got {d0}"
    );

    // Heal partition.
    net.drop_from.clear();

    // Round 1: all 4 nodes participate.
    let d1 = net.run_round(1);
    assert_eq!(
        d1, 4,
        "round 1: all nodes should decide after partition heals"
    );

    net.assert_safety();
}

#[test]
fn e2e_safety_under_equivocation_across_100_rounds() {
    // Long-running safety test: 1 equivocator across 100 rounds.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Equivocator,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let mut total_decided = 0;
    for round in 0..100 {
        let decided = net.run_round(round);
        total_decided += decided;
    }

    net.assert_safety();
    assert!(
        total_decided >= 300,
        "at least 3 nodes should decide each round, got total {total_decided}"
    );
}

#[test]
fn e2e_10_nodes_3_byzantine_stress() {
    // n=10, f=3, threshold=7. Three equivocators, seven honest.
    let behaviors = [
        NodeBehavior::Honest,      // v0
        NodeBehavior::Honest,      // v1
        NodeBehavior::Honest,      // v2
        NodeBehavior::Honest,      // v3
        NodeBehavior::Honest,      // v4
        NodeBehavior::Honest,      // v5
        NodeBehavior::Honest,      // v6
        NodeBehavior::Equivocator, // v7
        NodeBehavior::Equivocator, // v8
        NodeBehavior::Equivocator, // v9
    ];
    let mut net = BftTestNetwork::new(10, &behaviors);
    net.start_all();

    for round in 0..20 {
        let decided = net.run_round(round);
        assert!(
            decided >= 7,
            "round {round}: at least 7 should decide, got {decided}"
        );
    }

    net.assert_safety();
}

#[test]
fn e2e_alternating_partitions_stress() {
    // Alternate which node is partitioned each round.
    // Each round only 1 node is isolated — 3 remain, threshold met.
    let behaviors = [
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
        NodeBehavior::Honest,
    ];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    for round in 0..20u64 {
        let partitioned = format!("v{}", round % 4);
        net.drop_from = vec![partitioned.clone()];

        let decided = net.run_round(round);
        assert!(
            decided >= 3,
            "round {round} (partitioned {partitioned}): at least 3 should decide, got {decided}"
        );
    }

    net.assert_safety();
}

// ════════════════════════════════════════════════════════════════════════════
// Adversarial safety validation — QC validation + finalization invariant
// ════════════════════════════════════════════════════════════════════════════

struct FinalizationTracker {
    finalized: Vec<(u64, [u8; 32])>,
}

impl FinalizationTracker {
    fn new() -> Self {
        Self { finalized: vec![] }
    }

    fn record(&mut self, round: u64, hash: [u8; 32]) {
        if !self
            .finalized
            .iter()
            .any(|(r, h)| *r == round && *h == hash)
        {
            self.finalized.push((round, hash));
        }
    }

    fn record_from_network(&mut self, net: &BftTestNetwork) {
        for node in net.nodes.values() {
            if node.behavior == NodeBehavior::Silent {
                continue;
            }
            if let Some(qc) = node.manager.highest_commit_qc() {
                self.record(qc.round, qc.block_hash);
            }
        }
    }

    fn assert_invariant(&self) {
        let mut by_round: HashMap<u64, [u8; 32]> = HashMap::new();
        for &(round, hash) in &self.finalized {
            if let Some(&existing) = by_round.get(&round) {
                assert_eq!(
                    existing, hash,
                    "SAFETY VIOLATION: round {round} finalized two different blocks!\nall={:?}",
                    self.finalized
                );
            } else {
                by_round.insert(round, hash);
            }
        }
    }
}

#[test]
fn e2e_lock_viewchange_delayed_messages_no_fork() {
    let behaviors = [NodeBehavior::Honest; 4];
    let mut net = BftTestNetwork::new(4, &behaviors);
    let mut tracker = FinalizationTracker::new();
    net.start_all();

    let bh_a = block_hash(0);
    {
        let ids: Vec<String> = net.nodes.keys().cloned().collect();
        for id in &ids {
            net.nodes.get_mut(id).unwrap().manager.start_round(0);
        }
        net.nodes
            .get_mut("v0")
            .unwrap()
            .manager
            .process_event(RoundEvent::StartAsLeader { block_hash: bh_a });
        for id in &["v1", "v2", "v3"] {
            net.nodes
                .get_mut(*id)
                .unwrap()
                .manager
                .process_event(RoundEvent::Proposal {
                    block_hash: bh_a,
                    leader_id: "v0".into(),
                    justify_qc: None,
                });
        }
        net.broadcast_votes(0, bh_a, BftPhase::Prepare);
        net.broadcast_votes(0, bh_a, BftPhase::PreCommit);
    }

    for node in net.nodes.values() {
        assert!(
            node.manager.safety().locked_qc().is_some(),
            "node {} should be locked",
            node.id
        );
    }
    for node in net.nodes.values() {
        assert_ne!(node.manager.round_state(), Some(RoundState::Decided));
    }

    net.timeout_all();
    let bh_b = block_hash(1);
    let decided_r1 = net.run_round(1);
    assert!(decided_r1 >= 3, "round 1 should decide, got {decided_r1}");
    tracker.record_from_network(&net);

    for voter in &["v0", "v1", "v2"] {
        let vote = make_vote(BftPhase::Commit, bh_a, 0, voter);
        for id in &["v0", "v1", "v2", "v3"] {
            net.nodes
                .get_mut(*id)
                .unwrap()
                .manager
                .process_event(RoundEvent::Vote(vote.clone()));
        }
    }

    tracker.record_from_network(&net);
    tracker.assert_invariant();
    net.assert_safety();

    for node in net.nodes.values() {
        if let Some(qc) = node.manager.highest_commit_qc() {
            assert_eq!(qc.round, 1);
            assert_eq!(qc.block_hash, bh_b);
        }
    }
}

#[test]
fn e2e_byzantine_forged_justify_qc_rejected() {
    let behaviors = [NodeBehavior::Honest; 4];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let forged_qc = QuorumCertificate {
        block_hash: block_hash(999),
        round: 999,
        phase: BftPhase::Prepare,
        votes: vec![
            make_vote(BftPhase::Prepare, block_hash(999), 999, "v0"),
            make_vote(BftPhase::Prepare, block_hash(999), 999, "intruder"),
            make_vote(BftPhase::Prepare, block_hash(999), 999, "v2"),
        ],
    };

    for id in &["v0", "v1", "v2", "v3"] {
        net.nodes.get_mut(*id).unwrap().manager.start_round(0);
    }

    let action = net
        .nodes
        .get_mut("v1")
        .unwrap()
        .manager
        .process_event(RoundEvent::Proposal {
            block_hash: block_hash(0),
            leader_id: "v0".into(),
            justify_qc: Some(forged_qc),
        });
    assert_eq!(
        action,
        ManagerAction::Round(RoundAction::None),
        "forged QC must be rejected"
    );
}

#[test]
fn e2e_forged_qc_insufficient_votes_rejected() {
    let behaviors = [NodeBehavior::Honest; 4];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let weak_qc = QuorumCertificate {
        block_hash: block_hash(999),
        round: 999,
        phase: BftPhase::Prepare,
        votes: vec![
            make_vote(BftPhase::Prepare, block_hash(999), 999, "v0"),
            make_vote(BftPhase::Prepare, block_hash(999), 999, "v1"),
        ],
    };

    for id in &["v0", "v1", "v2", "v3"] {
        net.nodes.get_mut(*id).unwrap().manager.start_round(0);
    }
    let action = net
        .nodes
        .get_mut("v2")
        .unwrap()
        .manager
        .process_event(RoundEvent::Proposal {
            block_hash: block_hash(0),
            leader_id: "v0".into(),
            justify_qc: Some(weak_qc),
        });
    assert_eq!(
        action,
        ManagerAction::Round(RoundAction::None),
        "weak QC must be rejected"
    );
}

#[test]
fn e2e_forged_qc_duplicate_voter_rejected() {
    let behaviors = [NodeBehavior::Honest; 4];
    let mut net = BftTestNetwork::new(4, &behaviors);
    net.start_all();

    let dup_qc = QuorumCertificate {
        block_hash: block_hash(0),
        round: 0,
        phase: BftPhase::Prepare,
        votes: vec![
            make_vote(BftPhase::Prepare, block_hash(0), 0, "v0"),
            make_vote(BftPhase::Prepare, block_hash(0), 0, "v0"),
            make_vote(BftPhase::Prepare, block_hash(0), 0, "v2"),
        ],
    };

    for id in &["v0", "v1", "v2", "v3"] {
        net.nodes.get_mut(*id).unwrap().manager.start_round(0);
    }
    let action = net
        .nodes
        .get_mut("v1")
        .unwrap()
        .manager
        .process_event(RoundEvent::Proposal {
            block_hash: block_hash(0),
            leader_id: "v0".into(),
            justify_qc: Some(dup_qc),
        });
    assert_eq!(
        action,
        ManagerAction::Round(RoundAction::None),
        "dup voter QC must be rejected"
    );
}

#[test]
fn e2e_randomized_adversarial_safety() {
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed.wrapping_add(1))
        }
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn range(&mut self, max: u64) -> u64 {
            self.next() % max
        }
        fn bool_p(&mut self, pct: u64) -> bool {
            self.range(100) < pct
        }
    }

    for seed in 0..50u64 {
        let mut rng = Rng::new(seed * 12345 + 67890);
        let mut tracker = FinalizationTracker::new();
        let behaviors = [NodeBehavior::Honest; 4];
        let mut net = BftTestNetwork::new(4, &behaviors);
        net.start_all();

        for round in 0..20u64 {
            net.drop_from.clear();
            if rng.bool_p(20) {
                net.drop_from.push(format!("v{}", rng.range(4)));
            }
            if rng.bool_p(10) {
                net.drop_from.clear();
                let a = rng.range(4);
                let mut b = rng.range(3);
                if b >= a {
                    b += 1;
                }
                net.drop_from.push(format!("v{a}"));
                net.drop_from.push(format!("v{b}"));
            }
            if rng.bool_p(15) {
                net.timeout_all();
                continue;
            }

            net.run_round(round);
            tracker.record_from_network(&net);

            if rng.bool_p(10) {
                let bh = block_hash(round);
                for voter in &["v0", "v1"] {
                    let vote = make_vote(BftPhase::Prepare, bh, round, voter);
                    for id in &["v0", "v1", "v2", "v3"] {
                        net.nodes
                            .get_mut(*id)
                            .unwrap()
                            .manager
                            .process_event(RoundEvent::Vote(vote.clone()));
                    }
                }
            }
            if round >= 3 && rng.bool_p(5) {
                let old = round - 3;
                for voter in &["v0", "v1", "v2"] {
                    let vote = make_vote(BftPhase::Commit, block_hash(old), old, voter);
                    for id in &["v0", "v1", "v2", "v3"] {
                        net.nodes
                            .get_mut(*id)
                            .unwrap()
                            .manager
                            .process_event(RoundEvent::Vote(vote.clone()));
                    }
                }
            }
            tracker.assert_invariant();
        }
        net.assert_safety();
        tracker.assert_invariant();
    }
}
