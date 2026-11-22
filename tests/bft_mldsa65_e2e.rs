//! End-to-end BFT validation with REAL ML-DSA-65 signatures.
//!
//! No mocks. No AcceptAllVerifier. Every vote is signed with a real
//! ML-DSA-65 private key and verified against the registered public key.
//!
//! Proves: a decided block depends exclusively on real cryptographic
//! signatures and HotStuff safety rules.

use std::collections::HashMap;
use std::sync::Arc;

use rust_bc::consensus::bft::quorum::{QuorumValidator, SignatureVerifier};
use rust_bc::consensus::bft::round::{RoundEvent, RoundState};
use rust_bc::consensus::bft::round_manager::{RoundManager, RoundManagerConfig};
use rust_bc::consensus::bft::types::{BftPhase, QcError, QuorumCertificate, VoteMessage};
use rust_bc::consensus::bft::validator_registry::{RegistryVerifier, ValidatorRegistry};
use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider};

// ── Test infrastructure ─────────────────────────────────────────────────────

struct Validator {
    id: String,
    pk: Vec<u8>,
    signer: MlDsaSigningProvider,
}

impl Validator {
    fn generate(id: &str) -> Self {
        let signer = MlDsaSigningProvider::generate();
        let pk = signer.public_key();
        Self {
            id: id.to_string(),
            pk,
            signer,
        }
    }

    fn sign_vote(&self, phase: BftPhase, block_hash: &[u8; 32], round: u64) -> VoteMessage {
        let payload = VoteMessage::signing_payload_v2(phase, block_hash, round, &self.id);
        let sig = self.signer.sign(&payload).unwrap();
        VoteMessage {
            block_hash: *block_hash,
            round,
            phase,
            voter_id: self.id.clone(),
            signature: sig,
        }
    }
}

struct TestNet {
    validators: Vec<Validator>,
    #[allow(dead_code)]
    registry: Arc<ValidatorRegistry>,
    verifier: RegistryVerifier,
    managers: HashMap<String, RoundManager<RegistryVerifier>>,
}

impl TestNet {
    fn new() -> Self {
        let validators: Vec<Validator> = ["node-iad", "node-cdg", "node-nrt", "node-sin"]
            .iter()
            .map(|id| Validator::generate(id))
            .collect();

        let reg_map: HashMap<String, Vec<u8>> = validators
            .iter()
            .map(|v| (v.id.clone(), v.pk.clone()))
            .collect();
        let registry = Arc::new(ValidatorRegistry::from_map(reg_map));
        let verifier = RegistryVerifier::new(registry.clone());

        let ids: Vec<String> = validators.iter().map(|v| v.id.clone()).collect();
        let config = RoundManagerConfig {
            base_timeout_ms: 100,
            max_timeout_ms: 1000,
        };

        let mut managers = HashMap::new();
        for v in &validators {
            let m = RoundManager::new(v.id.clone(), ids.clone(), verifier.clone(), config.clone());
            managers.insert(v.id.clone(), m);
        }

        Self {
            validators,
            registry,
            verifier,
            managers,
        }
    }

    fn block_hash(round: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&round.to_le_bytes());
        h
    }

    fn leader(&self, round: u64) -> &str {
        let idx = (round as usize) % self.validators.len();
        &self.validators[idx].id
    }

    fn validator(&self, id: &str) -> &Validator {
        self.validators.iter().find(|v| v.id == id).unwrap()
    }

    /// Run a full round with real signatures. Returns (decided_count, block_hash).
    fn run_round(&mut self, round: u64, skip: &[&str]) -> (usize, [u8; 32]) {
        let bh = Self::block_hash(round);
        let leader_id = self.leader(round).to_string();

        // Start round on all active nodes.
        let ids: Vec<String> = self.managers.keys().cloned().collect();
        for id in &ids {
            if skip.contains(&id.as_str()) {
                continue;
            }
            self.managers.get_mut(id).unwrap().start_round(round);
        }

        // Leader proposes.
        if !skip.contains(&leader_id.as_str()) {
            let high_qc = self
                .managers
                .get(&leader_id)
                .unwrap()
                .safety()
                .high_qc()
                .cloned();
            self.managers
                .get_mut(&leader_id)
                .unwrap()
                .process_event(RoundEvent::StartAsLeader { block_hash: bh });

            // Leader votes Prepare (self-vote).
            let leader_vote = self
                .validator(&leader_id)
                .sign_vote(BftPhase::Prepare, &bh, round);
            self.managers
                .get_mut(&leader_id)
                .unwrap()
                .process_event(RoundEvent::Vote(leader_vote.clone()));

            // Followers receive proposal + leader's Prepare vote.
            for id in &ids {
                if *id == leader_id || skip.contains(&id.as_str()) {
                    continue;
                }
                self.managers
                    .get_mut(id)
                    .unwrap()
                    .process_event(RoundEvent::Proposal {
                        block_hash: bh,
                        leader_id: leader_id.clone(),
                        justify_qc: high_qc.clone(),
                    });
                self.managers
                    .get_mut(id)
                    .unwrap()
                    .process_event(RoundEvent::Vote(leader_vote.clone()));
            }
        }

        // Collect and broadcast votes for each phase.
        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            let mut votes: Vec<VoteMessage> = Vec::new();
            for v in &self.validators {
                if skip.contains(&v.id.as_str()) {
                    continue;
                }
                votes.push(v.sign_vote(phase, &bh, round));
            }
            for vote in &votes {
                for id in &ids {
                    if skip.contains(&id.as_str()) {
                        continue;
                    }
                    self.managers
                        .get_mut(id)
                        .unwrap()
                        .process_event(RoundEvent::Vote(vote.clone()));
                }
            }
        }

        let decided = ids
            .iter()
            .filter(|id| !skip.contains(&id.as_str()))
            .filter(|id| self.managers[id.as_str()].round_state() == Some(RoundState::Decided))
            .count();

        (decided, bh)
    }

    fn assert_all_same_commit(&self, skip: &[&str]) {
        let mut commits: Vec<(&str, &QuorumCertificate)> = Vec::new();
        for (id, m) in &self.managers {
            if skip.contains(&id.as_str()) {
                continue;
            }
            if let Some(qc) = m.highest_commit_qc() {
                commits.push((id.as_str(), qc));
            }
        }
        if commits.len() < 2 {
            return;
        }
        let (ref_id, ref_qc) = commits[0];
        for &(id, qc) in &commits[1..] {
            assert_eq!(
                ref_qc.block_hash,
                qc.block_hash,
                "FORK: {ref_id} committed {:?} but {id} committed {:?}",
                hex::encode(ref_qc.block_hash),
                hex::encode(qc.block_hash)
            );
            assert_eq!(ref_qc.round, qc.round);
        }
    }
}

/// Full QC validation: header/vote consistency + crypto (mirrors validate_received_qc).
fn validate_qc_full(
    qc: &QuorumCertificate,
    ids: &[String],
    verifier: &RegistryVerifier,
) -> Result<(), QcError> {
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
    let qv = QuorumValidator::new(ids.to_vec(), verifier.clone());
    qv.validate_qc(qc)
}

// ════════════════════════════════════════════════════════════════════════════
// Scenario 1: 4 validators, full consensus with real ML-DSA-65
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn s1_full_consensus_4_validators_real_mldsa65() {
    let mut net = TestNet::new();
    let (decided, bh) = net.run_round(0, &[]);
    assert_eq!(decided, 4, "all 4 validators should decide");

    // Verify CommitQC has 3+ real signatures.
    let qc = net.managers["node-iad"].highest_commit_qc().unwrap();
    assert_eq!(qc.block_hash, bh);
    assert_eq!(qc.round, 0);
    assert_eq!(qc.phase, BftPhase::Commit);
    assert!(qc.votes.len() >= 3, "QC should have >= 3 votes");

    // Verify each signature individually.
    for vote in &qc.votes {
        let payload = vote.full_payload();
        assert!(
            net.verifier
                .verify(&vote.voter_id, &payload, &vote.signature),
            "signature from {} must verify",
            vote.voter_id
        );
    }

    // Verify via QuorumValidator.
    let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
    let qv = QuorumValidator::new(ids, net.verifier.clone());
    assert!(qv.validate_qc(qc).is_ok(), "QC must pass full validation");

    net.assert_all_same_commit(&[]);

    println!("=== Scenario 1: Full Consensus ===");
    println!("  height/round: 0");
    println!("  block_hash:   {}", hex::encode(bh));
    println!("  QC phase:     {:?}", qc.phase);
    println!(
        "  QC voters:    {}",
        qc.votes
            .iter()
            .map(|v| v.voter_id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  Signatures verified: {}/{}",
        qc.votes.len(),
        qc.votes.len()
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Scenario 2: Tamper tests — modify any field → QC invalid
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn s2_tamper_signature_byte_invalidates_qc() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);
    let qc = net.managers["node-iad"]
        .highest_commit_qc()
        .unwrap()
        .clone();

    let mut tampered = qc.clone();
    tampered.votes[0].signature[100] ^= 0xFF;

    let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
    assert!(
        validate_qc_full(&tampered, &ids, &net.verifier).is_err(),
        "1-byte flip must invalidate QC"
    );
}

#[test]
fn s2_tamper_block_hash_invalidates_qc() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);
    let qc = net.managers["node-iad"]
        .highest_commit_qc()
        .unwrap()
        .clone();

    let mut tampered = qc.clone();
    tampered.block_hash[0] ^= 0xFF;

    let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
    assert!(
        validate_qc_full(&tampered, &ids, &net.verifier).is_err(),
        "modified block_hash must invalidate"
    );
}

#[test]
fn s2_tamper_round_invalidates_qc() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);
    let qc = net.managers["node-iad"]
        .highest_commit_qc()
        .unwrap()
        .clone();

    let mut tampered = qc.clone();
    tampered.round = 999;

    let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
    assert!(
        validate_qc_full(&tampered, &ids, &net.verifier).is_err(),
        "modified round must invalidate"
    );
}

#[test]
fn s2_tamper_phase_invalidates_qc() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);
    let qc = net.managers["node-iad"]
        .highest_commit_qc()
        .unwrap()
        .clone();

    let mut tampered = qc.clone();
    tampered.phase = BftPhase::Prepare;

    let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
    assert!(
        validate_qc_full(&tampered, &ids, &net.verifier).is_err(),
        "modified phase must invalidate"
    );
}

#[test]
fn s2_tamper_voter_id_invalidates_qc() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);
    let qc = net.managers["node-iad"]
        .highest_commit_qc()
        .unwrap()
        .clone();

    let mut tampered = qc.clone();
    tampered.votes[0].voter_id = "fake-node".to_string();

    let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
    assert!(
        validate_qc_full(&tampered, &ids, &net.verifier).is_err(),
        "modified voter_id must invalidate"
    );
}

#[test]
fn s2_swap_signature_between_validators_invalidates_qc() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);
    let qc = net.managers["node-iad"]
        .highest_commit_qc()
        .unwrap()
        .clone();

    if qc.votes.len() >= 2 {
        let mut tampered = qc.clone();
        let sig_0 = tampered.votes[0].signature.clone();
        tampered.votes[0].signature = tampered.votes[1].signature.clone();
        tampered.votes[1].signature = sig_0;

        let ids: Vec<String> = net.validators.iter().map(|v| v.id.clone()).collect();
        assert!(
            validate_qc_full(&tampered, &ids, &net.verifier).is_err(),
            "swapped signatures must invalidate"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Scenario 3: 1 validator offline, quorum 3/4
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn s3_one_offline_still_decides() {
    let mut net = TestNet::new();
    let (decided, bh) = net.run_round(0, &["node-nrt"]);
    assert!(
        decided >= 3,
        "3 validators should decide with NRT offline, got {decided}"
    );

    let qc = net.managers["node-iad"].highest_commit_qc().unwrap();
    assert_eq!(qc.block_hash, bh);

    // NRT must NOT be in the QC.
    let voters: Vec<&str> = qc.votes.iter().map(|v| v.voter_id.as_str()).collect();
    assert!(
        !voters.contains(&"node-nrt"),
        "offline node must not be in QC"
    );
    assert!(voters.len() >= 3);

    // Verify all signatures are real.
    for vote in &qc.votes {
        let payload = vote.full_payload();
        assert!(net
            .verifier
            .verify(&vote.voter_id, &payload, &vote.signature));
    }

    net.assert_all_same_commit(&["node-nrt"]);

    println!("=== Scenario 3: 1 Offline ===");
    println!("  QC voters: {:?}", voters);
    println!("  node-nrt: OFFLINE (not in QC)");
}

// ════════════════════════════════════════════════════════════════════════════
// Scenario 4: View change — lock, leader death, recovery, delayed msgs
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn s4_viewchange_lock_recovery_no_fork() {
    let mut net = TestNet::new();
    let bh_a = TestNet::block_hash(0);

    // Round 0: Prepare + PreCommit for A → lock.
    let ids: Vec<String> = net.managers.keys().cloned().collect();
    for id in &ids {
        net.managers.get_mut(id).unwrap().start_round(0);
    }

    // Leader proposes.
    net.managers
        .get_mut("node-iad")
        .unwrap()
        .process_event(RoundEvent::StartAsLeader { block_hash: bh_a });
    for id in &["node-cdg", "node-nrt", "node-sin"] {
        net.managers
            .get_mut(*id)
            .unwrap()
            .process_event(RoundEvent::Proposal {
                block_hash: bh_a,
                leader_id: "node-iad".into(),
                justify_qc: None,
            });
    }

    // Prepare + PreCommit votes (all 4).
    for phase in [BftPhase::Prepare, BftPhase::PreCommit] {
        let votes: Vec<VoteMessage> = net
            .validators
            .iter()
            .map(|v| v.sign_vote(phase, &bh_a, 0))
            .collect();
        for vote in &votes {
            for id in &ids {
                net.managers
                    .get_mut(id)
                    .unwrap()
                    .process_event(RoundEvent::Vote(vote.clone()));
            }
        }
    }

    // Verify lock.
    for id in &ids {
        let lock = net.managers[id.as_str()].safety().locked_qc();
        assert!(lock.is_some(), "{id} should be locked");
        assert_eq!(lock.unwrap().block_hash, bh_a);
    }

    // Leader "dies" — no Commit votes. Timeout.
    for id in &ids {
        {
            let manager = net.managers.get_mut(id).unwrap();
            manager.jump_to_round(manager.current_round() + 1)
        };
    }

    // Round 1: new leader (node-sin, idx 1) proposes B.
    let (decided, bh_b) = net.run_round(1, &[]);
    assert!(decided >= 3, "round 1 should decide, got {decided}");

    // Deliver delayed Commit votes from round 0.
    let delayed: Vec<VoteMessage> = net
        .validators
        .iter()
        .take(3)
        .map(|v| v.sign_vote(BftPhase::Commit, &bh_a, 0))
        .collect();
    for vote in &delayed {
        for id in &ids {
            net.managers
                .get_mut(id)
                .unwrap()
                .process_event(RoundEvent::Vote(vote.clone()));
        }
    }

    // Verify: B is committed, not A.
    net.assert_all_same_commit(&[]);
    let qc = net.managers["node-iad"].highest_commit_qc().unwrap();
    assert_eq!(qc.block_hash, bh_b, "B should be committed, not A");
    assert_eq!(qc.round, 1);

    println!("=== Scenario 4: View Change ===");
    println!("  Round 0: locked on A={}", hex::encode(bh_a));
    println!("  Round 1: decided B={}", hex::encode(bh_b));
    println!("  Delayed A messages: ignored (no fork)");
}

// ════════════════════════════════════════════════════════════════════════════
// Scenario 5: All nodes agree — same height, hash, parent, QC
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn s5_all_nodes_converge() {
    let mut net = TestNet::new();
    net.run_round(0, &[]);

    let mut qcs: Vec<(&str, QuorumCertificate)> = Vec::new();
    for (id, m) in &net.managers {
        let qc = m.highest_commit_qc().unwrap().clone();
        qcs.push((id.as_str(), qc));
    }

    let (_, ref_qc) = &qcs[0];
    for (id, qc) in &qcs[1..] {
        assert_eq!(
            ref_qc.block_hash, qc.block_hash,
            "{id} has different block_hash"
        );
        assert_eq!(ref_qc.round, qc.round, "{id} has different round");
        assert_eq!(ref_qc.phase, qc.phase, "{id} has different phase");
        assert_eq!(
            ref_qc.votes.len(),
            qc.votes.len(),
            "{id} has different vote count"
        );
    }

    println!("=== Scenario 5: Convergence ===");
    println!("  All 4 nodes: same block_hash, round, phase, QC");
}

// ════════════════════════════════════════════════════════════════════════════
// Scenario 6: Multi-round stress with real crypto
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn s6_multi_round_real_crypto() {
    let mut net = TestNet::new();
    for round in 0..10u64 {
        let (decided, _) = net.run_round(round, &[]);
        assert!(
            decided >= 3,
            "round {round}: expected >=3 decided, got {decided}"
        );
        net.assert_all_same_commit(&[]);
    }
    println!("=== Scenario 6: 10 rounds, all with real ML-DSA-65 ===");
}
