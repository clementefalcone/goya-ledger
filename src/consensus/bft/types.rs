//! Core BFT types: votes, quorum certificates, and related structures.

use serde::{Deserialize, Serialize};

/// HotStuff-inspired BFT phase.
///
/// Each round progresses through these phases sequentially.
/// A valid QC for phase N is required before advancing to phase N+1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BftPhase {
    /// Leader proposes a block; validators vote to prepare.
    Prepare,
    /// Validators confirm they have seen the prepare QC.
    PreCommit,
    /// Validators confirm the block is ready to finalize.
    Commit,
    /// Terminal: block is decided (QC from Commit phase).
    Decide,
}

impl BftPhase {
    /// Discriminant byte used in signing payloads for domain separation.
    pub fn as_byte(&self) -> u8 {
        match self {
            BftPhase::Prepare => 0,
            BftPhase::PreCommit => 1,
            BftPhase::Commit => 2,
            BftPhase::Decide => 3,
        }
    }
}

/// A validator's vote on a specific block in a given round and phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Hash of the block being voted on.
    pub block_hash: [u8; 32],
    /// BFT round number (view number in PBFT terminology).
    pub round: u64,
    /// HotStuff phase this vote belongs to.
    pub phase: BftPhase,
    /// Validator identity (e.g. DID or public key hex).
    pub voter_id: String,
    /// Cryptographic signature over `(phase || block_hash || round)`.
    /// Variable-length: Ed25519 = 64 bytes, ML-DSA-65 = 3309 bytes.
    pub signature: Vec<u8>,
}

/// Domain separator prefix for BFT vote signing payloads.
/// Prevents cross-protocol replay of signatures.
const VOTE_DOMAIN: &[u8] = b"GOYA-BFT-VOTE-V1";

const PROPOSAL_DOMAIN: &[u8] = b"GOYA-BFT-PROPOSAL-V1";

const TIMEOUT_DOMAIN: &[u8] = b"GOYA-BFT-TIMEOUT-V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub round: u64,
    pub voter_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutMessage {
    pub vote: TimeoutVote,
    pub high_qc: Option<QuorumCertificate>,
    pub round_certificate: Vec<TimeoutVote>,
}

pub fn timeout_signing_payload(round: u64, voter_id: &str) -> Vec<u8> {
    let voter_bytes = voter_id.as_bytes();
    let mut payload = Vec::with_capacity(TIMEOUT_DOMAIN.len() + 8 + 4 + voter_bytes.len());
    payload.extend_from_slice(TIMEOUT_DOMAIN);
    payload.extend_from_slice(&round.to_le_bytes());
    payload.extend_from_slice(&(voter_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(voter_bytes);
    payload
}

pub fn proposal_signing_payload(block_hash: &[u8; 32], round: u64, leader_id: &str) -> Vec<u8> {
    let leader_bytes = leader_id.as_bytes();
    let mut payload = Vec::with_capacity(PROPOSAL_DOMAIN.len() + 32 + 8 + 4 + leader_bytes.len());
    payload.extend_from_slice(PROPOSAL_DOMAIN);
    payload.extend_from_slice(block_hash);
    payload.extend_from_slice(&round.to_le_bytes());
    payload.extend_from_slice(&(leader_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(leader_bytes);
    payload
}

impl VoteMessage {
    /// Construct the canonical bytes that must be signed:
    /// `domain || phase_byte || block_hash || round_le || voter_id_len_le || voter_id`.
    ///
    /// Covers all vote fields to prevent:
    /// - Cross-phase replay (phase byte)
    /// - Cross-round replay (round)
    /// - Cross-voter replay (voter_id)
    /// - Cross-protocol replay (domain separator)
    pub fn signing_payload_v2(
        phase: BftPhase,
        block_hash: &[u8; 32],
        round: u64,
        voter_id: &str,
    ) -> Vec<u8> {
        let voter_bytes = voter_id.as_bytes();
        let mut payload =
            Vec::with_capacity(VOTE_DOMAIN.len() + 1 + 32 + 8 + 4 + voter_bytes.len());
        payload.extend_from_slice(VOTE_DOMAIN);
        payload.push(phase.as_byte());
        payload.extend_from_slice(block_hash);
        payload.extend_from_slice(&round.to_le_bytes());
        payload.extend_from_slice(&(voter_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(voter_bytes);
        payload
    }

    /// Legacy payload without voter_id/domain (kept for test compatibility).
    pub fn signing_payload(phase: BftPhase, block_hash: &[u8; 32], round: u64) -> Vec<u8> {
        // Delegate to v2 with empty voter_id for backward compat in tests
        // that use AcceptAllVerifier (signature content doesn't matter).
        let mut payload = Vec::with_capacity(41);
        payload.push(phase.as_byte());
        payload.extend_from_slice(block_hash);
        payload.extend_from_slice(&round.to_le_bytes());
        payload
    }

    /// Return the v2 signing payload for this vote (includes voter_id + domain).
    pub fn full_payload(&self) -> Vec<u8> {
        Self::signing_payload_v2(self.phase, &self.block_hash, self.round, &self.voter_id)
    }

    /// Return the legacy signing payload for this vote.
    pub fn payload(&self) -> Vec<u8> {
        Self::signing_payload(self.phase, &self.block_hash, self.round)
    }
}

/// Aggregated proof that a quorum of validators voted for a block.
///
/// A QC is valid when it contains >= `2f + 1` valid, distinct votes for
/// `(phase, block_hash, round)` where `f = (total_validators - 1) / 3`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Hash of the certified block.
    pub block_hash: [u8; 32],
    /// BFT round in which the certificate was formed.
    pub round: u64,
    /// HotStuff phase this QC certifies.
    pub phase: BftPhase,
    /// Individual votes that form the quorum.
    pub votes: Vec<VoteMessage>,
}

impl QuorumCertificate {
    /// Create a new (possibly incomplete) QC from a set of votes.
    ///
    /// All votes must reference the same `(phase, block_hash, round)`.
    /// Returns `Err` if votes are inconsistent.
    pub fn new(
        phase: BftPhase,
        block_hash: [u8; 32],
        round: u64,
        votes: Vec<VoteMessage>,
    ) -> Result<Self, QcError> {
        for vote in &votes {
            if vote.phase != phase {
                return Err(QcError::MismatchedPhase {
                    expected: phase,
                    got: vote.phase,
                });
            }
            if vote.block_hash != block_hash {
                return Err(QcError::MismatchedBlockHash {
                    expected: block_hash,
                    got: vote.block_hash,
                });
            }
            if vote.round != round {
                return Err(QcError::MismatchedRound {
                    expected: round,
                    got: vote.round,
                });
            }
        }
        Ok(Self {
            block_hash,
            round,
            phase,
            votes,
        })
    }

    /// Number of distinct voters in this QC.
    pub fn voter_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for v in &self.votes {
            seen.insert(&v.voter_id);
        }
        seen.len()
    }
}

/// Errors when constructing or validating a [`QuorumCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QcError {
    #[error("vote phase mismatch: expected {expected:?}, got {got:?}")]
    MismatchedPhase { expected: BftPhase, got: BftPhase },
    #[error("vote block_hash mismatch: expected {expected:?}, got {got:?}")]
    MismatchedBlockHash { expected: [u8; 32], got: [u8; 32] },
    #[error("vote round mismatch: expected {expected}, got {got}")]
    MismatchedRound { expected: u64, got: u64 },
    #[error("insufficient votes: need {needed}, have {have}")]
    InsufficientVotes { needed: usize, have: usize },
    #[error("duplicate voter: {0}")]
    DuplicateVoter(String),
    #[error("unknown voter: {0}")]
    UnknownVoter(String),
    #[error("invalid signature from voter: {0}")]
    InvalidSignature(String),
    #[error("insufficient validators for BFT: need >= {min}, have {have}")]
    InsufficientValidators { min: usize, have: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(hash_id: u8, round: u64, voter: &str) -> VoteMessage {
        vote_phase(BftPhase::Prepare, hash_id, round, voter)
    }

    fn vote_phase(phase: BftPhase, hash_id: u8, round: u64, voter: &str) -> VoteMessage {
        let mut block_hash = [0u8; 32];
        block_hash[0] = hash_id;
        VoteMessage {
            block_hash,
            round,
            phase,
            voter_id: voter.to_string(),
            signature: vec![1u8; 64],
        }
    }

    fn block_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    // --- signing payload ---

    #[test]
    fn signing_payload_deterministic() {
        let p1 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(1), 5);
        let p2 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(1), 5);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 41); // 1 + 32 + 8
    }

    #[test]
    fn signing_payload_differs_by_round() {
        let p1 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(1), 1);
        let p2 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(1), 2);
        assert_ne!(p1, p2);
    }

    #[test]
    fn signing_payload_differs_by_hash() {
        let p1 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(1), 1);
        let p2 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(2), 1);
        assert_ne!(p1, p2);
    }

    #[test]
    fn signing_payload_differs_by_phase() {
        let p1 = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(1), 1);
        let p2 = VoteMessage::signing_payload(BftPhase::Commit, &block_hash(1), 1);
        assert_ne!(p1, p2);
    }

    #[test]
    fn vote_payload_matches_static() {
        let v = vote(3, 7, "alice");
        let expected = VoteMessage::signing_payload(BftPhase::Prepare, &block_hash(3), 7);
        assert_eq!(v.payload(), expected);
    }

    // --- QC construction ---

    #[test]
    fn qc_new_accepts_consistent_votes() {
        let votes = vec![vote(1, 0, "alice"), vote(1, 0, "bob"), vote(1, 0, "carol")];
        let qc = QuorumCertificate::new(BftPhase::Prepare, block_hash(1), 0, votes).unwrap();
        assert_eq!(qc.voter_count(), 3);
        assert_eq!(qc.phase, BftPhase::Prepare);
    }

    #[test]
    fn qc_new_rejects_mismatched_block_hash() {
        let votes = vec![vote(1, 0, "alice"), vote(2, 0, "bob")];
        let result = QuorumCertificate::new(BftPhase::Prepare, block_hash(1), 0, votes);
        assert!(matches!(result, Err(QcError::MismatchedBlockHash { .. })));
    }

    #[test]
    fn qc_new_rejects_mismatched_round() {
        let votes = vec![vote(1, 0, "alice"), vote(1, 1, "bob")];
        let result = QuorumCertificate::new(BftPhase::Prepare, block_hash(1), 0, votes);
        assert!(matches!(result, Err(QcError::MismatchedRound { .. })));
    }

    #[test]
    fn qc_new_rejects_mismatched_phase() {
        let votes = vec![
            vote_phase(BftPhase::Prepare, 1, 0, "alice"),
            vote_phase(BftPhase::Commit, 1, 0, "bob"),
        ];
        let result = QuorumCertificate::new(BftPhase::Prepare, block_hash(1), 0, votes);
        assert!(matches!(result, Err(QcError::MismatchedPhase { .. })));
    }

    #[test]
    fn qc_new_accepts_empty_votes() {
        let qc = QuorumCertificate::new(BftPhase::Prepare, block_hash(1), 0, vec![]).unwrap();
        assert_eq!(qc.voter_count(), 0);
    }

    #[test]
    fn qc_voter_count_deduplicates() {
        let votes = vec![
            vote(1, 0, "alice"),
            vote(1, 0, "alice"), // duplicate
            vote(1, 0, "bob"),
        ];
        let qc = QuorumCertificate::new(BftPhase::Prepare, block_hash(1), 0, votes).unwrap();
        assert_eq!(qc.voter_count(), 2);
    }

    // --- BftPhase domain separation ---

    #[test]
    fn phase_bytes_are_distinct() {
        let phases = [
            BftPhase::Prepare,
            BftPhase::PreCommit,
            BftPhase::Commit,
            BftPhase::Decide,
        ];
        let bytes: Vec<u8> = phases.iter().map(|p| p.as_byte()).collect();
        let unique: std::collections::HashSet<u8> = bytes.iter().copied().collect();
        assert_eq!(unique.len(), 4, "all phase bytes must be distinct");
    }
}
