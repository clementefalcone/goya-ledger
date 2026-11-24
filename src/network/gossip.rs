use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::identity::signing::SigningAlgorithm;
use serde::{Deserialize, Serialize};

/// Serde helper for variable-length signature bytes — serializes as a hex string.
mod signature_hex {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Alive message broadcast periodically by each peer to signal liveness.
///
/// Based on Hyperledger Fabric's gossip protocol: peers exchange alive
/// messages so that the membership view stays current. A peer that stops
/// sending alive messages is marked as suspect after a configurable timeout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AliveMessage {
    /// Network address of the peer (`host:port`).
    pub peer_address: String,
    /// Organization the peer belongs to.
    pub org_id: String,
    /// Unix timestamp (seconds) when this message was created.
    pub timestamp: u64,
    /// Monotonically increasing sequence number (per peer).
    pub sequence: u64,
    /// Signature bytes (variable-length: Ed25519 = 64, ML-DSA-65 = 3309).
    #[serde(with = "signature_hex")]
    pub signature: Vec<u8>,
    /// Cryptographic algorithm used for this alive message signature.
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Latest block height known by this peer (used for anti-entropy gap detection).
    #[serde(default)]
    pub latest_height: u64,
}

impl AliveMessage {
    #[allow(dead_code)]
    /// Create a new alive message.
    ///
    /// `signature` should be produced by signing the canonical payload
    /// (`peer_address || org_id || timestamp || sequence`) with the peer's
    /// private key. For now this is left to the caller.
    pub fn new(
        peer_address: impl Into<String>,
        org_id: impl Into<String>,
        timestamp: u64,
        sequence: u64,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            peer_address: peer_address.into(),
            org_id: org_id.into(),
            timestamp,
            sequence,
            signature,
            signature_algorithm: SigningAlgorithm::default(),
            latest_height: 0,
        }
    }

    #[allow(dead_code)]
    /// Create an alive message that includes the peer's latest block height.
    pub fn with_height(
        peer_address: impl Into<String>,
        org_id: impl Into<String>,
        timestamp: u64,
        sequence: u64,
        signature: Vec<u8>,
        latest_height: u64,
    ) -> Self {
        Self {
            peer_address: peer_address.into(),
            org_id: org_id.into(),
            timestamp,
            sequence,
            signature,
            signature_algorithm: SigningAlgorithm::default(),
            latest_height,
        }
    }

    #[allow(dead_code)]
    /// Verify the signature against the provided public key bytes (Ed25519).
    ///
    /// Returns `true` when the signature matches. The canonical message that
    /// was signed is `"{peer_address}:{org_id}:{timestamp}:{sequence}"`.
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> bool {
        use pqc_crypto_module::legacy::ed25519::{Signature, Verifier, VerifyingKey};

        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let payload = self.signable_payload();
        let Ok(sig) = Signature::try_from(self.signature.as_slice()) else {
            return false;
        };
        verifying_key.verify(payload.as_bytes(), &sig).is_ok()
    }

    /// Canonical byte string used for signing / verification.
    pub fn signable_payload(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.peer_address, self.org_id, self.timestamp, self.sequence, self.latest_height
        )
    }
}

/// An anchor peer serves as a cross-organization entry point for gossip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorPeer {
    /// Network address of the anchor peer (`host:port`).
    pub peer_address: String,
    /// Organization the anchor peer belongs to.
    pub org_id: String,
}

impl AnchorPeer {
    pub fn new(peer_address: impl Into<String>, org_id: impl Into<String>) -> Self {
        Self {
            peer_address: peer_address.into(),
            org_id: org_id.into(),
        }
    }
}

/// Parse the `ANCHOR_PEERS` environment variable.
///
/// Format: comma-separated `org_id:address` pairs.
/// Example: `org1:10.0.0.1:7051,org2:10.0.0.2:7051`
///
/// The first colon separates org_id from address; the address may itself
/// contain colons (e.g. `host:port`).
pub fn parse_anchor_peers(env_value: &str) -> Vec<AnchorPeer> {
    let mut peers = Vec::new();
    for token in env_value.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        // Split on first colon only: org_id:address (address may contain ':')
        if let Some(idx) = t.find(':') {
            let org_id = &t[..idx];
            let address = &t[idx + 1..];
            if !org_id.is_empty() && !address.is_empty() {
                peers.push(AnchorPeer::new(address, org_id));
            }
        }
    }
    peers
}

#[allow(dead_code)]
/// Convert a `ChannelConfig`-style anchor peers map (`org_id → Vec<address>`)
/// into a flat list of [`AnchorPeer`].
pub fn anchor_peers_from_config(map: &HashMap<String, Vec<String>>) -> Vec<AnchorPeer> {
    let mut out = Vec::new();
    for (org_id, addrs) in map {
        for addr in addrs {
            out.push(AnchorPeer::new(addr, org_id));
        }
    }
    out
}

/// Leader election mode for peers within the same organization.
///
/// In `Static` mode the leader is predetermined (e.g. the first anchor peer).
/// In `Dynamic` mode the leader is elected deterministically: the alive peer
/// with the lexicographically smallest `peer_address` becomes the leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaderElectionMode {
    Static,
    Dynamic,
}

impl LeaderElectionMode {
    #[allow(dead_code)]
    /// Parse the `LEADER_ELECTION` env var. Defaults to `Static`.
    pub fn from_env() -> Self {
        match std::env::var("LEADER_ELECTION")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "dynamic" => Self::Dynamic,
            _ => Self::Static,
        }
    }
}

#[allow(dead_code)]
/// Default interval (ms) between alive broadcasts.
pub const ALIVE_INTERVAL_MS: u64 = 5000;

/// Default timeout (ms) after which a peer with no alive is marked suspect.
pub const ALIVE_TIMEOUT_MS: u64 = 15000;

/// Default interval (ms) between pull-sync rounds.
pub const PULL_INTERVAL_MS: u64 = 10000;

/// Maximum number of blocks returned in a single `StateResponse`.
pub const STATE_BATCH_SIZE: usize = 50;

pub const STATE_RESPONSE_BYTE_BUDGET: usize = 4 * 1024 * 1024;

/// Liveness status of a peer in the membership table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Alive,
    #[allow(dead_code)]
    Suspect,
}

/// Per-peer liveness record.
#[derive(Debug, Clone)]
pub struct PeerLiveness {
    pub status: PeerStatus,
    /// Organization this peer belongs to.
    pub org_id: String,
    /// Last alive sequence number seen from this peer.
    pub last_sequence: u64,
    /// Instant (ms since an arbitrary epoch) when the last alive was received.
    pub last_seen_ms: u64,
    /// Latest block height reported by this peer.
    pub latest_height: u64,
}

/// Default maximum number of tracked peers (prevents Sybil resource exhaustion).
pub const DEFAULT_MAX_PEERS: usize = 500;

/// Thread-safe membership table that tracks peer liveness.
#[derive(Debug, Clone)]
pub struct MembershipTable {
    inner: Arc<Mutex<HashMap<String, PeerLiveness>>>,
    #[allow(dead_code)]
    /// Timeout in ms before a silent peer is marked suspect.
    pub timeout_ms: u64,
    /// Maximum peers to track. New peers are rejected when at capacity.
    pub max_peers: usize,
}

impl MembershipTable {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            timeout_ms,
            max_peers: DEFAULT_MAX_PEERS,
        }
    }

    #[allow(dead_code)]
    /// Create a membership table with a custom peer capacity.
    pub fn with_capacity(timeout_ms: u64, max_peers: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            timeout_ms,
            max_peers,
        }
    }

    #[allow(dead_code)]
    /// Record an alive message from a peer, updating or inserting its entry.
    /// `now_ms` is the current timestamp in the same epoch used for timeout checks.
    pub fn record_alive(&self, peer_address: &str, sequence: u64, now_ms: u64) {
        self.record_alive_full(peer_address, "", sequence, now_ms, 0);
    }

    #[allow(dead_code)]
    /// Record an alive message that includes the peer's latest block height.
    pub fn record_alive_with_height(
        &self,
        peer_address: &str,
        sequence: u64,
        now_ms: u64,
        latest_height: u64,
    ) {
        self.record_alive_full(peer_address, "", sequence, now_ms, latest_height);
    }

    /// Full alive record including org_id, height, and sequence.
    ///
    /// Returns `false` if the table is at capacity and the peer is unknown
    /// (Sybil protection). Existing peers are always updated.
    pub fn record_alive_full(
        &self,
        peer_address: &str,
        org_id: &str,
        sequence: u64,
        now_ms: u64,
        latest_height: u64,
    ) -> bool {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Reject new peers when at capacity (Sybil protection)
        if !table.contains_key(peer_address) && table.len() >= self.max_peers {
            return false;
        }

        let entry = table
            .entry(peer_address.to_string())
            .or_insert(PeerLiveness {
                status: PeerStatus::Alive,
                org_id: org_id.to_string(),
                last_sequence: 0,
                last_seen_ms: now_ms,
                latest_height: 0,
            });
        if sequence >= entry.last_sequence {
            entry.last_sequence = sequence;
            entry.last_seen_ms = now_ms;
            entry.status = PeerStatus::Alive;
            entry.latest_height = latest_height;
            if !org_id.is_empty() {
                entry.org_id = org_id.to_string();
            }
        }
        true
    }

    #[allow(dead_code)]
    /// Elect the leader for a given org using dynamic election.
    ///
    /// The leader is the alive peer with the lexicographically smallest
    /// `peer_address` within the org. Returns `None` if no alive peer exists.
    pub fn elect_leader(&self, org_id: &str) -> Option<String> {
        let table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table
            .iter()
            .filter(|(_, e)| e.status == PeerStatus::Alive && e.org_id == org_id)
            .map(|(addr, _)| addr.clone())
            .min()
    }

    #[allow(dead_code)]
    /// Return peers whose reported `latest_height` exceeds `local_height`.
    /// These are candidates for pull-sync.
    pub fn peers_ahead_of(&self, local_height: u64) -> Vec<String> {
        let table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table
            .iter()
            .filter(|(_, e)| e.status == PeerStatus::Alive && e.latest_height > local_height)
            .map(|(addr, _)| addr.clone())
            .collect()
    }

    /// Sweep all peers: any peer whose `last_seen_ms + timeout_ms < now_ms`
    /// is marked `Suspect`. Returns the list of newly suspected peer addresses.
    pub fn sweep_suspects(&self, now_ms: u64) -> Vec<String> {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut newly_suspect = Vec::new();
        for (addr, entry) in table.iter_mut() {
            if entry.status == PeerStatus::Alive
                && now_ms.saturating_sub(entry.last_seen_ms) >= self.timeout_ms
            {
                entry.status = PeerStatus::Suspect;
                newly_suspect.push(addr.clone());
            }
        }
        newly_suspect
    }

    #[allow(dead_code)]
    /// Get the current status of a peer, if known.
    pub fn status(&self, peer_address: &str) -> Option<PeerStatus> {
        let table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table.get(peer_address).map(|e| e.status)
    }

    #[allow(dead_code)]
    /// Remove a peer from the membership table entirely.
    pub fn remove(&self, peer_address: &str) {
        let mut table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table.remove(peer_address);
    }

    #[allow(dead_code)]
    /// Return all known peers and their status.
    pub fn all_peers(&self) -> Vec<(String, PeerStatus)> {
        let table = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        table.iter().map(|(k, v)| (k.clone(), v.status)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_alive_message() {
        let sig = vec![0u8; 64];
        let msg = AliveMessage::new("127.0.0.1:8081", "org1", 1_700_000_000, 1, sig);

        assert_eq!(msg.peer_address, "127.0.0.1:8081");
        assert_eq!(msg.org_id, "org1");
        assert_eq!(msg.timestamp, 1_700_000_000);
        assert_eq!(msg.sequence, 1);
        assert_eq!(msg.signature, vec![0u8; 64]);
    }

    #[test]
    fn serde_roundtrip() {
        let sig = vec![42u8; 64];
        let original = AliveMessage::new("10.0.0.1:7051", "org2", 1_700_000_001, 5, sig);

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: AliveMessage = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn verify_signature_with_valid_key() {
        use pqc_crypto_module::legacy::ed25519::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();

        let mut msg = AliveMessage::new("127.0.0.1:8081", "org1", 1_700_000_000, 1, vec![0u8; 64]);
        let payload = msg.signable_payload();
        let sig = signing_key.sign(payload.as_bytes());
        msg.signature = sig.to_bytes().to_vec();

        assert!(msg.verify_signature(&public_key));
    }

    #[test]
    fn verify_signature_rejects_wrong_key() {
        use pqc_crypto_module::legacy::ed25519::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[2u8; 32]);

        let mut msg = AliveMessage::new("127.0.0.1:8081", "org1", 1_700_000_000, 1, vec![0u8; 64]);
        let payload = msg.signable_payload();
        let sig = signing_key.sign(payload.as_bytes());
        msg.signature = sig.to_bytes().to_vec();

        assert!(!msg.verify_signature(&wrong_key.verifying_key().to_bytes()));
    }

    #[test]
    fn message_alive_serde_roundtrip() {
        use crate::network::Message;

        let sig = vec![7u8; 64];
        let alive = AliveMessage::new("10.0.0.5:7051", "org3", 1_700_000_100, 42, sig);
        let msg = Message::Alive(alive.clone());

        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: Message = serde_json::from_str(&json).expect("deserialize");

        if let Message::Alive(decoded_alive) = decoded {
            assert_eq!(decoded_alive, alive);
        } else {
            panic!("expected Message::Alive variant");
        }
    }

    #[test]
    fn three_nodes_suspect_after_timeout() {
        // Nodes A, B, C — all send alive at t=0.
        // A and B keep sending; C stops.
        // After ALIVE_TIMEOUT_MS, sweep marks C as suspect on both A's and B's tables.

        let timeout = ALIVE_TIMEOUT_MS;
        let table_a = MembershipTable::new(timeout);
        let table_b = MembershipTable::new(timeout);

        let t0 = 0u64;

        // All three peers register alive at t=0
        for table in [&table_a, &table_b] {
            table.record_alive("A", 1, t0);
            table.record_alive("B", 1, t0);
            table.record_alive("C", 1, t0);
        }

        // At t=5000, A and B send alive again, C does not
        let t1 = 5000;
        for table in [&table_a, &table_b] {
            table.record_alive("A", 2, t1);
            table.record_alive("B", 2, t1);
            // C: no alive
        }

        // At t=10000, A and B again, C still silent
        let t2 = 10000;
        for table in [&table_a, &table_b] {
            table.record_alive("A", 3, t2);
            table.record_alive("B", 3, t2);
        }

        // Sweep at t=14999 — C last seen at t=0, delta=14999 < 15000 → still alive
        let suspects_a = table_a.sweep_suspects(14999);
        assert!(suspects_a.is_empty());

        // Sweep at t=15000 — C last seen at t=0, delta=15000 >= 15000 → suspect
        let suspects_a = table_a.sweep_suspects(15000);
        assert_eq!(suspects_a, vec!["C"]);
        assert_eq!(table_a.status("C"), Some(PeerStatus::Suspect));
        assert_eq!(table_a.status("A"), Some(PeerStatus::Alive));
        assert_eq!(table_a.status("B"), Some(PeerStatus::Alive));

        let suspects_b = table_b.sweep_suspects(15000);
        assert_eq!(suspects_b, vec!["C"]);
        assert_eq!(table_b.status("C"), Some(PeerStatus::Suspect));
    }

    #[test]
    fn suspect_recovers_on_new_alive() {
        let table = MembershipTable::new(1000);
        table.record_alive("X", 1, 0);

        // Sweep past timeout → suspect
        let suspects = table.sweep_suspects(1000);
        assert_eq!(suspects, vec!["X"]);
        assert_eq!(table.status("X"), Some(PeerStatus::Suspect));

        // X sends a new alive → back to Alive
        table.record_alive("X", 2, 1500);
        assert_eq!(table.status("X"), Some(PeerStatus::Alive));
    }

    #[test]
    fn state_response_limits_to_batch_size() {
        // Simulate building a StateResponse: clamp to STATE_BATCH_SIZE.
        let all_blocks: Vec<u64> = (0..100).collect();
        let batch: Vec<u64> = all_blocks.into_iter().take(STATE_BATCH_SIZE).collect();
        assert_eq!(batch.len(), STATE_BATCH_SIZE);
        assert_eq!(*batch.last().unwrap(), 49);
    }

    #[test]
    fn anti_entropy_detects_gap_from_alive_height() {
        let table = MembershipTable::new(15000);

        // Peer X reports height=20
        table.record_alive_with_height("X", 1, 0, 20);
        // Peer Y reports height=15
        table.record_alive_with_height("Y", 1, 0, 15);
        // Peer Z reports height=10
        table.record_alive_with_height("Z", 1, 0, 10);

        // Local height is 15 → X is ahead, Y is equal, Z is behind
        let ahead = table.peers_ahead_of(15);
        assert_eq!(ahead, vec!["X"]);

        // Local height is 5 → all ahead
        let mut ahead = table.peers_ahead_of(5);
        ahead.sort();
        assert_eq!(ahead, vec!["X", "Y", "Z"]);

        // Local height is 25 → none ahead
        let ahead = table.peers_ahead_of(25);
        assert!(ahead.is_empty());
    }

    #[test]
    fn parse_anchor_peers_valid() {
        let input = "org1:10.0.0.1:7051,org2:10.0.0.2:7051";
        let peers = parse_anchor_peers(input);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], AnchorPeer::new("10.0.0.1:7051", "org1"));
        assert_eq!(peers[1], AnchorPeer::new("10.0.0.2:7051", "org2"));
    }

    #[test]
    fn parse_anchor_peers_with_spaces_and_empty() {
        let input = " org1:10.0.0.1:7051 , , org3:10.0.0.3:9051 ";
        let peers = parse_anchor_peers(input);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].org_id, "org1");
        assert_eq!(peers[1].org_id, "org3");
    }

    #[test]
    fn parse_anchor_peers_empty_string() {
        assert!(parse_anchor_peers("").is_empty());
        assert!(parse_anchor_peers("  , , ").is_empty());
    }

    #[test]
    fn parse_anchor_peers_skips_invalid() {
        // No colon → skipped; empty org → skipped
        let input = "nocolon,:onlyaddress";
        let peers = parse_anchor_peers(input);
        assert!(peers.is_empty());
    }

    #[test]
    fn anchor_peer_serde_roundtrip() {
        let ap = AnchorPeer::new("10.0.0.1:7051", "org1");
        let json = serde_json::to_string(&ap).unwrap();
        let decoded: AnchorPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(ap, decoded);
    }

    #[test]
    fn anchor_peers_from_config_converts_map() {
        let mut map = HashMap::new();
        map.insert(
            "org1".to_string(),
            vec!["10.0.0.1:7051".to_string(), "10.0.0.2:7051".to_string()],
        );
        map.insert("org2".to_string(), vec!["10.0.0.3:7051".to_string()]);

        let mut peers = anchor_peers_from_config(&map);
        peers.sort_by(|a, b| a.peer_address.cmp(&b.peer_address));

        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0], AnchorPeer::new("10.0.0.1:7051", "org1"));
        assert_eq!(peers[1], AnchorPeer::new("10.0.0.2:7051", "org1"));
        assert_eq!(peers[2], AnchorPeer::new("10.0.0.3:7051", "org2"));
    }

    #[test]
    fn anchor_peers_from_config_empty_map() {
        let map = HashMap::new();
        assert!(anchor_peers_from_config(&map).is_empty());
    }

    #[test]
    fn leader_election_smallest_address_wins() {
        let table = MembershipTable::new(15000);

        // 3 peers in org1 with different addresses
        table.record_alive_full("10.0.0.3:7051", "org1", 1, 0, 0);
        table.record_alive_full("10.0.0.1:7051", "org1", 1, 0, 0);
        table.record_alive_full("10.0.0.2:7051", "org1", 1, 0, 0);

        // Leader = smallest address
        assert_eq!(
            table.elect_leader("org1"),
            Some("10.0.0.1:7051".to_string())
        );
    }

    #[test]
    fn leader_election_failover_on_suspect() {
        let table = MembershipTable::new(1000);

        table.record_alive_full("10.0.0.1:7051", "org1", 1, 0, 0);
        table.record_alive_full("10.0.0.2:7051", "org1", 1, 0, 0);
        table.record_alive_full("10.0.0.3:7051", "org1", 1, 0, 0);

        // Leader is 10.0.0.1
        assert_eq!(
            table.elect_leader("org1"),
            Some("10.0.0.1:7051".to_string())
        );

        // 10.0.0.1 stops sending alive → becomes suspect after sweep
        // Only update 10.0.0.2 and 10.0.0.3
        table.record_alive_full("10.0.0.2:7051", "org1", 2, 1500, 0);
        table.record_alive_full("10.0.0.3:7051", "org1", 2, 1500, 0);
        table.sweep_suspects(1500);

        // 10.0.0.1 is suspect → next leader is 10.0.0.2
        assert_eq!(
            table.elect_leader("org1"),
            Some("10.0.0.2:7051".to_string())
        );
    }

    #[test]
    fn leader_election_no_alive_peers_returns_none() {
        let table = MembershipTable::new(1000);
        table.record_alive_full("10.0.0.1:7051", "org1", 1, 0, 0);
        table.sweep_suspects(1000);

        assert_eq!(table.elect_leader("org1"), None);
    }

    #[test]
    fn leader_election_per_org_isolation() {
        let table = MembershipTable::new(15000);

        table.record_alive_full("10.0.0.1:7051", "org1", 1, 0, 0);
        table.record_alive_full("10.0.0.2:7051", "org2", 1, 0, 0);
        table.record_alive_full("10.0.0.3:7051", "org1", 1, 0, 0);

        assert_eq!(
            table.elect_leader("org1"),
            Some("10.0.0.1:7051".to_string())
        );
        assert_eq!(
            table.elect_leader("org2"),
            Some("10.0.0.2:7051".to_string())
        );
        assert_eq!(table.elect_leader("org3"), None);
    }

    #[test]
    fn leader_election_mode_from_env() {
        // Default is Static
        assert_eq!(LeaderElectionMode::from_env(), LeaderElectionMode::Static);
    }
}
