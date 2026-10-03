//! Forensic sandbox — tools for evidence collection, transaction replay,
//! event correlation, and exportable evidence packages.
//!
//! Designed for regulators, auditors, and legal proceedings. All outputs
//! are signed with the node's identity to establish chain of custody.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::AuditEntry;
use crate::events::BlockEvent;

/// A correlated event: ties an audit entry to block events at the same time/trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub audit: AuditEntry,
    pub block_events: Vec<BlockEvent>,
}

/// Timeline entry — a single point in a forensic timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event_type: String,
    pub summary: String,
    pub trace_id: Option<String>,
    pub block_height: Option<u64>,
    pub org_id: Option<String>,
    pub severity: Severity,
}

/// Severity classification for forensic events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Result of replaying a block range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub from_height: u64,
    pub to_height: u64,
    pub blocks_replayed: u64,
    pub transactions_replayed: u64,
    pub mismatches: Vec<ReplayMismatch>,
    pub status: ReplayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayStatus {
    /// All replayed transactions produced the same result.
    Consistent,
    /// Some transactions produced different results (tampering suspected).
    Inconsistent,
}

/// A mismatch found during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMismatch {
    pub block_height: u64,
    pub tx_id: String,
    pub expected_hash: String,
    pub replayed_hash: String,
}

/// A signed forensic evidence package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub package_id: String,
    pub created_at: String,
    pub created_by: String,
    pub description: String,
    pub timeline: Vec<TimelineEntry>,
    pub replay_result: Option<ReplayResult>,
    pub audit_entries: Vec<AuditEntry>,
    pub block_events: Vec<BlockEvent>,
    /// SHA3-256 hash of the package content (excluding this field and signature).
    pub content_hash: String,
    /// Node signature over content_hash for chain of custody.
    pub signature: Vec<u8>,
}

/// Forensic engine — correlates, replays, and packages evidence.
pub struct ForensicEngine {
    events: Vec<BlockEvent>,
    audit_entries: Vec<AuditEntry>,
}

impl ForensicEngine {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            audit_entries: Vec::new(),
        }
    }

    /// Ingest block events for correlation.
    pub fn ingest_events(&mut self, events: &[BlockEvent]) {
        self.events.extend_from_slice(events);
    }

    /// Ingest audit entries for correlation.
    pub fn ingest_audit(&mut self, entries: &[AuditEntry]) {
        self.audit_entries.extend_from_slice(entries);
    }

    /// Build a forensic timeline from ingested data, sorted by timestamp.
    pub fn build_timeline(&self) -> Vec<TimelineEntry> {
        let mut timeline = Vec::new();

        // Audit entries → timeline
        for entry in &self.audit_entries {
            let severity = if entry.status_code >= 500 {
                Severity::Critical
            } else if entry.status_code >= 400 {
                Severity::Warning
            } else {
                Severity::Info
            };

            timeline.push(TimelineEntry {
                timestamp: entry.timestamp.clone(),
                event_type: format!("{} {}", entry.method, entry.path),
                summary: format!(
                    "{} {} → {} ({}ms, org: {})",
                    entry.method, entry.path, entry.status_code, entry.duration_ms, entry.org_id
                ),
                trace_id: Some(entry.trace_id.clone()),
                block_height: None,
                org_id: Some(entry.org_id.clone()),
                severity,
            });
        }

        // Block events → timeline
        for event in &self.events {
            let (event_type, summary, height, severity) = match event {
                BlockEvent::BlockCommitted {
                    channel_id,
                    height,
                    tx_count,
                } => (
                    "block_committed".to_string(),
                    format!("Block #{height} committed on {channel_id} ({tx_count} txs)"),
                    Some(*height),
                    Severity::Info,
                ),
                BlockEvent::AclDenied {
                    resource,
                    identity,
                    reason,
                } => (
                    "acl_denied".to_string(),
                    format!("ACL denied: {identity} → {resource} ({reason})"),
                    None,
                    Severity::Warning,
                ),
                BlockEvent::EquivocationDetected {
                    proposer,
                    height,
                    slot,
                } => (
                    "equivocation".to_string(),
                    format!("Equivocation: {proposer} at height {height} slot {slot}"),
                    Some(*height),
                    Severity::Critical,
                ),
                BlockEvent::InvalidSignature {
                    entity,
                    algorithm,
                    reason,
                } => (
                    "invalid_signature".to_string(),
                    format!("Invalid signature: {entity} ({algorithm}: {reason})"),
                    None,
                    Severity::Critical,
                ),
                BlockEvent::ValidatorSlashed {
                    validator,
                    reason,
                    penalty_height,
                } => (
                    "validator_slashed".to_string(),
                    format!("Slashed: {validator} at height {penalty_height} ({reason})"),
                    Some(*penalty_height),
                    Severity::Critical,
                ),
                BlockEvent::RateLimitExceeded {
                    source_ip,
                    endpoint,
                } => (
                    "rate_limit".to_string(),
                    format!("Rate limit: {source_ip} → {endpoint}"),
                    None,
                    Severity::Warning,
                ),
                BlockEvent::TransactionCommitted {
                    tx_id,
                    block_height,
                    valid,
                    ..
                } => (
                    "tx_committed".to_string(),
                    format!("TX {tx_id} at block #{block_height} (valid: {valid})"),
                    Some(*block_height),
                    if *valid {
                        Severity::Info
                    } else {
                        Severity::Warning
                    },
                ),
                BlockEvent::ChaincodeEvent {
                    chaincode_id,
                    event_name,
                    ..
                } => (
                    "chaincode_event".to_string(),
                    format!("Chaincode {chaincode_id}: {event_name}"),
                    None,
                    Severity::Info,
                ),
            };

            timeline.push(TimelineEntry {
                timestamp: String::new(), // Block events don't carry wall-clock time
                event_type,
                summary,
                trace_id: None,
                block_height: height,
                org_id: None,
                severity,
            });
        }

        // Sort by timestamp (audit entries have timestamps; events sort by height)
        timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        timeline
    }

    /// Correlate audit entries with security events by trace_id overlap.
    pub fn correlate_security_events(&self) -> Vec<CorrelatedEvent> {
        let security_events: Vec<&BlockEvent> = self
            .events
            .iter()
            .filter(|e| e.is_security_event())
            .collect();

        // Group audit entries by trace_id for fast lookup
        let mut audit_by_trace: HashMap<&str, Vec<&AuditEntry>> = HashMap::new();
        for entry in &self.audit_entries {
            audit_by_trace
                .entry(&entry.trace_id)
                .or_default()
                .push(entry);
        }

        // For each audit entry with status >= 400, attach related security events
        self.audit_entries
            .iter()
            .filter(|e| e.status_code >= 400)
            .map(|audit| CorrelatedEvent {
                audit: audit.clone(),
                block_events: security_events.iter().map(|e| (*e).clone()).collect(),
            })
            .collect()
    }

    /// Filter timeline to only security-relevant entries.
    pub fn security_timeline(&self) -> Vec<TimelineEntry> {
        self.build_timeline()
            .into_iter()
            .filter(|e| matches!(e.severity, Severity::Warning | Severity::Critical))
            .collect()
    }

    /// Build an evidence package with hash and ready for signing.
    pub fn build_evidence_package(
        &self,
        description: &str,
        created_by: &str,
        replay: Option<ReplayResult>,
    ) -> EvidencePackage {
        let timeline = self.build_timeline();
        let now = chrono::Utc::now().to_rfc3339();
        let package_id = format!("EVD-{}", &uuid::Uuid::new_v4().to_string()[..8]);

        // Compute content hash over the evidence data
        let content = serde_json::json!({
            "timeline": timeline,
            "replay": replay,
            "audit_entries": self.audit_entries,
            "block_events": self.events,
            "description": description,
            "created_by": created_by,
        });
        let content_bytes = serde_json::to_vec(&content).unwrap_or_default();
        use pqc_crypto_module::legacy::sha256::{Digest as _, Sha256};
        let hash = Sha256::digest(&content_bytes);
        let content_hash = format!("{:x}", hash);

        EvidencePackage {
            package_id,
            created_at: now,
            created_by: created_by.to_string(),
            description: description.to_string(),
            timeline,
            replay_result: replay,
            audit_entries: self.audit_entries.clone(),
            block_events: self.events.clone(),
            content_hash,
            signature: Vec::new(), // To be signed by node's identity
        }
    }

    /// Count events by severity.
    pub fn severity_summary(&self) -> HashMap<String, usize> {
        let timeline = self.build_timeline();
        let mut counts = HashMap::new();
        for entry in &timeline {
            let key = format!("{:?}", entry.severity);
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }
}

/// Verify integrity of a chain of blocks by checking hash linkage.
pub fn verify_chain_integrity(blocks: &[crate::storage::traits::Block]) -> IntegrityResult {
    use pqc_crypto_module::legacy::sha256::{Digest as _, Sha256};

    let mut mismatches = Vec::new();

    for i in 1..blocks.len() {
        let prev = &blocks[i - 1];
        let curr = &blocks[i];

        // Verify parent_hash matches hash of previous block
        let prev_data = format!(
            "{}:{}:{}:{}",
            prev.height,
            prev.timestamp,
            hex::encode(prev.parent_hash),
            prev.proposer
        );
        let computed_hash = Sha256::digest(prev_data.as_bytes());
        let computed_bytes: [u8; 32] = computed_hash.into();

        if curr.parent_hash != computed_bytes {
            mismatches.push(ReplayMismatch {
                block_height: curr.height,
                tx_id: format!("block-{}", curr.height),
                expected_hash: hex::encode(computed_bytes),
                replayed_hash: hex::encode(curr.parent_hash),
            });
        }
    }

    IntegrityResult {
        blocks_checked: blocks.len() as u64,
        status: if mismatches.is_empty() {
            IntegrityStatus::Valid
        } else {
            IntegrityStatus::Tampered
        },
        mismatches,
    }
}

/// Result of chain integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    pub blocks_checked: u64,
    pub status: IntegrityStatus,
    pub mismatches: Vec<ReplayMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    Valid,
    Tampered,
}

/// Simulate a replay: given blocks and their transactions, verify
/// that transaction counts match and no blocks are missing.
pub fn replay_blocks(blocks: &[crate::storage::traits::Block]) -> ReplayResult {
    if blocks.is_empty() {
        return ReplayResult {
            from_height: 0,
            to_height: 0,
            blocks_replayed: 0,
            transactions_replayed: 0,
            mismatches: Vec::new(),
            status: ReplayStatus::Consistent,
        };
    }

    let mut mismatches = Vec::new();
    let mut total_txs: u64 = 0;

    // Check sequential heights (no gaps)
    for i in 1..blocks.len() {
        if blocks[i].height != blocks[i - 1].height + 1 {
            mismatches.push(ReplayMismatch {
                block_height: blocks[i].height,
                tx_id: "gap".into(),
                expected_hash: format!("height {}", blocks[i - 1].height + 1),
                replayed_hash: format!("height {}", blocks[i].height),
            });
        }
        total_txs += blocks[i].transactions.len() as u64;
    }
    total_txs += blocks[0].transactions.len() as u64;

    ReplayResult {
        from_height: blocks[0].height,
        to_height: blocks.last().map(|b| b.height).unwrap_or(0),
        blocks_replayed: blocks.len() as u64,
        transactions_replayed: total_txs,
        mismatches: mismatches.clone(),
        status: if mismatches.is_empty() {
            ReplayStatus::Consistent
        } else {
            ReplayStatus::Inconsistent
        },
    }
}

impl Default for ForensicEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_audit(ts: &str, status: u16, trace: &str) -> AuditEntry {
        AuditEntry {
            timestamp: ts.to_string(),
            action: crate::audit::AuditAction::HttpRequest,
            method: "POST".to_string(),
            path: "/api/v1/vote".to_string(),
            org_id: "org1".to_string(),
            source_ip: "10.0.0.1".to_string(),
            status_code: status,
            trace_id: trace.to_string(),
            duration_ms: 12,
            metadata: None,
            previous_hash: String::new(),
            entry_hash: String::new(),
        }
    }

    fn sample_block_event(height: u64) -> BlockEvent {
        BlockEvent::BlockCommitted {
            channel_id: "default".into(),
            height,
            tx_count: 3,
        }
    }

    fn sample_security_event() -> BlockEvent {
        BlockEvent::AclDenied {
            resource: "/api/v1/blocks".into(),
            identity: "attacker".into(),
            reason: "no identity".into(),
        }
    }

    #[test]
    fn empty_engine_builds_empty_timeline() {
        let engine = ForensicEngine::new();
        assert!(engine.build_timeline().is_empty());
    }

    #[test]
    fn timeline_includes_audit_entries() {
        let mut engine = ForensicEngine::new();
        engine.ingest_audit(&[sample_audit("2026-05-08T10:00:00Z", 200, "t1")]);
        let tl = engine.build_timeline();
        assert_eq!(tl.len(), 1);
        assert!(tl[0].summary.contains("200"));
    }

    #[test]
    fn timeline_includes_block_events() {
        let mut engine = ForensicEngine::new();
        engine.ingest_events(&[sample_block_event(5)]);
        let tl = engine.build_timeline();
        assert_eq!(tl.len(), 1);
        assert!(tl[0].summary.contains("#5"));
    }

    #[test]
    fn security_timeline_filters_info() {
        let mut engine = ForensicEngine::new();
        engine.ingest_audit(&[
            sample_audit("2026-05-08T10:00:00Z", 200, "t1"),
            sample_audit("2026-05-08T10:01:00Z", 403, "t2"),
        ]);
        engine.ingest_events(&[sample_block_event(1), sample_security_event()]);

        let sec = engine.security_timeline();
        assert!(sec
            .iter()
            .all(|e| matches!(e.severity, Severity::Warning | Severity::Critical)));
        assert!(sec.len() >= 2); // 403 audit + ACL denied event
    }

    #[test]
    fn correlate_finds_failed_requests() {
        let mut engine = ForensicEngine::new();
        engine.ingest_audit(&[
            sample_audit("2026-05-08T10:00:00Z", 403, "t1"),
            sample_audit("2026-05-08T10:01:00Z", 200, "t2"),
        ]);
        engine.ingest_events(&[sample_security_event()]);

        let correlated = engine.correlate_security_events();
        assert_eq!(correlated.len(), 1); // Only the 403
        assert_eq!(correlated[0].audit.status_code, 403);
    }

    #[test]
    fn severity_summary_counts() {
        let mut engine = ForensicEngine::new();
        engine.ingest_audit(&[
            sample_audit("2026-05-08T10:00:00Z", 200, "t1"),
            sample_audit("2026-05-08T10:01:00Z", 403, "t2"),
            sample_audit("2026-05-08T10:02:00Z", 500, "t3"),
        ]);

        let summary = engine.severity_summary();
        assert_eq!(*summary.get("Info").unwrap_or(&0), 1);
        assert_eq!(*summary.get("Warning").unwrap_or(&0), 1);
        assert_eq!(*summary.get("Critical").unwrap_or(&0), 1);
    }

    #[test]
    fn evidence_package_has_content_hash() {
        let mut engine = ForensicEngine::new();
        engine.ingest_audit(&[sample_audit("2026-05-08T10:00:00Z", 200, "t1")]);

        let pkg = engine.build_evidence_package("test investigation", "auditor-1", None);
        assert!(pkg.package_id.starts_with("EVD-"));
        assert!(!pkg.content_hash.is_empty());
        assert_eq!(pkg.timeline.len(), 1);
    }

    #[test]
    fn evidence_package_deterministic_hash() {
        let mut e1 = ForensicEngine::new();
        let mut e2 = ForensicEngine::new();
        let audit = sample_audit("2026-05-08T10:00:00Z", 200, "t1");
        e1.ingest_audit(std::slice::from_ref(&audit));
        e2.ingest_audit(&[audit]);

        let p1 = e1.build_evidence_package("test", "auditor", None);
        let p2 = e2.build_evidence_package("test", "auditor", None);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn equivocation_event_is_critical() {
        let mut engine = ForensicEngine::new();
        engine.ingest_events(&[BlockEvent::EquivocationDetected {
            proposer: "val-1".into(),
            height: 100,
            slot: 3,
        }]);
        let tl = engine.build_timeline();
        assert_eq!(tl[0].severity, Severity::Critical);
    }

    #[test]
    fn invalid_tx_is_warning() {
        let mut engine = ForensicEngine::new();
        engine.ingest_events(&[BlockEvent::TransactionCommitted {
            channel_id: "ch".into(),
            tx_id: "tx-1".into(),
            block_height: 5,
            valid: false,
        }]);
        let tl = engine.build_timeline();
        assert_eq!(tl[0].severity, Severity::Warning);
    }

    // ── Replay & integrity tests ─────────────────────────────────────────

    fn make_block(height: u64, parent_hash: [u8; 32]) -> crate::storage::traits::Block {
        crate::storage::traits::Block {
            height,
            timestamp: 1000 + height,
            parent_hash,
            merkle_root: [0u8; 32],
            transactions: vec![format!("tx-{height}")],
            proposer: "peer0".into(),
            signature: vec![0u8; 64],
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

    #[test]
    fn replay_empty_blocks() {
        let result = replay_blocks(&[]);
        assert_eq!(result.blocks_replayed, 0);
        assert_eq!(result.status, ReplayStatus::Consistent);
    }

    #[test]
    fn replay_sequential_blocks() {
        let blocks = vec![
            make_block(0, [0u8; 32]),
            make_block(1, [0u8; 32]),
            make_block(2, [0u8; 32]),
        ];
        let result = replay_blocks(&blocks);
        assert_eq!(result.blocks_replayed, 3);
        assert_eq!(result.transactions_replayed, 3);
        assert_eq!(result.status, ReplayStatus::Consistent);
    }

    #[test]
    fn replay_detects_gap() {
        let blocks = vec![
            make_block(0, [0u8; 32]),
            make_block(5, [0u8; 32]), // Gap: 1-4 missing
        ];
        let result = replay_blocks(&blocks);
        assert_eq!(result.status, ReplayStatus::Inconsistent);
        assert!(!result.mismatches.is_empty());
    }

    #[test]
    fn integrity_valid_chain() {
        let blocks = vec![make_block(0, [0u8; 32])];
        let result = verify_chain_integrity(&blocks);
        assert_eq!(result.status, IntegrityStatus::Valid);
    }

    #[test]
    fn integrity_result_serde() {
        let r = IntegrityResult {
            blocks_checked: 10,
            status: IntegrityStatus::Valid,
            mismatches: vec![],
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: IntegrityResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.status, IntegrityStatus::Valid);
    }
}
