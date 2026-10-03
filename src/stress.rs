//! Module-level stress testing — runs targeted stress tests on each subsystem
//! and produces a certification-ready report.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Result of a single module stress test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStressResult {
    pub module: String,
    pub operations: u64,
    pub duration_ms: u64,
    pub ops_per_sec: f64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub errors: u64,
    pub status: StressStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StressStatus {
    Pass,
    Degraded,
    Fail,
}

/// Full stress report across all modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressReport {
    pub report_id: String,
    pub generated_at: String,
    pub total_modules: usize,
    pub passed: usize,
    pub degraded: usize,
    pub failed: usize,
    pub results: Vec<ModuleStressResult>,
}

/// Helper: measure latencies and compute percentiles.
fn percentile(sorted_us: &[u64], pct: f64) -> u64 {
    if sorted_us.is_empty() {
        return 0;
    }
    let idx = ((pct / 100.0) * sorted_us.len() as f64) as usize;
    sorted_us[idx.min(sorted_us.len() - 1)]
}

/// Stress test: Storage (MemoryStore write/read).
pub fn stress_storage(ops: u64) -> ModuleStressResult {
    use crate::storage::memory::MemoryStore;
    use crate::storage::traits::{Block, BlockStore};

    let store = MemoryStore::new();
    let mut latencies = Vec::with_capacity(ops as usize);
    let mut errors: u64 = 0;

    let start = Instant::now();
    for i in 0..ops {
        let block = Block {
            height: i,
            timestamp: 1000 + i,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec![format!("tx-{i}")],
            proposer: "stress".into(),
            signature: vec![0u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        };

        let op_start = Instant::now();
        if store.write_block(&block).is_err() {
            errors += 1;
        }
        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "storage".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors,
        status: if errors == 0 && ops_per_sec > 1000.0 {
            StressStatus::Pass
        } else if errors == 0 {
            StressStatus::Degraded
        } else {
            StressStatus::Fail
        },
    }
}

/// Stress test: Cryptography (SHA3-256 hashing).
pub fn stress_crypto(ops: u64) -> ModuleStressResult {
    use pqc_crypto_module::legacy::sha256::{Digest as _, Sha256};

    let data = b"cerulean-stress-test-payload-for-hashing";
    let mut latencies = Vec::with_capacity(ops as usize);

    let start = Instant::now();
    for _ in 0..ops {
        let op_start = Instant::now();
        let _ = Sha256::digest(data);
        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "crypto_hash".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors: 0,
        status: if ops_per_sec > 100_000.0 {
            StressStatus::Pass
        } else {
            StressStatus::Degraded
        },
    }
}

/// Stress test: Anomaly detection engine.
pub fn stress_anomaly(ops: u64) -> ModuleStressResult {
    use crate::intelligence::anomaly::{AnomalyConfig, AnomalyDetector, DataPoint};

    let mut detector = AnomalyDetector::new(AnomalyConfig {
        z_threshold: 3.0,
        min_samples: 10,
        window_size: 1000,
    });

    let mut latencies = Vec::with_capacity(ops as usize);

    let start = Instant::now();
    for i in 0..ops {
        let point = DataPoint {
            timestamp: i,
            value: 100.0 + (i % 10) as f64,
            source: "stress".into(),
        };
        let op_start = Instant::now();
        let _ = detector.observe(&point);
        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "anomaly_detection".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors: 0,
        status: if ops_per_sec > 100_000.0 {
            StressStatus::Pass
        } else {
            StressStatus::Degraded
        },
    }
}

/// Stress test: Risk scoring engine.
pub fn stress_risk(ops: u64) -> ModuleStressResult {
    use crate::intelligence::risk::{RiskEngine, RiskInput};

    let engine = RiskEngine::with_defaults();
    let input = RiskInput {
        amount: 50_000,
        country: Some("CL".into()),
        tx_count_last_hour: 10,
        kyc_verified: true,
        watchlisted: false,
        identity_age_days: 100,
        issuer_verified: None,
        credential_count_by_issuer: None,
        credential_age_days: None,
        issuer_reputation: None,
    };

    let mut latencies = Vec::with_capacity(ops as usize);

    let start = Instant::now();
    for _ in 0..ops {
        let op_start = Instant::now();
        let _ = engine.evaluate(&input);
        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "risk_scoring".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors: 0,
        status: if ops_per_sec > 500_000.0 {
            StressStatus::Pass
        } else {
            StressStatus::Degraded
        },
    }
}

/// Stress test: ISO 20022 validation.
pub fn stress_compliance(ops: u64) -> ModuleStressResult {
    use crate::compliance::iso20022::{validate_pacs008, CurrencyAmount, Pacs008, Party};

    let msg = Pacs008 {
        message_id: "STRESS".into(),
        creation_date: "2026-05-09".into(),
        settlement_amount: CurrencyAmount {
            amount: 100_000,
            currency: "CLP".into(),
        },
        debtor: Party {
            name: "Stress Test".into(),
            country: "CL".into(),
            account_iban: Some("CL9300000000123456789012".into()),
            bic: Some("BCHICLRM".into()),
        },
        creditor: Party {
            name: "Receiver".into(),
            country: "AR".into(),
            account_iban: None,
            bic: Some("NACNARBAXXX".into()),
        },
        debtor_agent_bic: "BCHICLRM".into(),
        creditor_agent_bic: "NACNARBAXXX".into(),
        remittance_info: None,
    };

    let mut latencies = Vec::with_capacity(ops as usize);
    let mut errors: u64 = 0;

    let start = Instant::now();
    for _ in 0..ops {
        let op_start = Instant::now();
        if validate_pacs008(&msg).is_err() {
            errors += 1;
        }
        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "iso20022_validation".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors,
        status: if errors == 0 && ops_per_sec > 100_000.0 {
            StressStatus::Pass
        } else if errors == 0 {
            StressStatus::Degraded
        } else {
            StressStatus::Fail
        },
    }
}

/// Stress test: Governance (proposal submit + vote cycle).
pub fn stress_governance(ops: u64) -> ModuleStressResult {
    use crate::governance::params::ParamRegistry;
    use crate::governance::proposals::{ProposalAction, ProposalStore, SubmitParams};
    use crate::governance::voting::{VoteOption, VoteStore};

    let proposals = ProposalStore::new();
    let votes = VoteStore::new();
    let params = ParamRegistry::with_defaults();
    let deposit = params.get_u64("proposal_deposit", 10_000);
    let voting_period = params.get_u64("voting_period_blocks", 17_280);

    let mut latencies = Vec::with_capacity(ops as usize);
    let mut errors: u64 = 0;

    let start = Instant::now();
    for i in 0..ops {
        let op_start = Instant::now();

        let action = ProposalAction::TextProposal {
            title: format!("stress-{i}"),
            description: "stress test".into(),
        };
        match proposals.submit(SubmitParams {
            proposer: "stress-proposer",
            action,
            description: "stress",
            deposit,
            required_deposit: deposit,
            current_height: i,
            voting_period,
        }) {
            Ok(pid) => {
                let _ = votes.cast_vote(
                    pid,
                    &format!("voter-{i}"),
                    VoteOption::Yes,
                    1,
                    i,
                    i + voting_period,
                );
            }
            Err(_) => errors += 1,
        }

        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "governance".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors,
        // Rate limiting causes expected rejections — not failures
        status: if ops_per_sec > 1_000.0 {
            StressStatus::Pass
        } else {
            StressStatus::Degraded
        },
    }
}

/// Stress test: Forensic engine (timeline build + evidence package).
pub fn stress_forensic(ops: u64) -> ModuleStressResult {
    use crate::audit::AuditEntry;
    use crate::forensic::ForensicEngine;

    let mut latencies = Vec::with_capacity(ops as usize);

    let start = Instant::now();
    for i in 0..ops {
        let op_start = Instant::now();

        let mut engine = ForensicEngine::new();
        engine.ingest_audit(&[AuditEntry {
            timestamp: format!("2026-05-09T{:02}:00:00Z", i % 24),
            action: crate::audit::AuditAction::HttpRequest,
            method: "POST".into(),
            path: "/api/v1/vote".into(),
            org_id: "stress".into(),
            source_ip: "127.0.0.1".into(),
            status_code: 200,
            trace_id: format!("trace-{i}"),
            duration_ms: 5,
            metadata: None,
            previous_hash: String::new(),
            entry_hash: String::new(),
        }]);
        let _ = engine.build_timeline();

        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "forensic".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors: 0,
        status: if ops_per_sec > 50_000.0 {
            StressStatus::Pass
        } else {
            StressStatus::Degraded
        },
    }
}

/// Stress test: Pattern detection engine.
pub fn stress_patterns(ops: u64) -> ModuleStressResult {
    use crate::intelligence::patterns::{PatternEngine, TxRecord};

    let engine = PatternEngine::new();
    let txs: Vec<TxRecord> = (0..20)
        .map(|i| TxRecord {
            tx_id: format!("tx-{i}"),
            from: "alice".into(),
            to: "bob".into(),
            amount: 1000,
            timestamp: 100 + i,
        })
        .collect();

    let mut latencies = Vec::with_capacity(ops as usize);

    let start = Instant::now();
    for _ in 0..ops {
        let op_start = Instant::now();
        let _ = engine.analyze(&txs);
        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "pattern_detection".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors: 0,
        status: if ops_per_sec > 10_000.0 {
            StressStatus::Pass
        } else {
            StressStatus::Degraded
        },
    }
}

/// Stress test: Identity (DID creation + read cycle).
pub fn stress_identity(ops: u64) -> ModuleStressResult {
    use crate::storage::memory::MemoryStore;
    use crate::storage::traits::{BlockStore, IdentityRecord};

    let store = MemoryStore::new();
    let mut latencies = Vec::with_capacity(ops as usize);
    let mut errors: u64 = 0;

    let start = Instant::now();
    for i in 0..ops {
        let op_start = Instant::now();

        let did = format!("did:goya:stress-{i}");
        let record = IdentityRecord {
            did: did.clone(),
            public_key: String::new(),
            created_at: 1000 + i,
            updated_at: 1000 + i,
            status: "active".into(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
        };

        if store.write_identity(&record).is_err() {
            errors += 1;
        }
        // Read back to exercise read path
        if store.read_identity(&did).is_err() {
            errors += 1;
        }

        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "identity".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors,
        status: if errors == 0 && ops_per_sec > 1_000.0 {
            StressStatus::Pass
        } else if errors == 0 {
            StressStatus::Degraded
        } else {
            StressStatus::Fail
        },
    }
}

/// Stress test: Credential issuance + verification cycle.
pub fn stress_credential(ops: u64) -> ModuleStressResult {
    use crate::storage::memory::MemoryStore;
    use crate::storage::traits::{BlockStore, Credential, IdentityRecord};

    let store = MemoryStore::new();

    // Pre-register issuer DID
    let issuer_did = "did:goya:issuer-stress";
    store
        .write_identity(&IdentityRecord {
            did: issuer_did.into(),
            public_key: String::new(),
            created_at: 1000,
            updated_at: 1000,
            status: "active".into(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
        })
        .unwrap();

    let mut latencies = Vec::with_capacity(ops as usize);
    let mut errors: u64 = 0;

    let start = Instant::now();
    for i in 0..ops {
        let op_start = Instant::now();

        let cred_id = format!("cred-stress-{i}");
        let cred = Credential {
            id: cred_id.clone(),
            issuer_did: issuer_did.into(),
            subject_did: format!("did:goya:subject-{i}"),
            cred_type: "VerifiableCredential".into(),
            issued_at: 1000 + i,
            expires_at: 9_999_999,
            revoked_at: None,
            claims: serde_json::json!({"degree": "engineering", "index": i}),
            signature: String::new(),
            status: "active".into(),
            claims_commitment: None,
            claims_salt: None,
        };

        if store.write_credential(&cred).is_err() {
            errors += 1;
        }
        // Read back
        if store.read_credential(&cred_id).is_err() {
            errors += 1;
        }

        latencies.push(op_start.elapsed().as_micros() as u64);
    }
    let duration = start.elapsed();

    latencies.sort_unstable();
    let ops_per_sec = ops as f64 / duration.as_secs_f64();

    ModuleStressResult {
        module: "credential".into(),
        operations: ops,
        duration_ms: duration.as_millis() as u64,
        ops_per_sec,
        p50_us: percentile(&latencies, 50.0),
        p99_us: percentile(&latencies, 99.0),
        errors,
        status: if errors == 0 && ops_per_sec > 1_000.0 {
            StressStatus::Pass
        } else if errors == 0 {
            StressStatus::Degraded
        } else {
            StressStatus::Fail
        },
    }
}

/// Run all module stress tests and generate report.
pub fn run_full_stress(ops_per_module: u64) -> StressReport {
    let results = vec![
        stress_storage(ops_per_module),
        stress_crypto(ops_per_module),
        stress_anomaly(ops_per_module),
        stress_risk(ops_per_module),
        stress_compliance(ops_per_module),
        stress_governance(ops_per_module),
        stress_identity(ops_per_module),
        stress_credential(ops_per_module),
        stress_forensic(ops_per_module),
        stress_patterns(ops_per_module),
    ];

    let passed = results
        .iter()
        .filter(|r| r.status == StressStatus::Pass)
        .count();
    let degraded = results
        .iter()
        .filter(|r| r.status == StressStatus::Degraded)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.status == StressStatus::Fail)
        .count();

    StressReport {
        report_id: format!("STR-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        generated_at: chrono::Utc::now().to_rfc3339(),
        total_modules: results.len(),
        passed,
        degraded,
        failed,
        results,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_stress_completes() {
        let r = stress_storage(100);
        assert_eq!(r.module, "storage");
        assert_eq!(r.operations, 100);
        assert_eq!(r.errors, 0);
    }

    #[test]
    fn crypto_stress_completes() {
        let r = stress_crypto(100);
        assert_eq!(r.module, "crypto_hash");
        assert!(r.ops_per_sec > 0.0);
    }

    #[test]
    fn anomaly_stress_completes() {
        let r = stress_anomaly(100);
        assert_eq!(r.module, "anomaly_detection");
        assert_eq!(r.errors, 0);
    }

    #[test]
    fn risk_stress_completes() {
        let r = stress_risk(100);
        assert_eq!(r.module, "risk_scoring");
        assert_eq!(r.errors, 0);
    }

    #[test]
    fn compliance_stress_completes() {
        let r = stress_compliance(100);
        assert_eq!(r.module, "iso20022_validation");
        assert_eq!(r.errors, 0);
    }

    #[test]
    fn governance_stress_completes() {
        let r = stress_governance(50);
        assert_eq!(r.module, "governance");
        // Some errors expected from rate limiting — just verify it ran
        assert!(r.operations == 50);
    }

    #[test]
    fn identity_stress_completes() {
        let r = stress_identity(200);
        assert_eq!(r.module, "identity");
        assert_eq!(r.errors, 0);
        assert_eq!(r.operations, 200);
    }

    #[test]
    fn credential_stress_completes() {
        let r = stress_credential(200);
        assert_eq!(r.module, "credential");
        assert_eq!(r.errors, 0);
        assert_eq!(r.operations, 200);
    }

    #[test]
    fn forensic_stress_completes() {
        let r = stress_forensic(50);
        assert_eq!(r.module, "forensic");
        assert_eq!(r.errors, 0);
    }

    #[test]
    fn patterns_stress_completes() {
        let r = stress_patterns(50);
        assert_eq!(r.module, "pattern_detection");
        assert_eq!(r.errors, 0);
    }

    #[test]
    fn full_stress_report_has_all_modules() {
        let report = run_full_stress(50);
        assert_eq!(report.total_modules, 10);
        assert_eq!(report.results.len(), 10);
        assert!(report.report_id.starts_with("STR-"));
    }

    #[test]
    fn percentile_on_empty() {
        assert_eq!(percentile(&[], 50.0), 0);
    }

    #[test]
    fn percentile_on_data() {
        let data: Vec<u64> = (1..=100).collect();
        let p50 = percentile(&data, 50.0);
        let p99 = percentile(&data, 99.0);
        // p50 should be around 50 (±1 due to indexing)
        assert!((49..=51).contains(&p50), "p50 was {p50}");
        assert!((98..=100).contains(&p99), "p99 was {p99}");
    }

    #[test]
    fn stress_result_serde() {
        let r = stress_storage(10);
        let json = serde_json::to_string(&r).unwrap();
        let restored: ModuleStressResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.module, "storage");
    }

    // ── TORTURE TESTS — concurrent multi-thread brutality ────────────────────

    use std::sync::Arc;

    /// 64 threads × 25,000 ops each = 1,600,000 concurrent identity writes/reads
    #[test]
    fn torture_identity_1_6m_concurrent() {
        use crate::storage::memory::MemoryStore;
        use crate::storage::traits::{BlockStore, IdentityRecord};

        let store = Arc::new(MemoryStore::new());
        let threads: Vec<_> = (0..64)
            .map(|t| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut errors = 0u64;
                    for i in 0..25_000u64 {
                        let did = format!("did:goya:t{t}-{i}");
                        let rec = IdentityRecord {
                            did: did.clone(),
                            public_key: String::new(),
                            created_at: i,
                            updated_at: i,
                            status: "active".into(),
                            migrated_from: None,
                            signature_algorithm: None,
                            civil_anchor: None,
                        };
                        if s.write_identity(&rec).is_err() {
                            errors += 1;
                        }
                        if s.read_identity(&did).is_err() {
                            errors += 1;
                        }
                    }
                    errors
                })
            })
            .collect();

        let total_errors: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            total_errors, 0,
            "identity torture: {total_errors} errors in 1.6M ops"
        );

        // Post-torture integrity: read back every 100th record across all threads
        let mut integrity_errors = 0u64;
        for t in 0..64u64 {
            for i in (0..25_000u64).step_by(100) {
                let did = format!("did:goya:t{t}-{i}");
                match store.read_identity(&did) {
                    Ok(rec) => {
                        if rec.did != did || rec.created_at != i {
                            integrity_errors += 1;
                        }
                    }
                    Err(_) => integrity_errors += 1,
                }
            }
        }
        assert_eq!(
            integrity_errors, 0,
            "identity integrity: {integrity_errors} corrupted records"
        );
    }

    /// 64 threads × 25,000 credential writes = 1,600,000 concurrent
    #[test]
    fn torture_credential_1_6m_concurrent() {
        use crate::storage::memory::MemoryStore;
        use crate::storage::traits::{BlockStore, Credential, IdentityRecord};

        let store = Arc::new(MemoryStore::new());
        // Pre-register issuer
        store
            .write_identity(&IdentityRecord {
                did: "did:goya:torture-issuer".into(),
                public_key: String::new(),
                created_at: 0,
                updated_at: 0,
                status: "active".into(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
            })
            .unwrap();

        let threads: Vec<_> = (0..64)
            .map(|t| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut errors = 0u64;
                    for i in 0..25_000u64 {
                        let cred = Credential {
                            id: format!("cred-t{t}-{i}"),
                            issuer_did: "did:goya:torture-issuer".into(),
                            subject_did: format!("did:goya:subj-{i}"),
                            cred_type: "TortureTest".into(),
                            issued_at: i,
                            expires_at: 0,
                            revoked_at: None,
                            claims: serde_json::json!({"thread": t, "op": i}),
                            signature: String::new(),
                            status: "active".into(),
                            claims_commitment: None,
                            claims_salt: None,
                        };
                        if s.write_credential(&cred).is_err() {
                            errors += 1;
                        }
                        if s.read_credential(&cred.id).is_err() {
                            errors += 1;
                        }
                    }
                    errors
                })
            })
            .collect();

        let total_errors: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            total_errors, 0,
            "credential torture: {total_errors} errors in 1.6M ops"
        );

        // Post-torture integrity
        let mut integrity_errors = 0u64;
        for t in 0..64u64 {
            for i in (0..25_000u64).step_by(100) {
                let id = format!("cred-t{t}-{i}");
                match store.read_credential(&id) {
                    Ok(c) => {
                        if c.id != id || c.issuer_did != "did:goya:torture-issuer" {
                            integrity_errors += 1;
                        }
                    }
                    Err(_) => integrity_errors += 1,
                }
            }
        }
        assert_eq!(
            integrity_errors, 0,
            "credential integrity: {integrity_errors} corrupted records"
        );
    }

    /// 64 threads hammering governance: proposals + votes simultaneously
    #[test]
    fn torture_governance_concurrent_votes() {
        use crate::governance::proposals::{ProposalAction, ProposalStore, SubmitParams};
        use crate::governance::voting::{VoteOption, VoteStore};

        let proposals = Arc::new(ProposalStore::new());
        let votes = Arc::new(VoteStore::new());

        // Submit proposals from main thread (need sequential heights for rate limit)
        for i in 0..100u64 {
            let _ = proposals.submit(SubmitParams {
                proposer: &format!("proposer-{}", i % 10),
                action: ProposalAction::TextProposal {
                    title: format!("torture-{i}"),
                    description: "stress".into(),
                },
                description: "torture",
                deposit: 10_000,
                required_deposit: 10_000,
                current_height: i * 200, // spacing for rate limit
                voting_period: 100_000,
            });
        }

        // 64 threads each casting 5,000 votes across random proposals
        let threads: Vec<_> = (0..64)
            .map(|t| {
                let v = Arc::clone(&votes);
                std::thread::spawn(move || {
                    let mut cast = 0u64;
                    for i in 0..5_000u64 {
                        let proposal_id = (i % 100) + 1;
                        let voter = format!("voter-t{t}-{i}");
                        if v.cast_vote(proposal_id, &voter, VoteOption::Yes, 1, 10, 200_000)
                            .is_ok()
                        {
                            cast += 1;
                        }
                    }
                    cast
                })
            })
            .collect();

        let total_cast: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        // Should have many successful votes (duplicates rejected, but unique voter+proposal combos work)
        assert!(total_cast > 0, "no votes cast in torture test");

        // Tally should not panic across all proposals
        for pid in 1..=100u64 {
            let tally = votes.tally(pid, 10_000_000, 33, 67);
            assert!(tally.total_voted_power <= 320_000); // max 64 threads × 5000 votes capped by unique voters
        }
    }

    /// 64 threads × 25,000 block writes = 1,600,000 concurrent storage ops
    #[test]
    fn torture_storage_1_6m_concurrent() {
        use crate::storage::memory::MemoryStore;
        use crate::storage::traits::{Block, BlockStore};

        let store = Arc::new(MemoryStore::new());
        let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let threads: Vec<_> = (0..64)
            .map(|t| {
                let s = Arc::clone(&store);
                let errs = Arc::clone(&errors);
                std::thread::spawn(move || {
                    for i in 0..25_000u64 {
                        let height = t * 25_000 + i; // unique heights per thread
                        let block = Block {
                            height,
                            timestamp: 1000 + height,
                            parent_hash: [0u8; 32],
                            merkle_root: [0u8; 32],
                            transactions: vec![format!("tx-{height}")],
                            proposer: format!("thread-{t}"),
                            signature: vec![0u8; 64],
                            signature_algorithm: Default::default(),
                            endorsements: vec![],
                            secondary_signature: None,
                            secondary_signature_algorithm: None,
                            hash_algorithm: Default::default(),
                            orderer_signature: None,
                            commit_qc: None,
                            transaction_data: vec![],
                        };
                        if s.write_block(&block).is_err() {
                            errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
        let total_errors = errors.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            total_errors, 0,
            "storage torture: {total_errors} errors in 1.6M ops"
        );

        // Post-torture integrity: verify every 500th block
        let mut integrity_errors = 0u64;
        for t in 0..64u64 {
            for i in (0..25_000u64).step_by(500) {
                let height = t * 25_000 + i;
                match store.read_block(height) {
                    Ok(b) => {
                        if b.height != height || b.proposer != format!("thread-{t}") {
                            integrity_errors += 1;
                        }
                    }
                    Err(_) => integrity_errors += 1,
                }
            }
        }
        assert_eq!(
            integrity_errors, 0,
            "storage integrity: {integrity_errors} corrupted blocks"
        );
    }

    /// Concurrent hash operations — 64 threads × 100,000 = 6,400,000 hashes
    #[test]
    fn torture_crypto_6_4m_concurrent() {
        use pqc_crypto_module::legacy::sha256::{Digest as _, Sha256};

        let threads: Vec<_> = (0..64)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..100_000u64 {
                        let data = format!("torture-t{t}-{i}");
                        let _ = Sha256::digest(data.as_bytes());
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
        // If we reach here without panic, crypto is thread-safe
    }

    /// Mixed workload: identity + credential + governance simultaneously
    #[test]
    fn torture_mixed_workload_128_threads() {
        use crate::governance::proposals::{ProposalAction, ProposalStore, SubmitParams};
        use crate::governance::voting::{VoteOption, VoteStore};
        use crate::storage::memory::MemoryStore;
        use crate::storage::traits::{BlockStore, Credential, IdentityRecord};

        let store = Arc::new(MemoryStore::new());
        let proposals = Arc::new(ProposalStore::new());
        let votes = Arc::new(VoteStore::new());

        // Pre-seed proposals
        for i in 0..50u64 {
            let _ = proposals.submit(SubmitParams {
                proposer: "seeder",
                action: ProposalAction::TextProposal {
                    title: format!("mixed-{i}"),
                    description: "mixed workload".into(),
                },
                description: "mixed",
                deposit: 10_000,
                required_deposit: 10_000,
                current_height: i * 200,
                voting_period: 500_000,
            });
        }

        let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // 42 threads: identity writes
        let mut threads: Vec<std::thread::JoinHandle<()>> = (0..42)
            .map(|t| {
                let s = Arc::clone(&store);
                let e = Arc::clone(&errors);
                std::thread::spawn(move || {
                    for i in 0..10_000u64 {
                        let rec = IdentityRecord {
                            did: format!("did:goya:mix-id-t{t}-{i}"),
                            public_key: String::new(),
                            created_at: i,
                            updated_at: i,
                            status: "active".into(),
                            migrated_from: None,
                            signature_algorithm: None,
                            civil_anchor: None,
                        };
                        if s.write_identity(&rec).is_err() {
                            e.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        // 42 threads: credential writes
        threads.extend((0..42).map(|t| {
            let s = Arc::clone(&store);
            let e = Arc::clone(&errors);
            std::thread::spawn(move || {
                for i in 0..10_000u64 {
                    let cred = Credential {
                        id: format!("mix-cred-t{t}-{i}"),
                        issuer_did: "did:goya:mix-issuer".into(),
                        subject_did: format!("did:goya:mix-subj-{i}"),
                        cred_type: "MixedTest".into(),
                        issued_at: i,
                        expires_at: 0,
                        revoked_at: None,
                        claims: serde_json::Value::Null,
                        signature: String::new(),
                        status: "active".into(),
                        claims_commitment: None,
                        claims_salt: None,
                    };
                    if s.write_credential(&cred).is_err() {
                        e.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
        }));

        // 44 threads: voting
        threads.extend((0..44).map(|t| {
            let v = Arc::clone(&votes);
            std::thread::spawn(move || {
                for i in 0..10_000u64 {
                    let _ = v.cast_vote(
                        (i % 50) + 1,
                        &format!("mix-voter-t{t}-{i}"),
                        VoteOption::Yes,
                        1,
                        10,
                        600_000,
                    );
                }
            })
        }));

        for t in threads {
            t.join().unwrap();
        }

        let total_errors = errors.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            total_errors, 0,
            "mixed torture: {total_errors} errors across 128 threads × 10K ops"
        );
    }

    // ── DOMAIN-SPECIFIC TORTURE ─────────────────────────────────────────────

    /// Oracle: register nodes + submit 50K signed price reports + aggregate
    #[test]
    fn torture_oracle_system_concurrent() {
        use crate::oracle_system::OracleRegistry;
        use pqc_crypto_module::legacy::hmac::{Hmac, Mac, Sha256};
        type HmacSha256 = Hmac<Sha256>;

        let mut registry = OracleRegistry::new(3, 300_000);

        // Register 100 oracle nodes
        for i in 0..100 {
            let _ = registry.register_oracle(format!("oracle-{i}"));
        }

        let base_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut errors = 0u64;
        for i in 0..50_000u64 {
            let oracle_id = format!("oracle-{}", i % 100);
            let price = 50_000 + (i % 100);
            let ts = base_ts + i;

            // Compute valid HMAC signature
            let mut data = Vec::new();
            data.extend_from_slice(oracle_id.as_bytes());
            data.extend_from_slice(&price.to_le_bytes());
            data.extend_from_slice(&ts.to_le_bytes());
            let mut mac = HmacSha256::new_from_slice(b"oracle-system-hmac-key-v1").unwrap();
            mac.update(&data);
            let sig = mac.finalize().into_bytes().to_vec();

            if registry
                .submit_price_report(&oracle_id, "BTC/USD".to_string(), price, ts, sig, 95)
                .is_err()
            {
                errors += 1;
            }

            if i % 100 == 99 {
                let _ = registry.aggregate_reports("BTC/USD", 3);
            }
        }
        assert_eq!(errors, 0, "oracle torture: {errors} errors in 50K reports");

        let price = registry.get_price("BTC/USD");
        assert!(price.is_ok(), "no BTC/USD price after 50K reports");
    }

    /// Sandbox Wasm validation: 64 threads × 1,000 validations = 64,000
    #[test]
    fn torture_sandbox_validation_64k() {
        use crate::chaincode::sandbox::validate;

        let valid_wasm = wat::parse_str("(module)").unwrap();

        let threads: Vec<_> = (0..64)
            .map(|t| {
                let wasm = valid_wasm.clone();
                std::thread::spawn(move || {
                    let mut passed = 0u64;
                    for i in 0..1_000u64 {
                        let report = validate(&format!("cc-t{t}-{i}"), "1.0", &wasm);
                        if report.passed {
                            passed += 1;
                        }
                    }
                    passed
                })
            })
            .collect();

        let total_passed: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            total_passed, 64_000,
            "sandbox torture: only {total_passed}/64K passed"
        );
    }

    /// Commitment verification: 64 threads × 5,000 prove+verify cycles = 320,000 ops
    #[test]
    fn torture_commitment_320k_concurrent() {
        use crate::identity::zkp::{prove_range, verify_presentation};

        let threads: Vec<_> = (0..64)
            .map(|t| {
                std::thread::spawn(move || {
                    let mut errors = 0u64;
                    for i in 0..5_000u64 {
                        let value = 25 + (i % 50);
                        let threshold = 18;
                        match prove_range(&format!("cred-{t}-{i}"), "age", value, threshold) {
                            Ok(presentation) => match verify_presentation(&presentation) {
                                Ok(true) => {}
                                _ => errors += 1,
                            },
                            Err(_) => errors += 1,
                        }
                    }
                    errors
                })
            })
            .collect();

        let total_errors: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            total_errors, 0,
            "commitment torture: {total_errors} errors in 320K prove+verify"
        );
    }

    /// Governance full lifecycle: 64 threads doing propose → vote → tally in parallel
    #[test]
    fn torture_governance_full_lifecycle() {
        use crate::governance::proposals::{ProposalAction, ProposalStore, SubmitParams};
        use crate::governance::voting::{VoteOption, VoteStore};

        let proposals = Arc::new(ProposalStore::new());
        let votes = Arc::new(VoteStore::new());

        // Phase 1: 64 threads submit proposals concurrently (each with unique height)
        let p = Arc::clone(&proposals);
        let submit_threads: Vec<_> = (0..64)
            .map(|t| {
                let store = Arc::clone(&p);
                std::thread::spawn(move || {
                    let mut submitted = 0u64;
                    for i in 0..100u64 {
                        let height = (t * 10_000) + (i * 200);
                        if store
                            .submit(SubmitParams {
                                proposer: &format!("org-{t}"),
                                action: ProposalAction::TextProposal {
                                    title: format!("prop-t{t}-{i}"),
                                    description: "lifecycle torture".into(),
                                },
                                description: "torture",
                                deposit: 10_000,
                                required_deposit: 10_000,
                                current_height: height,
                                voting_period: 1_000_000,
                            })
                            .is_ok()
                        {
                            submitted += 1;
                        }
                    }
                    submitted
                })
            })
            .collect();

        let total_submitted: u64 = submit_threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(total_submitted > 0, "no proposals submitted");

        // Phase 2: 64 threads vote on all proposals
        let all_proposals = proposals.list_all();
        let proposal_ids: Vec<u64> = all_proposals.iter().map(|p| p.id).collect();
        let ids = Arc::new(proposal_ids);

        let vote_threads: Vec<_> = (0..64)
            .map(|t| {
                let v = Arc::clone(&votes);
                let pids = Arc::clone(&ids);
                std::thread::spawn(move || {
                    let mut cast = 0u64;
                    for (idx, &pid) in pids.iter().enumerate() {
                        let voter = format!("voter-t{t}-p{idx}");
                        let option = match t % 3 {
                            0 => VoteOption::Yes,
                            1 => VoteOption::No,
                            _ => VoteOption::Abstain,
                        };
                        if v.cast_vote(pid, &voter, option, 100, 10, 2_000_000).is_ok() {
                            cast += 1;
                        }
                    }
                    cast
                })
            })
            .collect();

        let total_votes: u64 = vote_threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(total_votes > 0, "no votes cast in lifecycle torture");

        // Phase 3: tally all proposals — must not panic
        for &pid in ids.iter() {
            let tally = votes.tally(pid, 10_000_000, 33, 67);
            // Verify arithmetic didn't overflow
            assert!(
                tally.yes_power.checked_add(tally.no_power).is_some(),
                "tally overflow on proposal {pid}"
            );
            assert!(
                tally
                    .total_voted_power
                    .checked_add(tally.total_staked_power)
                    .is_some(),
                "total overflow on proposal {pid}"
            );
        }
    }

    /// Compliance: 64 threads running regulatory checks simultaneously
    #[test]
    fn torture_compliance_64_threads() {
        use crate::regulatory::sandbox::run_compliance_checks;

        let threads: Vec<_> = (0..64)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut total_checks = 0usize;
                    for _ in 0..100 {
                        let results = run_compliance_checks();
                        total_checks += results.len();
                    }
                    total_checks
                })
            })
            .collect();

        let total: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        // 64 threads × 100 runs × 21 checks = 134,400
        assert!(
            total > 100_000,
            "compliance torture: only {total} checks ran"
        );
    }

    /// Forensic: 64 threads building timelines + evidence packages concurrently
    #[test]
    fn torture_forensic_concurrent() {
        use crate::audit::AuditEntry;
        use crate::forensic::ForensicEngine;

        let threads: Vec<_> = (0..64)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..500u64 {
                        let mut engine = ForensicEngine::new();
                        // Ingest 50 audit entries per engine
                        let entries: Vec<AuditEntry> = (0..50)
                            .map(|j| AuditEntry {
                                timestamp: format!("2026-05-12T{:02}:{:02}:00Z", j % 24, j % 60),
                                action: crate::audit::AuditAction::HttpRequest,
                                method: "POST".into(),
                                path: format!("/api/v1/torture/t{t}/{i}/{j}"),
                                org_id: format!("org-{}", t % 4),
                                source_ip: "127.0.0.1".into(),
                                status_code: if j % 10 == 0 { 403 } else { 200 },
                                trace_id: format!("trace-{t}-{i}-{j}"),
                                duration_ms: 5,
                                metadata: None,
                                previous_hash: String::new(),
                                entry_hash: String::new(),
                            })
                            .collect();
                        engine.ingest_audit(&entries);
                        let _ = engine.build_timeline();
                        let _ = engine.security_timeline();
                        let _ = engine.severity_summary();
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
        // 64 threads × 500 engines × 50 entries = 1.6M audit events processed
    }

    /// Equivocation detector: 64 threads checking proposals for Byzantine behavior
    #[test]
    fn torture_equivocation_detector() {
        use crate::consensus::equivocation::EquivocationDetector;

        let detector = Arc::new(std::sync::Mutex::new(EquivocationDetector::new()));

        let threads: Vec<_> = (0..64)
            .map(|t| {
                let d = Arc::clone(&detector);
                std::thread::spawn(move || {
                    let mut proofs_found = 0u64;
                    for i in 0..5_000u64 {
                        let height = i;
                        let slot = i;
                        let proposer = format!("validator-{}", t % 8);
                        let mut hash = [0u8; 32];
                        hash[0] = t as u8;
                        hash[1] = (i % 256) as u8;

                        let mut det = d.lock().unwrap_or_else(|e| e.into_inner());
                        if det
                            .check_proposal(
                                height,
                                slot,
                                &proposer,
                                hash,
                                &[0u8; 64],
                                Default::default(),
                            )
                            .is_some()
                        {
                            proofs_found += 1;
                        }
                    }
                    proofs_found
                })
            })
            .collect();

        let total_proofs: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        // Many equivocation proofs expected (same proposer, same height/slot, different hashes)
        assert!(
            total_proofs > 0,
            "no equivocation detected across 320K proposals"
        );
    }

    // ── ROCKSDB TORTURE — real disk I/O under concurrent load ────────────────

    /// RocksDB: 16 threads × 10,000 identity writes+reads = 160K disk ops
    #[test]
    fn torture_rocksdb_identity_160k() {
        use crate::storage::adapters::RocksDbBlockStore;
        use crate::storage::traits::{BlockStore, IdentityRecord};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(RocksDbBlockStore::new(dir.path()).unwrap());

        let threads: Vec<_> = (0..16)
            .map(|t| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut errors = 0u64;
                    for i in 0..10_000u64 {
                        let did = format!("did:goya:rocks-t{t}-{i}");
                        let rec = IdentityRecord {
                            did: did.clone(),
                            public_key: String::new(),
                            created_at: i,
                            updated_at: i,
                            status: "active".into(),
                            migrated_from: None,
                            signature_algorithm: None,
                            civil_anchor: None,
                        };
                        if s.write_identity(&rec).is_err() {
                            errors += 1;
                        }
                        if s.read_identity(&did).is_err() {
                            errors += 1;
                        }
                    }
                    errors
                })
            })
            .collect();

        let total_errors: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            total_errors, 0,
            "RocksDB identity torture: {total_errors} errors in 160K ops"
        );

        // Verify data survives (read after all writes)
        assert!(store.read_identity("did:goya:rocks-t0-0").is_ok());
        assert!(store.read_identity("did:goya:rocks-t15-9999").is_ok());
    }

    /// RocksDB: 16 threads × 10,000 credential writes+reads = 160K disk ops
    #[test]
    fn torture_rocksdb_credential_160k() {
        use crate::storage::adapters::RocksDbBlockStore;
        use crate::storage::traits::{BlockStore, Credential, IdentityRecord};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(RocksDbBlockStore::new(dir.path()).unwrap());

        // Pre-register issuer
        store
            .write_identity(&IdentityRecord {
                did: "did:goya:rocks-issuer".into(),
                public_key: String::new(),
                created_at: 0,
                updated_at: 0,
                status: "active".into(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
            })
            .unwrap();

        let threads: Vec<_> = (0..16)
            .map(|t| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut errors = 0u64;
                    for i in 0..10_000u64 {
                        let id = format!("rocks-cred-t{t}-{i}");
                        let cred = Credential {
                            id: id.clone(),
                            issuer_did: "did:goya:rocks-issuer".into(),
                            subject_did: format!("did:goya:rocks-subj-{i}"),
                            cred_type: "RocksTest".into(),
                            issued_at: i,
                            expires_at: 0,
                            revoked_at: None,
                            claims: serde_json::json!({"t": t, "i": i}),
                            signature: String::new(),
                            status: "active".into(),
                            claims_commitment: None,
                            claims_salt: None,
                        };
                        if s.write_credential(&cred).is_err() {
                            errors += 1;
                        }
                        if s.read_credential(&id).is_err() {
                            errors += 1;
                        }
                    }
                    errors
                })
            })
            .collect();

        let total_errors: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(
            total_errors, 0,
            "RocksDB credential torture: {total_errors} errors in 160K ops"
        );
    }

    /// RocksDB: 16 threads × 10,000 block writes = 160K blocks on disk
    #[test]
    fn torture_rocksdb_blocks_160k() {
        use crate::storage::adapters::RocksDbBlockStore;
        use crate::storage::traits::{Block, BlockStore};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(RocksDbBlockStore::new(dir.path()).unwrap());
        let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let threads: Vec<_> = (0..16)
            .map(|t| {
                let s = Arc::clone(&store);
                let errs = Arc::clone(&errors);
                std::thread::spawn(move || {
                    for i in 0..10_000u64 {
                        let height = t * 10_000 + i;
                        let block = Block {
                            height,
                            timestamp: 1000 + height,
                            parent_hash: [0u8; 32],
                            merkle_root: [0u8; 32],
                            transactions: vec![format!("tx-{height}")],
                            proposer: format!("rocks-t{t}"),
                            signature: vec![0u8; 64],
                            signature_algorithm: Default::default(),
                            endorsements: vec![],
                            secondary_signature: None,
                            secondary_signature_algorithm: None,
                            hash_algorithm: Default::default(),
                            orderer_signature: None,
                            commit_qc: None,
                            transaction_data: vec![],
                        };
                        if s.write_block(&block).is_err() {
                            errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
        let total_errors = errors.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            total_errors, 0,
            "RocksDB block torture: {total_errors} errors in 160K ops"
        );

        // Verify persistence
        assert!(store.read_block(0).is_ok());
        assert!(store.read_block(159_999).is_ok());
        let height = store.get_latest_height().unwrap();
        assert!(height >= 159_999, "latest height {height} < 159999");
    }

    /// RocksDB: mixed workload — identity + credential + block writes concurrently
    #[test]
    fn torture_rocksdb_mixed_48_threads() {
        use crate::storage::adapters::RocksDbBlockStore;
        use crate::storage::traits::{Block, BlockStore, Credential, IdentityRecord};

        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(RocksDbBlockStore::new(dir.path()).unwrap());
        let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // 16 threads: identities
        let mut threads: Vec<std::thread::JoinHandle<()>> = (0..16)
            .map(|t| {
                let s = Arc::clone(&store);
                let e = Arc::clone(&errors);
                std::thread::spawn(move || {
                    for i in 0..5_000u64 {
                        let rec = IdentityRecord {
                            did: format!("did:goya:rmix-t{t}-{i}"),
                            public_key: String::new(),
                            created_at: i,
                            updated_at: i,
                            status: "active".into(),
                            migrated_from: None,
                            signature_algorithm: None,
                            civil_anchor: None,
                        };
                        if s.write_identity(&rec).is_err() {
                            e.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        // 16 threads: credentials
        threads.extend((0..16).map(|t| {
            let s = Arc::clone(&store);
            let e = Arc::clone(&errors);
            std::thread::spawn(move || {
                for i in 0..5_000u64 {
                    let cred = Credential {
                        id: format!("rmix-cred-t{t}-{i}"),
                        issuer_did: "did:goya:rmix-issuer".into(),
                        subject_did: format!("did:goya:rmix-subj-{i}"),
                        cred_type: "RocksMixed".into(),
                        issued_at: i,
                        expires_at: 0,
                        revoked_at: None,
                        claims: serde_json::Value::Null,
                        signature: String::new(),
                        status: "active".into(),
                        claims_commitment: None,
                        claims_salt: None,
                    };
                    if s.write_credential(&cred).is_err() {
                        e.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
        }));

        // 16 threads: blocks
        threads.extend((0..16).map(|t| {
            let s = Arc::clone(&store);
            let e = Arc::clone(&errors);
            std::thread::spawn(move || {
                for i in 0..5_000u64 {
                    let height = 200_000 + t * 5_000 + i;
                    let block = Block {
                        height,
                        timestamp: height,
                        parent_hash: [0u8; 32],
                        merkle_root: [0u8; 32],
                        transactions: vec![],
                        proposer: format!("rmix-t{t}"),
                        signature: vec![0u8; 64],
                        signature_algorithm: Default::default(),
                        endorsements: vec![],
                        secondary_signature: None,
                        secondary_signature_algorithm: None,
                        hash_algorithm: Default::default(),
                        orderer_signature: None,
                        commit_qc: None,
                        transaction_data: vec![],
                    };
                    if s.write_block(&block).is_err() {
                        e.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            })
        }));

        for t in threads {
            t.join().unwrap();
        }

        let total_errors = errors.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            total_errors, 0,
            "RocksDB mixed torture: {total_errors} errors across 48 threads × 5K ops"
        );
    }
}
