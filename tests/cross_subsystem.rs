//! Cross-subsystem integration tests.
//!
//! These tests exercise multiple modules together to verify they integrate
//! correctly — something unit tests within each module cannot catch.

use std::sync::Arc;

use rust_bc::audit::{AuditAction, AuditStore, MemoryAuditStore};
use rust_bc::chaincode::sandbox::{validate, MemorySandboxReportStore, SandboxReportStore};
use rust_bc::legal_oracle::legal::{LegalOracle, LegalSourceConfig};
use rust_bc::legal_oracle::{MemoryOracleRecordStore, OracleRecordStore};
use rust_bc::storage::traits::{BlockStore, Credential, IdentityRecord};
use rust_bc::storage::MemoryStore;

// ── Identity → Credential → Audit ───────────────────────────────────────────

#[test]
fn identity_then_credential_produces_audit_trail() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let audit = Arc::new(MemoryAuditStore::new());

    // 1. Create identity
    let identity = IdentityRecord {
        did: "did:goya:alice".to_string(),
        public_key: "test_public_key".to_string(),
        created_at: 1000,
        updated_at: 1000,
        status: "active".to_string(),
        migrated_from: None,
        signature_algorithm: None,
        civil_anchor: None,
        recovery_commitment: None,
        vault_entries: Vec::new(),
    };
    store.write_identity(&identity).unwrap();
    rust_bc::audit::emit_domain_event(
        audit.as_ref(),
        AuditAction::DidRegistered,
        "org1",
        Some("did=did:goya:alice".to_string()),
    );

    // 2. Issue credential for that identity
    let credential = Credential {
        id: "cred-1".to_string(),
        issuer_did: "did:goya:university".to_string(),
        subject_did: "did:goya:alice".to_string(),
        cred_type: "Diploma".to_string(),
        issued_at: 1001,
        expires_at: 0,
        revoked_at: None,
        claims: serde_json::json!({"degree": "Computer Science"}),
        signature: String::new(),
        status: "active".to_string(),
        claims_commitment: None,
        claims_salt: None,
    };
    store.write_credential(&credential).unwrap();
    rust_bc::audit::emit_domain_event(
        audit.as_ref(),
        AuditAction::CredentialStored,
        "org1",
        Some("credential_id=cred-1".to_string()),
    );

    // 3. Verify: identity exists
    let read_id = store.read_identity("did:goya:alice").unwrap();
    assert_eq!(read_id.status, "active");

    // 4. Verify: credential linked to identity
    let creds = store.credentials_by_subject_did("did:goya:alice").unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].cred_type, "Diploma");

    // 5. Verify: audit trail has both events
    let events = audit.query(None, None, None, None, 100).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].action, AuditAction::DidRegistered);
    assert_eq!(events[1].action, AuditAction::CredentialStored);

    // 6. Verify: can filter audit by action
    let did_events = audit
        .query(None, None, None, Some(&AuditAction::DidRegistered), 100)
        .unwrap();
    assert_eq!(did_events.len(), 1);
}

// ── Chaincode Install → Sandbox → Audit ─────────────────────────────────────

#[test]
fn chaincode_install_triggers_sandbox_and_audit() {
    let sandbox_store = MemorySandboxReportStore::new();
    let audit = MemoryAuditStore::new();

    // Valid Wasm (minimal module)
    let valid_wasm: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // 1. Run sandbox validation
    let report = validate("mycc", "1.0", valid_wasm);
    assert!(report.passed);

    // 2. Store report
    sandbox_store.store_report(&report);

    // 3. Emit audit event
    rust_bc::audit::emit_domain_event(
        &audit,
        AuditAction::ChaincodeInstalled,
        "org1",
        Some("cc_id=mycc,version=1.0".to_string()),
    );

    // 4. Verify: sandbox report retrievable
    let stored = sandbox_store.get_report("mycc", "1.0").unwrap();
    assert!(stored.passed);

    // 5. Verify: audit event recorded
    let events = audit
        .query(
            None,
            None,
            None,
            Some(&AuditAction::ChaincodeInstalled),
            100,
        )
        .unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].metadata.as_ref().unwrap().contains("cc_id=mycc"));
}

#[test]
fn malformed_chaincode_fails_sandbox_before_audit() {
    let sandbox_store = MemorySandboxReportStore::new();
    let audit = MemoryAuditStore::new();

    // Invalid Wasm
    let report = validate("badcc", "1.0", b"not wasm");
    assert!(!report.passed);

    // Store failed report
    sandbox_store.store_report(&report);

    // NO audit event — chaincode was rejected
    let events = audit.query(None, None, None, None, 100).unwrap();
    assert_eq!(events.len(), 0);

    // Failed report is still queryable
    let stored = sandbox_store.get_report("badcc", "1.0").unwrap();
    assert!(!stored.passed);
}

// ── Legal Oracle → Audit ─────────────────────────────────────────────────────

#[test]
fn legal_oracle_query_stores_record_and_emits_audit() {
    let oracle_store = MemoryOracleRecordStore::new();
    let audit = MemoryAuditStore::new();

    let mut oracle = LegalOracle::new(300);
    oracle.register_source(LegalSourceConfig {
        id: "bcn".to_string(),
        base_url: "https://api.bcn.cl".to_string(),
        api_key: None,
    });

    // Query with mock fetch
    let record = oracle
        .query("bcn", "ley 21663", &oracle_store, |_config, _query| {
            Ok(br#"{"titulo": "Ley 21.663"}"#.to_vec())
        })
        .unwrap();

    // Emit audit
    rust_bc::audit::emit_domain_event(
        &audit,
        AuditAction::ProposalSubmitted,
        "org1",
        Some(format!("legal_oracle_query,source=bcn,id={}", record.id)),
    );

    // Verify: record in oracle store
    let stored = oracle_store.get(&record.id).unwrap().unwrap();
    assert_eq!(stored.source, "bcn");
    assert_eq!(stored.summary.as_deref(), Some("Ley 21.663"));

    // Verify: audit event
    let events = audit.query(None, None, None, None, 100).unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].metadata.as_ref().unwrap().contains("bcn"));
}

// ── Credential → Commitment Verification ────────────────────────────────────

#[test]
fn credential_to_commitment_range_proof_end_to_end() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());

    // 1. Store credential with age claim
    let credential = Credential {
        id: "cred-age".to_string(),
        issuer_did: "did:goya:gov".to_string(),
        subject_did: "did:goya:bob".to_string(),
        cred_type: "AgeVerification".to_string(),
        issued_at: 1000,
        expires_at: 0,
        revoked_at: None,
        claims: serde_json::json!({"age": 25}),
        signature: String::new(),
        status: "active".to_string(),
        claims_commitment: None,
        claims_salt: None,
    };
    store.write_credential(&credential).unwrap();

    // 2. Read credential and extract age
    let cred = store.read_credential("cred-age").unwrap();
    let age = cred.claims["age"].as_u64().unwrap();

    // 3. Generate range proof: age >= 18
    let presentation = rust_bc::identity::zkp::prove_range("cred-age", "age", age, 18).unwrap();

    // 4. Verify proof
    let valid = rust_bc::identity::zkp::verify_presentation(&presentation).unwrap();
    assert!(valid);
}

#[test]
fn credential_revocation_invalidates_validity_proof() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());

    // 1. Store active credential
    let mut credential = Credential {
        id: "cred-rev".to_string(),
        issuer_did: "did:goya:issuer".to_string(),
        subject_did: "did:goya:holder".to_string(),
        cred_type: "License".to_string(),
        issued_at: 1000,
        expires_at: 0,
        revoked_at: None,
        claims: serde_json::json!({}),
        signature: String::new(),
        status: "active".to_string(),
        claims_commitment: None,
        claims_salt: None,
    };
    store.write_credential(&credential).unwrap();

    // 2. Prove validity — should succeed
    let result = rust_bc::identity::zkp::prove_credential_validity(
        "cred-rev",
        &credential.status,
        credential.expires_at,
        credential.revoked_at,
    );
    assert!(result.is_ok());

    // 3. Revoke credential
    credential.revoked_at = Some(2000);
    credential.status = "revoked".to_string();
    store.write_credential(&credential).unwrap();

    // 4. Re-read and try to prove validity — should fail
    let cred = store.read_credential("cred-rev").unwrap();
    let result = rust_bc::identity::zkp::prove_credential_validity(
        "cred-rev",
        &cred.status,
        cred.expires_at,
        cred.revoked_at,
    );
    assert!(result.is_err());
}

// ── Multi-org audit isolation ───────────────────────────────────────────────

#[test]
fn audit_events_filterable_by_org() {
    let audit = MemoryAuditStore::new();

    // Org1 actions
    rust_bc::audit::emit_domain_event(
        &audit,
        AuditAction::BlockMined,
        "org1",
        Some("height=1".to_string()),
    );
    rust_bc::audit::emit_domain_event(
        &audit,
        AuditAction::DidRegistered,
        "org1",
        Some("did=did:goya:a".to_string()),
    );

    // Org2 actions
    rust_bc::audit::emit_domain_event(
        &audit,
        AuditAction::ChaincodeInstalled,
        "org2",
        Some("cc_id=cc1".to_string()),
    );

    // Filter by org
    let org1 = audit.query(None, None, Some("org1"), None, 100).unwrap();
    assert_eq!(org1.len(), 2);

    let org2 = audit.query(None, None, Some("org2"), None, 100).unwrap();
    assert_eq!(org2.len(), 1);
    assert_eq!(org2[0].action, AuditAction::ChaincodeInstalled);

    // Combined: org1 + action filter
    let org1_blocks = audit
        .query(
            None,
            None,
            Some("org1"),
            Some(&AuditAction::BlockMined),
            100,
        )
        .unwrap();
    assert_eq!(org1_blocks.len(), 1);
}
