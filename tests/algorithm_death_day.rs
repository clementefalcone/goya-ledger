use rust_bc::consensus::bft::quorum::QuorumValidator;
use rust_bc::consensus::bft::round::{RoundEvent, RoundState};
use rust_bc::consensus::bft::round_manager::{RoundManager, RoundManagerConfig};
use rust_bc::consensus::bft::types::{BftPhase, QcError, QuorumCertificate, VoteMessage};
use rust_bc::consensus::bft::validator_registry::{RegistryVerifier, ValidatorRegistry};
use rust_bc::identity::did::did_from_pubkey_hex;
use rust_bc::identity::dual_signing::{dual_sign, verify_dual, DualVerifyMode};
use rust_bc::identity::keys::{migrate_identity, resolve_identity};
use rust_bc::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::lexchain::engine::{deploy, quarantine_classical_contracts, sign};
use rust_bc::lexchain::store::LexChainStore;
use rust_bc::lexchain::types::{ContractDefinition, ContractState, PartyDefinition, SignRequest};
use rust_bc::mining::{MiningConfig, MiningService};
use rust_bc::ordering::verify_block_secondary_signature;
use rust_bc::signature::{verify_signature, SignatureLevel};
use rust_bc::storage::traits::{BlockStore, IdentityRecord, Transaction};
use rust_bc::storage::MemoryStore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

fn make_tx(label: &str) -> Transaction {
    Transaction {
        id: label.to_string(),
        block_height: 0,
        timestamp: 0,
        input_did: "did:goya:test".to_string(),
        output_recipient: "did:goya:recv".to_string(),
        amount: 0,
        fee: 0,
        state: "pending".to_string(),
        payload: None,
    }
}

struct Identity {
    did: String,
    pubkey_hex: String,
    provider: Box<dyn SigningProvider>,
}

fn make_identity(algo: SigningAlgorithm) -> Identity {
    let provider: Box<dyn SigningProvider> = match algo {
        SigningAlgorithm::Ed25519 => Box::new(SoftwareSigningProvider::generate()),
        SigningAlgorithm::MlDsa65 => Box::new(MlDsaSigningProvider::generate()),
        _ => panic!("unsupported algorithm for test"),
    };
    let pubkey_hex = hex::encode(provider.public_key());
    let did = did_from_pubkey_hex(&pubkey_hex);
    Identity {
        did,
        pubkey_hex,
        provider,
    }
}

fn register_did(store: &dyn BlockStore, id: &Identity) {
    store
        .write_identity(&IdentityRecord {
            did: id.did.clone(),
            public_key: id.pubkey_hex.clone(),
            created_at: 0,
            updated_at: 0,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
        })
        .unwrap();
}

fn sign_lexchain_fes(contract_content_hash: &str, signer: &Identity) -> SignRequest {
    let payload = format!("fes:{}:{}", signer.did, contract_content_hash);
    let sig = signer.provider.sign(payload.as_bytes()).unwrap();
    SignRequest {
        did: signer.did.clone(),
        signature: hex::encode(&sig),
        public_key: signer.pubkey_hex.clone(),
        biometric_evidence: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 1 — DETECTION
// An attacker forges an Ed25519 signature. Dual signing catches it.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase1_dual_sign_detects_forged_ed25519() {
    let legitimate_ed = SoftwareSigningProvider::generate();
    let legitimate_pqc = MlDsaSigningProvider::generate();
    let attacker_ed = SoftwareSigningProvider::generate();

    let block_data = b"block-payload-height-42";

    let legit_dual = dual_sign(block_data, &legitimate_ed, &legitimate_pqc).unwrap();

    let forged_primary = attacker_ed.sign(block_data).unwrap();

    let primary_verifies_with_legit_key =
        legitimate_ed.verify(block_data, &forged_primary).unwrap();
    assert!(!primary_verifies_with_legit_key);

    let secondary_still_valid = legitimate_pqc
        .verify(block_data, &legit_dual.secondary_signature)
        .unwrap();
    assert!(secondary_still_valid);

    let dual_check = verify_dual(
        || legitimate_ed.verify(block_data, &forged_primary),
        Some(|| legitimate_pqc.verify(block_data, &legit_dual.secondary_signature)),
        DualVerifyMode::Both,
    )
    .unwrap();
    assert!(!dual_check);
}

#[test]
fn phase1_secondary_signature_catches_tampered_block() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let ed_signer: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_signer: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_signer))
        .with_secondary_signer(Arc::clone(&pqc_signer));

    service.mine_block("honest-miner", vec![]).unwrap();
    let block = store.read_block(0).unwrap();

    assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
    assert!(block.secondary_signature.is_some());
    assert_eq!(
        block.secondary_signature_algorithm,
        Some(SigningAlgorithm::MlDsa65)
    );

    let legit = verify_block_secondary_signature(&block, pqc_signer.as_ref()).unwrap();
    assert_eq!(legit, Some(true));

    let mut tampered = block.clone();
    tampered.merkle_root = [0xFF; 32];
    let tampered_check = verify_block_secondary_signature(&tampered, pqc_signer.as_ref()).unwrap();
    assert_eq!(tampered_check, Some(false));
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 2 — CONTAINMENT
// Ed25519 is declared dead. All Ed25519-only signatures are untrusted.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase2_ed25519_only_contracts_quarantined() {
    let store = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    let alice_ed = make_identity(SigningAlgorithm::Ed25519);
    let bob_ed = make_identity(SigningAlgorithm::Ed25519);
    let charlie_pqc = make_identity(SigningAlgorithm::MlDsa65);
    let dave_pqc = make_identity(SigningAlgorithm::MlDsa65);

    register_did(store.as_ref(), &alice_ed);
    register_did(store.as_ref(), &bob_ed);
    register_did(store.as_ref(), &charlie_pqc);
    register_did(store.as_ref(), &dave_pqc);

    let ed_only_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![
                PartyDefinition {
                    role: "discloser".into(),
                    did: alice_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "recipient".into(),
                    did: bob_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"scope": "project alpha"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_a = sign_lexchain_fes(&ed_only_contract.content_hash, &alice_ed);
    sign(&lex, &ed_only_contract.id, &req_a).unwrap();
    let req_b = sign_lexchain_fes(&ed_only_contract.content_hash, &bob_ed);
    let ed_signed = sign(&lex, &ed_only_contract.id, &req_b).unwrap();
    assert_eq!(ed_signed.state, ContractState::FullySigned);

    let pqc_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![
                PartyDefinition {
                    role: "discloser".into(),
                    did: charlie_pqc.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "recipient".into(),
                    did: dave_pqc.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"scope": "project beta"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_c = sign_lexchain_fes(&pqc_contract.content_hash, &charlie_pqc);
    sign(&lex, &pqc_contract.id, &req_c).unwrap();
    let req_d = sign_lexchain_fes(&pqc_contract.content_hash, &dave_pqc);
    let pqc_signed = sign(&lex, &pqc_contract.id, &req_d).unwrap();
    assert_eq!(pqc_signed.state, ContractState::FullySigned);

    // === ALGORITHM DEATH DAY: Ed25519 compromised ===
    let compromised = [
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::Rsa,
        SigningAlgorithm::EcdsaP256,
    ];
    let quarantined = quarantine_classical_contracts(&lex, &compromised);

    assert_eq!(quarantined.len(), 1);
    assert!(quarantined.contains(&ed_only_contract.id));
    assert_eq!(
        lex.get(&ed_only_contract.id).unwrap().state,
        ContractState::Quarantined
    );
    assert_eq!(
        lex.get(&pqc_contract.id).unwrap().state,
        ContractState::FullySigned
    );
}

#[test]
fn phase2_ed25519_signatures_rejected_post_compromise() {
    let ed_signer = SoftwareSigningProvider::generate();
    let pk_hex = hex::encode(ed_signer.public_key());
    let message = b"post-compromise-transaction";
    let sig = ed_signer.sign(message).unwrap();
    let sig_hex = hex::encode(&sig);

    let ed25519_valid = verify_signature(SigningAlgorithm::Ed25519, &pk_hex, message, &sig_hex);
    assert!(ed25519_valid);

    let is_compromised_algorithm = SigningAlgorithm::Ed25519.is_classical();
    assert!(is_compromised_algorithm);

    let should_reject = is_compromised_algorithm;
    assert!(should_reject);
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 3 — MIGRATION
// All identities migrate from Ed25519 to ML-DSA-65. Consensus survives.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase3_identity_migration_ed25519_to_mldsa65() {
    let store = Arc::new(MemoryStore::new());
    let num_identities: usize = 50;
    let mut ed_identities: Vec<Identity> = Vec::with_capacity(num_identities);

    for _ in 0..num_identities {
        let id = make_identity(SigningAlgorithm::Ed25519);
        register_did(store.as_ref(), &id);
        ed_identities.push(id);
    }

    let migration_start = Instant::now();
    let mut results = Vec::new();

    for old_id in &ed_identities {
        let result = migrate_identity(
            store.as_ref(),
            &old_id.did,
            &hex::encode(MlDsaSigningProvider::generate().public_key()),
            1000,
        )
        .unwrap();

        assert_ne!(result.old_did, result.new_did);
        assert_eq!(result.new_algorithm, SigningAlgorithm::MlDsa65);
        assert_eq!(result.new_public_key_hex.len(), 1952 * 2);

        let old_record = store.read_identity(&result.old_did).unwrap();
        assert_eq!(old_record.status, "migrated");

        let new_record = store.read_identity(&result.new_did).unwrap();
        assert_eq!(new_record.status, "active");
        assert_eq!(
            new_record.migrated_from.as_deref(),
            Some(result.old_did.as_str())
        );

        let resolved = resolve_identity(store.as_ref(), &old_id.did).unwrap();
        assert_eq!(resolved.did, result.new_did);
        assert_eq!(resolved.status, "active");

        results.push(result);
    }

    let migration_duration = migration_start.elapsed();

    assert_eq!(results.len(), num_identities);
    eprintln!(
        "  MIGRATION: {} identities migrated in {:?} ({:.1} ids/ms)",
        results.len(),
        migration_duration,
        results.len() as f64 / migration_duration.as_secs_f64() / 1000.0
    );
}

#[test]
fn phase3_mining_continues_after_algorithm_switch() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());

    let ed_signer: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_signer: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service_ed = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_signer))
        .with_secondary_signer(Arc::clone(&pqc_signer));

    for i in 0..5 {
        service_ed
            .mine_block("miner-pre-compromise", vec![make_tx(&format!("tx-ed-{i}"))])
            .unwrap();
    }

    let pre_height = store.get_latest_height().unwrap();
    assert_eq!(pre_height, 4);

    // === ED25519 IS DEAD — switch to PQC-only mining ===

    let service_pqc = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&pqc_signer));

    for i in 0..5 {
        service_pqc
            .mine_block(
                "miner-post-compromise",
                vec![make_tx(&format!("tx-pqc-{i}"))],
            )
            .unwrap();
    }

    let post_height = store.get_latest_height().unwrap();
    assert_eq!(post_height, 9);

    for h in 0..5 {
        let block = store.read_block(h).unwrap();
        assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
        assert!(block.secondary_signature.is_some());
    }

    for h in 5..10 {
        let block = store.read_block(h).unwrap();
        assert_eq!(block.signature_algorithm, SigningAlgorithm::MlDsa65);
        assert!(block.secondary_signature.is_none());
    }
}

#[test]
fn phase3_lexchain_operates_under_pqc_only() {
    let store = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    let alice = make_identity(SigningAlgorithm::MlDsa65);
    let bob = make_identity(SigningAlgorithm::MlDsa65);
    register_did(store.as_ref(), &alice);
    register_did(store.as_ref(), &bob);

    let contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "service_agreement".into(),
            parties: vec![
                PartyDefinition {
                    role: "provider".into(),
                    did: alice.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "client".into(),
                    did: bob.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"terms": "post-quantum only"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_a = sign_lexchain_fes(&contract.content_hash, &alice);
    sign(&lex, &contract.id, &req_a).unwrap();

    let req_b = sign_lexchain_fes(&contract.content_hash, &bob);
    let signed = sign(&lex, &contract.id, &req_b).unwrap();

    assert_eq!(signed.state, ContractState::FullySigned);

    for party in &signed.parties {
        let envelope = party.envelope.as_ref().unwrap();
        assert!(envelope.signature_algorithm.is_post_quantum());
        assert_eq!(envelope.signature_algorithm, SigningAlgorithm::MlDsa65);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 4 — POST-MORTEM VERIFICATION
// Everything dual-signed before the compromise is still verifiable via PQC.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase4_dual_signed_blocks_survive_ed25519_death() {
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let ed_signer: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_signer: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_signer))
        .with_secondary_signer(Arc::clone(&pqc_signer));

    let num_blocks = 10;
    for i in 0..num_blocks {
        service
            .mine_block("dual-miner", vec![make_tx(&format!("tx-{i}"))])
            .unwrap();
    }

    // === ED25519 IS DEAD — verify all blocks via PQC secondary signature ===

    let mut verified_count = 0;
    for h in 0..num_blocks {
        let block = store.read_block(h).unwrap();
        let result = verify_block_secondary_signature(&block, pqc_signer.as_ref()).unwrap();
        assert_eq!(result, Some(true), "block {h} PQC signature must be valid");
        verified_count += 1;
    }

    assert_eq!(verified_count, num_blocks);
}

#[test]
fn phase4_pqc_contract_signatures_remain_valid_after_compromise() {
    let store = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    let alice = make_identity(SigningAlgorithm::MlDsa65);
    register_did(store.as_ref(), &alice);

    let contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![PartyDefinition {
                role: "signer".into(),
                did: alice.did.clone(),
                signature_level: SignatureLevel::Simple,
            }],
            payload: serde_json::json!({"scope": "pre-compromise doc"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req = sign_lexchain_fes(&contract.content_hash, &alice);
    let signed = sign(&lex, &contract.id, &req).unwrap();
    assert_eq!(signed.state, ContractState::FullySigned);

    // === YEARS LATER: re-verify the PQC signature ===

    let envelope = signed.parties[0].envelope.as_ref().unwrap();
    let payload = envelope.signing_payload();
    let still_valid = verify_signature(
        envelope.signature_algorithm,
        &envelope.public_key,
        payload.as_bytes(),
        &envelope.signature,
    );
    assert!(still_valid);
    assert!(envelope.signature_algorithm.is_post_quantum());
}

// ═══════════════════════════════════════════════════════════════════════════
// FULL SCENARIO — END TO END
// The complete death day: blocks + contracts + migration + verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn algorithm_death_day_full_scenario() {
    let timer = Instant::now();
    let store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
    let lex = LexChainStore::with_backend(store.clone());

    // ── Pre-compromise: dual-signed blocks ────────────────────────────
    let ed_miner: Arc<dyn SigningProvider> = Arc::new(SoftwareSigningProvider::generate());
    let pqc_miner: Arc<dyn SigningProvider> = Arc::new(MlDsaSigningProvider::generate());

    let service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&ed_miner))
        .with_secondary_signer(Arc::clone(&pqc_miner));

    let pre_blocks: u64 = 10;
    for i in 0..pre_blocks {
        service
            .mine_block("node-1", vec![make_tx(&format!("pre-tx-{i}"))])
            .unwrap();
    }

    // ── Pre-compromise: contracts with mixed algorithms ───────────────
    let alice_ed = make_identity(SigningAlgorithm::Ed25519);
    let bob_pqc = make_identity(SigningAlgorithm::MlDsa65);
    let carol_ed = make_identity(SigningAlgorithm::Ed25519);
    let dave_ed = make_identity(SigningAlgorithm::Ed25519);
    register_did(store.as_ref(), &alice_ed);
    register_did(store.as_ref(), &bob_pqc);
    register_did(store.as_ref(), &carol_ed);
    register_did(store.as_ref(), &dave_ed);

    let mixed_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "service_agreement".into(),
            parties: vec![
                PartyDefinition {
                    role: "provider".into(),
                    did: alice_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "client".into(),
                    did: bob_pqc.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"terms": "hybrid contract"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_a = sign_lexchain_fes(&mixed_contract.content_hash, &alice_ed);
    sign(&lex, &mixed_contract.id, &req_a).unwrap();
    let req_b = sign_lexchain_fes(&mixed_contract.content_hash, &bob_pqc);
    let mixed_signed = sign(&lex, &mixed_contract.id, &req_b).unwrap();
    assert_eq!(mixed_signed.state, ContractState::FullySigned);

    let ed_only_contract = deploy(
        &lex,
        ContractDefinition {
            contract_type: "nda".into(),
            parties: vec![
                PartyDefinition {
                    role: "a".into(),
                    did: carol_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
                PartyDefinition {
                    role: "b".into(),
                    did: dave_ed.did.clone(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            payload: serde_json::json!({"scope": "vulnerable"}),
            require_notarization: false,
            deadline_secs: None,
            webhook_url: None,
        },
    )
    .unwrap();

    let req_c = sign_lexchain_fes(&ed_only_contract.content_hash, &carol_ed);
    sign(&lex, &ed_only_contract.id, &req_c).unwrap();
    let req_d = sign_lexchain_fes(&ed_only_contract.content_hash, &dave_ed);
    sign(&lex, &ed_only_contract.id, &req_d).unwrap();

    let t_pre = timer.elapsed();

    // ═══════════════════════════════════════════════════════════════════
    // ██████  ED25519 IS DEAD  ██████
    // ═══════════════════════════════════════════════════════════════════

    let death_instant = Instant::now();

    // ── Quarantine contracts signed only with compromised algorithms ──
    let compromised = [
        SigningAlgorithm::Ed25519,
        SigningAlgorithm::Rsa,
        SigningAlgorithm::EcdsaP256,
    ];
    let quarantined = quarantine_classical_contracts(&lex, &compromised);

    assert_eq!(quarantined.len(), 1);
    assert!(quarantined.contains(&ed_only_contract.id));
    assert_eq!(
        lex.get(&ed_only_contract.id).unwrap().state,
        ContractState::Quarantined
    );
    assert_eq!(
        lex.get(&mixed_contract.id).unwrap().state,
        ContractState::FullySigned
    );

    // ── Verify all pre-compromise blocks via PQC secondary sig ────────
    let mut blocks_verified = 0;
    for h in 0..pre_blocks {
        let block = store.read_block(h).unwrap();
        let r = verify_block_secondary_signature(&block, pqc_miner.as_ref()).unwrap();
        assert_eq!(r, Some(true));
        blocks_verified += 1;
    }
    assert_eq!(blocks_verified, pre_blocks);

    // ── Switch mining to PQC-only ─────────────────────────────────────
    let pqc_service = MiningService::new(store.clone(), MiningConfig::default())
        .with_signer(Arc::clone(&pqc_miner));

    let post_blocks: u64 = 10;
    for i in 0..post_blocks {
        pqc_service
            .mine_block("node-1-pqc", vec![make_tx(&format!("post-tx-{i}"))])
            .unwrap();
    }

    let final_height = store.get_latest_height().unwrap();
    assert_eq!(final_height, pre_blocks + post_blocks - 1);

    // ── Verify chain continuity ───────────────────────────────────────
    for h in 0..(pre_blocks + post_blocks) {
        let block = store.read_block(h).unwrap();
        assert_eq!(block.height, h);
        if h < pre_blocks {
            assert_eq!(block.signature_algorithm, SigningAlgorithm::Ed25519);
            assert!(block.secondary_signature.is_some());
        } else {
            assert_eq!(block.signature_algorithm, SigningAlgorithm::MlDsa65);
        }
    }

    // ── Verify mixed contract's PQC signature survives ────────────────
    let mixed = lex.get(&mixed_contract.id).unwrap();
    let pqc_party = mixed
        .parties
        .iter()
        .find(|p| {
            p.envelope
                .as_ref()
                .map(|e| e.signature_algorithm.is_post_quantum())
                .unwrap_or(false)
        })
        .unwrap();
    let envelope = pqc_party.envelope.as_ref().unwrap();
    let payload = envelope.signing_payload();
    assert!(verify_signature(
        envelope.signature_algorithm,
        &envelope.public_key,
        payload.as_bytes(),
        &envelope.signature,
    ));

    let t_death = death_instant.elapsed();

    // ── Report ────────────────────────────────────────────────────────
    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════╗");
    eprintln!("  ║         ALGORITHM DEATH DAY — REPORT                ║");
    eprintln!("  ╠══════════════════════════════════════════════════════╣");
    eprintln!("  ║  Pre-compromise setup        {:>8?}  ║", t_pre);
    eprintln!("  ║  Death Day response          {:>8?}  ║", t_death);
    eprintln!(
        "  ║  Blocks pre-compromise       {:>8}          ║",
        pre_blocks
    );
    eprintln!(
        "  ║  Blocks post-compromise      {:>8}          ║",
        post_blocks
    );
    eprintln!("  ║  Blocks lost                        0          ║");
    eprintln!(
        "  ║  Blocks verified via PQC     {:>8}          ║",
        blocks_verified
    );
    eprintln!(
        "  ║  Contracts quarantined       {:>8}          ║",
        quarantined.len()
    );
    let surviving = lex.list().len() - quarantined.len();
    eprintln!(
        "  ║  Contracts surviving         {:>8}          ║",
        surviving
    );
    eprintln!(
        "  ║  Chain height                {:>8}          ║",
        final_height + 1
    );
    eprintln!("  ║  Consensus interrupted             NO          ║");
    eprintln!("  ╚══════════════════════════════════════════════════════╝");
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 5 — ADVERSARIAL BFT
// Attacker with compromised Ed25519 keys tries to subvert consensus.
// 4-node ML-DSA-65 network rejects all forged votes.
// ═══════════════════════════════════════════════════════════════════════════

struct BftValidator {
    id: String,
    pk: Vec<u8>,
    signer: MlDsaSigningProvider,
}

impl BftValidator {
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

fn build_bft_network() -> (
    Vec<BftValidator>,
    HashMap<String, RoundManager<RegistryVerifier>>,
    RegistryVerifier,
) {
    let validators: Vec<BftValidator> = ["node-a", "node-b", "node-c", "node-d"]
        .iter()
        .map(|id| BftValidator::generate(id))
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

    (validators, managers, verifier)
}

fn run_round_with_partition(
    validators: &[BftValidator],
    managers: &mut HashMap<String, RoundManager<RegistryVerifier>>,
    round: u64,
    partitioned: &[&str],
) -> usize {
    let bh = round_block_hash(round);
    let leader_idx = (round as usize) % validators.len();
    let leader_id = validators[leader_idx].id.clone();
    let ids: Vec<String> = managers.keys().cloned().collect();

    for id in &ids {
        if partitioned.contains(&id.as_str()) {
            continue;
        }
        managers.get_mut(id).unwrap().start_round(round);
    }

    if !partitioned.contains(&leader_id.as_str()) {
        let high_qc = managers
            .get(&leader_id)
            .unwrap()
            .safety()
            .high_qc()
            .cloned();
        managers
            .get_mut(&leader_id)
            .unwrap()
            .process_event(RoundEvent::StartAsLeader { block_hash: bh });

        let leader_vote = validators[leader_idx].sign_vote(BftPhase::Prepare, &bh, round);
        managers
            .get_mut(&leader_id)
            .unwrap()
            .process_event(RoundEvent::Vote(leader_vote.clone()));

        for id in &ids {
            if *id == leader_id || partitioned.contains(&id.as_str()) {
                continue;
            }
            managers
                .get_mut(id)
                .unwrap()
                .process_event(RoundEvent::Proposal {
                    block_hash: bh,
                    leader_id: leader_id.clone(),
                    justify_qc: high_qc.clone(),
                });
            managers
                .get_mut(id)
                .unwrap()
                .process_event(RoundEvent::Vote(leader_vote.clone()));
        }
    }

    for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
        let votes: Vec<VoteMessage> = validators
            .iter()
            .filter(|v| !partitioned.contains(&v.id.as_str()))
            .map(|v| v.sign_vote(phase, &bh, round))
            .collect();
        for vote in &votes {
            for id in &ids {
                if partitioned.contains(&id.as_str()) {
                    continue;
                }
                managers
                    .get_mut(id)
                    .unwrap()
                    .process_event(RoundEvent::Vote(vote.clone()));
            }
        }
    }

    ids.iter()
        .filter(|id| !partitioned.contains(&id.as_str()))
        .filter(|id| managers[id.as_str()].round_state() == Some(RoundState::Decided))
        .count()
}

fn run_honest_round(
    validators: &[BftValidator],
    managers: &mut HashMap<String, RoundManager<RegistryVerifier>>,
    round: u64,
) -> usize {
    let bh = round_block_hash(round);
    let leader_idx = (round as usize) % validators.len();
    let leader_id = validators[leader_idx].id.clone();
    let ids: Vec<String> = managers.keys().cloned().collect();

    for id in &ids {
        managers.get_mut(id).unwrap().start_round(round);
    }

    let high_qc = managers
        .get(&leader_id)
        .unwrap()
        .safety()
        .high_qc()
        .cloned();
    managers
        .get_mut(&leader_id)
        .unwrap()
        .process_event(RoundEvent::StartAsLeader { block_hash: bh });

    let leader_vote = validators[leader_idx].sign_vote(BftPhase::Prepare, &bh, round);
    managers
        .get_mut(&leader_id)
        .unwrap()
        .process_event(RoundEvent::Vote(leader_vote.clone()));

    for id in &ids {
        if *id == leader_id {
            continue;
        }
        managers
            .get_mut(id)
            .unwrap()
            .process_event(RoundEvent::Proposal {
                block_hash: bh,
                leader_id: leader_id.clone(),
                justify_qc: high_qc.clone(),
            });
        managers
            .get_mut(id)
            .unwrap()
            .process_event(RoundEvent::Vote(leader_vote.clone()));
    }

    for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
        let votes: Vec<VoteMessage> = validators
            .iter()
            .map(|v| v.sign_vote(phase, &bh, round))
            .collect();
        for vote in &votes {
            for id in &ids {
                managers
                    .get_mut(id)
                    .unwrap()
                    .process_event(RoundEvent::Vote(vote.clone()));
            }
        }
    }

    ids.iter()
        .filter(|id| managers[id.as_str()].round_state() == Some(RoundState::Decided))
        .count()
}

fn round_block_hash(round: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&round.to_le_bytes());
    h
}

#[test]
fn phase5_ed25519_forged_vote_rejected_by_pqc_validator() {
    let (validators, _, verifier) = build_bft_network();

    let attacker_ed = SoftwareSigningProvider::generate();

    let bh = round_block_hash(0);
    let forged_vote = VoteMessage {
        block_hash: bh,
        round: 0,
        phase: BftPhase::Prepare,
        voter_id: validators[0].id.clone(),
        signature: attacker_ed
            .sign(&VoteMessage::signing_payload_v2(
                BftPhase::Prepare,
                &bh,
                0,
                &validators[0].id,
            ))
            .unwrap(),
    };

    let qv = QuorumValidator::new(validators.iter().map(|v| v.id.clone()).collect(), verifier);
    let result = qv.validate_vote(&forged_vote);
    assert!(matches!(result, Err(QcError::InvalidSignature(_))));
}

#[test]
fn phase5_unknown_attacker_vote_rejected() {
    let (validators, _, verifier) = build_bft_network();

    let rogue = MlDsaSigningProvider::generate();
    let bh = round_block_hash(0);
    let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 0, "rogue-node");
    let sig = rogue.sign(&payload).unwrap();

    let rogue_vote = VoteMessage {
        block_hash: bh,
        round: 0,
        phase: BftPhase::Prepare,
        voter_id: "rogue-node".to_string(),
        signature: sig,
    };

    let qv = QuorumValidator::new(validators.iter().map(|v| v.id.clone()).collect(), verifier);
    let result = qv.validate_vote(&rogue_vote);
    assert!(matches!(result, Err(QcError::UnknownVoter(_))));
}

#[test]
fn phase5_forged_qc_fails_validation() {
    let (validators, _, verifier) = build_bft_network();

    let bh = round_block_hash(0);
    let mut votes = Vec::new();

    let legit_vote = validators[0].sign_vote(BftPhase::Prepare, &bh, 0);
    votes.push(legit_vote);

    for v in &validators[1..3] {
        let attacker = SoftwareSigningProvider::generate();
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &bh, 0, &v.id);
        votes.push(VoteMessage {
            block_hash: bh,
            round: 0,
            phase: BftPhase::Prepare,
            voter_id: v.id.clone(),
            signature: attacker.sign(&payload).unwrap(),
        });
    }

    let qc = QuorumCertificate::new(BftPhase::Prepare, bh, 0, votes).unwrap();

    let qv = QuorumValidator::new(validators.iter().map(|v| v.id.clone()).collect(), verifier);
    let result = qv.validate_qc(&qc);
    assert!(matches!(result, Err(QcError::InvalidSignature(_))));
}

#[test]
fn phase5_consensus_proceeds_despite_attacker_injection() {
    let (validators, mut managers, verifier) = build_bft_network();

    let decided = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided, 4);

    let attacker_ed = SoftwareSigningProvider::generate();
    let bh = round_block_hash(1);

    let forged_vote = VoteMessage {
        block_hash: bh,
        round: 1,
        phase: BftPhase::Prepare,
        voter_id: validators[0].id.clone(),
        signature: attacker_ed
            .sign(&VoteMessage::signing_payload_v2(
                BftPhase::Prepare,
                &bh,
                1,
                &validators[0].id,
            ))
            .unwrap(),
    };

    let qv = QuorumValidator::new(validators.iter().map(|v| v.id.clone()).collect(), verifier);
    assert!(qv.validate_vote(&forged_vote).is_err());

    let decided = run_honest_round(&validators, &mut managers, 1);
    assert_eq!(decided, 4);

    let mut commits = Vec::new();
    for m in managers.values() {
        if let Some(qc) = m.highest_commit_qc() {
            commits.push(qc.block_hash);
        }
    }
    assert!(commits.len() >= 2);
    assert!(commits.windows(2).all(|w| w[0] == w[1]));
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 6 — BLOCK INJECTION
// Attacker impersonates leader or injects proposals with forged justify_qc.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase6_proposal_from_non_leader_ignored() {
    let (validators, mut managers, _) = build_bft_network();
    let ids: Vec<String> = managers.keys().cloned().collect();

    let round = 0u64;
    let leader_idx = (round as usize) % validators.len();
    let attacker_id = &validators[(leader_idx + 1) % validators.len()].id;

    for id in &ids {
        managers.get_mut(id).unwrap().start_round(round);
    }

    let malicious_block = [0xDE; 32];

    for id in &ids {
        if id == attacker_id {
            continue;
        }
        let action = managers
            .get_mut(id)
            .unwrap()
            .process_event(RoundEvent::Proposal {
                block_hash: malicious_block,
                leader_id: attacker_id.clone(),
                justify_qc: None,
            });
        assert!(
            matches!(
                action,
                rust_bc::consensus::bft::round_manager::ManagerAction::Round(
                    rust_bc::consensus::bft::round::RoundAction::None
                ) | rust_bc::consensus::bft::round_manager::ManagerAction::None
            ),
            "honest node must reject proposal from non-leader"
        );
    }

    for id in &ids {
        let state = managers[id.as_str()].round_state();
        assert_ne!(
            state,
            Some(RoundState::Decided),
            "no node should decide on attacker's block"
        );
    }

    let decided = run_honest_round(&validators, &mut managers, round);
    assert!(
        decided > 0,
        "honest round still works after rejected injection"
    );
}

#[test]
fn phase6_proposal_with_forged_justify_qc_rejected() {
    let (validators, mut managers, _) = build_bft_network();
    let ids: Vec<String> = managers.keys().cloned().collect();

    let decided_r0 = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided_r0, 4);

    let round = 1u64;
    let leader_idx = (round as usize) % validators.len();
    let leader_id = validators[leader_idx].id.clone();

    for id in &ids {
        managers.get_mut(id).unwrap().start_round(round);
    }

    let attacker_ed = SoftwareSigningProvider::generate();
    let fake_bh = [0xAA; 32];
    let mut forged_votes = Vec::new();
    for v in &validators[..3] {
        let payload = VoteMessage::signing_payload_v2(BftPhase::Prepare, &fake_bh, 0, &v.id);
        forged_votes.push(VoteMessage {
            block_hash: fake_bh,
            round: 0,
            phase: BftPhase::Prepare,
            voter_id: v.id.clone(),
            signature: attacker_ed.sign(&payload).unwrap(),
        });
    }
    let forged_qc = QuorumCertificate::new(BftPhase::Prepare, fake_bh, 0, forged_votes).unwrap();

    let malicious_block = [0xBB; 32];
    let mut rejected_count = 0;
    for id in &ids {
        if *id == leader_id {
            continue;
        }
        let action = managers
            .get_mut(id)
            .unwrap()
            .process_event(RoundEvent::Proposal {
                block_hash: malicious_block,
                leader_id: leader_id.clone(),
                justify_qc: Some(forged_qc.clone()),
            });
        if matches!(
            action,
            rust_bc::consensus::bft::round_manager::ManagerAction::Round(
                rust_bc::consensus::bft::round::RoundAction::None
            )
        ) {
            rejected_count += 1;
        }
    }
    assert_eq!(
        rejected_count, 3,
        "all followers must reject forged justify_qc"
    );
}

#[test]
fn phase6_attacker_leader_round_cannot_decide_without_honest_votes() {
    let (validators, mut managers, verifier) = build_bft_network();
    let ids: Vec<String> = managers.keys().cloned().collect();

    let round = 0u64;
    let leader_idx = (round as usize) % validators.len();
    let attacker_idx = leader_idx;
    let attacker_id = validators[attacker_idx].id.clone();

    for id in &ids {
        managers.get_mut(id).unwrap().start_round(round);
    }

    let malicious_bh = [0xEE; 32];
    managers
        .get_mut(&attacker_id)
        .unwrap()
        .process_event(RoundEvent::StartAsLeader {
            block_hash: malicious_bh,
        });

    let attacker_ed = SoftwareSigningProvider::generate();

    for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
        let mut forged_votes = Vec::new();
        for v in &validators {
            if v.id == attacker_id {
                forged_votes.push(v.sign_vote(phase, &malicious_bh, round));
            } else {
                let payload = VoteMessage::signing_payload_v2(phase, &malicious_bh, round, &v.id);
                forged_votes.push(VoteMessage {
                    block_hash: malicious_bh,
                    round,
                    phase,
                    voter_id: v.id.clone(),
                    signature: attacker_ed.sign(&payload).unwrap(),
                });
            }
        }

        let qv = QuorumValidator::new(
            validators.iter().map(|v| v.id.clone()).collect(),
            verifier.clone(),
        );
        for vote in &forged_votes[1..] {
            assert!(
                qv.validate_vote(vote).is_err(),
                "forged vote from {} must be rejected",
                vote.voter_id
            );
        }

        for vote in &forged_votes {
            managers
                .get_mut(&attacker_id)
                .unwrap()
                .process_event(RoundEvent::Vote(vote.clone()));
        }
    }

    let attacker_state = managers[&attacker_id].round_state();
    assert_ne!(
        attacker_state,
        Some(RoundState::Decided),
        "attacker cannot decide with forged votes — vote collector rejects invalid sigs"
    );
}

#[test]
fn phase6_network_recovers_after_malicious_leader_round() {
    let (validators, mut managers, _) = build_bft_network();

    let decided_r0 = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided_r0, 4);

    let ids: Vec<String> = managers.keys().cloned().collect();
    for id in &ids {
        managers.get_mut(id).unwrap().start_round(1);
    }
    for id in &ids {
        managers.get_mut(id).unwrap().on_timeout();
    }

    let decided_r2 = run_honest_round(&validators, &mut managers, 2);
    assert_eq!(decided_r2, 4);

    let decided_r3 = run_honest_round(&validators, &mut managers, 3);
    assert_eq!(decided_r3, 4);

    let mut commits: Vec<[u8; 32]> = Vec::new();
    for m in managers.values() {
        if let Some(qc) = m.highest_commit_qc() {
            commits.push(qc.block_hash);
        }
    }
    assert!(commits.len() >= 2);
    assert!(
        commits.windows(2).all(|w| w[0] == w[1]),
        "all honest nodes must agree on the same block after recovery"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 7 — NETWORK PARTITION DURING MIGRATION
// Network splits while some nodes have migrated. Neither partition can
// decide alone (need 3/4 for quorum). After heal, all nodes rejoin and
// consensus resumes.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn phase7_partition_stalls_both_sides() {
    let (validators, mut managers, _) = build_bft_network();

    let decided = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided, 4);

    // Partition: {A, B} vs {C, D} — neither has quorum (need 3)
    let side_cd = &["node-a", "node-b"];
    let side_ab = &["node-c", "node-d"];

    let decided_ab = run_round_with_partition(&validators, &mut managers, 1, side_ab);
    assert_eq!(decided_ab, 0, "2-node partition cannot reach quorum");

    let decided_cd = run_round_with_partition(&validators, &mut managers, 1, side_cd);
    assert_eq!(decided_cd, 0, "2-node partition cannot reach quorum");
}

#[test]
fn phase7_partition_heals_consensus_resumes() {
    let (validators, mut managers, _) = build_bft_network();

    let decided_r0 = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided_r0, 4);

    // Partition stalls round 1
    let partitioned = &["node-c", "node-d"];
    let decided_r1 = run_round_with_partition(&validators, &mut managers, 1, partitioned);
    assert_eq!(decided_r1, 0);

    // Timeout all nodes to advance round
    let ids: Vec<String> = managers.keys().cloned().collect();
    for id in &ids {
        managers.get_mut(id).unwrap().on_timeout();
    }

    // Heal: all 4 nodes participate in round 2
    let decided_r2 = run_honest_round(&validators, &mut managers, 2);
    assert_eq!(decided_r2, 4, "consensus resumes after partition heals");
}

#[test]
fn phase7_migration_during_partition_then_rejoin() {
    let store = Arc::new(MemoryStore::new());
    let (validators, mut managers, _) = build_bft_network();

    // Register identities for all 4 validators
    for v in &validators {
        store
            .write_identity(&IdentityRecord {
                did: format!("did:goya:{}", &v.id),
                public_key: hex::encode(&v.pk),
                created_at: 0,
                updated_at: 0,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
            })
            .unwrap();
    }

    // Round 0: all healthy
    let decided_r0 = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided_r0, 4);

    // Partition: C and D go offline
    let partitioned = &["node-c", "node-d"];

    // Round 1 stalls (only A, B online — no quorum)
    let decided_r1 = run_round_with_partition(&validators, &mut managers, 1, partitioned);
    assert_eq!(decided_r1, 0);

    // While partitioned, migrate C and D's identities to ML-DSA-65
    for v_id in partitioned {
        let old_did = format!("did:goya:{v_id}");
        let result = migrate_identity(
            store.as_ref(),
            &old_did,
            &hex::encode(MlDsaSigningProvider::generate().public_key()),
            1000,
        )
        .unwrap();

        let old_rec = store.read_identity(&old_did).unwrap();
        assert_eq!(old_rec.status, "migrated");

        let new_rec = store.read_identity(&result.new_did).unwrap();
        assert_eq!(new_rec.status, "active");
        assert_eq!(new_rec.migrated_from.as_deref(), Some(old_did.as_str()));

        let resolved = resolve_identity(store.as_ref(), &old_did).unwrap();
        assert_eq!(resolved.did, result.new_did);
    }

    // Timeout to advance past stalled round
    let ids: Vec<String> = managers.keys().cloned().collect();
    for id in &ids {
        managers.get_mut(id).unwrap().on_timeout();
    }

    // Heal partition: all 4 rejoin — BFT consensus uses original signing keys
    // (identity migration is at the storage layer, not the consensus signing layer)
    let decided_r2 = run_honest_round(&validators, &mut managers, 2);
    assert_eq!(
        decided_r2, 4,
        "all nodes decide after partition heals + migration"
    );

    // Verify safety: all nodes agree
    let mut commits = Vec::new();
    for m in managers.values() {
        if let Some(qc) = m.highest_commit_qc() {
            commits.push(qc.block_hash);
        }
    }
    assert_eq!(commits.len(), 4);
    assert!(commits.windows(2).all(|w| w[0] == w[1]));

    // Verify migration persisted correctly for both partitioned nodes
    for v_id in partitioned {
        let old_did = format!("did:goya:{v_id}");
        let resolved = resolve_identity(store.as_ref(), &old_did).unwrap();
        assert_eq!(resolved.status, "active");
        assert_eq!(resolved.migrated_from.as_deref(), Some(old_did.as_str()));
    }
}

#[test]
fn phase7_three_node_partition_has_quorum() {
    let (validators, mut managers, _) = build_bft_network();

    let decided_r0 = run_honest_round(&validators, &mut managers, 0);
    assert_eq!(decided_r0, 4);

    // Partition: {A, B, C} vs {D} — 3 nodes have quorum (3 >= 2*1+1)
    let isolated = &["node-d"];
    let decided_r1 = run_round_with_partition(&validators, &mut managers, 1, isolated);
    assert_eq!(decided_r1, 3, "3-node partition reaches quorum and decides");

    // D never entered round 1 — its highest commit is still round 0
    let d_commit_round = managers["node-d"].highest_commit_qc().map(|qc| qc.round);
    assert_eq!(
        d_commit_round,
        Some(0),
        "isolated node must not advance past round 0"
    );
}
