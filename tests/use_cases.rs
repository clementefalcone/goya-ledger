//! Real-world use-case tests — prove goya-ledger works as a functional
//! post-quantum DLT across four verticals:
//!
//! 1. Document notarization (FES + FEA)
//! 2. Electronic signature (Simple + Advanced)
//! 3. Governance voting
//! 4. Verifiable credentials
//!
//! Each test exercises a complete user flow end-to-end via the HTTP API.

use actix_web::{test, web, App};
use rust_bc::api::handlers::{credentials, governance, notarize};
use rust_bc::app_state::AppState;
use rust_bc::identity::signing::{MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider};
use std::sync::Arc;

fn app_state() -> web::Data<AppState> {
    web::Data::new(AppState::test_default())
}

fn app_state_with_governance() -> web::Data<AppState> {
    let mut state = AppState::test_default();
    state.proposal_store = Some(Arc::new(
        rust_bc::governance::proposals::ProposalStore::new(),
    ));
    state.vote_store = Some(Arc::new(rust_bc::governance::voting::VoteStore::new()));
    state.param_registry = Some(Arc::new(
        rust_bc::governance::params::ParamRegistry::with_defaults(),
    ));
    web::Data::new(state)
}

fn ed25519_identity() -> (String, String, SoftwareSigningProvider) {
    let provider = SoftwareSigningProvider::generate();
    let pk_hex = hex::encode(provider.public_key());
    let did = rust_bc::identity::did::did_from_pubkey_hex(&pk_hex);
    (did, pk_hex, provider)
}

fn mldsa65_identity() -> (String, String, MlDsaSigningProvider) {
    let provider = MlDsaSigningProvider::generate();
    let pk_hex = hex::encode(provider.public_key());
    let did = rust_bc::identity::did::did_from_pubkey_hex(&pk_hex);
    (did, pk_hex, provider)
}

fn sha256_hex(data: &[u8]) -> String {
    use pqc_crypto_module::legacy::sha256::Digest;
    hex::encode(pqc_crypto_module::legacy::sha256::Sha256::digest(data))
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. NOTARIZATION — Document timestamping with proof of existence
// ═══════════════════════════════════════════════════════════════════════════

#[actix_web::test]
async fn uc_notarize_document_fes_and_verify() {
    let state = app_state();
    let app = test::init_service(
        App::new().app_data(state).service(
            web::scope("/api/v1")
                .service(notarize::submit_notarization)
                .service(notarize::verify_notarization)
                .service(notarize::get_document_owner)
                .service(notarize::get_document_provenance),
        ),
    )
    .await;

    let (did, pk, provider) = ed25519_identity();
    let hash = sha256_hex(b"Contrato de arriendo - Av. Providencia 1234, Santiago");
    let payload = format!("notarize:{did}:{hash}");
    let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

    // Step 1: Notarize
    let req = test::TestRequest::post()
        .uri("/api/v1/notarize")
        .set_json(serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk,
            "signature": sig,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "notarization should succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["signature_level"], "simple");

    // Step 2: Verify
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/verify/{hash}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["verified"], true);

    // Step 3: Owner
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/{hash}/owner"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["owner"], did);

    // Step 4: Provenance
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/{hash}/provenance"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["original_signer"], did);
    assert_eq!(body["data"]["transfers"].as_array().unwrap().len(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. ELECTRONIC SIGNATURE — FES (Simple) and FEA (Advanced + PQC + biometric)
// ═══════════════════════════════════════════════════════════════════════════

#[actix_web::test]
async fn uc_firma_electronica_simple_fes() {
    let state = app_state();
    let app = test::init_service(
        App::new().app_data(state).service(
            web::scope("/api/v1")
                .service(notarize::submit_notarization)
                .service(notarize::verify_notarization),
        ),
    )
    .await;

    let (did, pk, provider) = ed25519_identity();
    let hash = sha256_hex(b"Declaracion jurada - RUT 12.345.678-9");
    let payload = format!("notarize:{did}:{hash}");
    let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

    let req = test::TestRequest::post()
        .uri("/api/v1/notarize")
        .set_json(serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk,
            "signature": sig,
            "signature_level": "simple",
            "signature_algorithm": "Ed25519",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["signature_level"], "simple");
    assert_eq!(body["data"]["signature_algorithm"], "Ed25519");

    // Verify persisted
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/verify/{hash}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["verified"], true);
    assert_eq!(body["data"]["signature_level"], "simple");
}

#[actix_web::test]
async fn uc_firma_electronica_avanzada_fea_pqc_biometric() {
    let state = app_state();
    let app = test::init_service(
        App::new().app_data(state).service(
            web::scope("/api/v1")
                .service(notarize::submit_notarization)
                .service(notarize::verify_notarization),
        ),
    )
    .await;

    let (did, pk, provider) = mldsa65_identity();
    let hash = sha256_hex(b"Escritura publica - Notaria 42, Santiago");

    let fingerprint = sha256_hex(b"fingerprint-template-user-42");
    let rut = sha256_hex(b"12345678-9");
    let bio_evidence = vec![
        rust_bc::signature::BiometricEvidence {
            evidence_type: rust_bc::signature::BiometricType::Fingerprint,
            commitment: fingerprint.clone(),
            captured_at: 1700000000,
            capture_device: Some("BiometricScanner-v3".into()),
        },
        rust_bc::signature::BiometricEvidence {
            evidence_type: rust_bc::signature::BiometricType::Rut,
            commitment: rut.clone(),
            captured_at: 1700000000,
            capture_device: None,
        },
    ];
    let bio_hash = rust_bc::signature::compute_biometrics_hash(&bio_evidence);
    let payload = format!("notarize_fea:{did}:{hash}:{bio_hash}");
    let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

    let req = test::TestRequest::post()
        .uri("/api/v1/notarize")
        .set_json(serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk,
            "signature": sig,
            "signature_level": "advanced",
            "signature_algorithm": "MlDsa65",
            "biometric_evidence": [
                {
                    "evidence_type": "fingerprint",
                    "commitment": fingerprint,
                    "captured_at": 1700000000u64,
                    "capture_device": "BiometricScanner-v3",
                },
                {
                    "evidence_type": "rut",
                    "commitment": rut,
                    "captured_at": 1700000000u64,
                },
            ],
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "FEA notarization should succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["signature_level"], "advanced");
    assert_eq!(body["data"]["signature_algorithm"], "MlDsa65");

    // Verify preserves biometric evidence
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/verify/{hash}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["verified"], true);
    assert_eq!(body["data"]["signature_level"], "advanced");
    assert_eq!(body["data"]["signature_algorithm"], "MlDsa65");
    let bio = body["data"]["biometric_evidence"].as_array().unwrap();
    assert_eq!(bio.len(), 2);
    assert_eq!(bio[0]["evidence_type"], "fingerprint");
    assert_eq!(bio[1]["evidence_type"], "rut");
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. GOVERNANCE VOTING — Proposal lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[actix_web::test]
async fn uc_governance_proposal_lifecycle() {
    std::env::set_var("ACL_MODE", "permissive");
    let state = app_state_with_governance();
    let app = test::init_service(
        App::new().app_data(state).service(
            web::scope("/api/v1")
                .service(governance::submit_governance_proposal)
                .service(governance::get_governance_proposal)
                .service(governance::list_governance_proposals)
                .service(governance::cast_governance_vote)
                .service(governance::tally_governance_votes),
        ),
    )
    .await;

    // Step 1: Submit proposal
    let req = test::TestRequest::post()
        .uri("/api/v1/governance/proposals")
        .set_json(serde_json::json!({
            "proposer": "did:goya:municipio_santiago",
            "description": "Reducir quorum de votacion de 33% a 25%",
            "deposit": 10000,
            "action": {
                "type": "param_change",
                "changes": [{ "key": "quorum_percent", "value": 25 }],
            },
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "proposal should be created");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let proposal = &body["data"];
    assert_eq!(proposal["status"], "Voting");
    let proposal_id = proposal["id"].as_u64().unwrap();

    // Step 2: Get proposal
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/governance/proposals/{proposal_id}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Step 3: List proposals
    let req = test::TestRequest::get()
        .uri("/api/v1/governance/proposals")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let items = body["data"]["data"].as_array().unwrap();
    assert!(!items.is_empty(), "should list at least one proposal");

    // Step 4: Cast vote (permissive mode — no stake required)
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/governance/proposals/{proposal_id}/vote"))
        .set_json(serde_json::json!({
            "voter": "did:goya:concejal_01",
            "option": "Yes",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "vote should be accepted");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["data"]["yes_power"].as_u64().unwrap() > 0);

    // Step 5: Tally
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/governance/proposals/{proposal_id}/tally"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["data"]["total_voted_power"].as_u64().unwrap() > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. CREDENTIALS — Issue, verify, revoke
// ═══════════════════════════════════════════════════════════════════════════

#[actix_web::test]
async fn uc_credential_lifecycle() {
    let state = app_state();
    let app = test::init_service(
        App::new().app_data(state.clone()).service(
            web::scope("/api/v1")
                .service(credentials::issue_credential)
                .service(credentials::get_credential)
                .service(credentials::verify_credential)
                .service(credentials::revoke_credential),
        ),
    )
    .await;

    // Pre-requisite: register issuer identity
    let (issuer_did, issuer_pk, _) = ed25519_identity();
    {
        let store_map = state.store.read().unwrap();
        let store = store_map.get("default").unwrap();
        store
            .write_identity(&rust_bc::storage::traits::IdentityRecord {
                did: issuer_did.clone(),
                public_key: issuer_pk.clone(),
                created_at: 1700000000,
                updated_at: 1700000000,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: None,
            })
            .unwrap();
    }

    // Step 1: Issue credential
    let req = test::TestRequest::post()
        .uri("/api/v1/credentials/issue")
        .set_json(serde_json::json!({
            "issuer_did": issuer_did,
            "subject_did": "did:goya:estudiante_uchile_42",
            "claims": {
                "degree": "Ingenieria Civil Informatica",
                "university": "Universidad de Chile",
                "graduation_year": 2025,
            },
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "credential should be issued");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let cred_id = body["data"]["credential_id"].as_str().unwrap().to_string();

    // Step 2: Get credential
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/credentials/{cred_id}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["issuer_did"], issuer_did);

    // Step 3: Verify credential — should be valid
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/credentials/{cred_id}/verify"))
        .set_json(serde_json::json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["valid"], true);

    // Step 4: Revoke
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/credentials/{cred_id}/revoke"))
        .set_json(serde_json::json!({"reason": "degree rescinded"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["revoked"], true);

    // Step 5: Verify again — should be invalid
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/credentials/{cred_id}/verify"))
        .set_json(serde_json::json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["data"]["valid"], false,
        "revoked credential must be invalid"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. OWNERSHIP TRANSFER — Notarize then transfer with FES
// ═══════════════════════════════════════════════════════════════════════════

#[actix_web::test]
async fn uc_document_ownership_transfer() {
    let state = app_state();
    let app = test::init_service(
        App::new().app_data(state).service(
            web::scope("/api/v1")
                .service(notarize::submit_notarization)
                .service(notarize::transfer_document)
                .service(notarize::get_document_owner)
                .service(notarize::get_document_provenance),
        ),
    )
    .await;

    // Alice notarizes
    let (alice_did, alice_pk, alice_provider) = ed25519_identity();
    let hash = sha256_hex(b"Titulo de propiedad - Lote 7, Parcela 12, Rancagua");
    let payload = format!("notarize:{alice_did}:{hash}");
    let sig = hex::encode(alice_provider.sign(payload.as_bytes()).unwrap());

    let req = test::TestRequest::post()
        .uri("/api/v1/notarize")
        .set_json(serde_json::json!({
            "content_hash": hash,
            "signer": alice_did,
            "public_key": alice_pk,
            "signature": sig,
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 201);

    // Alice transfers to Bob
    let (bob_did, _, _) = ed25519_identity();
    let transfer_payload = format!("transfer_doc:{hash}:{alice_did}:{bob_did}");
    let transfer_sig = hex::encode(alice_provider.sign(transfer_payload.as_bytes()).unwrap());

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/notarize/{hash}/transfer"))
        .set_json(serde_json::json!({
            "from_did": alice_did,
            "to_did": bob_did,
            "public_key": alice_pk,
            "signature": transfer_sig,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "transfer should succeed");

    // Verify Bob is now owner
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/{hash}/owner"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"]["owner"], bob_did);
    assert_eq!(body["data"]["original_signer"], alice_did);
    assert_eq!(body["data"]["transfer_count"], 1);

    // Provenance shows transfer chain
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/notarize/{hash}/provenance"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let transfers = body["data"]["transfers"].as_array().unwrap();
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0]["from_did"], alice_did);
    assert_eq!(transfers[0]["to_did"], bob_did);
}
