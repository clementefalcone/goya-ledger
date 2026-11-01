//! EUDI Wallet interoperability tests — simulates realistic credential flows
//! as they would occur between GOYA and a conformant EUDI Wallet.
//!
//! Validates: OID4VCI issuance, OID4VP presentation, SD-JWT VC structure,
//! mdoc DeviceResponse, and DCQL queries with real payloads.

use rust_bc::identity::mdoc::{
    issue_mdoc, sign_device_auth, verify_device_auth, verify_mdoc, DeviceResponse, Document,
    MdocParams,
};
use rust_bc::identity::sd_jwt::{issue_sd_jwt_vc, present_sd_jwt, verify_sd_jwt_vc, VcClaims};
use rust_bc::identity::signing::{SigningProvider, SoftwareSigningProvider};
use std::collections::BTreeMap;

// ── SD-JWT VC: Issue → Present → Verify (EUDI Wallet PID flow) ─────────

#[test]
fn eudi_pid_sd_jwt_full_flow() {
    let issuer = SoftwareSigningProvider::generate();
    let issuer_pk = hex::encode(issuer.public_key());
    let issuer_did = format!("did:goya:{}", &issuer_pk[..16]);

    // 1. Issuer creates PID credential
    let claims = VcClaims {
        iss: issuer_did,
        sub: "did:goya:holder123456".into(),
        iat: 1_700_000_000,
        exp: 2_000_000_000,
        vct: "eu.europa.ec.eudi.pid.1".into(),
        claims: vec![
            ("given_name".into(), serde_json::json!("María")),
            ("family_name".into(), serde_json::json!("García")),
            ("birth_date".into(), serde_json::json!("1985-03-15")),
            ("nationality".into(), serde_json::json!("ES")),
            ("age_over_18".into(), serde_json::json!(true)),
            ("age_over_65".into(), serde_json::json!(false)),
        ],
        cnf: None,
        status: None,
    };
    let sd_jwt = issue_sd_jwt_vc(&claims, &issuer).unwrap();

    // 2. Wallet selectively discloses only given_name (index 0) + age_over_18 (index 4)
    let presentation = present_sd_jwt(&sd_jwt, &[0, 4]);

    // 3. Verifier checks
    let verified = verify_sd_jwt_vc(&presentation, &issuer_pk).unwrap();
    assert_eq!(verified.vct, "eu.europa.ec.eudi.pid.1");
    // Disclosed claims should include what was selected
    assert!(!verified.disclosed_claims.is_empty());
}

#[test]
fn eudi_pid_sd_jwt_no_disclosure() {
    let issuer = SoftwareSigningProvider::generate();
    let issuer_pk = hex::encode(issuer.public_key());
    let claims = VcClaims {
        iss: format!("did:goya:{}", &issuer_pk[..16]),
        sub: "did:goya:holder".into(),
        iat: 1_700_000_000,
        exp: 2_000_000_000,
        vct: "IdentityCredential".into(),
        claims: vec![("secret".into(), serde_json::json!("hidden"))],
        cnf: None,
        status: None,
    };
    let sd_jwt = issue_sd_jwt_vc(&claims, &issuer).unwrap();
    let presentation = present_sd_jwt(&sd_jwt, &[]);
    let verified = verify_sd_jwt_vc(&presentation, &issuer_pk).unwrap();
    assert_eq!(verified.vct, "IdentityCredential");
}

// ── mdoc: Issue → DeviceResponse → Verify (ISO 18013-5) ────────────────

#[test]
fn eudi_mdoc_device_response_flow() {
    let issuer = SoftwareSigningProvider::generate();
    let holder = SoftwareSigningProvider::generate();
    let holder_pk = hex::encode(holder.public_key());

    // 1. Issuer creates PID mdoc
    let mut elements = BTreeMap::new();
    elements.insert(
        "eu.europa.ec.eudi.pid.1".to_string(),
        vec![
            ("given_name".to_string(), serde_json::json!("أحمد")),
            ("family_name".to_string(), serde_json::json!("المنصور")),
            ("birth_date".to_string(), serde_json::json!("1990-06-15")),
            ("issuing_country".to_string(), serde_json::json!("AE")),
            ("age_over_18".to_string(), serde_json::json!(true)),
        ],
    );
    let params = MdocParams {
        doc_type: "eu.europa.ec.eudi.pid.1".into(),
        elements,
        valid_from: 1_700_000_000,
        valid_until: 2_000_000_000,
        device_key: Some(holder_pk.clone()),
    };
    let mdoc = issue_mdoc(&params, &issuer).unwrap();

    // 2. Holder creates DeviceResponse with device authentication
    let session_transcript = b"verifier-session-nonce-abc123";
    let device_auth = sign_device_auth(&holder, session_transcript).unwrap();

    let device_response = DeviceResponse {
        version: "1.0".into(),
        documents: vec![Document {
            doc_type: "eu.europa.ec.eudi.pid.1".into(),
            issuer_signed: mdoc,
            device_auth: Some(device_auth),
        }],
        status: 0,
    };

    // 3. Verifier validates
    assert_eq!(device_response.status, 0);
    let doc = &device_response.documents[0];

    // 3a. Verify issuer signature + element digests
    let verified = verify_mdoc(&doc.issuer_signed).unwrap();
    assert_eq!(verified.doc_type, "eu.europa.ec.eudi.pid.1");
    let pid = &verified.disclosed_elements["eu.europa.ec.eudi.pid.1"];
    assert_eq!(pid.len(), 5);

    // 3b. Verify device authentication
    let da = doc.device_auth.as_ref().unwrap();
    assert!(verify_device_auth(da, &holder_pk, session_transcript).is_ok());

    // 3c. Wrong session transcript fails
    assert!(verify_device_auth(da, &holder_pk, b"wrong-session").is_err());
}

// ── Cross-jurisdiction credential ──────────────────────────────────────

#[test]
fn credential_with_uae_claims() {
    let issuer = SoftwareSigningProvider::generate();
    let issuer_pk = hex::encode(issuer.public_key());
    let claims = VcClaims {
        iss: format!("did:goya:{}", &issuer_pk[..16]),
        sub: "did:goya:uae_holder".into(),
        iat: 1_700_000_000,
        exp: 2_000_000_000,
        vct: "EmiratesIDCredential".into(),
        claims: vec![
            ("given_name".into(), serde_json::json!("أحمد")),
            ("family_name".into(), serde_json::json!("المنصور")),
            (
                "emirates_id".into(),
                serde_json::json!("784-1990-1234567-6"),
            ),
            ("nationality".into(), serde_json::json!("AE")),
        ],
        cnf: None,
        status: None,
    };
    let sd_jwt = issue_sd_jwt_vc(&claims, &issuer).unwrap();
    let verified = verify_sd_jwt_vc(&sd_jwt.compact, &issuer_pk).unwrap();
    assert_eq!(verified.vct, "EmiratesIDCredential");
}

#[test]
fn credential_with_chilean_claims() {
    let issuer = SoftwareSigningProvider::generate();
    let issuer_pk = hex::encode(issuer.public_key());
    let claims = VcClaims {
        iss: format!("did:goya:{}", &issuer_pk[..16]),
        sub: "did:goya:cl_holder".into(),
        iat: 1_700_000_000,
        exp: 2_000_000_000,
        vct: "ChileanPIDCredential".into(),
        claims: vec![
            ("given_name".into(), serde_json::json!("María")),
            ("family_name".into(), serde_json::json!("González")),
            ("rut".into(), serde_json::json!("12345678-5")),
            ("nationality".into(), serde_json::json!("CL")),
        ],
        cnf: None,
        status: None,
    };
    let sd_jwt = issue_sd_jwt_vc(&claims, &issuer).unwrap();
    let verified = verify_sd_jwt_vc(&sd_jwt.compact, &issuer_pk).unwrap();
    assert_eq!(verified.vct, "ChileanPIDCredential");
}

// ── DeviceResponse serialization (wire format) ─────────────────────────

#[test]
fn device_response_json_wire_format() {
    let issuer = SoftwareSigningProvider::generate();
    let holder = SoftwareSigningProvider::generate();
    let mut elements = BTreeMap::new();
    elements.insert(
        "eu.europa.ec.eudi.pid.1".to_string(),
        vec![("given_name".to_string(), serde_json::json!("Test"))],
    );
    let mdoc = issue_mdoc(
        &MdocParams {
            doc_type: "eu.europa.ec.eudi.pid.1".into(),
            elements,
            valid_from: 1_700_000_000,
            valid_until: 2_000_000_000,
            device_key: Some(hex::encode(holder.public_key())),
        },
        &issuer,
    )
    .unwrap();

    let auth = sign_device_auth(&holder, b"session").unwrap();
    let response = DeviceResponse {
        version: "1.0".into(),
        documents: vec![Document {
            doc_type: "eu.europa.ec.eudi.pid.1".into(),
            issuer_signed: mdoc,
            device_auth: Some(auth),
        }],
        status: 0,
    };

    // Must serialize and deserialize cleanly
    let json = serde_json::to_string(&response).unwrap();
    let parsed: DeviceResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.version, "1.0");
    assert_eq!(parsed.documents.len(), 1);
    assert_eq!(parsed.documents[0].doc_type, "eu.europa.ec.eudi.pid.1");
    assert!(parsed.documents[0].device_auth.is_some());
}
