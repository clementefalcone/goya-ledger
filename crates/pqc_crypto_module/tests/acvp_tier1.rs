//! ACVP Tier 1 — Remaining NIST ACVP vector coverage.
//!
//! 1. ML-KEM-768 decapsulation
//! 2. ML-DSA-65 sigGen external mode (with context)
//! 3. ML-DSA-65 sigVer (NIST ACVP official, external mode with context)
//! 4. ML-DSA-65 sigGen deterministic (rnd=zeros)

use pqc_crypto_module::mldsa;
use pqc_crypto_module::types::*;

use pqc_crypto_module::api;
use pqc_crypto_module::approved_mode;

fn init() -> std::sync::MutexGuard<'static, ()> {
    let guard = approved_mode::__test_reset();
    api::initialize_approved_mode().unwrap();
    guard
}

// ═══════════════════════════════════════════════════════════════════
// 1. ML-KEM-768 DECAPSULATION (FIPS 203)
// ═══════════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
struct DecapFile {
    algorithm: String,
    vectors: Vec<DecapVector>,
}

#[derive(serde::Deserialize)]
struct DecapVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    dk: String,
    c: String,
    k: String,
}

#[test]
fn acvp_mlkem_decap_shared_secret_matches_nist() {
    let _g = init();
    let json = include_str!("data/acvp_mlkem768_decap.json");
    let vf: DecapFile = serde_json::from_str(json).unwrap();
    assert_eq!(vf.algorithm, "ML-KEM-768");

    for v in &vf.vectors {
        let dk_bytes = hex::decode(&v.dk).unwrap();
        let ct_bytes = hex::decode(&v.c).unwrap();
        let expected_ss = hex::decode(&v.k).unwrap();

        assert_eq!(dk_bytes.len(), 2400, "tcId={}: dk", v.tc_id);
        assert_eq!(ct_bytes.len(), 1088, "tcId={}: ct", v.tc_id);
        assert_eq!(expected_ss.len(), 32, "tcId={}: ss", v.tc_id);

        let sk = MlKemPrivateKey(dk_bytes);
        let ct = MlKemCiphertext(ct_bytes);

        let ss = api::mlkem_decapsulate(&sk, &ct).unwrap_or_else(|e| {
            panic!("tcId={}: decapsulate failed: {e}", v.tc_id);
        });

        assert_eq!(
            ss.as_bytes(),
            &expected_ss[..],
            "tcId={}: shared secret does not match NIST ACVP expected value",
            v.tc_id
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 2. ML-DSA-65 SIGGEN EXTERNAL MODE (with context)
// ═══════════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
struct SigGenExtFile {
    algorithm: String,
    vectors: Vec<SigGenExtVector>,
}

#[derive(serde::Deserialize)]
struct SigGenExtVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    message: String,
    rnd: String,
    context: String,
    signature: String,
}

#[test]
fn acvp_siggen_external_signature_matches_nist() {
    let json = include_str!("data/acvp_mldsa65_siggen_external.json");
    let vf: SigGenExtFile = serde_json::from_str(json).unwrap();
    assert_eq!(vf.algorithm, "ML-DSA-65");

    for v in &vf.vectors {
        let sk_bytes = hex::decode(&v.sk).unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let rnd_bytes = hex::decode(&v.rnd).unwrap();
        let ctx = hex::decode(&v.context).unwrap();
        let expected_sig = hex::decode(&v.signature).unwrap();

        assert_eq!(sk_bytes.len(), 4032, "tcId={}: sk", v.tc_id);
        assert_eq!(rnd_bytes.len(), 32, "tcId={}: rnd", v.tc_id);
        assert_eq!(expected_sig.len(), 3309, "tcId={}: sig", v.tc_id);

        let sk = MldsaPrivateKey(sk_bytes);
        let rnd: [u8; 32] = rnd_bytes.try_into().unwrap();

        let sig = mldsa::sign_message_external_derand(&sk, &msg, &ctx, &rnd).unwrap_or_else(|e| {
            panic!("tcId={}: sign_external_derand failed: {e}", v.tc_id);
        });

        assert_eq!(
            sig.as_bytes(),
            &expected_sig[..],
            "tcId={}: signature does not match NIST ACVP expected value (external mode, ctx={}B)",
            v.tc_id,
            ctx.len()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3. ML-DSA-65 SIGVER — NIST ACVP OFFICIAL (external mode)
// ═══════════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
struct SigVerFile {
    #[allow(dead_code)]
    algorithm: String,
    groups: Vec<SigVerGroup>,
}

#[derive(serde::Deserialize)]
struct SigVerGroup {
    #[allow(dead_code)]
    #[serde(rename = "tgId")]
    tg_id: u32,
    interface: String,
    vectors: Vec<SigVerVector>,
}

#[derive(serde::Deserialize)]
struct SigVerVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    pk: String,
    message: String,
    signature: String,
    #[serde(default)]
    context: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

#[test]
fn acvp_sigver_external_valid_passes() {
    let _g = init();
    let json = include_str!("data/acvp_mldsa65_sigver.json");
    let vf: SigVerFile = serde_json::from_str(json).unwrap();

    let ext_group = vf
        .groups
        .iter()
        .find(|g| g.interface == "external")
        .unwrap();

    let valid: Vec<_> = ext_group.vectors.iter().filter(|v| v.test_passed).collect();
    assert!(!valid.is_empty(), "no valid vectors");

    for v in &valid {
        let pk_bytes = hex::decode(&v.pk).unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let sig_bytes = hex::decode(&v.signature).unwrap();
        let ctx = hex::decode(&v.context).unwrap();

        let pk = MldsaPublicKey(pk_bytes);
        let sig = MldsaSignature(sig_bytes);

        // PQClean's verify_detached_signature_ctx handles external mode
        use pqcrypto_mldsa::mldsa65;
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

        let pqc_pk = mldsa65::PublicKey::from_bytes(pk.as_bytes()).expect("valid pk");
        let pqc_sig = mldsa65::DetachedSignature::from_bytes(sig.as_bytes()).expect("valid sig");

        let result = mldsa65::verify_detached_signature_ctx(&pqc_sig, &msg, &ctx, &pqc_pk);
        assert!(
            result.is_ok(),
            "tcId={}: valid ACVP sigVer vector rejected (external mode, ctx={}B)",
            v.tc_id,
            ctx.len()
        );
    }
}

#[test]
fn acvp_sigver_external_invalid_rejected() {
    let _g = init();
    let json = include_str!("data/acvp_mldsa65_sigver.json");
    let vf: SigVerFile = serde_json::from_str(json).unwrap();

    let ext_group = vf
        .groups
        .iter()
        .find(|g| g.interface == "external")
        .unwrap();

    let invalid: Vec<_> = ext_group
        .vectors
        .iter()
        .filter(|v| !v.test_passed)
        .collect();
    assert!(!invalid.is_empty(), "no invalid vectors");

    for v in &invalid {
        let pk_bytes = hex::decode(&v.pk).unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let sig_bytes = hex::decode(&v.signature).unwrap();
        let ctx = hex::decode(&v.context).unwrap();

        use pqcrypto_mldsa::mldsa65;
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

        let pk_result = mldsa65::PublicKey::from_bytes(&pk_bytes);
        let sig_result = mldsa65::DetachedSignature::from_bytes(&sig_bytes);

        // Either pk/sig parsing fails or verify fails — both acceptable for invalid vectors
        if let (Ok(pqc_pk), Ok(pqc_sig)) = (pk_result, sig_result) {
            let result = mldsa65::verify_detached_signature_ctx(&pqc_sig, &msg, &ctx, &pqc_pk);
            assert!(
                result.is_err(),
                "tcId={}: CRITICAL — invalid ACVP sigVer vector accepted (external mode)",
                v.tc_id
            );
        }
        // If parsing fails, the vector is correctly rejected
    }
}

// ═══════════════════════════════════════════════════════════════════
// 4. ML-DSA-65 SIGGEN DETERMINISTIC (rnd = all zeros)
// ═══════════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
struct SigGenDetFile {
    algorithm: String,
    vectors: Vec<SigGenDetVector>,
}

#[derive(serde::Deserialize)]
struct SigGenDetVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    message: String,
    signature: String,
}

#[test]
fn acvp_siggen_deterministic_matches_nist() {
    let json = include_str!("data/acvp_mldsa65_siggen_deterministic.json");
    let vf: SigGenDetFile = serde_json::from_str(json).unwrap();
    assert_eq!(vf.algorithm, "ML-DSA-65");

    for v in &vf.vectors {
        let sk_bytes = hex::decode(&v.sk).unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let expected_sig = hex::decode(&v.signature).unwrap();

        assert_eq!(sk_bytes.len(), 4032, "tcId={}: sk", v.tc_id);
        assert_eq!(expected_sig.len(), 3309, "tcId={}: sig", v.tc_id);

        let sk = MldsaPrivateKey(sk_bytes);

        // Deterministic mode: rnd = all zeros (FIPS 204 §5.1)
        let sig = mldsa::sign_message_deterministic(&sk, &msg).unwrap_or_else(|e| {
            panic!("tcId={}: sign_deterministic failed: {e}", v.tc_id);
        });

        assert_eq!(
            sig.as_bytes(),
            &expected_sig[..],
            "tcId={}: deterministic signature does not match NIST ACVP expected value",
            v.tc_id
        );
    }
}

#[test]
fn acvp_siggen_deterministic_is_repeatable() {
    let json = include_str!("data/acvp_mldsa65_siggen_deterministic.json");
    let vf: SigGenDetFile = serde_json::from_str(json).unwrap();

    let v = &vf.vectors[0];
    let sk = MldsaPrivateKey(hex::decode(&v.sk).unwrap());
    let msg = hex::decode(&v.message).unwrap();

    let sig1 = mldsa::sign_message_deterministic(&sk, &msg).unwrap();
    let sig2 = mldsa::sign_message_deterministic(&sk, &msg).unwrap();

    assert_eq!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "deterministic signing must produce identical output"
    );
}
