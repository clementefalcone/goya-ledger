//! Time Stamping Authority (TSA) — RFC 3161 compliant.
//!
//! Produces signed timestamp tokens that bind a content hash to a
//! precise point in time. The TSA signs each token with the node's
//! signing provider (Ed25519, ML-DSA-65, or RSA).
//!
//! Two output formats:
//! - JSON: `issue()` returns structured `TimeStampToken` (original)
//! - DER: `issue_der()` returns binary RFC 3161 `TimeStampResp`
//!
//! Time is sourced from a pluggable `TimeSource` (NTP-aware).

pub mod rfc3161_der;

use crate::crypto::hasher::HashAlgorithm;
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use crate::time_source::TimeSource;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// TSA policy OID (private arc under Goya namespace).
pub const TSA_POLICY_OID: &str = "1.3.6.1.4.1.99999.1.1";

/// Default accuracy: 1 second.
const DEFAULT_ACCURACY_SECS: u32 = 1;

/// Request for a timestamp token (mirrors RFC 3161 TimeStampReq).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStampRequest {
    /// Hash algorithm used to produce the imprint.
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,
    /// Hash of the data to timestamp (hex-encoded).
    pub message_imprint: String,
    /// Client-supplied nonce for replay protection.
    #[serde(default)]
    pub nonce: Option<u64>,
    /// Whether the client requests ordering.
    #[serde(default)]
    pub require_ordering: bool,
}

/// RFC 3161 TSTInfo — the core timestamp token content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TstInfo {
    /// Version (always 1 per RFC 3161).
    pub version: u32,
    /// TSA policy OID.
    pub policy: String,
    /// Hash algorithm used for the imprint.
    pub hash_algorithm: HashAlgorithm,
    /// Hash of the timestamped data (hex).
    pub message_imprint: String,
    /// Monotonically increasing serial number.
    pub serial_number: u64,
    /// Generation time (UNIX seconds, UTC).
    pub gen_time: u64,
    /// Accuracy in seconds.
    pub accuracy_secs: u32,
    /// Whether ordering is guaranteed among tokens from this TSA.
    pub ordering: bool,
    /// Client-supplied nonce echoed back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// TSA name (DID or identifier).
    pub tsa_name: String,
}

/// Complete signed timestamp token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeStampToken {
    /// Unique token ID.
    pub id: String,
    /// The timestamp info.
    pub tst_info: TstInfo,
    /// Signature over the canonical TstInfo (hex-encoded).
    pub signature: String,
    /// Public key of the TSA (hex-encoded).
    pub public_key: String,
    /// Signing algorithm used.
    pub signature_algorithm: SigningAlgorithm,
}

/// Response to a timestamp request (mirrors RFC 3161 TimeStampResp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStampResponse {
    /// Status: 0 = granted, 2 = rejection.
    pub status: u32,
    /// Human-readable status string.
    pub status_string: String,
    /// The token (present when status == 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TimeStampToken>,
}

/// TSA provider — generates and verifies timestamp tokens.
pub struct TsaProvider {
    signer: Arc<dyn SigningProvider>,
    serial: AtomicU64,
    tsa_name: String,
    policy_oid: String,
    accuracy_secs: u32,
    time_source: Option<Arc<dyn TimeSource>>,
    serial_path: Option<std::path::PathBuf>,
}

impl TsaProvider {
    pub fn new(signer: Arc<dyn SigningProvider>, tsa_name: String) -> Self {
        let initial_serial = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            signer,
            serial: AtomicU64::new(initial_serial),
            tsa_name,
            policy_oid: TSA_POLICY_OID.to_string(),
            accuracy_secs: DEFAULT_ACCURACY_SECS,
            time_source: None,
            serial_path: None,
        }
    }

    /// Enable serial persistence. Loads the last serial from `path` on init
    /// (falls back to epoch-seeded if file missing), persists after each issuance.
    pub fn with_serial_path(mut self, path: std::path::PathBuf) -> Self {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(saved) = contents.trim().parse::<u64>() {
                let epoch_seed = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                // Use whichever is higher: saved serial or epoch seed
                let initial = saved.max(epoch_seed);
                self.serial.store(initial, Ordering::SeqCst);
            }
        }
        self.serial_path = Some(path);
        self
    }

    pub fn with_accuracy(mut self, secs: u32) -> Self {
        self.accuracy_secs = secs;
        self
    }

    pub fn with_time_source(mut self, ts: Arc<dyn TimeSource>) -> Self {
        self.time_source = Some(ts);
        self
    }

    /// Current serial value (for inspection/testing).
    pub fn current_serial(&self) -> u64 {
        self.serial.load(Ordering::SeqCst)
    }

    fn next_serial(&self) -> u64 {
        let s = self.serial.fetch_add(1, Ordering::SeqCst);
        self.persist_serial(s + 1);
        s
    }

    fn persist_serial(&self, value: u64) {
        if let Some(path) = &self.serial_path {
            let _ = std::fs::write(path, value.to_string());
        }
    }

    fn validate_signer(&self) -> Result<(), String> {
        let test_msg = b"tsa-self-check";
        let sig = self
            .signer
            .sign(test_msg)
            .map_err(|e| format!("TSA signer unhealthy: {e}"))?;
        if !self.signer.verify(test_msg, &sig).unwrap_or(false) {
            return Err("TSA signer self-verification failed".into());
        }
        Ok(())
    }

    fn validated_time(&self) -> Result<u64, String> {
        match &self.time_source {
            Some(ts) => {
                ts.validate()
                    .map_err(|e| format!("time source not trusted: {e}"))?;
                Ok(ts.now().unix_secs)
            }
            None => Ok(now_secs()),
        }
    }

    pub fn issue(&self, req: &TimeStampRequest) -> TimeStampResponse {
        if let Err(msg) = self.validate_signer() {
            return TimeStampResponse {
                status: 2,
                status_string: msg,
                token: None,
            };
        }

        if let Err(msg) = validate_imprint(&req.message_imprint) {
            return TimeStampResponse {
                status: 2,
                status_string: msg,
                token: None,
            };
        }

        let gen_time = match self.validated_time() {
            Ok(t) => t,
            Err(msg) => {
                return TimeStampResponse {
                    status: 2,
                    status_string: msg,
                    token: None,
                };
            }
        };
        let serial = self.next_serial();

        let tst_info = TstInfo {
            version: 1,
            policy: self.policy_oid.clone(),
            hash_algorithm: req.hash_algorithm,
            message_imprint: req.message_imprint.clone(),
            serial_number: serial,
            gen_time,
            accuracy_secs: self.accuracy_secs,
            ordering: req.require_ordering,
            nonce: req.nonce,
            tsa_name: self.tsa_name.clone(),
        };

        let canonical = tst_info.signing_payload();
        let signature = match self.signer.sign(canonical.as_bytes()) {
            Ok(sig) => hex::encode(sig),
            Err(e) => {
                return TimeStampResponse {
                    status: 2,
                    status_string: format!("signing failed: {e}"),
                    token: None,
                };
            }
        };

        let token = TimeStampToken {
            id: uuid::Uuid::new_v4().to_string(),
            tst_info,
            signature,
            public_key: hex::encode(self.signer.public_key()),
            signature_algorithm: self.signer.algorithm(),
        };

        TimeStampResponse {
            status: 0,
            status_string: "granted".to_string(),
            token: Some(token),
        }
    }

    /// Issue a DER-encoded RFC 3161 TimeStampResp.
    pub fn issue_der(&self, req: &TimeStampRequest) -> Result<Vec<u8>, rfc3161_der::Rfc3161Error> {
        if let Err(msg) = validate_imprint(&req.message_imprint) {
            return Err(rfc3161_der::Rfc3161Error::Invalid(msg));
        }

        let gen_time = self
            .validated_time()
            .map_err(rfc3161_der::Rfc3161Error::Invalid)?;

        let imprint_bytes = hex::decode(&req.message_imprint)
            .map_err(|e| rfc3161_der::Rfc3161Error::Invalid(e.to_string()))?;

        let serial = self.next_serial();

        let params = rfc3161_der::TstInfoParams {
            policy_oid: &self.policy_oid,
            hash_algorithm: req.hash_algorithm,
            message_imprint: &imprint_bytes,
            serial_number: serial,
            gen_time,
            accuracy_secs: self.accuracy_secs,
            ordering: req.require_ordering,
            nonce: req.nonce,
            tsa_name: &self.tsa_name,
        };

        rfc3161_der::build_timestamp_resp_der(&params, self.signer.as_ref())
    }

    pub fn policy_info(&self) -> serde_json::Value {
        serde_json::json!({
            "policy_oid": self.policy_oid,
            "tsa_name": self.tsa_name,
            "hash_algorithms": ["SHA-256", "SHA3-256"],
            "signing_algorithm": self.signer.algorithm(),
            "accuracy_secs": self.accuracy_secs,
            "ordering_supported": true,
        })
    }
}

impl TstInfo {
    /// Deterministic signing payload (canonical string representation).
    pub fn signing_payload(&self) -> String {
        format!(
            "tsa:v{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.version,
            self.policy,
            self.hash_algorithm,
            self.message_imprint,
            self.serial_number,
            self.gen_time,
            self.accuracy_secs,
            self.ordering,
            self.nonce.unwrap_or(0),
        )
    }
}

/// Verify a timestamp token's signature.
pub fn verify_token(token: &TimeStampToken) -> bool {
    let payload = token.tst_info.signing_payload();
    crate::signature::verify_signature(
        token.signature_algorithm,
        &token.public_key,
        payload.as_bytes(),
        &token.signature,
    )
}

fn validate_imprint(imprint: &str) -> Result<(), String> {
    if imprint.len() != 64 {
        return Err(format!(
            "message_imprint must be 64 hex chars, got {}",
            imprint.len()
        ));
    }
    if hex::decode(imprint).is_err() {
        return Err("message_imprint is not valid hex".to_string());
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;

    fn make_provider() -> TsaProvider {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        TsaProvider::new(signer, "did:goya:tsa-test".to_string())
    }

    fn valid_imprint() -> String {
        use crate::crypto::hasher::{hash_with, HashAlgorithm};
        hex::encode(hash_with(HashAlgorithm::Sha256, b"test data"))
    }

    #[test]
    fn issue_granted_token() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(42),
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.status_string, "granted");
        let token = resp.token.unwrap();
        assert_eq!(token.tst_info.version, 1);
        assert_eq!(token.tst_info.message_imprint, req.message_imprint);
        assert_eq!(token.tst_info.nonce, Some(42));
        assert_eq!(token.tst_info.policy, TSA_POLICY_OID);
        assert_eq!(token.tst_info.accuracy_secs, 1);
    }

    #[test]
    fn serial_numbers_are_monotonic() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let s1 = tsa.issue(&req).token.unwrap().tst_info.serial_number;
        let s2 = tsa.issue(&req).token.unwrap().tst_info.serial_number;
        let s3 = tsa.issue(&req).token.unwrap().tst_info.serial_number;
        assert_eq!(s1 + 1, s2);
        assert_eq!(s2 + 1, s3);
    }

    #[test]
    fn nonce_echoed_back() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(123456),
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.nonce, Some(123456));
    }

    #[test]
    fn nonce_none_when_not_requested() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.nonce, None);
    }

    #[test]
    fn token_signature_verifies() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(99),
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert!(verify_token(&token));
    }

    #[test]
    fn tampered_token_fails_verification() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let mut token = tsa.issue(&req).token.unwrap();
        token.tst_info.gen_time += 1;
        assert!(!verify_token(&token));
    }

    #[test]
    fn rejects_short_imprint() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "abcd".to_string(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 2);
        assert!(resp.token.is_none());
    }

    #[test]
    fn rejects_non_hex_imprint() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "z".repeat(64),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 2);
    }

    #[test]
    fn ordering_flag_preserved() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: true,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert!(token.tst_info.ordering);
    }

    #[test]
    fn custom_accuracy() {
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa".to_string()).with_accuracy(5);
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.accuracy_secs, 5);
    }

    #[test]
    fn sha3_hash_algorithm() {
        let tsa = make_provider();
        let imprint = hex::encode(crate::crypto::hasher::hash_with(
            HashAlgorithm::Sha3_256,
            b"sha3 data",
        ));
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha3_256,
            message_imprint: imprint.clone(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.hash_algorithm, HashAlgorithm::Sha3_256);
        assert_eq!(token.tst_info.message_imprint, imprint);
    }

    #[test]
    fn signing_payload_is_deterministic() {
        let info = TstInfo {
            version: 1,
            policy: TSA_POLICY_OID.to_string(),
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "aa".repeat(32),
            serial_number: 42,
            gen_time: 1700000000,
            accuracy_secs: 1,
            ordering: false,
            nonce: Some(99),
            tsa_name: "did:goya:tsa".to_string(),
        };
        assert_eq!(info.signing_payload(), info.signing_payload());
    }

    #[test]
    fn different_fields_produce_different_payloads() {
        let base = TstInfo {
            version: 1,
            policy: TSA_POLICY_OID.to_string(),
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "aa".repeat(32),
            serial_number: 1,
            gen_time: 1700000000,
            accuracy_secs: 1,
            ordering: false,
            nonce: None,
            tsa_name: "did:goya:tsa".to_string(),
        };
        let mut modified = base.clone();
        modified.serial_number = 2;
        assert_ne!(base.signing_payload(), modified.signing_payload());
    }

    #[test]
    fn policy_info_contains_required_fields() {
        let tsa = make_provider();
        let info = tsa.policy_info();
        assert_eq!(info["policy_oid"], TSA_POLICY_OID);
        assert!(info["hash_algorithms"].as_array().unwrap().len() >= 2);
        assert!(info["accuracy_secs"].as_u64().is_some());
    }

    #[test]
    fn token_serialization_roundtrip() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(7),
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        let json = serde_json::to_string(&token).unwrap();
        let parsed: TimeStampToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tst_info, token.tst_info);
        assert!(verify_token(&parsed));
    }

    #[test]
    fn mldsa65_signing() {
        use crate::identity::signing::MlDsaSigningProvider;
        let signer = Arc::new(MlDsaSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-pqc".to_string());
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);
        let token = resp.token.unwrap();
        assert_eq!(token.signature_algorithm, SigningAlgorithm::MlDsa65);
        assert!(verify_token(&token));
    }

    #[test]
    fn gen_time_is_recent() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        let now = now_secs();
        assert!(token.tst_info.gen_time <= now);
        assert!(token.tst_info.gen_time >= now - 2);
    }

    #[test]
    fn issue_der_roundtrip() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(99),
            require_ordering: false,
        };
        let der = tsa.issue_der(&req).unwrap();
        assert_eq!(der[0], 0x30);
        let pk_hex = hex::encode(tsa.signer.public_key());
        let fields = rfc3161_der::verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert_eq!(fields.nonce, Some(99));
    }

    #[test]
    fn issue_der_rejects_bad_imprint() {
        let tsa = make_provider();
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: "short".to_string(),
            nonce: None,
            require_ordering: false,
        };
        assert!(tsa.issue_der(&req).is_err());
    }

    #[test]
    fn time_source_integration() {
        use crate::time_source::SimulatedTimeSource;
        let sim = Arc::new(SimulatedTimeSource::new(1_800_000_000));
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa =
            TsaProvider::new(signer, "did:goya:tsa-sim".to_string()).with_time_source(sim.clone());
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let token = tsa.issue(&req).token.unwrap();
        assert_eq!(token.tst_info.gen_time, 1_800_000_000);

        sim.advance(100);
        let token2 = tsa.issue(&req).token.unwrap();
        assert_eq!(token2.tst_info.gen_time, 1_800_000_100);
    }

    #[test]
    fn issue_der_with_time_source() {
        use crate::time_source::SimulatedTimeSource;
        let sim = Arc::new(SimulatedTimeSource::new(1_800_000_000));
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa =
            TsaProvider::new(signer.clone(), "did:goya:tsa-sim".to_string()).with_time_source(sim);
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: Some(7),
            require_ordering: false,
        };
        let der = tsa.issue_der(&req).unwrap();
        let pk_hex = hex::encode(signer.public_key());
        let fields = rfc3161_der::verify_timestamp_resp_der(&der, &pk_hex).unwrap();
        assert!(fields.gen_time_raw.contains("20270115"));
    }

    #[test]
    fn rejects_when_ntp_desynced() {
        use crate::time_source::NtpTimeSource;
        let ntp = Arc::new(NtpTimeSource::new(1));
        // NTP starts as not synced by default
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-ntp".to_string()).with_time_source(ntp);
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 2);
        assert!(resp.status_string.contains("not trusted"));
        assert!(resp.token.is_none());
    }

    #[test]
    fn rejects_der_when_ntp_desynced() {
        use crate::time_source::NtpTimeSource;
        let ntp = Arc::new(NtpTimeSource::new(1));
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-ntp".to_string()).with_time_source(ntp);
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let result = tsa.issue_der(&req);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_when_ntp_synced() {
        use crate::time_source::NtpTimeSource;
        let ntp = Arc::new(NtpTimeSource::new(5));
        ntp.set_sync_status(true, 0);
        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-ntp".to_string()).with_time_source(ntp);
        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);
        assert!(resp.token.is_some());
    }

    #[test]
    fn serial_persists_to_disk() {
        let dir = tempfile::TempDir::new().unwrap();
        let serial_path = dir.path().join("tsa_serial");

        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-persist".to_string())
            .with_serial_path(serial_path.clone());

        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        assert_eq!(resp.status, 0);

        // File should exist with a serial value
        let contents = std::fs::read_to_string(&serial_path).unwrap();
        let saved: u64 = contents.trim().parse().unwrap();
        assert!(saved > 0);
    }

    #[test]
    fn serial_reloads_from_disk() {
        let dir = tempfile::TempDir::new().unwrap();
        let serial_path = dir.path().join("tsa_serial");

        // Write a known serial
        std::fs::write(&serial_path, "999999999999").unwrap();

        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa = TsaProvider::new(signer, "did:goya:tsa-reload".to_string())
            .with_serial_path(serial_path);

        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };
        let resp = tsa.issue(&req);
        let serial = resp.token.unwrap().tst_info.serial_number;
        // Should be >= the saved value (may be epoch-seeded if higher)
        assert!(serial >= 999_999_999_999);
    }

    #[test]
    fn serial_survives_restart_simulation() {
        let dir = tempfile::TempDir::new().unwrap();
        let serial_path = dir.path().join("tsa_serial");

        let req = TimeStampRequest {
            hash_algorithm: HashAlgorithm::Sha256,
            message_imprint: valid_imprint(),
            nonce: None,
            require_ordering: false,
        };

        // "First boot"
        let signer1 = Arc::new(SoftwareSigningProvider::generate());
        let tsa1 = TsaProvider::new(signer1, "did:goya:tsa".to_string())
            .with_serial_path(serial_path.clone());
        let s1 = tsa1.issue(&req).token.unwrap().tst_info.serial_number;
        let s2 = tsa1.issue(&req).token.unwrap().tst_info.serial_number;
        assert_eq!(s2, s1 + 1);

        // "Second boot" — should continue from where we left off
        let signer2 = Arc::new(SoftwareSigningProvider::generate());
        let tsa2 =
            TsaProvider::new(signer2, "did:goya:tsa".to_string()).with_serial_path(serial_path);
        let s3 = tsa2.issue(&req).token.unwrap().tst_info.serial_number;
        assert!(s3 >= s2, "serial must not go backwards: s3={s3}, s2={s2}");
    }

    #[test]
    fn serial_missing_file_uses_epoch_seed() {
        let dir = tempfile::TempDir::new().unwrap();
        let serial_path = dir.path().join("nonexistent_serial");

        let signer = Arc::new(SoftwareSigningProvider::generate());
        let tsa =
            TsaProvider::new(signer, "did:goya:tsa".to_string()).with_serial_path(serial_path);

        let serial = tsa.current_serial();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(serial >= now - 2 && serial <= now + 2);
    }
}
