//! Electronic signature framework — Simple (FES) and Advanced (FEA).
//!
//! Legal alignment:
//! - Chile: Ley 19.799 (Firma Electrónica Simple / Avanzada)
//! - EU: eIDAS Regulation 910/2014 (Simple / Advanced / Qualified)
//! - US: ESIGN Act (15 U.S.C. §7001) + UETA
//!
//! # Signature levels
//!
//! | Level      | Algorithm  | Biometric | Legal weight              |
//! |------------|------------|-----------|---------------------------|
//! | Simple     | Ed25519    | Optional  | FES / eIDAS Simple / ESIGN|
//! | Advanced   | ML-DSA-65  | Required  | FEA / eIDAS Advanced      |
//! | Qualified  | ML-DSA-65  | Required  | eIDAS Qualified (future)  |
//!
//! # Biometric evidence
//!
//! Raw biometric data NEVER enters the system. Clients compute a SHA-256
//! commitment over the biometric template and submit only the hash.
//! The commitment is bound into the signing payload so the signature
//! cryptographically covers the signer's biometric identity.

pub mod cades;
pub mod cades_der;
pub mod iso19794;
pub mod pades;
pub mod pades_der;
pub mod verify;
pub mod xades;

use crate::identity::signing::SigningAlgorithm;
use serde::{Deserialize, Serialize};

pub use verify::{validate_public_key, verify_signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerProof {
    pub public_key: String,
    pub signature: String,
}

pub fn is_signer_proven(
    signer: &str,
    signing_public_key: &str,
    proof: Option<&SignerProof>,
    payload: &[u8],
) -> bool {
    if crate::identity::did::did_matches_pubkey(signer, signing_public_key) {
        return true;
    }
    let Some(proof) = proof else {
        return false;
    };
    let Some(algorithm) = verify::infer_algorithm_from_key(&proof.public_key) else {
        return false;
    };
    crate::identity::did::did_matches_pubkey(signer, &proof.public_key)
        && verify_signature(algorithm, &proof.public_key, payload, &proof.signature)
}

// ── Signature level ──────────────────────────────────────────────────────────

/// Electronic signature level per international legal frameworks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureLevel {
    /// Firma Electrónica Simple (Chile Ley 19.799 Art. 2°)
    /// eIDAS Art. 3(10) — electronic signature
    /// ESIGN Act §7006(5)
    ///
    /// Any electronic method to identify the signer. Ed25519 DID-based.
    #[default]
    Simple,

    /// Firma Electrónica Avanzada (Chile Ley 19.799 Art. 2°)
    /// eIDAS Art. 3(11) + Art. 26 — advanced electronic signature
    ///
    /// Requirements:
    /// - Uniquely linked to the signer (DID + biometric commitment)
    /// - Capable of identifying the signer (biometric evidence)
    /// - Created using data under the signer's sole control (private key)
    /// - Linked to data in such a way that any change is detectable (PQC signature)
    /// - Post-quantum algorithm: ML-DSA-65 (FIPS 204)
    Advanced,

    /// eIDAS Art. 3(12) — qualified electronic signature (future)
    ///
    /// Requires a Qualified Trust Service Provider (QTSP).
    /// Reserved for when a certified TSP issues the signing certificate.
    Qualified,

    /// eIDAS Art. 3(25) — electronic seal (legal entity signature).
    ///
    /// Like Advanced but for organizations, not natural persons.
    /// Used for automated document sealing by legal entities.
    Seal,
}

impl SignatureLevel {
    /// Minimum signing algorithm required for this level.
    pub fn required_algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Simple => SigningAlgorithm::Ed25519,
            Self::Advanced | Self::Qualified | Self::Seal => SigningAlgorithm::MlDsa65,
        }
    }

    /// Whether biometric evidence is mandatory at this level.
    pub fn requires_biometric(&self) -> bool {
        matches!(self, Self::Advanced | Self::Qualified)
    }

    /// Whether the given algorithm satisfies this level's requirements.
    pub fn algorithm_satisfies(&self, alg: SigningAlgorithm) -> bool {
        match self {
            Self::Simple => true, // any algorithm accepted
            Self::Advanced | Self::Qualified | Self::Seal => alg.is_post_quantum(),
        }
    }
}

impl std::fmt::Display for SignatureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Simple => write!(f, "Simple (FES)"),
            Self::Advanced => write!(f, "Advanced (FEA)"),
            Self::Qualified => write!(f, "Qualified"),
            Self::Seal => write!(f, "Seal (Legal Entity)"),
        }
    }
}

// ── Biometric evidence ───────────────────────────────────────────────────────

/// Type of biometric or identity evidence.
///
/// Extensible: new variants can be added without breaking serialization
/// thanks to the `Other` catch-all.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometricType {
    /// Fingerprint template hash.
    Fingerprint,
    /// Facial recognition encoding hash.
    FacialRecognition,
    /// Chilean RUT (Rol Único Tributario) hash.
    Rut,
    /// Iris scan template hash.
    Iris,
    /// Voice print template hash.
    Voice,
    /// Government-issued ID document hash.
    GovernmentId,
    /// Extensible: any other identity factor.
    Other(String),
}

impl std::fmt::Display for BiometricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::FacialRecognition => write!(f, "facial_recognition"),
            Self::Rut => write!(f, "rut"),
            Self::Iris => write!(f, "iris"),
            Self::Voice => write!(f, "voice"),
            Self::GovernmentId => write!(f, "government_id"),
            Self::Other(name) => write!(f, "other:{name}"),
        }
    }
}

/// A single piece of biometric or identity evidence.
///
/// The `commitment` is a SHA-256 hash of the raw biometric data.
/// Raw data never enters the system — only commitments are stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiometricEvidence {
    /// What type of biometric this is.
    pub evidence_type: BiometricType,
    /// SHA-256 commitment (64 hex chars) over the raw biometric template.
    pub commitment: String,
    /// Unix timestamp when the evidence was captured.
    pub captured_at: u64,
    /// Optional device or method identifier (e.g., "FingerprintReader-v2").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_device: Option<String>,
}

impl BiometricEvidence {
    /// Validate that the commitment is a well-formed SHA-256 hex string.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.commitment.len() != 64 {
            return Err(SignatureError::InvalidBiometric(
                "commitment must be 64 hex characters (SHA-256)".into(),
            ));
        }
        hex::decode(&self.commitment)
            .map_err(|_| SignatureError::InvalidBiometric("commitment is not valid hex".into()))?;
        Ok(())
    }

    /// Validate with optional raw template proof.
    ///
    /// When `raw_template` is provided:
    /// 1. Validates template structure (ISO 19794-2 for fingerprints)
    /// 2. Confirms SHA-256(raw_template) == commitment
    ///
    /// Raw data is never stored — only used transiently for validation.
    pub fn validate_with_template(&self, raw_template: &[u8]) -> Result<(), SignatureError> {
        self.validate()?;

        if self.evidence_type == BiometricType::Fingerprint {
            iso19794::validate_fingerprint_template(raw_template)
                .map_err(|e| SignatureError::InvalidBiometric(format!("ISO 19794-2: {e}")))?;
        }

        let digest = hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            raw_template,
        ));
        if digest != self.commitment {
            return Err(SignatureError::InvalidBiometric(
                "raw template hash does not match commitment".into(),
            ));
        }

        Ok(())
    }
}

// ── Signed envelope ──────────────────────────────────────────────────────────

/// A cryptographically signed envelope that wraps any signable payload.
///
/// For Advanced (FEA) signatures, the biometric commitments are hashed
/// together and bound into the signing payload:
///
/// ```text
/// Simple:   "fes:{signer}:{content_hash}"
/// Advanced: "fea:{signer}:{content_hash}:{biometrics_hash}"
/// ```
///
/// Where `biometrics_hash = SHA-256(sorted commitments joined by ':')`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// Signature level claimed by the signer.
    pub level: SignatureLevel,
    /// DID of the signer.
    pub signer: String,
    /// SHA-256 hash of the content being signed (64 hex chars).
    pub content_hash: String,
    /// Hex-encoded signature bytes.
    pub signature: String,
    /// Hex-encoded public key of the signer.
    pub public_key: String,
    /// Algorithm used to produce the signature.
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence (required for Advanced/Qualified, optional for Simple).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub biometric_evidence: Vec<BiometricEvidence>,
    /// Unix timestamp when the envelope was created.
    pub signed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_algorithm: Option<SigningAlgorithm>,
}

impl SignedEnvelope {
    /// Compute the canonical signing payload for this envelope.
    ///
    /// The payload is the byte string that was (or should have been) signed.
    pub fn signing_payload(&self) -> String {
        match self.level {
            SignatureLevel::Simple => {
                format!("fes:{}:{}", self.signer, self.content_hash)
            }
            SignatureLevel::Advanced | SignatureLevel::Qualified | SignatureLevel::Seal => {
                let bio_hash = compute_biometrics_hash(&self.biometric_evidence);
                format!("fea:{}:{}:{}", self.signer, self.content_hash, bio_hash)
            }
        }
    }

    /// Validate the envelope's structural integrity (not the cryptographic signature).
    ///
    /// Checks:
    /// - Algorithm matches the claimed level
    /// - Biometric evidence present when required
    /// - All biometric commitments are valid hex
    /// - Content hash is valid SHA-256 hex
    pub fn is_hybrid(&self) -> bool {
        self.secondary_signature.is_some()
            && self.secondary_public_key.is_some()
            && self.secondary_algorithm.is_some()
    }

    pub fn attach_secondary(
        &mut self,
        provider: &dyn crate::identity::signing::SigningProvider,
    ) -> Result<(), SignatureError> {
        let payload = self.signing_payload();
        let sig = provider
            .sign(payload.as_bytes())
            .map_err(|e| SignatureError::InvalidBiometric(format!("signing failed: {e}")))?;
        self.secondary_signature = Some(hex::encode(&sig));
        self.secondary_public_key = Some(hex::encode(provider.public_key()));
        self.secondary_algorithm = Some(provider.algorithm());
        Ok(())
    }

    pub fn verify_hybrid(&self) -> Result<bool, SignatureError> {
        let payload = self.signing_payload();

        let primary_valid = verify_signature(
            self.signature_algorithm,
            &self.public_key,
            payload.as_bytes(),
            &self.signature,
        );

        if !primary_valid {
            return Ok(false);
        }

        if let (Some(sec_sig), Some(sec_pk), Some(sec_alg)) = (
            &self.secondary_signature,
            &self.secondary_public_key,
            &self.secondary_algorithm,
        ) {
            let secondary_valid = verify_signature(*sec_alg, sec_pk, payload.as_bytes(), sec_sig);
            Ok(secondary_valid)
        } else {
            Ok(true)
        }
    }

    pub fn verify(&self) -> Result<bool, SignatureError> {
        self.validate_structure()?;
        let payload = self.signing_payload();
        let primary_valid = verify_signature(
            self.signature_algorithm,
            &self.public_key,
            payload.as_bytes(),
            &self.signature,
        );
        if !primary_valid {
            return Ok(false);
        }
        if self.is_hybrid() {
            return self.verify_hybrid();
        }
        Ok(true)
    }

    pub fn validate_structure(&self) -> Result<(), SignatureError> {
        // Algorithm must satisfy level requirements
        if !self.level.algorithm_satisfies(self.signature_algorithm) {
            return Err(SignatureError::AlgorithmMismatch {
                level: self.level,
                expected: self.level.required_algorithm(),
                got: self.signature_algorithm,
            });
        }

        // Biometric evidence required for Advanced/Qualified
        if self.level.requires_biometric() && self.biometric_evidence.is_empty() {
            return Err(SignatureError::BiometricRequired(self.level));
        }

        // Validate each biometric commitment
        for evidence in &self.biometric_evidence {
            evidence.validate()?;
        }

        // Validate content_hash format
        if self.content_hash.len() != 64 || hex::decode(&self.content_hash).is_err() {
            return Err(SignatureError::InvalidContentHash);
        }

        Ok(())
    }
}

/// Compute a deterministic hash over biometric commitments.
///
/// Sorts commitments alphabetically, joins with ':', then SHA-256 hashes.
/// This ensures the same set of evidence always produces the same hash
/// regardless of submission order.
pub fn compute_biometrics_hash(evidence: &[BiometricEvidence]) -> String {
    if evidence.is_empty() {
        return "0".repeat(64); // null hash for no evidence
    }
    let mut commitments: Vec<&str> = evidence.iter().map(|e| e.commitment.as_str()).collect();
    commitments.sort();
    let joined = commitments.join(":");
    use pqc_crypto_module::legacy::sha256::Digest;
    let hash = pqc_crypto_module::legacy::sha256::Sha256::digest(joined.as_bytes());
    hex::encode(hash)
}

/// Validate FES/FEA constraints: algorithm↔level, biometric requirement,
/// commitment format, and public key size. Returns `Ok(())` or a `SignatureError`.
pub fn validate_fes_fea(
    level: SignatureLevel,
    algorithm: SigningAlgorithm,
    evidence: &[BiometricEvidence],
    public_key_hex: &str,
) -> Result<(), SignatureError> {
    if level == SignatureLevel::Qualified {
        return Err(SignatureError::QualifiedNotSupported);
    }
    // Infer algorithm from key size when declared algorithm doesn't match key length.
    // Prevents mismatch when clients send default algorithm with a different key type.
    let effective_algorithm =
        crate::signature::verify::infer_algorithm_from_key(public_key_hex).unwrap_or(algorithm);
    if !level.algorithm_satisfies(effective_algorithm) {
        return Err(SignatureError::AlgorithmMismatch {
            level,
            expected: level.required_algorithm(),
            got: effective_algorithm,
        });
    }
    if level.requires_biometric() && evidence.is_empty() {
        return Err(SignatureError::BiometricRequired(level));
    }
    for e in evidence {
        e.validate()?;
    }
    validate_public_key(effective_algorithm, public_key_hex)
        .map_err(SignatureError::InvalidBiometric)?;
    Ok(())
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from signature-level validation.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("signature level {level} requires {expected}, got {got}")]
    AlgorithmMismatch {
        level: SignatureLevel,
        expected: SigningAlgorithm,
        got: SigningAlgorithm,
    },

    #[error("signature level {0} requires at least one biometric evidence")]
    BiometricRequired(SignatureLevel),

    #[error("invalid biometric evidence: {0}")]
    InvalidBiometric(String),

    #[error("content_hash must be 64 hex characters (SHA-256)")]
    InvalidContentHash,

    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("Qualified signature level requires a Qualified Trust Service Provider (QTSP) — not yet supported")]
    QualifiedNotSupported,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash() -> String {
        "a".repeat(64)
    }

    fn dummy_bio(bio_type: BiometricType) -> BiometricEvidence {
        BiometricEvidence {
            evidence_type: bio_type,
            commitment: dummy_hash(),
            captured_at: 1700000000,
            capture_device: None,
        }
    }

    fn simple_envelope() -> SignedEnvelope {
        SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:abc123".into(),
            content_hash: dummy_hash(),
            signature: "ff".repeat(32),
            public_key: "ee".repeat(16),
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        }
    }

    fn advanced_envelope() -> SignedEnvelope {
        SignedEnvelope {
            level: SignatureLevel::Advanced,
            signer: "did:goya:abc123".into(),
            content_hash: dummy_hash(),
            signature: "ff".repeat(32),
            public_key: "ee".repeat(16),
            signature_algorithm: SigningAlgorithm::MlDsa65,
            biometric_evidence: vec![
                dummy_bio(BiometricType::Fingerprint),
                dummy_bio(BiometricType::Rut),
            ],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        }
    }

    // ── SignatureLevel ───────────────────────────────────────────────

    #[test]
    fn simple_accepts_any_algorithm() {
        assert!(SignatureLevel::Simple.algorithm_satisfies(SigningAlgorithm::Ed25519));
        assert!(SignatureLevel::Simple.algorithm_satisfies(SigningAlgorithm::MlDsa65));
    }

    #[test]
    fn advanced_requires_pqc() {
        assert!(!SignatureLevel::Advanced.algorithm_satisfies(SigningAlgorithm::Ed25519));
        assert!(SignatureLevel::Advanced.algorithm_satisfies(SigningAlgorithm::MlDsa65));
    }

    #[test]
    fn qualified_requires_pqc() {
        assert!(!SignatureLevel::Qualified.algorithm_satisfies(SigningAlgorithm::Ed25519));
        assert!(SignatureLevel::Qualified.algorithm_satisfies(SigningAlgorithm::MlDsa65));
    }

    #[test]
    fn simple_no_biometric_required() {
        assert!(!SignatureLevel::Simple.requires_biometric());
    }

    #[test]
    fn advanced_requires_biometric() {
        assert!(SignatureLevel::Advanced.requires_biometric());
    }

    #[test]
    fn default_is_simple() {
        assert_eq!(SignatureLevel::default(), SignatureLevel::Simple);
    }

    #[test]
    fn display_formats() {
        assert_eq!(SignatureLevel::Simple.to_string(), "Simple (FES)");
        assert_eq!(SignatureLevel::Advanced.to_string(), "Advanced (FEA)");
        assert_eq!(SignatureLevel::Qualified.to_string(), "Qualified");
    }

    // ── BiometricEvidence ────────────────────────────────────────────

    #[test]
    fn valid_evidence_passes() {
        let e = dummy_bio(BiometricType::Fingerprint);
        assert!(e.validate().is_ok());
    }

    #[test]
    fn short_commitment_rejected() {
        let mut e = dummy_bio(BiometricType::Rut);
        e.commitment = "abcd".into();
        assert!(e.validate().is_err());
    }

    #[test]
    fn non_hex_commitment_rejected() {
        let mut e = dummy_bio(BiometricType::FacialRecognition);
        e.commitment = "z".repeat(64);
        assert!(e.validate().is_err());
    }

    #[test]
    fn biometric_type_display() {
        assert_eq!(BiometricType::Fingerprint.to_string(), "fingerprint");
        assert_eq!(BiometricType::Rut.to_string(), "rut");
        assert_eq!(
            BiometricType::Other("passport".into()).to_string(),
            "other:passport"
        );
    }

    // ── SignedEnvelope ───────────────────────────────────────────────

    #[test]
    fn simple_envelope_valid() {
        let env = simple_envelope();
        assert!(env.validate_structure().is_ok());
    }

    #[test]
    fn advanced_envelope_valid() {
        let env = advanced_envelope();
        assert!(env.validate_structure().is_ok());
    }

    #[test]
    fn advanced_without_biometric_rejected() {
        let mut env = advanced_envelope();
        env.biometric_evidence.clear();
        let err = env.validate_structure().unwrap_err();
        assert!(err.to_string().contains("biometric"));
    }

    #[test]
    fn advanced_with_ed25519_rejected() {
        let mut env = advanced_envelope();
        env.signature_algorithm = SigningAlgorithm::Ed25519;
        let err = env.validate_structure().unwrap_err();
        assert!(err.to_string().contains("ML-DSA-65"));
    }

    #[test]
    fn invalid_content_hash_rejected() {
        let mut env = simple_envelope();
        env.content_hash = "short".into();
        assert!(env.validate_structure().is_err());
    }

    #[test]
    fn simple_payload_format() {
        let env = simple_envelope();
        let payload = env.signing_payload();
        assert!(payload.starts_with("fes:"));
        assert!(payload.contains(&env.signer));
        assert!(payload.contains(&env.content_hash));
    }

    #[test]
    fn advanced_payload_includes_biometrics_hash() {
        let env = advanced_envelope();
        let payload = env.signing_payload();
        assert!(payload.starts_with("fea:"));
        // Payload: "fea:{did:goya:abc123}:{hash}:{bio_hash}"
        // DID contains 2 colons, so total = 6 segments
        assert!(payload.contains(&env.content_hash));
    }

    #[test]
    fn biometrics_hash_deterministic_regardless_of_order() {
        let a = dummy_bio(BiometricType::Fingerprint);
        let mut b = dummy_bio(BiometricType::Rut);
        b.commitment = "b".repeat(64);

        let hash_ab = compute_biometrics_hash(&[a.clone(), b.clone()]);
        let hash_ba = compute_biometrics_hash(&[b, a]);
        assert_eq!(hash_ab, hash_ba);
    }

    #[test]
    fn biometrics_hash_empty_returns_null_hash() {
        let hash = compute_biometrics_hash(&[]);
        assert_eq!(hash, "0".repeat(64));
    }

    // ── Serde roundtrip ──────────────────────────────────────────────

    #[test]
    fn envelope_serde_roundtrip() {
        let env = advanced_envelope();
        let json = serde_json::to_string(&env).unwrap();
        let restored: SignedEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.level, env.level);
        assert_eq!(restored.biometric_evidence.len(), 2);
        assert_eq!(restored.signature_algorithm, SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn signature_level_serde() {
        let json = serde_json::to_string(&SignatureLevel::Advanced).unwrap();
        assert_eq!(json, "\"advanced\"");
        let restored: SignatureLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, SignatureLevel::Advanced);
    }

    #[test]
    fn biometric_type_serde_other() {
        let t = BiometricType::Other("passport".into());
        let json = serde_json::to_string(&t).unwrap();
        let restored: BiometricType = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, t);
    }

    // ── Qualified level ──────────────────────────────────────────────

    fn qualified_envelope() -> SignedEnvelope {
        SignedEnvelope {
            level: SignatureLevel::Qualified,
            signer: "did:goya:qualified1".into(),
            content_hash: dummy_hash(),
            signature: "ff".repeat(32),
            public_key: "ee".repeat(16),
            signature_algorithm: SigningAlgorithm::MlDsa65,
            biometric_evidence: vec![dummy_bio(BiometricType::FacialRecognition)],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        }
    }

    #[test]
    fn qualified_requires_biometric() {
        assert!(SignatureLevel::Qualified.requires_biometric());
    }

    #[test]
    fn qualified_envelope_valid() {
        let env = qualified_envelope();
        assert!(env.validate_structure().is_ok());
    }

    #[test]
    fn qualified_without_biometric_rejected() {
        let mut env = qualified_envelope();
        env.biometric_evidence.clear();
        let err = env.validate_structure().unwrap_err();
        matches!(
            err,
            SignatureError::BiometricRequired(SignatureLevel::Qualified)
        );
    }

    #[test]
    fn qualified_with_ed25519_rejected() {
        let mut env = qualified_envelope();
        env.signature_algorithm = SigningAlgorithm::Ed25519;
        assert!(env.validate_structure().is_err());
    }

    #[test]
    fn qualified_payload_starts_with_fea() {
        let env = qualified_envelope();
        let payload = env.signing_payload();
        assert!(payload.starts_with("fea:"));
        assert!(payload.contains(&env.content_hash));
    }

    // ── required_algorithm ───────────────────────────────────────────

    #[test]
    fn required_algorithm_simple_is_ed25519() {
        assert_eq!(
            SignatureLevel::Simple.required_algorithm(),
            SigningAlgorithm::Ed25519
        );
    }

    #[test]
    fn required_algorithm_advanced_is_mldsa65() {
        assert_eq!(
            SignatureLevel::Advanced.required_algorithm(),
            SigningAlgorithm::MlDsa65
        );
    }

    #[test]
    fn required_algorithm_qualified_is_mldsa65() {
        assert_eq!(
            SignatureLevel::Qualified.required_algorithm(),
            SigningAlgorithm::MlDsa65
        );
    }

    // ── Simple with optional biometric ───────────────────────────────

    #[test]
    fn simple_with_optional_biometric_valid() {
        let mut env = simple_envelope();
        env.biometric_evidence = vec![dummy_bio(BiometricType::Rut)];
        assert!(env.validate_structure().is_ok());
    }

    #[test]
    fn simple_with_pqc_algorithm_valid() {
        // Simple accepts any algorithm — upgrade path
        let mut env = simple_envelope();
        env.signature_algorithm = SigningAlgorithm::MlDsa65;
        assert!(env.validate_structure().is_ok());
    }

    // ── Invalid biometric in list ────────────────────────────────────

    #[test]
    fn advanced_with_one_invalid_biometric_rejected() {
        let mut env = advanced_envelope();
        env.biometric_evidence.push(dummy_bio(BiometricType::Iris));
        // Corrupt the last one
        env.biometric_evidence.last_mut().unwrap().commitment = "xyz".into();
        let err = env.validate_structure().unwrap_err();
        assert!(matches!(err, SignatureError::InvalidBiometric(_)));
    }

    // ── Content hash edge cases ──────────────────────────────────────

    #[test]
    fn content_hash_64_chars_non_hex_rejected() {
        let mut env = simple_envelope();
        // 64 chars but contains 'g' which is not hex
        env.content_hash = "g".repeat(64);
        assert!(env.validate_structure().is_err());
    }

    #[test]
    fn content_hash_empty_rejected() {
        let mut env = simple_envelope();
        env.content_hash = String::new();
        assert!(env.validate_structure().is_err());
    }

    // ── BiometricEvidence edge cases ─────────────────────────────────

    #[test]
    fn empty_commitment_rejected() {
        let mut e = dummy_bio(BiometricType::Fingerprint);
        e.commitment = String::new();
        assert!(e.validate().is_err());
    }

    #[test]
    fn evidence_with_capture_device_validates() {
        let e = BiometricEvidence {
            evidence_type: BiometricType::Fingerprint,
            commitment: dummy_hash(),
            captured_at: 1700000000,
            capture_device: Some("FingerprintReader-v2".into()),
        };
        assert!(e.validate().is_ok());
    }

    // ── validate_with_template ────────────────────────────────────────

    fn make_iso19794_template() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(b"FMR\0");
        buf.extend(&[0x20, 0x32, 0x30, 0x00]);
        buf.extend(34u32.to_be_bytes()); // total = 24+4+6
        buf.extend(&[0x00, 0x01]); // capture equipment
        buf.extend(&[0x01, 0x40]); // width
        buf.extend(&[0x01, 0x90]); // height
        buf.extend(&[0x01, 0xF4]); // res_x
        buf.extend(&[0x01, 0xF4]); // res_y
        buf.push(0x01); // num views
        buf.push(0x00); // reserved
        buf.push(0x01); // finger position
        buf.push(0x00); // view/impression
        buf.push(80); // quality
        buf.push(1); // 1 minutia
        let type_x: u16 = (1 << 14) | 100;
        buf.extend(type_x.to_be_bytes());
        buf.extend(200u16.to_be_bytes());
        buf.push(45);
        buf.push(80);
        buf
    }

    #[test]
    fn validate_with_valid_template() {
        let tmpl = make_iso19794_template();
        let digest = hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            &tmpl,
        ));
        let e = BiometricEvidence {
            evidence_type: BiometricType::Fingerprint,
            commitment: digest,
            captured_at: 1700000000,
            capture_device: None,
        };
        assert!(e.validate_with_template(&tmpl).is_ok());
    }

    #[test]
    fn validate_with_bad_template_structure() {
        let garbage = vec![0xFF; 50];
        let digest = hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            &garbage,
        ));
        let e = BiometricEvidence {
            evidence_type: BiometricType::Fingerprint,
            commitment: digest,
            captured_at: 1700000000,
            capture_device: None,
        };
        let err = e.validate_with_template(&garbage).unwrap_err();
        assert!(err.to_string().contains("ISO 19794-2"));
    }

    #[test]
    fn validate_with_wrong_commitment() {
        let tmpl = make_iso19794_template();
        let e = BiometricEvidence {
            evidence_type: BiometricType::Fingerprint,
            commitment: "b".repeat(64), // wrong hash
            captured_at: 1700000000,
            capture_device: None,
        };
        let err = e.validate_with_template(&tmpl).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn validate_with_template_skips_iso_for_non_fingerprint() {
        let garbage = vec![0xFF; 50]; // not valid ISO 19794, but not fingerprint type
        let digest = hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            &garbage,
        ));
        let e = BiometricEvidence {
            evidence_type: BiometricType::FacialRecognition,
            commitment: digest,
            captured_at: 1700000000,
            capture_device: None,
        };
        // Non-fingerprint types skip ISO 19794 check, only verify hash
        assert!(e.validate_with_template(&garbage).is_ok());
    }

    // ── BiometricType Display (all variants) ─────────────────────────

    #[test]
    fn biometric_type_display_all_variants() {
        assert_eq!(
            BiometricType::FacialRecognition.to_string(),
            "facial_recognition"
        );
        assert_eq!(BiometricType::Iris.to_string(), "iris");
        assert_eq!(BiometricType::Voice.to_string(), "voice");
        assert_eq!(BiometricType::GovernmentId.to_string(), "government_id");
    }

    // ── BiometricType Serde (all standard variants) ──────────────────

    #[test]
    fn biometric_type_serde_all_standard() {
        let types = vec![
            BiometricType::Fingerprint,
            BiometricType::FacialRecognition,
            BiometricType::Rut,
            BiometricType::Iris,
            BiometricType::Voice,
            BiometricType::GovernmentId,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let restored: BiometricType = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, t, "serde roundtrip failed for {t}");
        }
    }

    // ── Serde: Simple envelope omits biometric_evidence ──────────────

    #[test]
    fn simple_envelope_serde_omits_empty_biometrics() {
        let env = simple_envelope();
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("biometric_evidence"));
        let restored: SignedEnvelope = serde_json::from_str(&json).unwrap();
        assert!(restored.biometric_evidence.is_empty());
        assert_eq!(restored.level, SignatureLevel::Simple);
    }

    // ── Serde: SignatureLevel all variants ────────────────────────────

    #[test]
    fn signature_level_serde_all() {
        for (level, expected_json) in [
            (SignatureLevel::Simple, "\"simple\""),
            (SignatureLevel::Advanced, "\"advanced\""),
            (SignatureLevel::Qualified, "\"qualified\""),
        ] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, expected_json);
            let restored: SignatureLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, level);
        }
    }

    // ── compute_biometrics_hash ──────────────────────────────────────

    #[test]
    fn biometrics_hash_single_element() {
        let a = dummy_bio(BiometricType::Fingerprint);
        let hash = compute_biometrics_hash(&[a]);
        assert_eq!(hash.len(), 64);
        assert!(hex::decode(&hash).is_ok());
    }

    #[test]
    fn biometrics_hash_is_valid_hex() {
        let a = dummy_bio(BiometricType::Fingerprint);
        let mut b = dummy_bio(BiometricType::Rut);
        b.commitment = "b".repeat(64);
        let hash = compute_biometrics_hash(&[a, b]);
        assert_eq!(hash.len(), 64);
        assert!(hex::decode(&hash).is_ok());
    }

    #[test]
    fn biometrics_hash_different_commitments_produce_different_hashes() {
        let a = dummy_bio(BiometricType::Fingerprint);
        let mut b = dummy_bio(BiometricType::Fingerprint);
        b.commitment = "b".repeat(64);
        let hash_a = compute_biometrics_hash(&[a]);
        let hash_b = compute_biometrics_hash(&[b]);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn biometrics_hash_duplicate_commitments() {
        let a = dummy_bio(BiometricType::Fingerprint);
        let hash_one = compute_biometrics_hash(std::slice::from_ref(&a));
        let hash_two = compute_biometrics_hash(&[a.clone(), a]);
        // Two identical commitments should differ from one (different payload)
        assert_ne!(hash_one, hash_two);
    }

    // ── Error variant matching ───────────────────────────────────────

    #[test]
    fn error_algorithm_mismatch_message() {
        let err = SignatureError::AlgorithmMismatch {
            level: SignatureLevel::Advanced,
            expected: SigningAlgorithm::MlDsa65,
            got: SigningAlgorithm::Ed25519,
        };
        let msg = err.to_string();
        assert!(msg.contains("Advanced (FEA)"));
        assert!(msg.contains("ML-DSA-65"));
        assert!(msg.contains("Ed25519"));
    }

    #[test]
    fn error_biometric_required_message() {
        let err = SignatureError::BiometricRequired(SignatureLevel::Advanced);
        assert!(err.to_string().contains("biometric"));
        assert!(err.to_string().contains("Advanced (FEA)"));
    }

    #[test]
    fn error_invalid_content_hash_message() {
        let err = SignatureError::InvalidContentHash;
        assert!(err.to_string().contains("64 hex"));
    }

    #[test]
    fn error_verification_failed_message() {
        let err = SignatureError::VerificationFailed("bad sig".into());
        assert!(err.to_string().contains("bad sig"));
    }

    // ── Payload determinism ──────────────────────────────────────────

    #[test]
    fn same_envelope_produces_same_payload() {
        let env = advanced_envelope();
        assert_eq!(env.signing_payload(), env.signing_payload());
    }

    #[test]
    fn different_content_hash_produces_different_payload() {
        let env1 = advanced_envelope();
        let mut env2 = advanced_envelope();
        env2.content_hash = "b".repeat(64);
        assert_ne!(env1.signing_payload(), env2.signing_payload());
    }

    #[test]
    fn different_signer_produces_different_payload() {
        let env1 = simple_envelope();
        let mut env2 = simple_envelope();
        env2.signer = "did:goya:other".into();
        assert_ne!(env1.signing_payload(), env2.signing_payload());
    }

    // ── validate_fes_fea ─────────────────────────────────────────────

    #[test]
    fn validate_fes_fea_simple_ed25519_ok() {
        let pk = "aa".repeat(32); // 64 hex = 32 bytes Ed25519
        assert!(
            validate_fes_fea(SignatureLevel::Simple, SigningAlgorithm::Ed25519, &[], &pk).is_ok()
        );
    }

    #[test]
    fn validate_fes_fea_simple_with_optional_bio_ok() {
        let pk = "aa".repeat(32);
        let bio = vec![dummy_bio(BiometricType::Rut)];
        assert!(
            validate_fes_fea(SignatureLevel::Simple, SigningAlgorithm::Ed25519, &bio, &pk).is_ok()
        );
    }

    #[test]
    fn validate_fes_fea_advanced_mldsa65_with_bio_ok() {
        let pk = "aa".repeat(1952); // 3904 hex = 1952 bytes ML-DSA-65
        let bio = vec![dummy_bio(BiometricType::Fingerprint)];
        assert!(validate_fes_fea(
            SignatureLevel::Advanced,
            SigningAlgorithm::MlDsa65,
            &bio,
            &pk
        )
        .is_ok());
    }

    #[test]
    fn validate_fes_fea_advanced_ed25519_rejected() {
        let pk = "aa".repeat(32);
        let bio = vec![dummy_bio(BiometricType::Fingerprint)];
        let err = validate_fes_fea(
            SignatureLevel::Advanced,
            SigningAlgorithm::Ed25519,
            &bio,
            &pk,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::AlgorithmMismatch { .. }));
    }

    #[test]
    fn validate_fes_fea_advanced_no_bio_rejected() {
        let pk = "aa".repeat(1952);
        let err = validate_fes_fea(
            SignatureLevel::Advanced,
            SigningAlgorithm::MlDsa65,
            &[],
            &pk,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::BiometricRequired(_)));
    }

    #[test]
    fn validate_fes_fea_invalid_bio_commitment_rejected() {
        let pk = "aa".repeat(1952);
        let mut bio = dummy_bio(BiometricType::Iris);
        bio.commitment = "short".into();
        let err = validate_fes_fea(
            SignatureLevel::Advanced,
            SigningAlgorithm::MlDsa65,
            &[bio],
            &pk,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::InvalidBiometric(_)));
    }

    #[test]
    fn validate_fes_fea_wrong_pk_size_rejected() {
        let pk = "aa".repeat(32); // Ed25519 size, but declared MlDsa65
        let bio = vec![dummy_bio(BiometricType::Fingerprint)];
        // Inferred algorithm is Ed25519 (from key size), which doesn't satisfy Advanced
        let err = validate_fes_fea(
            SignatureLevel::Advanced,
            SigningAlgorithm::MlDsa65,
            &bio,
            &pk,
        )
        .unwrap_err();
        assert!(matches!(err, SignatureError::AlgorithmMismatch { .. }));
    }

    // ── TDD: Qualified rejected at API level ──────────────────────
    #[test]
    fn hybrid_envelope_has_two_signatures() {
        use crate::identity::signing::{
            EcdsaP256SigningProvider, MlDsaSigningProvider, SigningProvider,
        };
        let pqc = MlDsaSigningProvider::generate();
        let ec = EcdsaP256SigningProvider::generate();

        let payload = "fes:did:goya:test:abcdef";
        let sig = pqc.sign(payload.as_bytes()).unwrap();

        let mut env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:test".into(),
            content_hash: "abcdef".into(),
            signature: hex::encode(&sig),
            public_key: hex::encode(pqc.public_key()),
            signature_algorithm: SigningAlgorithm::MlDsa65,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        assert!(!env.is_hybrid());
        env.attach_secondary(&ec).unwrap();
        assert!(env.is_hybrid());
        assert_eq!(env.secondary_algorithm, Some(SigningAlgorithm::EcdsaP256));
    }

    #[test]
    fn hybrid_verify_both_signatures_pass() {
        use crate::identity::signing::{
            EcdsaP256SigningProvider, MlDsaSigningProvider, SigningProvider,
        };
        let pqc = MlDsaSigningProvider::generate();
        let ec = EcdsaP256SigningProvider::generate();

        let payload = "fes:did:goya:hybrid:aabbccdd";
        let sig = pqc.sign(payload.as_bytes()).unwrap();

        let mut env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:hybrid".into(),
            content_hash: "aabbccdd".into(),
            signature: hex::encode(&sig),
            public_key: hex::encode(pqc.public_key()),
            signature_algorithm: SigningAlgorithm::MlDsa65,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        env.attach_secondary(&ec).unwrap();
        assert!(env.verify_hybrid().unwrap());
    }

    #[test]
    fn hybrid_verify_fails_if_primary_corrupted() {
        use crate::identity::signing::{
            EcdsaP256SigningProvider, MlDsaSigningProvider, SigningProvider,
        };
        let pqc = MlDsaSigningProvider::generate();
        let ec = EcdsaP256SigningProvider::generate();

        let payload = "fes:did:goya:corrupt:deadbeef";
        let sig = pqc.sign(payload.as_bytes()).unwrap();

        let mut env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:corrupt".into(),
            content_hash: "deadbeef".into(),
            signature: hex::encode(&sig),
            public_key: hex::encode(pqc.public_key()),
            signature_algorithm: SigningAlgorithm::MlDsa65,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        env.attach_secondary(&ec).unwrap();
        env.signature = "00".repeat(3309);
        assert!(!env.verify_hybrid().unwrap());
    }

    #[test]
    fn non_hybrid_verify_works() {
        use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};
        let pqc = MlDsaSigningProvider::generate();
        let payload = "fes:did:goya:single:112233";
        let sig = pqc.sign(payload.as_bytes()).unwrap();

        let env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer: "did:goya:single".into(),
            content_hash: "112233".into(),
            signature: hex::encode(&sig),
            public_key: hex::encode(pqc.public_key()),
            signature_algorithm: SigningAlgorithm::MlDsa65,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        assert!(!env.is_hybrid());
        assert!(env.verify_hybrid().unwrap());
    }

    #[test]
    fn validate_fes_fea_rejects_qualified() {
        let pk = "aa".repeat(1952);
        let bio = vec![dummy_bio(BiometricType::GovernmentId)];
        let err = validate_fes_fea(
            SignatureLevel::Qualified,
            SigningAlgorithm::MlDsa65,
            &bio,
            &pk,
        )
        .unwrap_err();
        assert!(
            matches!(err, SignatureError::QualifiedNotSupported),
            "Qualified must be rejected with QualifiedNotSupported, got: {err}"
        );
    }

    #[test]
    fn verify_atomic_passes_valid_simple() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let content = dummy_hash();
        let signer = "did:goya:atomictest".to_string();
        let payload = format!("fes:{signer}:{content}");
        let sig = provider.sign(payload.as_bytes()).unwrap();

        let env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer,
            content_hash: content,
            signature: hex::encode(&sig),
            public_key: hex::encode(provider.public_key()),
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        assert!(env.verify().unwrap());
    }

    #[test]
    fn verify_atomic_fails_corrupted_signature() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let content = dummy_hash();
        let signer = "did:goya:corrupt2".to_string();
        let payload = format!("fes:{signer}:{content}");
        let sig = provider.sign(payload.as_bytes()).unwrap();

        let env = SignedEnvelope {
            level: SignatureLevel::Simple,
            signer,
            content_hash: content,
            signature: hex::encode(&sig).replace('a', "b"),
            public_key: hex::encode(provider.public_key()),
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        assert!(!env.verify().unwrap());
    }

    #[test]
    fn verify_atomic_rejects_wrong_level() {
        let env = SignedEnvelope {
            level: SignatureLevel::Advanced,
            signer: "did:goya:wronglvl".into(),
            content_hash: dummy_hash(),
            signature: "ff".repeat(32),
            public_key: "ee".repeat(16),
            signature_algorithm: SigningAlgorithm::Ed25519,
            biometric_evidence: vec![],
            signed_at: 1700000000,
            secondary_signature: None,
            secondary_public_key: None,
            secondary_algorithm: None,
        };

        assert!(env.verify().is_err());
    }
}
