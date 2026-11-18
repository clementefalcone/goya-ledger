//! Pluggable signing provider abstraction.
//!
//! `SigningProvider` decouples cryptographic operations from key storage.
//! Implementations exist for Ed25519 (`SoftwareSigningProvider`) and
//! ML-DSA (`MlDsaSigningProvider`) for post-quantum readiness.
//!
//! Signatures and public keys are variable-length (`Vec<u8>`) to support
//! algorithms with different output sizes (Ed25519: 64-byte sig / 32-byte pk,
//! ML-DSA-65: 3309-byte sig / 1952-byte pk).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("signing failed: {0}")]
    SignFailed(String),
    #[error("verification failed: {0}")]
    VerifyFailed(String),
    #[allow(dead_code)]
    #[error("key not available: {0}")]
    KeyNotAvailable(String),
}

/// Identifies the cryptographic algorithm used by a `SigningProvider`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub enum SigningAlgorithm {
    #[default]
    Ed25519,
    MlDsa65,
    SlhDsa128s,
    Rsa,
    EcdsaP256,
}

impl SigningAlgorithm {
    /// Returns `true` if this algorithm is post-quantum resistant.
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::MlDsa65 | Self::SlhDsa128s)
    }

    pub fn is_classical(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Rsa | Self::EcdsaP256)
    }
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
            Self::SlhDsa128s => write!(f, "SLH-DSA-SHAKE-128s"),
            Self::Rsa => write!(f, "RSA"),
            Self::EcdsaP256 => write!(f, "ES256"),
        }
    }
}

/// Abstraction over cryptographic signing operations.
///
/// Signatures and public keys are returned as `Vec<u8>` to accommodate
/// algorithms with different output sizes.
pub trait SigningProvider: Send + Sync {
    #[allow(dead_code)]
    /// The algorithm this provider uses.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Sign `data` and return the signature bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError>;

    /// Return the public key bytes.
    fn public_key(&self) -> Vec<u8>;

    /// Verify `sig` over `data` using the provider's public key.
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, SigningError>;
}

/// Software-based signing provider using in-memory Ed25519 keys.
///
/// The inner `SigningKey` implements `ZeroizeOnDrop` — key material is
/// automatically overwritten when the provider is dropped.
pub struct SoftwareSigningProvider {
    signing_key: pqc_crypto_module::legacy::ed25519::SigningKey,
}

impl SoftwareSigningProvider {
    #[allow(dead_code)]
    /// Create a provider from an existing signing key.
    pub fn from_key(signing_key: pqc_crypto_module::legacy::ed25519::SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a new random signing key.
    pub fn generate() -> Self {
        use pqc_crypto_module::legacy::rng::OsRng;
        Self {
            signing_key: pqc_crypto_module::legacy::ed25519::SigningKey::generate(&mut OsRng),
        }
    }
}

impl SigningProvider for SoftwareSigningProvider {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        use pqc_crypto_module::legacy::ed25519::Signer;
        let sig = self.signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, SigningError> {
        use pqc_crypto_module::legacy::ed25519::{Signature, Verifier};
        let sig_bytes: [u8; 64] = sig
            .try_into()
            .map_err(|_| SigningError::VerifyFailed("Ed25519 signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);
        Ok(self
            .signing_key
            .verifying_key()
            .verify(data, &signature)
            .is_ok())
    }
}

/// Post-quantum signing provider using ML-DSA-65 (FIPS 204, security level 3).
///
/// Routes through `pqc_crypto_module::mldsa` (approved-mode guarded) — NOT
/// through `legacy::mldsa_raw`. This ensures all ML-DSA operations respect
/// the FIPS 140-3 state machine and cryptographic boundary.
///
/// Key and signature sizes:
/// - Public key: 1952 bytes
/// - Secret key: 4032 bytes
/// - Signature:  3309 bytes
pub struct MlDsaSigningProvider {
    public_key: pqc_crypto_module::types::MldsaPublicKey,
    private_key: pqc_crypto_module::types::MldsaPrivateKey,
}

impl MlDsaSigningProvider {
    /// Generate a new random ML-DSA-65 keypair via the approved API.
    pub fn generate() -> Self {
        let kp = pqc_crypto_module::mldsa::generate_keypair_raw();
        Self {
            public_key: kp.public_key,
            private_key: kp.private_key,
        }
    }

    pub fn export_key_bytes(&self) -> Vec<u8> {
        let mut buf = self.public_key.as_bytes().to_vec();
        buf.extend_from_slice(self.private_key.as_bytes());
        buf
    }

    pub fn from_keys(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, SigningError> {
        let pk = pqc_crypto_module::types::MldsaPublicKey::from_bytes(pk_bytes).map_err(|e| {
            SigningError::KeyNotAvailable(format!("invalid ML-DSA-65 public key: {e}"))
        })?;
        let sk = pqc_crypto_module::types::MldsaPrivateKey::from_bytes(sk_bytes).map_err(|e| {
            SigningError::KeyNotAvailable(format!("invalid ML-DSA-65 secret key: {e}"))
        })?;
        Ok(Self {
            public_key: pk,
            private_key: sk,
        })
    }
}

impl SigningProvider for MlDsaSigningProvider {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::MlDsa65
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        let sig = pqc_crypto_module::mldsa::sign_message_raw(&self.private_key, data)
            .map_err(|e| SigningError::SignFailed(format!("ML-DSA-65 sign: {e}")))?;
        Ok(sig.as_bytes().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, SigningError> {
        let signature = pqc_crypto_module::types::MldsaSignature::from_bytes(sig)
            .map_err(|e| SigningError::VerifyFailed(format!("invalid ML-DSA-65 signature: {e}")))?;
        match pqc_crypto_module::mldsa::verify_signature_raw(&self.public_key, data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// ── RSA Signing Provider ────────────────────────────────────────────────────

/// Software-based signing provider using RSA-2048 with PKCS#1 v1.5 SHA-256.
///
/// Key and signature sizes:
/// - Public key (DER-encoded): variable (~294 bytes for RSA-2048)
/// - Signature: 256 bytes (2048-bit)
pub struct RsaSigningProvider {
    private_key: rsa::RsaPrivateKey,
}

impl RsaSigningProvider {
    /// Generate a new random RSA-2048 keypair.
    pub fn generate() -> Self {
        use pqc_crypto_module::legacy::rng::OsRng;
        let private_key =
            rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key generation failed");
        Self { private_key }
    }

    #[allow(dead_code)]
    pub fn from_key(private_key: rsa::RsaPrivateKey) -> Self {
        Self { private_key }
    }
}

impl SigningProvider for RsaSigningProvider {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Rsa
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_key = SigningKey::<sha2::Sha256>::new(self.private_key.clone());
        let sig = signing_key.sign(data);
        Ok(sig.to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.private_key
            .to_public_key()
            .to_pkcs1_der()
            .expect("RSA public key encoding failed")
            .as_bytes()
            .to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, SigningError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(self.private_key.to_public_key());
        let signature = Signature::try_from(sig)
            .map_err(|e| SigningError::VerifyFailed(format!("invalid RSA signature: {e}")))?;
        Ok(verifying_key.verify(data, &signature).is_ok())
    }
}

// ── ECDSA P-256 (ES256) Signing Provider ───────────────────────────────────

/// ECDSA P-256 signing provider for EUDI interoperability (ES256).
///
/// Key and signature sizes:
/// - Public key (SEC1 uncompressed): 65 bytes (0x04 || x || y)
/// - Public key (SEC1 compressed): 33 bytes
/// - Signature (DER): variable (~70-72 bytes)
/// - Signature (raw r||s): 64 bytes
///
/// Uses SHA-256 as the hash function (NIST FIPS 186-5).
pub struct EcdsaP256SigningProvider {
    signing_key: p256::ecdsa::SigningKey,
}

impl EcdsaP256SigningProvider {
    /// Generate a new random P-256 keypair.
    pub fn generate() -> Self {
        use pqc_crypto_module::legacy::rng::OsRng;
        Self {
            signing_key: p256::ecdsa::SigningKey::random(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, SigningError> {
        p256::ecdsa::SigningKey::from_slice(secret)
            .map(|signing_key| Self { signing_key })
            .map_err(|e| SigningError::KeyNotAvailable(format!("invalid P-256 secret key: {e}")))
    }

    pub fn secret_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.signing_key.to_bytes().to_vec())
    }
}

impl SigningProvider for EcdsaP256SigningProvider {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        use p256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        let vk = self.signing_key.verifying_key();
        vk.to_sec1_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, SigningError> {
        use p256::ecdsa::{signature::Verifier, Signature};
        if sig.len() != 64 {
            return Err(SigningError::VerifyFailed(
                "ES256 signature must be 64 bytes".into(),
            ));
        }
        let signature = Signature::from_bytes(sig.into())
            .map_err(|e| SigningError::VerifyFailed(format!("invalid P-256 signature: {e}")))?;
        Ok(self
            .signing_key
            .verifying_key()
            .verify(data, &signature)
            .is_ok())
    }
}

// ── SLH-DSA-128s (FIPS 205 — hash-based, stateless) ──────────────────────────

pub struct SlhDsaSigningProvider {
    keypair: pqc_crypto_module::slhdsa::SlhDsaKeyPair,
}

impl SlhDsaSigningProvider {
    pub fn generate() -> Self {
        let _ = pqc_crypto_module::api::initialize_approved_mode();
        Self {
            keypair: pqc_crypto_module::slhdsa::generate_keypair()
                .expect("SLH-DSA keypair generation"),
        }
    }

    pub fn from_bytes(
        secret_key_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<Self, SigningError> {
        Ok(Self {
            keypair: pqc_crypto_module::slhdsa::SlhDsaKeyPair {
                public_key: pqc_crypto_module::slhdsa::SlhDsaPublicKey::from_bytes(
                    public_key_bytes,
                )
                .map_err(|e| SigningError::KeyNotAvailable(format!("SLH-DSA pubkey: {e}")))?,
                private_key: pqc_crypto_module::slhdsa::SlhDsaPrivateKey(secret_key_bytes.to_vec()),
            },
        })
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.keypair.public_key.as_bytes()
    }

    pub fn private_key_bytes(&self) -> &[u8] {
        self.keypair.private_key.as_bytes()
    }
}

impl SigningProvider for SlhDsaSigningProvider {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::SlhDsa128s
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        let sig = pqc_crypto_module::slhdsa::sign_message_raw(&self.keypair.private_key, data)
            .map_err(|e| SigningError::SignFailed(format!("SLH-DSA sign: {e}")))?;
        Ok(sig.as_bytes().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key.as_bytes().to_vec()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<bool, SigningError> {
        let signature = pqc_crypto_module::slhdsa::SlhDsaSignature(sig.to_vec());
        match pqc_crypto_module::slhdsa::verify_signature_raw(
            &self.keypair.public_key,
            data,
            &signature,
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// ── FIPS 140-3 Power-Up Self-Tests (Known Answer Tests) ─────────────────────

/// Run cryptographic self-tests for all supported algorithms.
///
/// FIPS 140-3 requires that a cryptographic module verify its own correctness
/// at power-up before processing any external data. This function:
///
/// 1. Generates a keypair for each algorithm
/// 2. Signs a known test vector
/// 3. Verifies the signature
/// 4. Verifies that a corrupted signature is rejected
///
/// Returns `Ok(())` if all tests pass, or an error describing the failure.
/// Call this at node startup before accepting any requests.
pub fn run_crypto_self_tests() -> Result<(), SigningError> {
    // Ed25519 KAT
    {
        let provider = SoftwareSigningProvider::generate();
        let test_data = b"FIPS-140-3-KAT-Ed25519";
        let sig = provider.sign(test_data)?;
        if !provider.verify(test_data, &sig)? {
            return Err(SigningError::SignFailed(
                "Ed25519 KAT: sign-then-verify failed".into(),
            ));
        }
        // Corrupt one byte and verify rejection
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;
        if provider.verify(test_data, &bad_sig).unwrap_or(true) {
            return Err(SigningError::VerifyFailed(
                "Ed25519 KAT: corrupted signature was accepted".into(),
            ));
        }
    }

    // ML-DSA-65 KAT
    {
        let provider = MlDsaSigningProvider::generate();
        let test_data = b"FIPS-140-3-KAT-ML-DSA-65";
        let sig = provider.sign(test_data)?;
        if !provider.verify(test_data, &sig)? {
            return Err(SigningError::SignFailed(
                "ML-DSA-65 KAT: sign-then-verify failed".into(),
            ));
        }
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;
        if provider.verify(test_data, &bad_sig).unwrap_or(true) {
            return Err(SigningError::VerifyFailed(
                "ML-DSA-65 KAT: corrupted signature was accepted".into(),
            ));
        }
    }

    // RSA KAT
    {
        let provider = RsaSigningProvider::generate();
        let test_data = b"FIPS-140-3-KAT-RSA";
        let sig = provider.sign(test_data)?;
        if !provider.verify(test_data, &sig)? {
            return Err(SigningError::SignFailed(
                "RSA KAT: sign-then-verify failed".into(),
            ));
        }
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;
        if provider.verify(test_data, &bad_sig).unwrap_or(true) {
            return Err(SigningError::VerifyFailed(
                "RSA KAT: corrupted signature was accepted".into(),
            ));
        }
    }

    // ECDSA P-256 (ES256) KAT
    {
        let provider = EcdsaP256SigningProvider::generate();
        let test_data = b"FIPS-140-3-KAT-ES256";
        let sig = provider.sign(test_data)?;
        if !provider.verify(test_data, &sig)? {
            return Err(SigningError::SignFailed(
                "ES256 KAT: sign-then-verify failed".into(),
            ));
        }
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;
        if provider.verify(test_data, &bad_sig).unwrap_or(true) {
            return Err(SigningError::VerifyFailed(
                "ES256 KAT: corrupted signature was accepted".into(),
            ));
        }
    }

    // SHA-256 KAT (used for block hashing, merkle roots, payload hashes)
    {
        use pqc_crypto_module::legacy::sha256::Digest;
        let input = b"FIPS-140-3-KAT-SHA256";
        let hash = pqc_crypto_module::legacy::sha256::Sha256::digest(input);
        let expected =
            hex::decode("11ffe3edcec6203b91f4f575c8d51dad935ea2a40e0bed0e5f9f69575afb80d0")
                .expect("valid hex");
        if hash[..] != expected[..] {
            return Err(SigningError::SignFailed(
                "SHA-256 KAT: digest mismatch".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_self_tests_pass() {
        run_crypto_self_tests().expect("KAT self-tests must pass");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let provider = SoftwareSigningProvider::generate();
        let data = b"hello world";

        let sig = provider.sign(data).unwrap();
        assert!(provider.verify(data, &sig).unwrap());
    }

    #[test]
    fn verify_wrong_data_fails() {
        let provider = SoftwareSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        assert!(!provider.verify(b"wrong", &sig).unwrap());
    }

    #[test]
    fn ed25519_public_key_is_32_bytes() {
        let provider = SoftwareSigningProvider::generate();
        let pk = provider.public_key();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn ed25519_signature_is_64_bytes() {
        let provider = SoftwareSigningProvider::generate();
        let sig = provider.sign(b"test").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn ed25519_algorithm_identifier() {
        let provider = SoftwareSigningProvider::generate();
        assert_eq!(provider.algorithm(), SigningAlgorithm::Ed25519);
    }

    #[test]
    fn from_known_key() {
        let key = pqc_crypto_module::legacy::ed25519::SigningKey::from_bytes(&[42u8; 32]);
        let provider = SoftwareSigningProvider::from_key(key);
        let sig = provider.sign(b"test").unwrap();
        assert!(provider.verify(b"test", &sig).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let provider = SoftwareSigningProvider::generate();
        let bad_sig = vec![0u8; 32]; // wrong length
        assert!(provider.verify(b"data", &bad_sig).is_err());
    }

    #[test]
    fn trait_object_usage() {
        let provider: Box<dyn SigningProvider> = Box::new(SoftwareSigningProvider::generate());
        let sig = provider.sign(b"data").unwrap();
        assert!(provider.verify(b"data", &sig).unwrap());
    }

    // --- ML-DSA-65 tests ---

    #[test]
    fn mldsa65_sign_and_verify_roundtrip() {
        let provider = MlDsaSigningProvider::generate();
        let data = b"post-quantum hello";
        let sig = provider.sign(data).unwrap();
        assert!(provider.verify(data, &sig).unwrap());
    }

    #[test]
    fn mldsa65_verify_wrong_data_fails() {
        let provider = MlDsaSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        assert!(!provider.verify(b"wrong", &sig).unwrap());
    }

    #[test]
    fn mldsa65_algorithm_identifier() {
        let provider = MlDsaSigningProvider::generate();
        assert_eq!(provider.algorithm(), SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn mldsa65_signature_is_3309_bytes() {
        let provider = MlDsaSigningProvider::generate();
        let sig = provider.sign(b"test").unwrap();
        assert_eq!(sig.len(), 3309);
    }

    #[test]
    fn mldsa65_public_key_is_1952_bytes() {
        let provider = MlDsaSigningProvider::generate();
        assert_eq!(provider.public_key().len(), 1952);
    }

    #[test]
    fn mldsa65_verify_rejects_wrong_signature() {
        let provider = MlDsaSigningProvider::generate();
        // A wrong-length or garbage signature must not verify successfully
        let bad_sig = vec![0u8; 64];
        let result = provider.verify(b"data", &bad_sig);
        assert!(result.is_err() || matches!(result, Ok(false)));
    }

    #[test]
    fn mldsa65_from_keys_roundtrip() {
        let provider = MlDsaSigningProvider::generate();
        let pk = provider.public_key();
        let sk = provider.private_key.as_bytes().to_vec();
        let restored = MlDsaSigningProvider::from_keys(&pk, &sk).unwrap();
        let sig = restored.sign(b"roundtrip").unwrap();
        assert!(restored.verify(b"roundtrip", &sig).unwrap());
    }

    #[test]
    fn mldsa65_trait_object_usage() {
        let provider: Box<dyn SigningProvider> = Box::new(MlDsaSigningProvider::generate());
        let sig = provider.sign(b"pqc data").unwrap();
        assert!(provider.verify(b"pqc data", &sig).unwrap());
    }

    // --- RSA tests ---

    #[test]
    fn rsa_sign_and_verify_roundtrip() {
        let provider = RsaSigningProvider::generate();
        let data = b"rsa test message";
        let sig = provider.sign(data).unwrap();
        assert!(provider.verify(data, &sig).unwrap());
    }

    #[test]
    fn rsa_verify_wrong_data_fails() {
        let provider = RsaSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        assert!(!provider.verify(b"wrong", &sig).unwrap());
    }

    #[test]
    fn rsa_algorithm_identifier() {
        let provider = RsaSigningProvider::generate();
        assert_eq!(provider.algorithm(), SigningAlgorithm::Rsa);
    }

    #[test]
    fn rsa_signature_is_256_bytes() {
        let provider = RsaSigningProvider::generate();
        let sig = provider.sign(b"test").unwrap();
        assert_eq!(sig.len(), 256); // RSA-2048
    }

    #[test]
    fn rsa_public_key_is_der_encoded() {
        let provider = RsaSigningProvider::generate();
        let pk = provider.public_key();
        assert!(pk.len() > 128, "RSA-2048 DER pk should be > 128 bytes");
        assert_eq!(pk[0], 0x30, "DER SEQUENCE tag");
    }

    #[test]
    fn rsa_trait_object_usage() {
        let provider: Box<dyn SigningProvider> = Box::new(RsaSigningProvider::generate());
        let sig = provider.sign(b"rsa data").unwrap();
        assert!(provider.verify(b"rsa data", &sig).unwrap());
    }

    #[test]
    fn cross_provider_signatures_incompatible() {
        let ed = SoftwareSigningProvider::generate();
        let pqc = MlDsaSigningProvider::generate();
        let ed_sig = ed.sign(b"data").unwrap();
        let pqc_sig = pqc.sign(b"data").unwrap();
        // Ed25519 sig on ML-DSA provider: wrong size or fails verification
        let pqc_result = pqc.verify(b"data", &ed_sig);
        assert!(pqc_result.is_err() || matches!(pqc_result, Ok(false)));
        // ML-DSA sig on Ed25519 provider: wrong size (must be exactly 64 bytes)
        assert!(ed.verify(b"data", &pqc_sig).is_err());
    }

    // --- ECDSA P-256 (ES256) tests ---

    #[test]
    fn es256_sign_and_verify_roundtrip() {
        let provider = EcdsaP256SigningProvider::generate();
        let data = b"eudi interop test";
        let sig = provider.sign(data).unwrap();
        assert!(provider.verify(data, &sig).unwrap());
    }

    #[test]
    fn es256_verify_wrong_data_fails() {
        let provider = EcdsaP256SigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        assert!(!provider.verify(b"wrong", &sig).unwrap());
    }

    #[test]
    fn es256_algorithm_identifier() {
        let provider = EcdsaP256SigningProvider::generate();
        assert_eq!(provider.algorithm(), SigningAlgorithm::EcdsaP256);
    }

    #[test]
    fn es256_signature_is_64_bytes() {
        let provider = EcdsaP256SigningProvider::generate();
        let sig = provider.sign(b"test").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn es256_public_key_is_65_bytes_uncompressed() {
        let provider = EcdsaP256SigningProvider::generate();
        let pk = provider.public_key();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04, "SEC1 uncompressed prefix");
    }

    #[test]
    fn es256_trait_object_usage() {
        let provider: Box<dyn SigningProvider> = Box::new(EcdsaP256SigningProvider::generate());
        let sig = provider.sign(b"es256 data").unwrap();
        assert!(provider.verify(b"es256 data", &sig).unwrap());
    }

    #[test]
    fn es256_verify_rejects_wrong_length_sig() {
        let provider = EcdsaP256SigningProvider::generate();
        let bad_sig = vec![0u8; 32];
        assert!(provider.verify(b"data", &bad_sig).is_err());
    }

    #[test]
    fn es256_tampered_signature_rejected() {
        let provider = EcdsaP256SigningProvider::generate();
        let mut sig = provider.sign(b"important data").unwrap();
        sig[0] ^= 0xff;
        assert!(!provider.verify(b"important data", &sig).unwrap_or(true));
    }

    #[test]
    fn es256_wrong_key_rejects() {
        let signer = EcdsaP256SigningProvider::generate();
        let verifier = EcdsaP256SigningProvider::generate();
        let sig = signer.sign(b"data").unwrap();
        assert!(!verifier.verify(b"data", &sig).unwrap());
    }

    #[test]
    fn es256_ed25519_cross_incompatible() {
        let es = EcdsaP256SigningProvider::generate();
        let ed = SoftwareSigningProvider::generate();
        let es_sig = es.sign(b"data").unwrap();
        let ed_sig = ed.sign(b"data").unwrap();
        // Both are 64 bytes but different curves — must not verify
        assert!(!ed.verify(b"data", &es_sig).unwrap());
        let es_result = es.verify(b"data", &ed_sig);
        assert!(es_result.is_err() || matches!(es_result, Ok(false)));
    }

    #[test]
    fn es256_is_classical_not_pqc() {
        assert!(SigningAlgorithm::EcdsaP256.is_classical());
        assert!(!SigningAlgorithm::EcdsaP256.is_post_quantum());
    }

    #[test]
    fn es256_display() {
        assert_eq!(format!("{}", SigningAlgorithm::EcdsaP256), "ES256");
    }

    // --- Property-based tests ---

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn ed25519_sign_verify_any_data(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let provider = SoftwareSigningProvider::generate();
                let sig = provider.sign(&data).unwrap();
                prop_assert!(provider.verify(&data, &sig).unwrap());
            }

            #[test]
            fn ed25519_verify_rejects_different_data(
                data_a in proptest::collection::vec(any::<u8>(), 1..512),
                data_b in proptest::collection::vec(any::<u8>(), 1..512),
            ) {
                prop_assume!(data_a != data_b);
                let provider = SoftwareSigningProvider::generate();
                let sig = provider.sign(&data_a).unwrap();
                prop_assert!(!provider.verify(&data_b, &sig).unwrap());
            }

            #[test]
            fn ed25519_signature_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..256)) {
                let provider = SoftwareSigningProvider::generate();
                let sig1 = provider.sign(&data).unwrap();
                let sig2 = provider.sign(&data).unwrap();
                prop_assert_eq!(sig1, sig2);
            }

            #[test]
            fn mldsa65_sign_verify_any_data(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let provider = MlDsaSigningProvider::generate();
                let sig = provider.sign(&data).unwrap();
                prop_assert!(provider.verify(&data, &sig).unwrap());
            }

            #[test]
            fn mldsa65_verify_rejects_different_data(
                data_a in proptest::collection::vec(any::<u8>(), 1..512),
                data_b in proptest::collection::vec(any::<u8>(), 1..512),
            ) {
                prop_assume!(data_a != data_b);
                let provider = MlDsaSigningProvider::generate();
                let sig = provider.sign(&data_a).unwrap();
                prop_assert!(!provider.verify(&data_b, &sig).unwrap());
            }
        }
    }

    // ── CAVP: RFC 8032 §7.1 Ed25519 test vectors ────────────────────

    #[test]
    fn cavp_ed25519_test_vector_1() {
        // RFC 8032 §7.1 — TEST 1: verify known signature over empty message
        // Uses project's verify dispatcher (same path as production)
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert!(crate::signature::verify_signature(
            SigningAlgorithm::Ed25519,
            pk_hex,
            b"",
            sig_hex,
        ));
    }

    #[test]
    fn cavp_ed25519_test_vector_2() {
        // RFC 8032 §7.1 — TEST 2: single byte 0x72
        let pk_hex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let sig_hex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
        assert!(crate::signature::verify_signature(
            SigningAlgorithm::Ed25519,
            pk_hex,
            &[0x72],
            sig_hex,
        ));
    }

    #[test]
    fn cavp_ed25519_test_vector_3() {
        // RFC 8032 §7.1 — TEST 3: 2-byte message af82
        let pk_hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        let sig_hex = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
        let msg = hex::decode("af82").unwrap();
        assert!(crate::signature::verify_signature(
            SigningAlgorithm::Ed25519,
            pk_hex,
            &msg,
            sig_hex,
        ));
    }

    #[test]
    fn slhdsa_generate_and_sign() {
        let provider = SlhDsaSigningProvider::generate();
        assert_eq!(provider.algorithm(), SigningAlgorithm::SlhDsa128s);
        assert!(provider.algorithm().is_post_quantum());
        let sig = provider.sign(b"test message").unwrap();
        assert!(
            sig.len() > 7000,
            "SLH-DSA-128s sig should be ~7856B, got {}",
            sig.len()
        );
    }

    #[test]
    fn slhdsa_sign_and_verify() {
        let provider = SlhDsaSigningProvider::generate();
        let msg = b"post-quantum backup signing";
        let sig = provider.sign(msg).unwrap();
        assert!(provider.verify(msg, &sig).unwrap());
    }

    #[test]
    fn slhdsa_verify_rejects_wrong_message() {
        let provider = SlhDsaSigningProvider::generate();
        let sig = provider.sign(b"correct").unwrap();
        assert!(!provider.verify(b"wrong", &sig).unwrap());
    }

    #[test]
    fn slhdsa_from_bytes_roundtrip() {
        let provider = SlhDsaSigningProvider::generate();
        let sk = provider.private_key_bytes().to_vec();
        let pk = provider.public_key_bytes().to_vec();

        let restored = SlhDsaSigningProvider::from_bytes(&sk, &pk).unwrap();
        let msg = b"persistence test";
        let sig = provider.sign(msg).unwrap();
        assert!(restored.verify(msg, &sig).unwrap());
    }

    #[test]
    fn slhdsa_pubkey_size() {
        let provider = SlhDsaSigningProvider::generate();
        assert_eq!(
            provider.public_key().len(),
            32,
            "SLH-DSA-SHAKE-128s pubkey is 32 bytes"
        );
    }

    #[test]
    fn cavp_ed25519_wrong_message_rejects() {
        // RFC 8032 TEST 1 sig must fail on non-empty message
        let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert!(!crate::signature::verify_signature(
            SigningAlgorithm::Ed25519,
            pk_hex,
            b"wrong",
            sig_hex,
        ));
    }

    #[test]
    fn mldsa65_key_persistence_roundtrip() {
        let original = MlDsaSigningProvider::generate();
        let msg = b"persistence roundtrip";
        let sig = original.sign(msg).unwrap();

        let exported = original.export_key_bytes();
        assert_eq!(exported.len(), 1952 + 4032);

        let restored =
            MlDsaSigningProvider::from_keys(&exported[..1952], &exported[1952..]).unwrap();
        assert_eq!(restored.public_key(), original.public_key());
        assert!(restored.verify(msg, &sig).unwrap());

        let sig2 = restored.sign(b"new message").unwrap();
        assert!(original.verify(b"new message", &sig2).unwrap());
    }
}
