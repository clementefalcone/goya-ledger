//! Key management for identity system
//!
//! Algorithm-agnostic key rotation via `SigningProvider` trait.

use crate::identity::did::did_from_pubkey_hex;
use crate::identity::signing::{
    MlDsaSigningProvider, SigningAlgorithm, SigningError, SigningProvider, SoftwareSigningProvider,
};

/// Public key information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Public key bytes (variable length per algorithm)
    pub public_key: Vec<u8>,
    /// Algorithm used to generate this key
    pub algorithm: SigningAlgorithm,
    /// Key creation timestamp
    pub created_at: u64,
    /// Key expiration (optional)
    pub expires_at: Option<u64>,
    /// Whether this key is currently active
    pub is_active: bool,
}

/// Key manager for identity — delegates to `SigningProvider`.
pub struct KeyManager {
    provider: Box<dyn SigningProvider>,
    created_at: u64,
    retired_keys: Vec<PublicKeyInfo>,
}

fn new_provider(algorithm: SigningAlgorithm) -> Box<dyn SigningProvider> {
    match algorithm {
        SigningAlgorithm::Ed25519 => Box::new(SoftwareSigningProvider::generate()),
        SigningAlgorithm::MlDsa65 => Box::new(MlDsaSigningProvider::generate()),
        _ => Box::new(SoftwareSigningProvider::generate()),
    }
}

impl KeyManager {
    /// Create a new key manager with the given algorithm.
    pub fn with_algorithm(algorithm: SigningAlgorithm, timestamp: u64) -> Self {
        KeyManager {
            provider: new_provider(algorithm),
            created_at: timestamp,
            retired_keys: Vec::new(),
        }
    }

    /// Create a new key manager defaulting to Ed25519 (backward compat).
    pub fn new(timestamp: u64) -> Self {
        Self::with_algorithm(SigningAlgorithm::Ed25519, timestamp)
    }

    /// The algorithm of the active key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.provider.algorithm()
    }

    /// Get the current public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        self.provider.public_key()
    }

    /// Get all public keys (active + retired).
    pub fn all_public_keys(&self) -> Vec<PublicKeyInfo> {
        let mut keys = vec![PublicKeyInfo {
            public_key: self.provider.public_key(),
            algorithm: self.provider.algorithm(),
            created_at: self.created_at,
            expires_at: None,
            is_active: true,
        }];

        keys.extend(self.retired_keys.clone());
        keys
    }

    /// Rotate to a new keypair of the same algorithm.
    pub fn rotate_key(&mut self, timestamp: u64) {
        self.retire_and_replace(self.provider.algorithm(), timestamp);
    }

    /// Rotate to a new keypair of a different algorithm (e.g. Ed25519 → ML-DSA-65).
    pub fn rotate_algorithm(&mut self, new_algorithm: SigningAlgorithm, timestamp: u64) {
        self.retire_and_replace(new_algorithm, timestamp);
    }

    fn retire_and_replace(&mut self, algorithm: SigningAlgorithm, timestamp: u64) {
        let retired = PublicKeyInfo {
            public_key: self.provider.public_key(),
            algorithm: self.provider.algorithm(),
            created_at: self.created_at,
            expires_at: Some(timestamp),
            is_active: false,
        };
        self.retired_keys.push(retired);
        self.provider = new_provider(algorithm);
        self.created_at = timestamp;
    }

    /// Sign data with the active key.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.provider.sign(data)
    }

    /// Verify a signature with the active key.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SigningError> {
        self.provider.verify(data, signature)
    }

    /// Get key creation timestamp.
    pub fn key_created_at(&self) -> u64 {
        self.created_at
    }

    /// Number of retired keys.
    pub fn retired_key_count(&self) -> usize {
        self.retired_keys.len()
    }

    /// Public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.provider.public_key())
    }

    /// DID derived from the current public key.
    pub fn did(&self) -> String {
        did_from_pubkey_hex(&self.public_key_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_keypair_generation() {
        let km = KeyManager::new(1000);
        assert_eq!(km.key_created_at(), 1000);
        assert_eq!(km.public_key().len(), 32);
        assert_eq!(km.algorithm(), SigningAlgorithm::Ed25519);
    }

    #[test]
    fn mldsa65_keypair_generation() {
        let km = KeyManager::with_algorithm(SigningAlgorithm::MlDsa65, 1000);
        assert_eq!(km.public_key().len(), 1952);
        assert_eq!(km.algorithm(), SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn ed25519_sign_and_verify() {
        let km = KeyManager::new(1000);
        let data = b"test message";
        let signature = km.sign(data).unwrap();
        assert!(km.verify(data, &signature).unwrap());
    }

    #[test]
    fn mldsa65_sign_and_verify() {
        let km = KeyManager::with_algorithm(SigningAlgorithm::MlDsa65, 1000);
        let data = b"pqc test message";
        let signature = km.sign(data).unwrap();
        assert_eq!(signature.len(), 3309);
        assert!(km.verify(data, &signature).unwrap());
    }

    #[test]
    fn verify_fails_with_wrong_data() {
        let km = KeyManager::new(1000);
        let signature = km.sign(b"test message").unwrap();
        assert!(!km.verify(b"different message", &signature).unwrap());
    }

    #[test]
    fn ed25519_key_rotation() {
        let mut km = KeyManager::new(1000);
        let old_key = km.public_key();
        km.rotate_key(2000);
        let new_key = km.public_key();
        assert_ne!(old_key, new_key);
        assert_eq!(km.retired_key_count(), 1);
        assert_eq!(km.algorithm(), SigningAlgorithm::Ed25519);
    }

    #[test]
    fn mldsa65_key_rotation() {
        let mut km = KeyManager::with_algorithm(SigningAlgorithm::MlDsa65, 1000);
        let old_key = km.public_key();
        km.rotate_key(2000);
        let new_key = km.public_key();
        assert_ne!(old_key, new_key);
        assert_eq!(km.retired_key_count(), 1);
        assert_eq!(km.algorithm(), SigningAlgorithm::MlDsa65);
    }

    #[test]
    fn all_public_keys_tracks_algorithm() {
        let mut km = KeyManager::with_algorithm(SigningAlgorithm::MlDsa65, 1000);
        km.rotate_key(2000);
        km.rotate_key(3000);
        let keys = km.all_public_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys[0].is_active);
        assert!(!keys[1].is_active);
        for k in &keys {
            assert_eq!(k.algorithm, SigningAlgorithm::MlDsa65);
        }
    }

    #[test]
    fn ed25519_signature_format() {
        let km = KeyManager::new(1000);
        let signature = km.sign(b"test").unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn multiple_rotations() {
        let mut km = KeyManager::new(1000);
        for i in 1..=5 {
            km.rotate_key(1000 + i as u64 * 1000);
        }
        assert_eq!(km.retired_key_count(), 5);
    }
}
