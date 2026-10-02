#[cfg(feature = "raft-ordering")]
pub mod raft_node;
#[cfg(feature = "raft-ordering")]
pub mod raft_service;
#[cfg(feature = "raft-ordering")]
pub mod raft_storage;
#[cfg(feature = "raft-ordering")]
pub mod raft_transport;
pub mod service;

use std::str::FromStr;

use crate::identity::signing::SigningProvider;
use crate::storage::errors::StorageResult;
use crate::storage::traits::{Block, Transaction};
use pqc_crypto_module::legacy::ed25519::Signer;
use pqc_crypto_module::legacy::sha256::{Digest, Sha256};

/// Compute a block hash for orderer signing: `sha256(height || parent_hash || merkle_root)`.
pub fn block_hash_for_signing(block: &Block) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(block.height.to_le_bytes());
    hasher.update(block.parent_hash);
    hasher.update(block.merkle_root);
    hasher.finalize().into()
}

/// Sign a block with an Ed25519 signing key, populating `orderer_signature`.
pub fn sign_block(block: &mut Block, key: &pqc_crypto_module::legacy::ed25519::SigningKey) {
    let hash = block_hash_for_signing(block);
    let sig = key.sign(&hash);
    block.orderer_signature = Some(sig.to_bytes().to_vec());
}

/// Sign a block using a pluggable `SigningProvider` (Ed25519 or ML-DSA-65).
///
/// Populates both the proposer `signature` + `signature_algorithm` fields,
/// and the `orderer_signature` field.
pub fn sign_block_with_provider(block: &mut Block, provider: &dyn SigningProvider) {
    let hash = block_hash_for_signing(block);
    match provider.sign(&hash) {
        Ok(sig) => {
            log::debug!(
                "Block {} signed with {:?} | sig_len={} bytes",
                block.height,
                provider.algorithm(),
                sig.len()
            );
            block.signature = sig.clone();
            block.signature_algorithm = provider.algorithm();
            block.orderer_signature = Some(sig);
        }
        Err(e) => {
            log::error!("Block {} signing FAILED: {e}", block.height);
        }
    }
}

#[allow(dead_code)]
/// Verify a block's orderer signature against the orderer's public key (Ed25519 only).
///
/// Returns:
/// - `Ok(true)` if signature is present and valid
/// - `Ok(false)` if signature is absent (backward compat with legacy blocks)
/// - `Err(...)` if signature is present but invalid
pub fn verify_orderer_signature(
    block: &Block,
    orderer_key: &pqc_crypto_module::legacy::ed25519::VerifyingKey,
) -> Result<bool, String> {
    let sig_bytes = match &block.orderer_signature {
        None => return Ok(false),
        Some(s) => s,
    };
    let hash = block_hash_for_signing(block);
    let sig_array: &[u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid signature length: expected 64 bytes".to_string())?;
    let sig = pqc_crypto_module::legacy::ed25519::Signature::from_bytes(sig_array);
    use pqc_crypto_module::legacy::ed25519::Verifier;
    orderer_key
        .verify(&hash, &sig)
        .map(|()| true)
        .map_err(|e| format!("invalid orderer signature: {e}"))
}

#[allow(dead_code)]
/// Verify a block's signature using a `SigningProvider`.
///
/// Dispatches to Ed25519 or ML-DSA-65 based on `block.signature_algorithm`.
/// Returns `Err` if the algorithm doesn't match or verification fails.
pub fn verify_block_signature(
    block: &Block,
    provider: &dyn SigningProvider,
) -> Result<bool, String> {
    if block.signature_algorithm != provider.algorithm() {
        return Err(format!(
            "algorithm mismatch: block uses {:?}, provider uses {:?}",
            block.signature_algorithm,
            provider.algorithm()
        ));
    }

    if block.signature.is_empty() {
        return Ok(false);
    }

    let hash = block_hash_for_signing(block);
    provider
        .verify(&hash, &block.signature)
        .map_err(|e| format!("block signature verification failed: {e}"))
}

/// Verify a block's secondary (dual) signature, if present.
///
/// Returns `Ok(None)` when no secondary signature exists,
/// `Ok(Some(true/false))` for verification result.
#[allow(dead_code)]
pub fn verify_block_secondary_signature(
    block: &Block,
    provider: &dyn SigningProvider,
) -> Result<Option<bool>, String> {
    let (Some(ref sig), Some(algo)) = (
        &block.secondary_signature,
        block.secondary_signature_algorithm,
    ) else {
        return Ok(None);
    };

    if algo != provider.algorithm() {
        return Err(format!(
            "secondary algorithm mismatch: block uses {algo:?}, provider uses {:?}",
            provider.algorithm()
        ));
    }

    let hash = block_hash_for_signing(block);
    let result = provider
        .verify(&hash, sig)
        .map_err(|e| format!("secondary signature verification failed: {e}"))?;
    Ok(Some(result))
}

/// Common interface for ordering backends (solo batching vs Raft consensus).
pub trait OrderingBackend: Send + Sync {
    fn submit_tx(&self, tx: &Transaction) -> StorageResult<()>;
    fn cut_block(
        &self,
        height: u64,
        parent_hash: [u8; 32],
        proposer: &str,
    ) -> StorageResult<Option<Block>>;
    #[allow(dead_code)]
    fn pending_count(&self) -> usize;
}

/// Role of this node in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeRole {
    Peer,
    Orderer,
    PeerAndOrderer,
}

impl FromStr for NodeRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "peer" => Ok(NodeRole::Peer),
            "orderer" => Ok(NodeRole::Orderer),
            "" | "peerandorderer" => Ok(NodeRole::PeerAndOrderer),
            other => Err(format!("unknown node role: {other}")),
        }
    }
}

impl NodeRole {
    /// Read from the `NODE_ROLE` environment variable; defaults to `PeerAndOrderer`.
    pub fn from_env() -> Self {
        std::env::var("NODE_ROLE")
            .unwrap_or_default()
            .to_lowercase()
            .parse()
            .unwrap_or(NodeRole::PeerAndOrderer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peer() {
        assert_eq!("peer".parse::<NodeRole>().unwrap(), NodeRole::Peer);
    }

    #[test]
    fn parse_orderer() {
        assert_eq!("orderer".parse::<NodeRole>().unwrap(), NodeRole::Orderer);
    }

    #[test]
    fn parse_empty_defaults_to_peer_and_orderer() {
        assert_eq!("".parse::<NodeRole>().unwrap(), NodeRole::PeerAndOrderer);
    }

    #[test]
    fn parse_invalid_returns_error() {
        assert!("invalid".parse::<NodeRole>().is_err());
    }

    fn make_tx(id: &str) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: "did:goya:alice".to_string(),
            output_recipient: "did:goya:bob".to_string(),
            amount: 1,
            state: "pending".to_string(),
            fee: 0,
            payload: None,
        }
    }

    /// Verify that both backends work behind `Box<dyn OrderingBackend>`.
    fn assert_backend_works(backend: &dyn OrderingBackend) {
        assert_eq!(backend.pending_count(), 0);
        assert!(backend.cut_block(1, [0u8; 32], "o").unwrap().is_none());
    }

    #[test]
    fn solo_backend_as_trait_object() {
        let svc = service::OrderingService::with_config(100, 2000);
        let backend: Box<dyn OrderingBackend> = Box::new(svc);
        assert_backend_works(&*backend);

        backend.submit_tx(&make_tx("tx1")).unwrap();
        let block = backend.cut_block(1, [0u8; 32], "orderer").unwrap().unwrap();
        assert_eq!(block.transactions, vec!["tx1"]);
    }

    #[cfg(feature = "raft-ordering")]
    #[test]
    fn raft_backend_as_trait_object() {
        let svc = raft_service::RaftOrderingService::new(1, vec![1], 100, 2000).unwrap();
        let backend: Box<dyn OrderingBackend> = Box::new(svc);
        assert_backend_works(&*backend);
    }

    #[test]
    fn cut_block_signs_with_orderer_key() {
        use pqc_crypto_module::legacy::ed25519::{Signature, SigningKey, Verifier, VerifyingKey};

        let key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying = VerifyingKey::from(&key);

        let svc = service::OrderingService::with_config(100, 2000).with_signing_key(key);
        svc.submit_tx(make_tx("tx1").clone()).unwrap();

        let block = svc.cut_block(1, [0u8; 32], "orderer").unwrap().unwrap();
        assert!(
            block.orderer_signature.is_some(),
            "expected orderer_signature"
        );

        // Verify the signature.
        let hash = block_hash_for_signing(&block);
        let sig_vec = block.orderer_signature.unwrap();
        let sig_arr: &[u8; 64] = sig_vec.as_slice().try_into().unwrap();
        let sig = Signature::from_bytes(sig_arr);
        assert!(
            verifying.verify(&hash, &sig).is_ok(),
            "signature verification failed"
        );
    }

    #[test]
    fn verify_valid_orderer_signature_accepts() {
        use pqc_crypto_module::legacy::ed25519::{SigningKey, VerifyingKey};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = VerifyingKey::from(&key);

        let svc = service::OrderingService::with_config(100, 2000).with_signing_key(key);
        svc.submit_tx(make_tx("tx1").clone()).unwrap();
        let block = svc.cut_block(1, [0u8; 32], "orderer").unwrap().unwrap();

        assert_eq!(verify_orderer_signature(&block, &verifying), Ok(true));
    }

    #[test]
    fn verify_invalid_orderer_signature_rejects() {
        use pqc_crypto_module::legacy::ed25519::{SigningKey, VerifyingKey};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
        let wrong_verifying = VerifyingKey::from(&wrong_key);

        let svc = service::OrderingService::with_config(100, 2000).with_signing_key(key);
        svc.submit_tx(make_tx("tx1").clone()).unwrap();
        let block = svc.cut_block(1, [0u8; 32], "orderer").unwrap().unwrap();

        assert!(verify_orderer_signature(&block, &wrong_verifying).is_err());
    }

    #[test]
    fn verify_absent_orderer_signature_accepts() {
        use pqc_crypto_module::legacy::ed25519::{SigningKey, VerifyingKey};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = VerifyingKey::from(&key);

        // Block without signing key → no orderer_signature.
        let svc = service::OrderingService::with_config(100, 2000);
        svc.submit_tx(make_tx("tx1").clone()).unwrap();
        let block = svc.cut_block(1, [0u8; 32], "orderer").unwrap().unwrap();

        assert_eq!(verify_orderer_signature(&block, &verifying), Ok(false));
    }
}
