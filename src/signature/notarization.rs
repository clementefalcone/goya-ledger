use crate::identity::operations::key_controls_did;
use crate::signature::{
    compute_biometrics_hash, is_signer_proven, verify_signature, BiometricEvidence, SignatureLevel,
    SignerClaim,
};
use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::{BlockStore, NotarizationEntry};

pub fn notarize_payload(
    level: SignatureLevel,
    signer: &str,
    content_hash: &str,
    biometric_evidence: &[BiometricEvidence],
) -> String {
    match level {
        SignatureLevel::Simple => format!("notarize:{signer}:{content_hash}"),
        SignatureLevel::Advanced | SignatureLevel::Qualified | SignatureLevel::Seal => {
            let bio_hash = compute_biometrics_hash(biometric_evidence);
            format!("notarize_fea:{signer}:{content_hash}:{bio_hash}")
        }
    }
}

pub fn apply_notarization(store: &dyn BlockStore, entry: &NotarizationEntry) -> StorageResult<()> {
    let payload = notarize_payload(
        entry.signature_level,
        &entry.signer,
        &entry.content_hash,
        &entry.biometric_evidence,
    );
    if !verify_signature(
        entry.signature_algorithm,
        &entry.public_key,
        payload.as_bytes(),
        &entry.signature,
    ) {
        return Err(StorageError::Other(format!(
            "notarization {} of {}: signature does not verify against its public_key",
            entry.id, entry.content_hash
        )));
    }
    let signer_is_proven = is_signer_proven(
        &SignerClaim {
            signer: &entry.signer,
            signing_public_key: &entry.public_key,
            proof: entry.signer_proof.as_ref(),
            payload: payload.as_bytes(),
        },
        &|did, key| key_controls_did(store, did, key),
    );
    if !signer_is_proven {
        return Err(StorageError::Other(format!(
            "notarization {} of {}: signer {} is not proven by the signing key or signer_proof",
            entry.id, entry.content_hash, entry.signer
        )));
    }
    match store.read_notarization_by_hash(&entry.content_hash) {
        Ok(existing) if existing == *entry => Ok(()),
        Ok(existing) => Err(StorageError::Other(format!(
            "notarization {} of {}: hash already notarized by entry {}",
            entry.id, entry.content_hash, existing.id
        ))),
        Err(StorageError::KeyNotFound(_)) => store.write_notarization(entry),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did::did_from_pubkey_hex;
    use crate::identity::signing::{SigningAlgorithm, SigningProvider, SoftwareSigningProvider};
    use crate::storage::MemoryStore;

    const HASH: &str = "4f1c2a9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928170605f4e3";

    fn signed_entry(key: &SoftwareSigningProvider, id: &str) -> NotarizationEntry {
        let public_key = hex::encode(key.public_key());
        let signer = did_from_pubkey_hex(&public_key);
        let payload = notarize_payload(SignatureLevel::Simple, &signer, HASH, &[]);
        NotarizationEntry {
            id: id.to_string(),
            content_hash: HASH.to_string(),
            signer,
            metadata: None,
            notarized_at: 100,
            block_height: 1,
            signature: hex::encode(key.sign(payload.as_bytes()).unwrap()),
            public_key,
            cades_der: None,
            signature_algorithm: SigningAlgorithm::Ed25519,
            signature_level: SignatureLevel::Simple,
            biometric_evidence: Vec::new(),
            signer_proof: None,
        }
    }

    #[test]
    fn writes_a_notarization_signed_by_its_signer() {
        let store = MemoryStore::new();
        let entry = signed_entry(&SoftwareSigningProvider::generate(), "n-1");
        apply_notarization(&store, &entry).unwrap();
        assert_eq!(store.read_notarization_by_hash(HASH).unwrap(), entry);
    }

    #[test]
    fn rejects_a_notarization_with_a_forged_signature() {
        let store = MemoryStore::new();
        let mut entry = signed_entry(&SoftwareSigningProvider::generate(), "n-1");
        entry.signature = "00".repeat(64);
        assert!(apply_notarization(&store, &entry).is_err());
        assert!(store.read_notarization_by_hash(HASH).is_err());
    }

    #[test]
    fn rejects_a_notarization_claiming_someone_elses_did() {
        let store = MemoryStore::new();
        let mut entry = signed_entry(&SoftwareSigningProvider::generate(), "n-1");
        let victim = did_from_pubkey_hex(&hex::encode(
            SoftwareSigningProvider::generate().public_key(),
        ));
        entry.signer = victim;
        let payload = notarize_payload(SignatureLevel::Simple, &entry.signer, HASH, &[]);
        let key = SoftwareSigningProvider::generate();
        entry.public_key = hex::encode(key.public_key());
        entry.signature = hex::encode(key.sign(payload.as_bytes()).unwrap());
        assert!(apply_notarization(&store, &entry).is_err());
    }

    #[test]
    fn reapplying_the_same_notarization_is_a_no_op() {
        let store = MemoryStore::new();
        let entry = signed_entry(&SoftwareSigningProvider::generate(), "n-1");
        apply_notarization(&store, &entry).unwrap();
        apply_notarization(&store, &entry).unwrap();
        assert_eq!(store.read_notarization_by_hash(HASH).unwrap().id, "n-1");
    }

    #[test]
    fn rejects_a_second_notarization_of_the_same_hash() {
        let store = MemoryStore::new();
        let first = signed_entry(&SoftwareSigningProvider::generate(), "n-1");
        let second = signed_entry(&SoftwareSigningProvider::generate(), "n-2");
        apply_notarization(&store, &first).unwrap();
        assert!(apply_notarization(&store, &second).is_err());
        assert_eq!(store.read_notarization_by_hash(HASH).unwrap().id, "n-1");
    }
}
