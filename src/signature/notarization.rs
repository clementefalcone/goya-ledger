use crate::identity::operations::key_controls_identity;
use crate::signature::{
    compute_biometrics_hash, is_signer_proven, verify_signature, BiometricEvidence, SignatureLevel,
    SignerClaim,
};
use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::{BlockStore, NotarizationEntry, OwnershipTransfer};

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

pub fn transfer_payload(transfer: &OwnershipTransfer, sequence: usize) -> String {
    let OwnershipTransfer {
        content_hash,
        from_did,
        to_did,
        ..
    } = transfer;
    match transfer.signature_level {
        SignatureLevel::Simple => {
            format!("transfer_doc:{content_hash}:{sequence}:{from_did}:{to_did}")
        }
        SignatureLevel::Advanced | SignatureLevel::Qualified | SignatureLevel::Seal => {
            let bio_hash = compute_biometrics_hash(&transfer.biometric_evidence);
            format!("transfer_fea:{content_hash}:{sequence}:{from_did}:{to_did}:{bio_hash}")
        }
    }
}

pub fn current_owner(store: &dyn BlockStore, content_hash: &str) -> StorageResult<String> {
    let notarization = store.read_notarization_by_hash(content_hash)?;
    let transfers = store.read_ownership_transfers(content_hash)?;
    Ok(transfers
        .last()
        .map_or(notarization.signer, |t| t.to_did.clone()))
}

pub fn apply_ownership_transfer(
    store: &dyn BlockStore,
    transfer: &OwnershipTransfer,
) -> StorageResult<()> {
    let hash = &transfer.content_hash;
    let transfers = store.read_ownership_transfers(hash)?;
    if transfers.last() == Some(transfer) {
        return Ok(());
    }
    if !verify_signature(
        transfer.signature_algorithm,
        &transfer.public_key,
        transfer_payload(transfer, transfers.len()).as_bytes(),
        &transfer.signature,
    ) {
        return Err(StorageError::Other(format!(
            "transfer #{} of {hash} from {}: signature does not verify against its public_key",
            transfers.len(),
            transfer.from_did
        )));
    }
    if !key_controls_identity(store, &transfer.from_did, &transfer.public_key) {
        return Err(StorageError::Other(format!(
            "transfer of {hash}: public_key does not control {}",
            transfer.from_did
        )));
    }
    let owner = current_owner(store, hash)?;
    if owner != transfer.from_did {
        return Err(StorageError::Other(format!(
            "transfer of {hash} from {}: current owner is {owner}",
            transfer.from_did
        )));
    }
    store.write_ownership_transfer(transfer)
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
        &|did, key| key_controls_identity(store, did, key),
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

    fn signed_transfer(from: &SoftwareSigningProvider, to_did: &str) -> OwnershipTransfer {
        signed_transfer_at(from, to_did, 0)
    }

    fn signed_transfer_at(
        from: &SoftwareSigningProvider,
        to_did: &str,
        sequence: usize,
    ) -> OwnershipTransfer {
        let public_key = hex::encode(from.public_key());
        let mut transfer = OwnershipTransfer {
            content_hash: HASH.to_string(),
            from_did: did_from_pubkey_hex(&public_key),
            to_did: to_did.to_string(),
            signature: String::new(),
            public_key,
            transferred_at: 200,
            signature_algorithm: SigningAlgorithm::Ed25519,
            signature_level: SignatureLevel::Simple,
            biometric_evidence: Vec::new(),
        };
        let message = transfer_payload(&transfer, sequence);
        transfer.signature = hex::encode(from.sign(message.as_bytes()).unwrap());
        transfer
    }

    fn did_of(key: &SoftwareSigningProvider) -> String {
        did_from_pubkey_hex(&hex::encode(key.public_key()))
    }

    fn notarized_by(owner: &SoftwareSigningProvider) -> MemoryStore {
        let store = MemoryStore::new();
        apply_notarization(&store, &signed_entry(owner, "n-1")).unwrap();
        store
    }

    #[test]
    fn transfers_ownership_signed_by_the_owner() {
        let (alice, bob) = (
            SoftwareSigningProvider::generate(),
            SoftwareSigningProvider::generate(),
        );
        let store = notarized_by(&alice);
        apply_ownership_transfer(&store, &signed_transfer(&alice, &did_of(&bob))).unwrap();
        assert_eq!(current_owner(&store, HASH).unwrap(), did_of(&bob));
    }

    #[test]
    fn rejects_a_transfer_with_a_forged_signature() {
        let alice = SoftwareSigningProvider::generate();
        let store = notarized_by(&alice);
        let mut transfer = signed_transfer(&alice, "did:goya:thief");
        transfer.signature = "00".repeat(64);
        assert!(apply_ownership_transfer(&store, &transfer).is_err());
        assert_eq!(current_owner(&store, HASH).unwrap(), did_of(&alice));
    }

    #[test]
    fn rejects_a_transfer_from_someone_who_is_not_the_owner() {
        let (alice, mallory) = (
            SoftwareSigningProvider::generate(),
            SoftwareSigningProvider::generate(),
        );
        let store = notarized_by(&alice);
        assert!(
            apply_ownership_transfer(&store, &signed_transfer(&mallory, "did:goya:x")).is_err()
        );
        assert_eq!(current_owner(&store, HASH).unwrap(), did_of(&alice));
    }

    #[test]
    fn reapplying_the_same_transfer_is_a_no_op() {
        let (alice, bob) = (
            SoftwareSigningProvider::generate(),
            SoftwareSigningProvider::generate(),
        );
        let store = notarized_by(&alice);
        let transfer = signed_transfer(&alice, &did_of(&bob));
        apply_ownership_transfer(&store, &transfer).unwrap();
        apply_ownership_transfer(&store, &transfer).unwrap();
        assert_eq!(store.read_ownership_transfers(HASH).unwrap().len(), 1);
    }

    #[test]
    fn rejects_a_replayed_transfer_after_the_document_came_back() {
        let (alice, bob) = (
            SoftwareSigningProvider::generate(),
            SoftwareSigningProvider::generate(),
        );
        let store = notarized_by(&alice);
        let alice_to_bob = signed_transfer(&alice, &did_of(&bob));
        apply_ownership_transfer(&store, &alice_to_bob).unwrap();
        apply_ownership_transfer(&store, &signed_transfer_at(&bob, &did_of(&alice), 1)).unwrap();
        assert!(apply_ownership_transfer(&store, &alice_to_bob).is_err());
        assert_eq!(current_owner(&store, HASH).unwrap(), did_of(&alice));
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
