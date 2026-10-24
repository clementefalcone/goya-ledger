use crate::identity::did::did_from_pubkey_hex;
use crate::identity::operations::{is_signed_by, Change, IdentityOpError};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, IdentityRecord};

pub struct CommitRecoveryRequest<'a> {
    pub did: &'a str,
    pub recovery_commitment: &'a str,
    pub owner_signature: &'a str,
}

pub fn commit_recovery_message(did: &str, recovery_commitment: &str) -> String {
    format!("identity:recovery:commit:{did}:{recovery_commitment}")
}

fn read_active_owner(store: &dyn BlockStore, did: &str) -> Result<IdentityRecord, IdentityOpError> {
    let record = store
        .read_identity(did)
        .map_err(|_| IdentityOpError::NotFound(format!("identity {did} is not registered")))?;
    if record.status != "active" {
        return Err(IdentityOpError::Conflict(format!(
            "identity {did} is {}; only active identities commit a recovery key",
            record.status
        )));
    }
    Ok(record)
}

fn is_did_shaped(text: &str) -> bool {
    text.strip_prefix("did:goya:").is_some_and(|digest| {
        digest.len() == 128
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub fn check_commit_recovery(
    store: &dyn BlockStore,
    request: &CommitRecoveryRequest,
) -> Result<Change, IdentityOpError> {
    if !is_did_shaped(request.recovery_commitment) {
        return Err(IdentityOpError::Invalid(format!(
            "recovery_commitment {:?} must be a did:goya identifier",
            request.recovery_commitment
        )));
    }
    let record = read_active_owner(store, request.did)?;
    let message = commit_recovery_message(request.did, request.recovery_commitment);
    if !is_signed_by(&record.public_key, &message, request.owner_signature) {
        return Err(IdentityOpError::BadSignature(format!(
            "signature over {message:?} does not verify against the key of {}",
            request.did
        )));
    }
    if request.recovery_commitment == did_from_pubkey_hex(&record.public_key) {
        return Err(IdentityOpError::Invalid(format!(
            "recovery commitment of {} must not be its own signing key",
            request.did
        )));
    }
    match record.recovery_commitment.as_deref() {
        None => Ok(Change::Write),
        Some(existing) if existing == request.recovery_commitment => Ok(Change::AlreadyApplied),
        Some(_) => Err(IdentityOpError::Conflict(format!(
            "identity {} already has a recovery key; only the recovery key can replace it by rotating",
            request.did
        ))),
    }
}

pub fn apply_commit_recovery(
    store: &dyn BlockStore,
    request: &CommitRecoveryRequest,
    committed_at: u64,
) -> StorageResult<()> {
    if check_commit_recovery(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    let record = store.read_identity(request.did)?;
    store.write_identity(&IdentityRecord {
        recovery_commitment: Some(request.recovery_commitment.to_string()),
        updated_at: committed_at,
        ..record
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use crate::storage::memory::MemoryStore;
    use crate::storage::traits::{VaultEntry, VaultEntryKind};

    struct Owner {
        store: MemoryStore,
        key: MlDsaSigningProvider,
        did: String,
    }

    fn sign(key: &MlDsaSigningProvider, message: &str) -> String {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    }

    fn did_of(key: &MlDsaSigningProvider) -> String {
        did_from_pubkey_hex(&hex::encode(key.public_key()))
    }

    fn phone_copy() -> VaultEntry {
        VaultEntry {
            entry_id: "aa01".to_string(),
            kind: VaultEntryKind::Device,
            label: "iPhone".to_string(),
            sealed_key: "{}".to_string(),
            added_at: 5,
            revoked_at: None,
        }
    }

    fn registered_owner() -> Owner {
        let key = MlDsaSigningProvider::generate();
        let did = did_of(&key);
        let store = MemoryStore::new();
        store
            .write_identity(&IdentityRecord {
                did: did.clone(),
                public_key: hex::encode(key.public_key()),
                created_at: 1,
                updated_at: 1,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: Some("MlDsa65".to_string()),
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: vec![phone_copy()],
            })
            .unwrap();
        Owner { store, key, did }
    }

    fn commit(owner: &Owner, commitment: &str, signer: &MlDsaSigningProvider) -> StorageResult<()> {
        let signature = sign(signer, &commit_recovery_message(&owner.did, commitment));
        apply_commit_recovery(
            &owner.store,
            &CommitRecoveryRequest {
                did: &owner.did,
                recovery_commitment: commitment,
                owner_signature: &signature,
            },
            50,
        )
    }

    fn stored(owner: &Owner) -> IdentityRecord {
        owner.store.read_identity(&owner.did).unwrap()
    }

    #[test]
    fn owner_commits_a_recovery_key_once() {
        let owner = registered_owner();
        let recovery = did_of(&MlDsaSigningProvider::generate());
        commit(&owner, &recovery, &owner.key).unwrap();
        let record = stored(&owner);
        assert_eq!(record.recovery_commitment, Some(recovery));
        assert_eq!(record.updated_at, 50);
        assert_eq!(record.vault_entries, vec![phone_copy()]);
    }

    #[test]
    fn replaying_the_same_commitment_is_idempotent() {
        let owner = registered_owner();
        let recovery = did_of(&MlDsaSigningProvider::generate());
        commit(&owner, &recovery, &owner.key).unwrap();
        commit(&owner, &recovery, &owner.key).unwrap();
        assert_eq!(stored(&owner).recovery_commitment, Some(recovery));
    }

    #[test]
    fn owner_key_cannot_replace_an_existing_commitment() {
        let owner = registered_owner();
        let first = did_of(&MlDsaSigningProvider::generate());
        let second = did_of(&MlDsaSigningProvider::generate());
        commit(&owner, &first, &owner.key).unwrap();
        assert!(commit(&owner, &second, &owner.key).is_err());
        assert_eq!(stored(&owner).recovery_commitment, Some(first));
    }

    #[test]
    fn stranger_cannot_commit_a_recovery_key() {
        let owner = registered_owner();
        let stranger = MlDsaSigningProvider::generate();
        assert!(commit(&owner, &did_of(&stranger), &stranger).is_err());
        assert_eq!(stored(&owner).recovery_commitment, None);
    }

    #[test]
    fn signing_key_cannot_be_its_own_recovery_key() {
        let owner = registered_owner();
        let own_did = owner.did.clone();
        assert!(commit(&owner, &own_did, &owner.key).is_err());
        assert_eq!(stored(&owner).recovery_commitment, None);
    }

    #[test]
    fn rejects_a_commitment_that_is_not_a_did() {
        let owner = registered_owner();
        for malformed in ["", "did:goya:zz", "did:web:example.com", &"a".repeat(138)] {
            let signature = sign(&owner.key, &commit_recovery_message(&owner.did, malformed));
            let result = check_commit_recovery(
                &owner.store,
                &CommitRecoveryRequest {
                    did: &owner.did,
                    recovery_commitment: malformed,
                    owner_signature: &signature,
                },
            );
            assert!(
                matches!(result, Err(IdentityOpError::Invalid(_))),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn revoked_identity_cannot_commit_a_recovery_key() {
        let owner = registered_owner();
        owner
            .store
            .write_identity(&IdentityRecord {
                status: "revoked".to_string(),
                ..stored(&owner)
            })
            .unwrap();
        let recovery = did_of(&MlDsaSigningProvider::generate());
        assert!(commit(&owner, &recovery, &owner.key).is_err());
    }
}
