use crate::identity::operations::{is_signed_by, Change, IdentityOpError};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, IdentityRecord, VaultEntry, VaultEntryKind};

pub struct AddVaultEntryRequest<'a> {
    pub did: &'a str,
    pub entry: &'a VaultEntry,
    pub owner_signature: &'a str,
}

pub struct RevokeVaultEntryRequest<'a> {
    pub did: &'a str,
    pub entry_id: &'a str,
    pub revoked_at: u64,
    pub owner_signature: &'a str,
}

const MAX_LABEL_CHARS: usize = 64;
const MAX_SEALED_KEY_CHARS: usize = 16_384;
const MAX_ENTRY_ID_CHARS: usize = 128;
const MAX_ENTRIES: usize = 16;

fn sha3_hex(text: &str) -> String {
    hex::encode(crate::crypto::hasher::hash_with(
        crate::crypto::hasher::HashAlgorithm::Sha3_256,
        text.as_bytes(),
    ))
}

fn kind_key(kind: VaultEntryKind) -> &'static str {
    match kind {
        VaultEntryKind::Device => "device",
        VaultEntryKind::Recovery => "recovery",
        VaultEntryKind::Reader => "reader",
    }
}

pub fn add_vault_entry_message(did: &str, entry: &VaultEntry) -> String {
    format!(
        "identity:vault:add:{did}:{}:{}:{}:{}",
        entry.entry_id,
        kind_key(entry.kind),
        sha3_hex(&entry.label),
        sha3_hex(&entry.sealed_key)
    )
}

pub fn revoke_vault_entry_message(did: &str, entry_id: &str) -> String {
    format!("identity:vault:revoke:{did}:{entry_id}")
}

fn read_active_owner(store: &dyn BlockStore, did: &str) -> Result<IdentityRecord, IdentityOpError> {
    let record = store
        .read_identity(did)
        .map_err(|_| IdentityOpError::NotFound(format!("identity {did} is not registered")))?;
    if record.status != "active" {
        return Err(IdentityOpError::Conflict(format!(
            "identity {did} is {}; only active identities manage their vault",
            record.status
        )));
    }
    Ok(record)
}

fn require_owner_signature(
    record: &IdentityRecord,
    message: &str,
    signature: &str,
) -> Result<(), IdentityOpError> {
    if is_signed_by(&record.public_key, message, signature) {
        return Ok(());
    }
    Err(IdentityOpError::BadSignature(format!(
        "signature over {message:?} does not verify against the key of {}",
        record.did
    )))
}

fn validate_entry(entry: &VaultEntry) -> Result<(), IdentityOpError> {
    let is_hex_id = !entry.entry_id.is_empty()
        && entry.entry_id.len() <= MAX_ENTRY_ID_CHARS
        && entry
            .entry_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let problem = [
        (
            !is_hex_id,
            format!(
                "entry_id {:?} must be 1-{MAX_ENTRY_ID_CHARS} lowercase hex characters",
                entry.entry_id
            ),
        ),
        (
            entry.label.is_empty() || entry.label.chars().count() > MAX_LABEL_CHARS,
            format!("label must be 1-{MAX_LABEL_CHARS} characters"),
        ),
        (
            entry.sealed_key.is_empty() || entry.sealed_key.len() > MAX_SEALED_KEY_CHARS,
            format!("sealed_key must be 1-{MAX_SEALED_KEY_CHARS} bytes"),
        ),
        (
            entry.revoked_at.is_some(),
            "a new vault entry cannot be revoked".to_string(),
        ),
        (
            entry.kind == VaultEntryKind::Reader
                && !crate::identity::reader_login::is_reader_public_key(&entry.sealed_key),
            "a reader entry carries its 64-hex Ed25519 public key in sealed_key".to_string(),
        ),
    ]
    .into_iter()
    .find_map(|(is_broken, reason)| is_broken.then_some(reason));
    problem.map_or(Ok(()), |reason| Err(IdentityOpError::Invalid(reason)))
}

fn has_same_content(stored: &VaultEntry, submitted: &VaultEntry) -> bool {
    stored.kind == submitted.kind
        && stored.label == submitted.label
        && stored.sealed_key == submitted.sealed_key
        && stored.revoked_at.is_none()
}

pub fn check_add_vault_entry(
    store: &dyn BlockStore,
    request: &AddVaultEntryRequest,
) -> Result<Change, IdentityOpError> {
    validate_entry(request.entry)?;
    let record = read_active_owner(store, request.did)?;
    require_owner_signature(
        &record,
        &add_vault_entry_message(request.did, request.entry),
        request.owner_signature,
    )?;
    match record
        .vault_entries
        .iter()
        .find(|existing| existing.entry_id == request.entry.entry_id)
    {
        Some(existing) if has_same_content(existing, request.entry) => Ok(Change::AlreadyApplied),
        Some(_) => Err(IdentityOpError::Conflict(format!(
            "vault entry {} of {} already exists with different content",
            request.entry.entry_id, request.did
        ))),
        None if record.vault_entries.len() >= MAX_ENTRIES => {
            Err(IdentityOpError::Conflict(format!(
                "identity {} already holds {MAX_ENTRIES} vault entries",
                request.did
            )))
        }
        None => Ok(Change::Write),
    }
}

pub fn check_revoke_vault_entry(
    store: &dyn BlockStore,
    request: &RevokeVaultEntryRequest,
) -> Result<Change, IdentityOpError> {
    let record = read_active_owner(store, request.did)?;
    require_owner_signature(
        &record,
        &revoke_vault_entry_message(request.did, request.entry_id),
        request.owner_signature,
    )?;
    let entry = record
        .vault_entries
        .iter()
        .find(|existing| existing.entry_id == request.entry_id)
        .ok_or_else(|| {
            IdentityOpError::NotFound(format!(
                "vault entry {} of {} does not exist",
                request.entry_id, request.did
            ))
        })?;
    Ok(match entry.revoked_at {
        Some(_) => Change::AlreadyApplied,
        None => Change::Write,
    })
}

pub fn apply_add_vault_entry(
    store: &dyn BlockStore,
    request: &AddVaultEntryRequest,
) -> StorageResult<()> {
    if check_add_vault_entry(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    let record = store.read_identity(request.did)?;
    let vault_entries = record
        .vault_entries
        .iter()
        .cloned()
        .chain(std::iter::once(request.entry.clone()))
        .collect();
    store.write_identity(&IdentityRecord {
        vault_entries,
        ..record
    })
}

pub fn apply_revoke_vault_entry(
    store: &dyn BlockStore,
    request: &RevokeVaultEntryRequest,
) -> StorageResult<()> {
    if check_revoke_vault_entry(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    let record = store.read_identity(request.did)?;
    let vault_entries = record
        .vault_entries
        .iter()
        .map(|entry| match entry.entry_id == request.entry_id {
            true => VaultEntry {
                revoked_at: Some(request.revoked_at),
                ..entry.clone()
            },
            false => entry.clone(),
        })
        .collect();
    store.write_identity(&IdentityRecord {
        vault_entries,
        ..record
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use crate::storage::memory::MemoryStore;

    struct Owner {
        store: MemoryStore,
        key: MlDsaSigningProvider,
        did: String,
    }

    fn sign(key: &MlDsaSigningProvider, message: &str) -> String {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    }

    fn registered_owner() -> Owner {
        let key = MlDsaSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        let store = MemoryStore::new();
        store
            .write_identity(&IdentityRecord {
                did: did.clone(),
                public_key,
                created_at: 1,
                updated_at: 1,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: Some("MlDsa65".to_string()),
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            })
            .unwrap();
        Owner { store, key, did }
    }

    fn device_entry(entry_id: &str) -> VaultEntry {
        VaultEntry {
            entry_id: entry_id.to_string(),
            kind: VaultEntryKind::Device,
            label: "iPhone de Clemente".to_string(),
            sealed_key: r#"{"kdf":"hkdf","ciphertext":"00"}"#.to_string(),
            added_at: 10,
            revoked_at: None,
        }
    }

    fn add(owner: &Owner, entry: &VaultEntry, signer: &MlDsaSigningProvider) -> StorageResult<()> {
        let signature = sign(signer, &add_vault_entry_message(&owner.did, entry));
        apply_add_vault_entry(
            &owner.store,
            &AddVaultEntryRequest {
                did: &owner.did,
                entry,
                owner_signature: &signature,
            },
        )
    }

    fn revoke(owner: &Owner, entry_id: &str, signer: &MlDsaSigningProvider) -> StorageResult<()> {
        let signature = sign(signer, &revoke_vault_entry_message(&owner.did, entry_id));
        apply_revoke_vault_entry(
            &owner.store,
            &RevokeVaultEntryRequest {
                did: &owner.did,
                entry_id,
                revoked_at: 20,
                owner_signature: &signature,
            },
        )
    }

    fn entries(owner: &Owner) -> Vec<VaultEntry> {
        owner.store.read_identity(&owner.did).unwrap().vault_entries
    }

    #[test]
    fn owner_adds_a_device_copy() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        assert_eq!(entries(&owner), vec![device_entry("aa01")]);
    }

    #[test]
    fn stranger_cannot_add_a_copy() {
        let owner = registered_owner();
        let stranger = MlDsaSigningProvider::generate();
        assert!(add(&owner, &device_entry("aa01"), &stranger).is_err());
        assert!(entries(&owner).is_empty());
    }

    #[test]
    fn signature_covers_the_sealed_key() {
        let owner = registered_owner();
        let entry = device_entry("aa01");
        let signature = sign(&owner.key, &add_vault_entry_message(&owner.did, &entry));
        let swapped = VaultEntry {
            sealed_key: r#"{"kdf":"hkdf","ciphertext":"ff"}"#.to_string(),
            ..entry
        };
        let result = check_add_vault_entry(
            &owner.store,
            &AddVaultEntryRequest {
                did: &owner.did,
                entry: &swapped,
                owner_signature: &signature,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::BadSignature(_))));
    }

    #[test]
    fn signature_covers_the_label() {
        let owner = registered_owner();
        let entry = device_entry("aa01");
        let signature = sign(&owner.key, &add_vault_entry_message(&owner.did, &entry));
        let relabeled = VaultEntry {
            label: "Otro".to_string(),
            ..entry
        };
        let result = check_add_vault_entry(
            &owner.store,
            &AddVaultEntryRequest {
                did: &owner.did,
                entry: &relabeled,
                owner_signature: &signature,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::BadSignature(_))));
    }

    #[test]
    fn replaying_the_same_copy_is_idempotent() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        assert_eq!(entries(&owner).len(), 1);
    }

    #[test]
    fn retrying_the_same_copy_later_is_idempotent() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        let retried = VaultEntry {
            added_at: 99,
            ..device_entry("aa01")
        };
        add(&owner, &retried, &owner.key).unwrap();
        assert_eq!(entries(&owner), vec![device_entry("aa01")]);
    }

    #[test]
    fn a_different_copy_under_a_used_id_conflicts() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        let other = VaultEntry {
            label: "Otro".to_string(),
            ..device_entry("aa01")
        };
        let signature = sign(&owner.key, &add_vault_entry_message(&owner.did, &other));
        let result = check_add_vault_entry(
            &owner.store,
            &AddVaultEntryRequest {
                did: &owner.did,
                entry: &other,
                owner_signature: &signature,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::Conflict(_))));
    }

    #[test]
    fn rejects_malformed_entries() {
        let owner = registered_owner();
        let cases = [
            VaultEntry {
                entry_id: "".to_string(),
                ..device_entry("aa01")
            },
            VaultEntry {
                entry_id: "ZZ".to_string(),
                ..device_entry("aa01")
            },
            VaultEntry {
                label: "".to_string(),
                ..device_entry("aa01")
            },
            VaultEntry {
                label: "x".repeat(65),
                ..device_entry("aa01")
            },
            VaultEntry {
                sealed_key: "".to_string(),
                ..device_entry("aa01")
            },
            VaultEntry {
                sealed_key: "x".repeat(16_385),
                ..device_entry("aa01")
            },
            VaultEntry {
                revoked_at: Some(5),
                ..device_entry("aa01")
            },
            VaultEntry {
                kind: VaultEntryKind::Reader,
                ..device_entry("aa01")
            },
        ];
        for entry in cases {
            let signature = sign(&owner.key, &add_vault_entry_message(&owner.did, &entry));
            let result = check_add_vault_entry(
                &owner.store,
                &AddVaultEntryRequest {
                    did: &owner.did,
                    entry: &entry,
                    owner_signature: &signature,
                },
            );
            assert!(
                matches!(result, Err(IdentityOpError::Invalid(_))),
                "{entry:?}"
            );
        }
    }

    #[test]
    fn owner_adds_a_reader_key() {
        let owner = registered_owner();
        let reader = VaultEntry {
            kind: VaultEntryKind::Reader,
            sealed_key: "ab".repeat(32),
            ..device_entry("cc03")
        };
        add(&owner, &reader, &owner.key).unwrap();
        assert_eq!(entries(&owner), vec![reader]);
    }

    #[test]
    fn owner_revokes_a_device_copy() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        revoke(&owner, "aa01", &owner.key).unwrap();
        assert_eq!(entries(&owner)[0].revoked_at, Some(20));
    }

    #[test]
    fn stranger_cannot_revoke_a_copy() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        let stranger = MlDsaSigningProvider::generate();
        assert!(revoke(&owner, "aa01", &stranger).is_err());
        assert_eq!(entries(&owner)[0].revoked_at, None);
    }

    #[test]
    fn revoking_an_unknown_copy_is_not_found() {
        let owner = registered_owner();
        let signature = sign(&owner.key, &revoke_vault_entry_message(&owner.did, "bb02"));
        let result = check_revoke_vault_entry(
            &owner.store,
            &RevokeVaultEntryRequest {
                did: &owner.did,
                entry_id: "bb02",
                revoked_at: 20,
                owner_signature: &signature,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::NotFound(_))));
    }

    #[test]
    fn revoked_copy_cannot_be_added_back_under_its_id() {
        let owner = registered_owner();
        add(&owner, &device_entry("aa01"), &owner.key).unwrap();
        revoke(&owner, "aa01", &owner.key).unwrap();
        assert!(add(&owner, &device_entry("aa01"), &owner.key).is_err());
        assert_eq!(entries(&owner)[0].revoked_at, Some(20));
    }

    #[test]
    fn revoked_identity_cannot_add_copies() {
        let owner = registered_owner();
        let record = owner.store.read_identity(&owner.did).unwrap();
        owner
            .store
            .write_identity(&IdentityRecord {
                status: "revoked".to_string(),
                ..record
            })
            .unwrap();
        assert!(add(&owner, &device_entry("aa01"), &owner.key).is_err());
    }
}
