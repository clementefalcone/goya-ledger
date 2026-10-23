use crate::identity::did::{did_from_pubkey_hex, did_matches_pubkey};
use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::{BlockStore, IdentityRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOpError {
    NotFound(String),
    BadSignature(String),
    Conflict(String),
    Invalid(String),
}

impl std::fmt::Display for IdentityOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(reason)
            | Self::BadSignature(reason)
            | Self::Conflict(reason)
            | Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl From<IdentityOpError> for StorageError {
    fn from(error: IdentityOpError) -> Self {
        StorageError::Other(error.to_string())
    }
}

pub fn register_message(did: &str, recovery_commitment: Option<&str>) -> String {
    match recovery_commitment {
        Some(commitment) => format!("identity:register:{did}:{commitment}"),
        None => format!("identity:register:{did}"),
    }
}

pub fn revoke_message(did: &str) -> String {
    format!("identity:revoke:{did}")
}

pub fn rotate_message(did: &str, new_public_key: &str, new_recovery_commitment: &str) -> String {
    format!("identity:rotate:{did}:{new_public_key}:{new_recovery_commitment}")
}

pub fn is_signed_by(public_key_hex: &str, message: &str, signature_hex: &str) -> bool {
    crate::signature::verify::infer_algorithm_from_key(public_key_hex).is_some_and(|algorithm| {
        crate::signature::verify_signature(
            algorithm,
            public_key_hex,
            message.as_bytes(),
            signature_hex,
        )
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Write,
    AlreadyApplied,
}

fn read_existing(store: &dyn BlockStore, did: &str) -> Result<IdentityRecord, IdentityOpError> {
    store
        .read_identity(did)
        .map_err(|_| IdentityOpError::NotFound(format!("identity {did} is not registered")))
}

fn require_signature(
    public_key_hex: &str,
    message: &str,
    signature_hex: &str,
    signer: &str,
) -> Result<(), IdentityOpError> {
    if is_signed_by(public_key_hex, message, signature_hex) {
        return Ok(());
    }
    Err(IdentityOpError::BadSignature(format!(
        "signature over {message:?} does not verify against the key of {signer}"
    )))
}

pub fn check_register(
    store: &dyn BlockStore,
    record: &IdentityRecord,
    civil_anchor: Option<&str>,
    owner_signature: Option<&str>,
) -> Result<Change, IdentityOpError> {
    if !did_matches_pubkey(&record.did, &record.public_key) {
        return Err(IdentityOpError::Invalid(format!(
            "did {} is not derived from its public_key",
            record.did
        )));
    }
    if record.status != "active" {
        return Err(IdentityOpError::Invalid(format!(
            "new identities must be active, got {:?}",
            record.status
        )));
    }
    if record.recovery_commitment.as_deref() == Some(record.did.as_str()) {
        return Err(IdentityOpError::Invalid(format!(
            "recovery commitment of {} must not be its own signing key",
            record.did
        )));
    }
    if let Some(signature) = owner_signature {
        require_signature(
            &record.public_key,
            &register_message(&record.did, record.recovery_commitment.as_deref()),
            signature,
            &record.did,
        )?;
    }
    if let Some(anchor) = civil_anchor {
        if let Ok(anchored_did) = store.resolve_by_civil_anchor(anchor) {
            if anchored_did != record.did {
                return Err(IdentityOpError::Conflict(
                    "identity with document already exists".to_string(),
                ));
            }
        }
    }
    match store.read_identity(&record.did) {
        Ok(existing) if existing == *record => Ok(Change::AlreadyApplied),
        Ok(_) => Err(IdentityOpError::Conflict(format!(
            "identity {} already registered",
            record.did
        ))),
        Err(_) => Ok(Change::Write),
    }
}

pub fn check_revoke(
    store: &dyn BlockStore,
    did: &str,
    owner_signature: &str,
) -> Result<Change, IdentityOpError> {
    let record = read_existing(store, did)?;
    require_signature(
        &record.public_key,
        &revoke_message(did),
        owner_signature,
        did,
    )?;
    if record.status == "revoked" {
        return Ok(Change::AlreadyApplied);
    }
    Ok(Change::Write)
}

pub struct RotateRequest<'a> {
    pub did: &'a str,
    pub new_public_key: &'a str,
    pub recovery_public_key: &'a str,
    pub new_recovery_commitment: &'a str,
    pub recovery_signature: &'a str,
    pub new_key_signature: &'a str,
}

pub fn check_rotate(
    store: &dyn BlockStore,
    request: &RotateRequest,
) -> Result<Change, IdentityOpError> {
    let record = read_existing(store, request.did)?;
    if record.public_key == request.new_public_key
        && record.recovery_commitment.as_deref() == Some(request.new_recovery_commitment)
    {
        return Ok(Change::AlreadyApplied);
    }
    if record.status != "active" && record.status != "revoked" {
        return Err(IdentityOpError::Conflict(format!(
            "identity {} is {}; only active or revoked identities can rotate",
            request.did, record.status
        )));
    }
    let commitment = record.recovery_commitment.as_deref().ok_or_else(|| {
        IdentityOpError::Conflict(format!(
            "identity {} has no recovery key committed",
            request.did
        ))
    })?;
    let recovery_algorithm =
        crate::signature::verify::infer_algorithm_from_key(request.recovery_public_key);
    if recovery_algorithm != Some(crate::identity::signing::SigningAlgorithm::MlDsa65) {
        return Err(IdentityOpError::Invalid(format!(
            "recovery key of {} must be ML-DSA-65, got {recovery_algorithm:?}",
            request.did
        )));
    }
    if did_from_pubkey_hex(request.recovery_public_key) != commitment {
        return Err(IdentityOpError::BadSignature(format!(
            "recovery key does not match the commitment registered for {}",
            request.did
        )));
    }
    if request.new_recovery_commitment == commitment
        || request.new_recovery_commitment == did_from_pubkey_hex(request.new_public_key)
    {
        return Err(IdentityOpError::Invalid(format!(
            "rotation of {} must commit a fresh recovery key distinct from the new signing key",
            request.did
        )));
    }
    let message = rotate_message(
        request.did,
        request.new_public_key,
        request.new_recovery_commitment,
    );
    require_signature(
        request.recovery_public_key,
        &message,
        request.recovery_signature,
        &format!("the recovery key of {}", request.did),
    )?;
    require_signature(
        request.new_public_key,
        &message,
        request.new_key_signature,
        &format!("the new key of {}", request.did),
    )?;
    Ok(Change::Write)
}

pub fn apply_register(
    store: &dyn BlockStore,
    record: &IdentityRecord,
    civil_anchor: Option<&str>,
    owner_signature: Option<&str>,
) -> StorageResult<()> {
    if check_register(store, record, civil_anchor, owner_signature)? == Change::AlreadyApplied {
        return Ok(());
    }
    store.write_identity(record)?;
    if let Some(anchor) = civil_anchor {
        store.write_civil_anchor(anchor, &record.did)?;
    }
    Ok(())
}

pub fn apply_revoke(
    store: &dyn BlockStore,
    did: &str,
    revoked_at: u64,
    owner_signature: &str,
) -> StorageResult<()> {
    if check_revoke(store, did, owner_signature)? == Change::AlreadyApplied {
        return Ok(());
    }
    let record = store.read_identity(did)?;
    store.write_identity(&IdentityRecord {
        status: "revoked".to_string(),
        updated_at: revoked_at,
        ..record
    })
}

pub fn apply_rotate(
    store: &dyn BlockStore,
    request: &RotateRequest,
    rotated_at: u64,
) -> StorageResult<()> {
    if check_rotate(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    let record = store.read_identity(request.did)?;
    let new_algorithm = crate::signature::verify::infer_algorithm_from_key(request.new_public_key);
    store.write_identity(&IdentityRecord {
        public_key: request.new_public_key.to_string(),
        recovery_commitment: Some(request.new_recovery_commitment.to_string()),
        vault_entries: Vec::new(),
        status: "active".to_string(),
        updated_at: rotated_at,
        signature_algorithm: new_algorithm.map(|algorithm| format!("{algorithm:?}")),
        ..record
    })
}

pub fn key_controls_did(store: &dyn BlockStore, did: &str, public_key: &str) -> bool {
    match store.read_identity(did) {
        Ok(record) => record.status == "active" && record.public_key == public_key,
        Err(StorageError::IdentityNotFound(_)) => did_matches_pubkey(did, public_key),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{
        MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider,
    };
    use crate::storage::MemoryStore;

    struct Owner {
        provider: Box<dyn SigningProvider>,
        did: String,
        public_key: String,
    }

    impl Owner {
        fn from(provider: Box<dyn SigningProvider>) -> Self {
            let public_key = hex::encode(provider.public_key());
            let did = did_from_pubkey_hex(&public_key);
            Self {
                provider,
                did,
                public_key,
            }
        }

        fn ed25519() -> Self {
            Self::from(Box::new(SoftwareSigningProvider::generate()))
        }

        fn ml_dsa() -> Self {
            Self::from(Box::new(MlDsaSigningProvider::generate()))
        }

        fn sign(&self, message: &str) -> String {
            hex::encode(self.provider.sign(message.as_bytes()).unwrap())
        }

        fn record(&self) -> IdentityRecord {
            IdentityRecord {
                did: self.did.clone(),
                public_key: self.public_key.clone(),
                created_at: 10,
                updated_at: 10,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            }
        }

        fn register_on(&self, store: &dyn BlockStore) {
            let signature = self.sign(&register_message(&self.did, None));
            apply_register(store, &self.record(), None, Some(&signature)).unwrap();
        }
    }

    struct Rotation {
        did: String,
        new_public_key: String,
        recovery_public_key: String,
        new_recovery_commitment: String,
        recovery_signature: String,
        new_key_signature: String,
    }

    impl Rotation {
        fn signed(owner: &Owner, recovery: &Owner, successor: &Owner, next: &Owner) -> Self {
            let message = rotate_message(&owner.did, &successor.public_key, &next.did);
            Self {
                did: owner.did.clone(),
                new_public_key: successor.public_key.clone(),
                recovery_public_key: recovery.public_key.clone(),
                new_recovery_commitment: next.did.clone(),
                recovery_signature: recovery.sign(&message),
                new_key_signature: successor.sign(&message),
            }
        }

        fn request(&self) -> RotateRequest<'_> {
            RotateRequest {
                did: &self.did,
                new_public_key: &self.new_public_key,
                recovery_public_key: &self.recovery_public_key,
                new_recovery_commitment: &self.new_recovery_commitment,
                recovery_signature: &self.recovery_signature,
                new_key_signature: &self.new_key_signature,
            }
        }
    }

    fn register_with_recovery(store: &dyn BlockStore, owner: &Owner, recovery: &Owner) {
        let record = IdentityRecord {
            recovery_commitment: Some(recovery.did.clone()),
            vault_entries: Vec::new(),
            ..owner.record()
        };
        let signature = owner.sign(&register_message(&owner.did, Some(&recovery.did)));
        apply_register(store, &record, None, Some(&signature)).unwrap();
    }

    #[test]
    fn signature_check_accepts_owner_and_rejects_stranger() {
        let owner = Owner::ml_dsa();
        let stranger = Owner::ml_dsa();
        let message = register_message(&owner.did, None);
        assert!(is_signed_by(
            &owner.public_key,
            &message,
            &owner.sign(&message)
        ));
        assert!(!is_signed_by(
            &owner.public_key,
            &message,
            &stranger.sign(&message)
        ));
    }

    #[test]
    fn register_rejects_signature_from_another_key() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let attacker = Owner::ed25519();
        let forged = attacker.sign(&register_message(&owner.did, None));
        let result = apply_register(&store, &owner.record(), None, Some(&forged));
        assert!(result.is_err());
        assert!(store.read_identity(&owner.did).is_err());
    }

    #[test]
    fn register_rejects_did_not_derived_from_key() {
        let store = MemoryStore::new();
        let victim = Owner::ed25519();
        let attacker = Owner::ed25519();
        let record = IdentityRecord {
            public_key: attacker.public_key.clone(),
            ..victim.record()
        };
        let signature = attacker.sign(&register_message(&victim.did, None));
        assert!(apply_register(&store, &record, None, Some(&signature)).is_err());
    }

    #[test]
    fn register_rejects_non_active_status() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let record = IdentityRecord {
            status: "revoked".to_string(),
            ..owner.record()
        };
        let signature = owner.sign(&register_message(&owner.did, None));
        assert!(matches!(
            check_register(&store, &record, None, Some(&signature)),
            Err(IdentityOpError::Invalid(_))
        ));
    }

    #[test]
    fn register_twice_with_same_record_is_idempotent() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        owner.register_on(&store);
        owner.register_on(&store);
        assert_eq!(store.read_identity(&owner.did).unwrap(), owner.record());
    }

    #[test]
    fn register_rejects_different_record_for_existing_did() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        owner.register_on(&store);
        let altered = IdentityRecord {
            created_at: 99,
            ..owner.record()
        };
        let signature = owner.sign(&register_message(&owner.did, None));
        assert!(matches!(
            check_register(&store, &altered, None, Some(&signature)),
            Err(IdentityOpError::Conflict(_))
        ));
    }

    #[test]
    fn revoke_marks_identity_revoked_at_given_time() {
        let store = MemoryStore::new();
        let owner = Owner::ml_dsa();
        owner.register_on(&store);
        let signature = owner.sign(&revoke_message(&owner.did));
        apply_revoke(&store, &owner.did, 500, &signature).unwrap();
        let record = store.read_identity(&owner.did).unwrap();
        assert_eq!(record.status, "revoked");
        assert_eq!(record.updated_at, 500);
    }

    #[test]
    fn revoke_rejects_signature_from_another_key() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let thief = Owner::ed25519();
        owner.register_on(&store);
        let forged = thief.sign(&revoke_message(&owner.did));
        assert!(matches!(
            check_revoke(&store, &owner.did, &forged),
            Err(IdentityOpError::BadSignature(_))
        ));
        assert_eq!(store.read_identity(&owner.did).unwrap().status, "active");
    }

    #[test]
    fn revoke_of_unknown_did_is_not_found() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let signature = owner.sign(&revoke_message(&owner.did));
        assert!(matches!(
            check_revoke(&store, &owner.did, &signature),
            Err(IdentityOpError::NotFound(_))
        ));
    }

    #[test]
    fn revoke_twice_is_idempotent_and_keeps_first_time() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        owner.register_on(&store);
        let signature = owner.sign(&revoke_message(&owner.did));
        apply_revoke(&store, &owner.did, 500, &signature).unwrap();
        apply_revoke(&store, &owner.did, 900, &signature).unwrap();
        assert_eq!(store.read_identity(&owner.did).unwrap().updated_at, 500);
    }

    #[test]
    fn unregistered_did_is_controlled_only_by_the_key_it_derives_from() {
        let store = MemoryStore::new();
        let (owner, stranger) = (Owner::ml_dsa(), Owner::ml_dsa());
        assert!(key_controls_did(&store, &owner.did, &owner.public_key));
        assert!(!key_controls_did(&store, &owner.did, &stranger.public_key));
    }

    #[test]
    fn rotated_did_is_controlled_by_new_key_and_not_by_first_key() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        assert!(key_controls_did(&store, &owner.did, &owner.public_key));
        apply_rotate(
            &store,
            &Rotation::signed(&owner, &recovery, &successor, &next).request(),
            700,
        )
        .unwrap();
        assert!(key_controls_did(&store, &owner.did, &successor.public_key));
        assert!(!key_controls_did(&store, &owner.did, &owner.public_key));
    }

    #[test]
    fn revoked_did_is_controlled_by_no_key() {
        let store = MemoryStore::new();
        let owner = Owner::ml_dsa();
        owner.register_on(&store);
        let revocation = owner.sign(&revoke_message(&owner.did));
        apply_revoke(&store, &owner.did, 500, &revocation).unwrap();
        assert!(!key_controls_did(&store, &owner.did, &owner.public_key));
    }

    #[test]
    fn register_signature_must_cover_recovery_commitment() {
        let store = MemoryStore::new();
        let owner = Owner::ml_dsa();
        let swapped_in = Owner::ml_dsa();
        let record = IdentityRecord {
            recovery_commitment: Some(swapped_in.did.clone()),
            vault_entries: Vec::new(),
            ..owner.record()
        };
        let signature_without_commitment = owner.sign(&register_message(&owner.did, None));
        assert!(matches!(
            check_register(&store, &record, None, Some(&signature_without_commitment)),
            Err(IdentityOpError::BadSignature(_))
        ));
    }

    #[test]
    fn register_rejects_recovery_commitment_to_own_signing_key() {
        let store = MemoryStore::new();
        let owner = Owner::ml_dsa();
        let record = IdentityRecord {
            recovery_commitment: Some(owner.did.clone()),
            vault_entries: Vec::new(),
            ..owner.record()
        };
        let signature = owner.sign(&register_message(&owner.did, Some(&owner.did)));
        assert!(matches!(
            check_register(&store, &record, None, Some(&signature)),
            Err(IdentityOpError::Invalid(_))
        ));
    }

    #[test]
    fn rotate_replaces_key_and_keeps_did() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let rotation = Rotation::signed(&owner, &recovery, &successor, &next);
        apply_rotate(&store, &rotation.request(), 700).unwrap();

        let record = store.read_identity(&owner.did).unwrap();
        assert_eq!(record.did, owner.did);
        assert_eq!(record.public_key, successor.public_key);
        assert_eq!(
            record.recovery_commitment.as_deref(),
            Some(next.did.as_str())
        );
        assert_eq!(record.status, "active");
        assert_eq!(record.updated_at, 700);
        assert!(store.read_identity(&successor.did).is_err());
    }

    #[test]
    fn rotate_kills_the_previous_key() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        apply_rotate(
            &store,
            &Rotation::signed(&owner, &recovery, &successor, &next).request(),
            700,
        )
        .unwrap();
        let stolen_key_revocation = owner.sign(&revoke_message(&owner.did));
        assert!(matches!(
            check_revoke(&store, &owner.did, &stolen_key_revocation),
            Err(IdentityOpError::BadSignature(_))
        ));
    }

    #[test]
    fn rotate_rejects_thief_holding_the_current_key() {
        let store = MemoryStore::new();
        let (owner, recovery, thief_key, thief_next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let rotation = Rotation::signed(&owner, &owner, &thief_key, &thief_next);
        assert!(matches!(
            check_rotate(&store, &rotation.request()),
            Err(IdentityOpError::BadSignature(_))
        ));
        assert_eq!(
            store.read_identity(&owner.did).unwrap().public_key,
            owner.public_key
        );
    }

    #[test]
    fn rotate_rejects_recovery_key_that_was_not_committed() {
        let store = MemoryStore::new();
        let (owner, recovery, impostor, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let rotation = Rotation::signed(&owner, &impostor, &successor, &next);
        assert!(matches!(
            check_rotate(&store, &rotation.request()),
            Err(IdentityOpError::BadSignature(_))
        ));
    }

    #[test]
    fn rotate_rejects_identity_without_recovery_commitment() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        owner.register_on(&store);
        let rotation = Rotation::signed(&owner, &recovery, &successor, &next);
        assert!(matches!(
            check_rotate(&store, &rotation.request()),
            Err(IdentityOpError::Conflict(_))
        ));
    }

    #[test]
    fn rotate_rejects_classical_recovery_key() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ed25519(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let rotation = Rotation::signed(&owner, &recovery, &successor, &next);
        assert!(matches!(
            check_rotate(&store, &rotation.request()),
            Err(IdentityOpError::Invalid(_))
        ));
    }

    #[test]
    fn rotate_requires_a_fresh_recovery_commitment() {
        let store = MemoryStore::new();
        let (owner, recovery, successor) = (Owner::ml_dsa(), Owner::ml_dsa(), Owner::ml_dsa());
        register_with_recovery(&store, &owner, &recovery);
        let reused = Rotation::signed(&owner, &recovery, &successor, &recovery);
        assert!(matches!(
            check_rotate(&store, &reused.request()),
            Err(IdentityOpError::Invalid(_))
        ));
        let self_recovering = Rotation::signed(&owner, &recovery, &successor, &successor);
        assert!(matches!(
            check_rotate(&store, &self_recovering.request()),
            Err(IdentityOpError::Invalid(_))
        ));
    }

    #[test]
    fn rotate_rejects_successor_that_did_not_sign() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let mut rotation = Rotation::signed(&owner, &recovery, &successor, &next);
        rotation.new_key_signature = rotation.recovery_signature.clone();
        assert!(matches!(
            check_rotate(&store, &rotation.request()),
            Err(IdentityOpError::BadSignature(_))
        ));
    }

    #[test]
    fn rotate_restores_a_revoked_identity() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let revocation = owner.sign(&revoke_message(&owner.did));
        apply_revoke(&store, &owner.did, 500, &revocation).unwrap();
        apply_rotate(
            &store,
            &Rotation::signed(&owner, &recovery, &successor, &next).request(),
            700,
        )
        .unwrap();
        let record = store.read_identity(&owner.did).unwrap();
        assert_eq!(record.status, "active");
        assert_eq!(record.public_key, successor.public_key);
    }

    #[test]
    fn rotate_twice_is_idempotent() {
        let store = MemoryStore::new();
        let (owner, recovery, successor, next) = (
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
            Owner::ml_dsa(),
        );
        register_with_recovery(&store, &owner, &recovery);
        let rotation = Rotation::signed(&owner, &recovery, &successor, &next);
        apply_rotate(&store, &rotation.request(), 700).unwrap();
        apply_rotate(&store, &rotation.request(), 800).unwrap();
        assert_eq!(store.read_identity(&owner.did).unwrap().updated_at, 700);
    }
}
