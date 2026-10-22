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

pub fn register_message(did: &str) -> String {
    format!("identity:register:{did}")
}

pub fn revoke_message(did: &str) -> String {
    format!("identity:revoke:{did}")
}

pub fn migrate_message(did: &str, new_did: &str) -> String {
    format!("identity:migrate:{did}:{new_did}")
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
    if let Some(signature) = owner_signature {
        require_signature(
            &record.public_key,
            &register_message(&record.did),
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

pub struct MigrateRequest<'a> {
    pub did: &'a str,
    pub new_public_key: &'a str,
    pub owner_signature: &'a str,
    pub new_key_signature: &'a str,
}

pub fn check_migrate(
    store: &dyn BlockStore,
    request: &MigrateRequest,
) -> Result<Change, IdentityOpError> {
    let record = read_existing(store, request.did)?;
    let new_did = did_from_pubkey_hex(request.new_public_key);
    let message = migrate_message(request.did, &new_did);
    require_signature(
        &record.public_key,
        &message,
        request.owner_signature,
        request.did,
    )?;
    require_signature(
        request.new_public_key,
        &message,
        request.new_key_signature,
        &new_did,
    )?;
    let successor = store.read_identity(&new_did).ok();
    match (record.status.as_str(), successor) {
        ("migrated", Some(next)) if next.migrated_from.as_deref() == Some(request.did) => {
            Ok(Change::AlreadyApplied)
        }
        ("active", None) => Ok(Change::Write),
        ("active", Some(_)) => Err(IdentityOpError::Conflict(format!(
            "identity {new_did} already registered"
        ))),
        (status, _) => Err(IdentityOpError::Conflict(format!(
            "identity {} is {status}; only active identities can migrate",
            request.did
        ))),
    }
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

pub fn apply_migrate(
    store: &dyn BlockStore,
    request: &MigrateRequest,
    migrated_at: u64,
) -> StorageResult<()> {
    if check_migrate(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    crate::identity::keys::migrate_identity(
        store,
        request.did,
        request.new_public_key,
        migrated_at,
    )?;
    Ok(())
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
            }
        }

        fn register_on(&self, store: &dyn BlockStore) {
            let signature = self.sign(&register_message(&self.did));
            apply_register(store, &self.record(), None, Some(&signature)).unwrap();
        }
    }

    fn migrate_request<'a>(
        owner: &'a Owner,
        successor: &'a Owner,
        signatures: &'a (String, String),
    ) -> MigrateRequest<'a> {
        MigrateRequest {
            did: &owner.did,
            new_public_key: &successor.public_key,
            owner_signature: &signatures.0,
            new_key_signature: &signatures.1,
        }
    }

    fn migrate_signatures(owner: &Owner, successor: &Owner) -> (String, String) {
        let message = migrate_message(&owner.did, &successor.did);
        (owner.sign(&message), successor.sign(&message))
    }

    #[test]
    fn signature_check_accepts_owner_and_rejects_stranger() {
        let owner = Owner::ml_dsa();
        let stranger = Owner::ml_dsa();
        let message = register_message(&owner.did);
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
        let forged = attacker.sign(&register_message(&owner.did));
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
        let signature = attacker.sign(&register_message(&victim.did));
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
        let signature = owner.sign(&register_message(&owner.did));
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
        let signature = owner.sign(&register_message(&owner.did));
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
    fn migrate_moves_identity_to_successor_key() {
        let store = MemoryStore::new();
        let owner = Owner::ml_dsa();
        let successor = Owner::ml_dsa();
        owner.register_on(&store);
        let signatures = migrate_signatures(&owner, &successor);
        apply_migrate(
            &store,
            &migrate_request(&owner, &successor, &signatures),
            700,
        )
        .unwrap();
        assert_eq!(store.read_identity(&owner.did).unwrap().status, "migrated");
        let new_record = store.read_identity(&successor.did).unwrap();
        assert_eq!(new_record.status, "active");
        assert_eq!(
            new_record.migrated_from.as_deref(),
            Some(owner.did.as_str())
        );
        assert_eq!(new_record.created_at, 700);
    }

    #[test]
    fn migrate_twice_is_idempotent() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let successor = Owner::ed25519();
        owner.register_on(&store);
        let signatures = migrate_signatures(&owner, &successor);
        let request = migrate_request(&owner, &successor, &signatures);
        apply_migrate(&store, &request, 700).unwrap();
        apply_migrate(&store, &request, 800).unwrap();
        assert_eq!(store.read_identity(&successor.did).unwrap().created_at, 700);
    }

    #[test]
    fn migrate_rejects_when_successor_did_not_sign() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let successor = Owner::ed25519();
        owner.register_on(&store);
        let message = migrate_message(&owner.did, &successor.did);
        let signatures = (owner.sign(&message), owner.sign(&message));
        assert!(matches!(
            check_migrate(&store, &migrate_request(&owner, &successor, &signatures)),
            Err(IdentityOpError::BadSignature(_))
        ));
    }

    #[test]
    fn migrate_rejects_revoked_identity() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let successor = Owner::ed25519();
        owner.register_on(&store);
        let revocation = owner.sign(&revoke_message(&owner.did));
        apply_revoke(&store, &owner.did, 500, &revocation).unwrap();
        let signatures = migrate_signatures(&owner, &successor);
        assert!(matches!(
            check_migrate(&store, &migrate_request(&owner, &successor, &signatures)),
            Err(IdentityOpError::Conflict(_))
        ));
        assert!(store.read_identity(&successor.did).is_err());
    }

    #[test]
    fn migrate_rejects_successor_already_registered() {
        let store = MemoryStore::new();
        let owner = Owner::ed25519();
        let successor = Owner::ed25519();
        owner.register_on(&store);
        successor.register_on(&store);
        let signatures = migrate_signatures(&owner, &successor);
        assert!(matches!(
            check_migrate(&store, &migrate_request(&owner, &successor, &signatures)),
            Err(IdentityOpError::Conflict(_))
        ));
    }
}
