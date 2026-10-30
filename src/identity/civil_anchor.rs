use crate::identity::operations::{is_signed_by, Change, IdentityOpError};
use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::{BlockStore, IdentityRecord};
use std::sync::OnceLock;

const ANCHOR_HEX_LEN: usize = 64;

pub struct BindCivilAnchorRequest<'a> {
    pub did: &'a str,
    pub anchor: &'a str,
    pub replaces: Option<&'a str>,
    pub issuer_public_key: &'a str,
    pub issuer_signature: &'a str,
    pub owner_signature: &'a str,
}

pub fn bind_civil_anchor_message(did: &str, anchor: &str, replaces: Option<&str>) -> String {
    match replaces {
        Some(previous_did) => {
            format!("identity:civil-anchor:{did}:{anchor}:replaces:{previous_did}")
        }
        None => format!("identity:civil-anchor:{did}:{anchor}"),
    }
}

pub fn trusted_issuers() -> &'static [String] {
    static ISSUERS: OnceLock<Vec<String>> = OnceLock::new();
    ISSUERS.get_or_init(|| {
        std::env::var("CIVIL_ANCHOR_ISSUERS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(str::to_lowercase)
            .collect()
    })
}

fn is_anchor_shaped(text: &str) -> bool {
    text.len() == ANCHOR_HEX_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn current_holder(store: &dyn BlockStore, anchor: &str) -> Result<Option<String>, IdentityOpError> {
    match store.resolve_by_civil_anchor(anchor) {
        Ok(did) => Ok(Some(did)),
        Err(StorageError::KeyNotFound(_)) => Ok(None),
        Err(error) => Err(IdentityOpError::Conflict(format!(
            "civil anchor index could not be read for {anchor}: {error}"
        ))),
    }
}

fn require_issuer(
    issuers: &[String],
    request: &BindCivilAnchorRequest,
    message: &str,
) -> Result<(), IdentityOpError> {
    if !issuers.iter().any(|key| key == request.issuer_public_key) {
        return Err(IdentityOpError::BadSignature(format!(
            "{} is not a trusted civil anchor issuer",
            request.issuer_public_key
        )));
    }
    if !is_signed_by(request.issuer_public_key, message, request.issuer_signature) {
        return Err(IdentityOpError::BadSignature(format!(
            "issuer signature over {message:?} does not verify"
        )));
    }
    Ok(())
}

fn read_consenting_owner(
    store: &dyn BlockStore,
    request: &BindCivilAnchorRequest,
    message: &str,
) -> Result<IdentityRecord, IdentityOpError> {
    let record = store.read_identity(request.did).map_err(|_| {
        IdentityOpError::NotFound(format!("identity {} is not registered", request.did))
    })?;
    if record.status != "active" {
        return Err(IdentityOpError::Conflict(format!(
            "identity {} is {}; only active identities take a civil anchor",
            request.did, record.status
        )));
    }
    if !is_signed_by(&record.public_key, message, request.owner_signature) {
        return Err(IdentityOpError::BadSignature(format!(
            "owner signature over {message:?} does not verify against the key of {}",
            request.did
        )));
    }
    Ok(record)
}

fn check_holder(
    request: &BindCivilAnchorRequest,
    holder: Option<&str>,
) -> Result<Change, IdentityOpError> {
    match (holder, request.replaces) {
        (Some(did), _) if did == request.did => Ok(Change::AlreadyApplied),
        (Some(did), Some(replaced)) if did == replaced => Ok(Change::Write),
        (Some(did), _) => Err(IdentityOpError::Conflict(format!(
            "civil anchor already belongs to {did}; a rebind must name it in replaces"
        ))),
        (None, None) => Ok(Change::Write),
        (None, Some(replaced)) => Err(IdentityOpError::Conflict(format!(
            "civil anchor is not bound to {replaced}, so there is nothing to replace"
        ))),
    }
}

pub fn check_bind_civil_anchor(
    store: &dyn BlockStore,
    issuers: &[String],
    request: &BindCivilAnchorRequest,
) -> Result<Change, IdentityOpError> {
    if !is_anchor_shaped(request.anchor) {
        return Err(IdentityOpError::Invalid(format!(
            "civil anchor {:?} must be {ANCHOR_HEX_LEN} lowercase hex characters",
            request.anchor
        )));
    }
    let message = bind_civil_anchor_message(request.did, request.anchor, request.replaces);
    require_issuer(issuers, request, &message)?;
    let record = read_consenting_owner(store, request, &message)?;
    if let Some(existing) = record.civil_anchor.as_deref() {
        if existing != request.anchor {
            return Err(IdentityOpError::Conflict(format!(
                "identity {} is already anchored to another document",
                request.did
            )));
        }
    }
    check_holder(request, current_holder(store, request.anchor)?.as_deref())
}

pub fn apply_bind_civil_anchor(
    store: &dyn BlockStore,
    issuers: &[String],
    request: &BindCivilAnchorRequest,
    bound_at: u64,
) -> StorageResult<()> {
    if check_bind_civil_anchor(store, issuers, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    if let Some(previous_did) = request.replaces {
        let previous = store.read_identity(previous_did)?;
        store.write_identity(&IdentityRecord {
            civil_anchor: None,
            updated_at: bound_at,
            ..previous
        })?;
    }
    store.write_civil_anchor(request.anchor, request.did)?;
    let record = store.read_identity(request.did)?;
    store.write_identity(&IdentityRecord {
        civil_anchor: Some(request.anchor.to_string()),
        updated_at: bound_at,
        ..record
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did::did_from_pubkey_hex;
    use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use crate::storage::memory::MemoryStore;

    const ANCHOR: &str = "4f1c2a9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928170605f4e3";

    struct Person {
        key: MlDsaSigningProvider,
        did: String,
    }

    struct Network {
        store: MemoryStore,
        issuer: MlDsaSigningProvider,
        issuers: Vec<String>,
    }

    fn sign(key: &MlDsaSigningProvider, message: &str) -> String {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    }

    fn public_key_of(key: &MlDsaSigningProvider) -> String {
        hex::encode(key.public_key())
    }

    fn network() -> Network {
        let issuer = MlDsaSigningProvider::generate();
        let issuers = vec![public_key_of(&issuer)];
        Network {
            store: MemoryStore::new(),
            issuer,
            issuers,
        }
    }

    fn register(network: &Network) -> Person {
        let key = MlDsaSigningProvider::generate();
        let did = did_from_pubkey_hex(&public_key_of(&key));
        network
            .store
            .write_identity(&IdentityRecord {
                did: did.clone(),
                public_key: public_key_of(&key),
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
        Person { key, did }
    }

    fn bind_signed_by(
        network: &Network,
        person: &Person,
        replaces: Option<&str>,
        issuer: &MlDsaSigningProvider,
        owner: &MlDsaSigningProvider,
    ) -> StorageResult<()> {
        let message = bind_civil_anchor_message(&person.did, ANCHOR, replaces);
        apply_bind_civil_anchor(
            &network.store,
            &network.issuers,
            &BindCivilAnchorRequest {
                did: &person.did,
                anchor: ANCHOR,
                replaces,
                issuer_public_key: &public_key_of(issuer),
                issuer_signature: &sign(issuer, &message),
                owner_signature: &sign(owner, &message),
            },
            70,
        )
    }

    fn bind(network: &Network, person: &Person, replaces: Option<&str>) -> StorageResult<()> {
        bind_signed_by(network, person, replaces, &network.issuer, &person.key)
    }

    fn anchor_of(network: &Network, person: &Person) -> Option<String> {
        network
            .store
            .read_identity(&person.did)
            .unwrap()
            .civil_anchor
    }

    fn holder(network: &Network) -> Option<String> {
        network.store.resolve_by_civil_anchor(ANCHOR).ok()
    }

    #[test]
    fn issuer_and_owner_bind_a_document_to_a_did() {
        let network = network();
        let person = register(&network);
        bind(&network, &person, None).unwrap();
        assert_eq!(anchor_of(&network, &person).as_deref(), Some(ANCHOR));
        assert_eq!(holder(&network), Some(person.did.clone()));
    }

    #[test]
    fn replaying_the_same_bind_is_idempotent() {
        let network = network();
        let person = register(&network);
        bind(&network, &person, None).unwrap();
        bind(&network, &person, None).unwrap();
        assert_eq!(holder(&network), Some(person.did));
    }

    #[test]
    fn a_second_did_cannot_take_a_bound_document() {
        let network = network();
        let first = register(&network);
        let second = register(&network);
        bind(&network, &first, None).unwrap();
        assert!(bind(&network, &second, None).is_err());
        assert_eq!(holder(&network), Some(first.did));
        assert_eq!(anchor_of(&network, &second), None);
    }

    #[test]
    fn rebind_moves_the_document_and_unanchors_the_lost_did() {
        let network = network();
        let lost = register(&network);
        let fresh = register(&network);
        bind(&network, &lost, None).unwrap();
        bind(&network, &fresh, Some(&lost.did)).unwrap();
        assert_eq!(holder(&network), Some(fresh.did.clone()));
        assert_eq!(anchor_of(&network, &fresh).as_deref(), Some(ANCHOR));
        assert_eq!(anchor_of(&network, &lost), None);
        let lost_record = network.store.read_identity(&lost.did).unwrap();
        assert_eq!(lost_record.status, "active");
    }

    #[test]
    fn rebind_must_name_the_current_holder() {
        let network = network();
        let holder_person = register(&network);
        let bystander = register(&network);
        let claimant = register(&network);
        bind(&network, &holder_person, None).unwrap();
        assert!(bind(&network, &claimant, Some(&bystander.did)).is_err());
        assert!(bind(&network, &bystander, Some(&claimant.did)).is_err());
        assert_eq!(holder(&network), Some(holder_person.did));
    }

    #[test]
    fn untrusted_issuer_cannot_bind() {
        let network = network();
        let person = register(&network);
        let impostor = MlDsaSigningProvider::generate();
        assert!(bind_signed_by(&network, &person, None, &impostor, &person.key).is_err());
        assert_eq!(holder(&network), None);
    }

    #[test]
    fn issuer_cannot_bind_without_the_owner_consent() {
        let network = network();
        let person = register(&network);
        let stranger = MlDsaSigningProvider::generate();
        assert!(bind_signed_by(&network, &person, None, &network.issuer, &stranger).is_err());
        assert_eq!(anchor_of(&network, &person), None);
    }

    #[test]
    fn a_did_keeps_a_single_document() {
        let network = network();
        let person = register(&network);
        bind(&network, &person, None).unwrap();
        let other_anchor = "a".repeat(ANCHOR_HEX_LEN);
        let message = bind_civil_anchor_message(&person.did, &other_anchor, None);
        let result = check_bind_civil_anchor(
            &network.store,
            &network.issuers,
            &BindCivilAnchorRequest {
                did: &person.did,
                anchor: &other_anchor,
                replaces: None,
                issuer_public_key: &public_key_of(&network.issuer),
                issuer_signature: &sign(&network.issuer, &message),
                owner_signature: &sign(&person.key, &message),
            },
        );
        assert!(matches!(result, Err(IdentityOpError::Conflict(_))));
    }

    #[test]
    fn rejects_anchors_that_are_not_a_keyed_digest() {
        let network = network();
        let person = register(&network);
        let too_long = "a".repeat(128);
        for malformed in ["", "12345678-9", &ANCHOR.to_uppercase(), &too_long] {
            let message = bind_civil_anchor_message(&person.did, malformed, None);
            let result = check_bind_civil_anchor(
                &network.store,
                &network.issuers,
                &BindCivilAnchorRequest {
                    did: &person.did,
                    anchor: malformed,
                    replaces: None,
                    issuer_public_key: &public_key_of(&network.issuer),
                    issuer_signature: &sign(&network.issuer, &message),
                    owner_signature: &sign(&person.key, &message),
                },
            );
            assert!(
                matches!(result, Err(IdentityOpError::Invalid(_))),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn revoked_identity_cannot_take_a_document() {
        let network = network();
        let person = register(&network);
        let record = network.store.read_identity(&person.did).unwrap();
        network
            .store
            .write_identity(&IdentityRecord {
                status: "revoked".to_string(),
                ..record
            })
            .unwrap();
        assert!(bind(&network, &person, None).is_err());
        assert_eq!(holder(&network), None);
    }
}
