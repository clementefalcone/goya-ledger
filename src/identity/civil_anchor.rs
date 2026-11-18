use crate::identity::operations::{is_signed_by, Change, IdentityOpError};
use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::{BlockStore, CivilAnchor, IdentityRecord};

const ANCHOR_HEX_LEN: usize = 64;

pub struct BindCivilAnchorRequest<'a> {
    pub did: &'a str,
    pub issuer_did: &'a str,
    pub anchor: &'a str,
    pub replaces: Option<&'a str>,
    pub issuer_signature: &'a str,
    pub owner_signature: &'a str,
}

pub fn bind_civil_anchor_message(
    issuer_did: &str,
    did: &str,
    anchor: &str,
    replaces: Option<&str>,
) -> String {
    let message = format!("identity:civil-anchor:{issuer_did}:{did}:{anchor}");
    match replaces {
        Some(previous_did) => format!("{message}:replaces:{previous_did}"),
        None => message,
    }
}

pub fn anchor_key(issuer_did: &str, anchor: &str) -> String {
    format!("{issuer_did}:{anchor}")
}

fn is_anchor_shaped(text: &str) -> bool {
    text.len() == ANCHOR_HEX_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn current_holder(
    store: &dyn BlockStore,
    request: &BindCivilAnchorRequest,
) -> Result<Option<String>, IdentityOpError> {
    let key = anchor_key(request.issuer_did, request.anchor);
    match store.resolve_by_civil_anchor(&key) {
        Ok(did) => Ok(Some(did)),
        Err(StorageError::KeyNotFound(_)) => Ok(None),
        Err(error) => Err(IdentityOpError::Conflict(format!(
            "civil anchor index could not be read for {key}: {error}"
        ))),
    }
}

fn read_active_signer(
    store: &dyn BlockStore,
    did: &str,
    message: &str,
    signature: &str,
) -> Result<IdentityRecord, IdentityOpError> {
    let record = store
        .read_identity(did)
        .map_err(|_| IdentityOpError::NotFound(format!("identity {did} is not registered")))?;
    if record.status != "active" {
        return Err(IdentityOpError::Conflict(format!(
            "identity {did} is {}; only active identities sign civil anchors",
            record.status
        )));
    }
    if !is_signed_by(&record.public_key, message, signature) {
        return Err(IdentityOpError::BadSignature(format!(
            "signature over {message:?} does not verify against the key of {did}"
        )));
    }
    Ok(record)
}

fn anchor_from<'a>(record: &'a IdentityRecord, issuer_did: &str) -> Option<&'a CivilAnchor> {
    record
        .civil_anchors
        .iter()
        .find(|held| held.issuer_did == issuer_did)
}

fn check_holder(
    request: &BindCivilAnchorRequest,
    holder: Option<&str>,
) -> Result<Change, IdentityOpError> {
    match (holder, request.replaces) {
        (Some(did), _) if did == request.did => Ok(Change::AlreadyApplied),
        (Some(did), Some(replaced)) if did == replaced => Ok(Change::Write),
        (Some(did), _) => Err(IdentityOpError::Conflict(format!(
            "civil anchor of {} already belongs to {did}; a rebind must name it in replaces",
            request.issuer_did
        ))),
        (None, None) => Ok(Change::Write),
        (None, Some(replaced)) => Err(IdentityOpError::Conflict(format!(
            "civil anchor is not bound to {replaced}, so there is nothing to replace"
        ))),
    }
}

pub fn check_bind_civil_anchor(
    store: &dyn BlockStore,
    request: &BindCivilAnchorRequest,
) -> Result<Change, IdentityOpError> {
    if !is_anchor_shaped(request.anchor) {
        return Err(IdentityOpError::Invalid(format!(
            "civil anchor {:?} must be {ANCHOR_HEX_LEN} lowercase hex characters",
            request.anchor
        )));
    }
    let message = bind_civil_anchor_message(
        request.issuer_did,
        request.did,
        request.anchor,
        request.replaces,
    );
    read_active_signer(
        store,
        request.issuer_did,
        &message,
        request.issuer_signature,
    )?;
    let record = read_active_signer(store, request.did, &message, request.owner_signature)?;
    if let Some(held) = anchor_from(&record, request.issuer_did) {
        if held.anchor != request.anchor {
            return Err(IdentityOpError::Conflict(format!(
                "identity {} already holds another document anchored by {}",
                request.did, request.issuer_did
            )));
        }
    }
    check_holder(request, current_holder(store, request)?.as_deref())
}

pub fn apply_bind_civil_anchor(
    store: &dyn BlockStore,
    request: &BindCivilAnchorRequest,
    bound_at: u64,
) -> StorageResult<()> {
    if check_bind_civil_anchor(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    if let Some(previous_did) = request.replaces {
        let previous = store.read_identity(previous_did)?;
        store.write_identity(&IdentityRecord {
            civil_anchors: previous
                .civil_anchors
                .iter()
                .filter(|held| held.issuer_did != request.issuer_did)
                .cloned()
                .collect(),
            updated_at: bound_at,
            ..previous
        })?;
    }
    store.write_civil_anchor(&anchor_key(request.issuer_did, request.anchor), request.did)?;
    let record = store.read_identity(request.did)?;
    let civil_anchors = record
        .civil_anchors
        .iter()
        .cloned()
        .chain(std::iter::once(CivilAnchor {
            issuer_did: request.issuer_did.to_string(),
            anchor: request.anchor.to_string(),
        }))
        .collect();
    store.write_identity(&IdentityRecord {
        civil_anchors,
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
        issuer: Person,
    }

    fn sign(key: &MlDsaSigningProvider, message: &str) -> String {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    }

    fn unregistered() -> Person {
        let key = MlDsaSigningProvider::generate();
        let did = did_from_pubkey_hex(&hex::encode(key.public_key()));
        Person { key, did }
    }

    fn register_in(store: &MemoryStore) -> Person {
        let person = unregistered();
        store
            .write_identity(&IdentityRecord {
                did: person.did.clone(),
                public_key: hex::encode(person.key.public_key()),
                created_at: 1,
                updated_at: 1,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: Some("MlDsa65".to_string()),
                civil_anchors: Vec::new(),
                recovery_commitment: None,
                vault_entries: Vec::new(),
            })
            .unwrap();
        person
    }

    fn network() -> Network {
        let store = MemoryStore::new();
        let issuer = register_in(&store);
        Network { store, issuer }
    }

    fn register(network: &Network) -> Person {
        register_in(&network.store)
    }

    struct Bind<'a> {
        person: &'a Person,
        anchor: &'a str,
        replaces: Option<&'a str>,
        issuer: &'a Person,
        owner: &'a MlDsaSigningProvider,
    }

    fn with_request<T>(bind: &Bind, run: impl FnOnce(&BindCivilAnchorRequest) -> T) -> T {
        let message = bind_civil_anchor_message(
            &bind.issuer.did,
            &bind.person.did,
            bind.anchor,
            bind.replaces,
        );
        run(&BindCivilAnchorRequest {
            did: &bind.person.did,
            issuer_did: &bind.issuer.did,
            anchor: bind.anchor,
            replaces: bind.replaces,
            issuer_signature: &sign(&bind.issuer.key, &message),
            owner_signature: &sign(bind.owner, &message),
        })
    }

    fn check(network: &Network, bind: &Bind) -> Result<Change, IdentityOpError> {
        with_request(bind, |request| {
            check_bind_civil_anchor(&network.store, request)
        })
    }

    fn apply(network: &Network, bind: &Bind) -> StorageResult<()> {
        with_request(bind, |request| {
            apply_bind_civil_anchor(&network.store, request, 70)
        })
    }

    fn bind(network: &Network, person: &Person, replaces: Option<&str>) -> StorageResult<()> {
        apply(
            network,
            &Bind {
                person,
                anchor: ANCHOR,
                replaces,
                issuer: &network.issuer,
                owner: &person.key,
            },
        )
    }

    fn anchors_of(network: &Network, person: &Person) -> Vec<CivilAnchor> {
        network
            .store
            .read_identity(&person.did)
            .unwrap()
            .civil_anchors
    }

    fn holder_under(network: &Network, issuer: &Person) -> Option<String> {
        network
            .store
            .resolve_by_civil_anchor(&anchor_key(&issuer.did, ANCHOR))
            .ok()
    }

    fn holder(network: &Network) -> Option<String> {
        holder_under(network, &network.issuer)
    }

    #[test]
    fn issuer_and_owner_bind_a_document_to_a_did() {
        let network = network();
        let person = register(&network);
        bind(&network, &person, None).unwrap();
        assert_eq!(
            anchors_of(&network, &person),
            vec![CivilAnchor {
                issuer_did: network.issuer.did.clone(),
                anchor: ANCHOR.to_string(),
            }]
        );
        assert_eq!(holder(&network), Some(person.did.clone()));
    }

    #[test]
    fn replaying_the_same_bind_is_idempotent() {
        let network = network();
        let person = register(&network);
        bind(&network, &person, None).unwrap();
        bind(&network, &person, None).unwrap();
        assert_eq!(anchors_of(&network, &person).len(), 1);
        assert_eq!(holder(&network), Some(person.did));
    }

    #[test]
    fn a_second_did_cannot_take_a_document_from_the_same_issuer() {
        let network = network();
        let first = register(&network);
        let second = register(&network);
        bind(&network, &first, None).unwrap();
        assert!(bind(&network, &second, None).is_err());
        assert_eq!(holder(&network), Some(first.did));
        assert!(anchors_of(&network, &second).is_empty());
    }

    #[test]
    fn another_issuer_cannot_take_over_an_anchor_it_did_not_issue() {
        let network = network();
        let owner = register(&network);
        let squatter = register(&network);
        let rogue_issuer = register(&network);
        bind(&network, &owner, None).unwrap();
        apply(
            &network,
            &Bind {
                person: &squatter,
                anchor: ANCHOR,
                replaces: None,
                issuer: &rogue_issuer,
                owner: &squatter.key,
            },
        )
        .unwrap();
        assert_eq!(holder(&network), Some(owner.did.clone()));
        assert_eq!(holder_under(&network, &rogue_issuer), Some(squatter.did));
    }

    #[test]
    fn a_did_holds_one_document_per_issuer() {
        let network = network();
        let person = register(&network);
        let notary = register(&network);
        bind(&network, &person, None).unwrap();
        apply(
            &network,
            &Bind {
                person: &person,
                anchor: ANCHOR,
                replaces: None,
                issuer: &notary,
                owner: &person.key,
            },
        )
        .unwrap();
        assert_eq!(anchors_of(&network, &person).len(), 2);
        let other_anchor = "a".repeat(ANCHOR_HEX_LEN);
        let result = check(
            &network,
            &Bind {
                person: &person,
                anchor: &other_anchor,
                replaces: None,
                issuer: &network.issuer,
                owner: &person.key,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::Conflict(_))));
    }

    #[test]
    fn rebind_moves_the_document_and_unanchors_the_lost_did() {
        let network = network();
        let lost = register(&network);
        let fresh = register(&network);
        bind(&network, &lost, None).unwrap();
        bind(&network, &fresh, Some(&lost.did)).unwrap();
        assert_eq!(holder(&network), Some(fresh.did.clone()));
        assert_eq!(anchors_of(&network, &fresh).len(), 1);
        assert!(anchors_of(&network, &lost).is_empty());
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
    fn unregistered_issuer_cannot_bind() {
        let network = network();
        let person = register(&network);
        let impostor = unregistered();
        let result = check(
            &network,
            &Bind {
                person: &person,
                anchor: ANCHOR,
                replaces: None,
                issuer: &impostor,
                owner: &person.key,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::NotFound(_))));
    }

    #[test]
    fn issuer_cannot_bind_without_the_owner_consent() {
        let network = network();
        let person = register(&network);
        let stranger = MlDsaSigningProvider::generate();
        let result = check(
            &network,
            &Bind {
                person: &person,
                anchor: ANCHOR,
                replaces: None,
                issuer: &network.issuer,
                owner: &stranger,
            },
        );
        assert!(matches!(result, Err(IdentityOpError::BadSignature(_))));
    }

    #[test]
    fn owner_consent_names_the_issuer() {
        let network = network();
        let person = register(&network);
        let other_issuer = register(&network);
        let consented_to_other =
            bind_civil_anchor_message(&other_issuer.did, &person.did, ANCHOR, None);
        let message = bind_civil_anchor_message(&network.issuer.did, &person.did, ANCHOR, None);
        let result = check_bind_civil_anchor(
            &network.store,
            &BindCivilAnchorRequest {
                did: &person.did,
                issuer_did: &network.issuer.did,
                anchor: ANCHOR,
                replaces: None,
                issuer_signature: &sign(&network.issuer.key, &message),
                owner_signature: &sign(&person.key, &consented_to_other),
            },
        );
        assert!(matches!(result, Err(IdentityOpError::BadSignature(_))));
    }

    #[test]
    fn rejects_anchors_that_are_not_a_keyed_digest() {
        let network = network();
        let person = register(&network);
        let too_long = "a".repeat(128);
        for malformed in ["", "12345678-9", &ANCHOR.to_uppercase(), &too_long] {
            let result = check(
                &network,
                &Bind {
                    person: &person,
                    anchor: malformed,
                    replaces: None,
                    issuer: &network.issuer,
                    owner: &person.key,
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
