use crate::identity::operations::{is_signed_by, key_controls_identity, Change, IdentityOpError};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, Credential};

pub fn issue_message(credential: &Credential) -> String {
    let Credential {
        id,
        issuer_did,
        subject_did,
        cred_type,
        issued_at,
        expires_at,
        ..
    } = credential;
    let commitment = credential.claims_commitment.as_deref().unwrap_or_default();
    format!(
        "credential:issue:{id}:{issuer_did}:{subject_did}:{cred_type}:{issued_at}:{expires_at}:{commitment}"
    )
}

pub fn revoke_message(id: &str, revoked_at: u64) -> String {
    format!("credential:revoke:{id}:{revoked_at}")
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn require_issuer_signature(
    store: &dyn BlockStore,
    issuer_did: &str,
    issuer_public_key: &str,
    message: &str,
    signature: &str,
) -> Result<(), IdentityOpError> {
    if !key_controls_identity(store, issuer_did, issuer_public_key) {
        return Err(IdentityOpError::BadSignature(format!(
            "issuer_public_key does not control {issuer_did}"
        )));
    }
    if !is_signed_by(issuer_public_key, message, signature) {
        return Err(IdentityOpError::BadSignature(format!(
            "signature by {issuer_did} does not verify over {message}"
        )));
    }
    Ok(())
}

fn require_commitment_only(credential: &Credential) -> Result<(), IdentityOpError> {
    let has_claims = !(credential.claims.is_null()
        || credential.claims.as_object().is_some_and(|c| c.is_empty()));
    if has_claims || credential.claims_salt.is_some() {
        return Err(IdentityOpError::Invalid(format!(
            "credential {}: claims and claims_salt stay with the issuer; send only claims_commitment",
            credential.id
        )));
    }
    if !credential
        .claims_commitment
        .as_deref()
        .is_some_and(is_hex_digest)
    {
        return Err(IdentityOpError::Invalid(format!(
            "credential {}: claims_commitment must be 64 hex characters",
            credential.id
        )));
    }
    if credential.status != "active" || credential.revoked_at.is_some() {
        return Err(IdentityOpError::Invalid(format!(
            "credential {}: a new credential must be active and not revoked",
            credential.id
        )));
    }
    Ok(())
}

pub fn check_issue(
    store: &dyn BlockStore,
    credential: &Credential,
    issuer_public_key: &str,
) -> Result<Change, IdentityOpError> {
    require_commitment_only(credential)?;
    require_issuer_signature(
        store,
        &credential.issuer_did,
        issuer_public_key,
        &issue_message(credential),
        &credential.signature,
    )?;
    match store.read_credential(&credential.id) {
        Ok(existing) if existing == *credential => Ok(Change::AlreadyApplied),
        Ok(_) => Err(IdentityOpError::Conflict(format!(
            "credential {} already exists",
            credential.id
        ))),
        Err(_) => Ok(Change::Write),
    }
}

pub struct RevokeRequest<'a> {
    pub id: &'a str,
    pub revoked_at: u64,
    pub issuer_public_key: &'a str,
    pub signature: &'a str,
}

pub fn check_revoke(
    store: &dyn BlockStore,
    request: &RevokeRequest,
) -> Result<Change, IdentityOpError> {
    let credential = store
        .read_credential(request.id)
        .map_err(|_| IdentityOpError::NotFound(format!("credential {}", request.id)))?;
    require_issuer_signature(
        store,
        &credential.issuer_did,
        request.issuer_public_key,
        &revoke_message(request.id, request.revoked_at),
        request.signature,
    )?;
    match credential.revoked_at {
        None => Ok(Change::Write),
        Some(at) if at == request.revoked_at => Ok(Change::AlreadyApplied),
        Some(at) => Err(IdentityOpError::Conflict(format!(
            "credential {} was already revoked at {at}",
            request.id
        ))),
    }
}

pub fn apply_issue(
    store: &dyn BlockStore,
    credential: &Credential,
    issuer_public_key: &str,
) -> StorageResult<()> {
    if check_issue(store, credential, issuer_public_key)? == Change::AlreadyApplied {
        return Ok(());
    }
    store.write_credential(credential)
}

pub fn apply_revoke(store: &dyn BlockStore, request: &RevokeRequest) -> StorageResult<()> {
    if check_revoke(store, request)? == Change::AlreadyApplied {
        return Ok(());
    }
    let credential = store.read_credential(request.id)?;
    store.write_credential(&Credential {
        revoked_at: Some(request.revoked_at),
        status: "revoked".to_string(),
        ..credential
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did::did_from_pubkey_hex;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
    use crate::storage::MemoryStore;

    struct Issuer {
        key: SoftwareSigningProvider,
        public_key: String,
        did: String,
    }

    fn issuer() -> Issuer {
        let key = SoftwareSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = did_from_pubkey_hex(&public_key);
        Issuer {
            key,
            public_key,
            did,
        }
    }

    fn sign(issuer: &Issuer, message: &str) -> String {
        hex::encode(issuer.key.sign(message.as_bytes()).unwrap())
    }

    fn signed_credential(issuer: &Issuer) -> Credential {
        let mut credential = Credential {
            id: "cred-1".to_string(),
            issuer_did: issuer.did.clone(),
            subject_did: "did:goya:subject".to_string(),
            cred_type: "consent".to_string(),
            issued_at: 100,
            expires_at: 0,
            revoked_at: None,
            claims: serde_json::Value::Null,
            signature: String::new(),
            status: "active".to_string(),
            claims_commitment: Some("ab".repeat(32)),
            claims_salt: None,
        };
        credential.signature = sign(issuer, &issue_message(&credential));
        credential
    }

    fn revocation<'a>(issuer: &'a Issuer, signature: &'a str) -> RevokeRequest<'a> {
        RevokeRequest {
            id: "cred-1",
            revoked_at: 200,
            issuer_public_key: &issuer.public_key,
            signature,
        }
    }

    #[test]
    fn stores_a_credential_signed_by_its_issuer() {
        let (store, issuer) = (MemoryStore::new(), issuer());
        let credential = signed_credential(&issuer);
        apply_issue(&store, &credential, &issuer.public_key).unwrap();
        assert_eq!(store.read_credential("cred-1").unwrap(), credential);
    }

    #[test]
    fn rejects_a_credential_signed_by_someone_else() {
        let (store, issuer, impostor) = (MemoryStore::new(), issuer(), issuer());
        let mut credential = signed_credential(&issuer);
        credential.signature = sign(&impostor, &issue_message(&credential));
        assert!(apply_issue(&store, &credential, &impostor.public_key).is_err());
        assert!(store.read_credential("cred-1").is_err());
    }

    #[test]
    fn rejects_a_credential_carrying_personal_claims() {
        let (store, issuer) = (MemoryStore::new(), issuer());
        let mut credential = signed_credential(&issuer);
        credential.claims = serde_json::json!({ "rut": "11111111-1" });
        assert!(matches!(
            check_issue(&store, &credential, &issuer.public_key),
            Err(IdentityOpError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_a_different_credential_reusing_an_id() {
        let (store, issuer) = (MemoryStore::new(), issuer());
        apply_issue(&store, &signed_credential(&issuer), &issuer.public_key).unwrap();
        let mut other = signed_credential(&issuer);
        other.subject_did = "did:goya:other".to_string();
        other.signature = sign(&issuer, &issue_message(&other));
        assert!(matches!(
            check_issue(&store, &other, &issuer.public_key),
            Err(IdentityOpError::Conflict(_))
        ));
    }

    #[test]
    fn only_the_issuer_can_revoke() {
        let (store, issuer, stranger) = (MemoryStore::new(), issuer(), issuer());
        apply_issue(&store, &signed_credential(&issuer), &issuer.public_key).unwrap();
        let forged = sign(&stranger, &revoke_message("cred-1", 200));
        assert!(apply_revoke(&store, &revocation(&stranger, &forged)).is_err());
        assert_eq!(store.read_credential("cred-1").unwrap().status, "active");

        let signature = sign(&issuer, &revoke_message("cred-1", 200));
        apply_revoke(&store, &revocation(&issuer, &signature)).unwrap();
        apply_revoke(&store, &revocation(&issuer, &signature)).unwrap();
        let revoked = store.read_credential("cred-1").unwrap();
        assert_eq!(
            (revoked.status.as_str(), revoked.revoked_at),
            ("revoked", Some(200))
        );
    }
}
