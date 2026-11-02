use crate::identity::credential_ops::require_issuer_signature;
use crate::identity::operations::{Change, IdentityOpError};
use crate::identity::signing::{EcdsaP256SigningProvider, SigningProvider};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, IssuerCredentialKey, P256PublicJwk};

pub fn credential_key_message(did: &str, jwk: &P256PublicJwk, registered_at: u64) -> String {
    format!(
        "oid4vci:issuer-key:{did}:{}:{}:{registered_at}",
        jwk.x, jwk.y
    )
}

pub fn issuer_path(did: &str) -> String {
    format!("/api/v1/issuers/{did}")
}

pub fn https_url_path(url: &str) -> Option<&str> {
    let authority_and_path = url.strip_prefix("https://")?;
    let path_start = authority_and_path.find('/').filter(|&start| start > 0)?;
    Some(&authority_and_path[path_start..])
}

pub fn sec1_public_key_hex(jwk: &P256PublicJwk) -> Option<String> {
    let decode = |coordinate: &str| {
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            coordinate,
        )
        .ok()
    };
    Some(format!(
        "04{}{}",
        hex::encode(decode(&jwk.x)?),
        hex::encode(decode(&jwk.y)?)
    ))
}

pub fn p256_public_jwk(credential_key: &EcdsaP256SigningProvider) -> P256PublicJwk {
    let sec1 = credential_key.public_key();
    let encode = |coordinate: &[u8]| {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            coordinate,
        )
    };
    P256PublicJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: encode(&sec1[1..33]),
        y: encode(&sec1[33..65]),
    }
}

fn is_p256_coordinate(coordinate: &str) -> bool {
    base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        coordinate,
    )
    .is_ok_and(|bytes| bytes.len() == 32)
}

fn require_p256_public_jwk(jwk: &P256PublicJwk) -> Result<(), IdentityOpError> {
    let is_p256 = jwk.kty == "EC"
        && jwk.crv == "P-256"
        && is_p256_coordinate(&jwk.x)
        && is_p256_coordinate(&jwk.y);
    if !is_p256 {
        return Err(IdentityOpError::Invalid(format!(
            "jwk must be kty EC, crv P-256 with 32-byte base64url x and y, got kty {} crv {}",
            jwk.kty, jwk.crv
        )));
    }
    Ok(())
}

pub fn check_register_credential_key(
    store: &dyn BlockStore,
    registration: &IssuerCredentialKey,
) -> Result<Change, IdentityOpError> {
    require_p256_public_jwk(&registration.jwk)?;
    require_issuer_signature(
        store,
        &registration.did,
        &registration.public_key,
        &credential_key_message(
            &registration.did,
            &registration.jwk,
            registration.registered_at,
        ),
        &registration.signature,
    )?;
    match store.read_issuer_credential_key(&registration.did) {
        Ok(current) if current.jwk == registration.jwk => Ok(Change::AlreadyApplied),
        Ok(current) if registration.registered_at <= current.registered_at => {
            Err(IdentityOpError::Conflict(format!(
                "{} already registered a credential key at {}; a new key needs a later registered_at",
                registration.did, current.registered_at
            )))
        }
        _ => Ok(Change::Write),
    }
}

pub fn apply_register_credential_key(
    store: &dyn BlockStore,
    registration: &IssuerCredentialKey,
) -> StorageResult<()> {
    if check_register_credential_key(store, registration)? == Change::AlreadyApplied {
        return Ok(());
    }
    store.write_issuer_credential_key(registration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did::did_from_pubkey_hex;
    use crate::identity::signing::MlDsaSigningProvider;
    use crate::storage::MemoryStore;

    fn p256_jwk() -> P256PublicJwk {
        p256_public_jwk(&EcdsaP256SigningProvider::generate())
    }

    fn registration(
        issuer: &MlDsaSigningProvider,
        jwk: P256PublicJwk,
        registered_at: u64,
    ) -> IssuerCredentialKey {
        let public_key = hex::encode(issuer.public_key());
        let did = did_from_pubkey_hex(&public_key);
        let message = credential_key_message(&did, &jwk, registered_at);
        IssuerCredentialKey {
            did,
            jwk,
            registered_at,
            public_key,
            signature: hex::encode(issuer.sign(message.as_bytes()).unwrap()),
        }
    }

    #[test]
    fn stores_a_key_signed_by_the_did_key() {
        let store = MemoryStore::new();
        let signed = registration(&MlDsaSigningProvider::generate(), p256_jwk(), 100);
        apply_register_credential_key(&store, &signed).unwrap();
        assert_eq!(
            store.read_issuer_credential_key(&signed.did).unwrap(),
            signed
        );
    }

    #[test]
    fn refuses_a_key_signed_by_another_did_key() {
        let store = MemoryStore::new();
        let mut forged = registration(&MlDsaSigningProvider::generate(), p256_jwk(), 100);
        forged.did = registration(&MlDsaSigningProvider::generate(), p256_jwk(), 100).did;
        assert!(matches!(
            check_register_credential_key(&store, &forged),
            Err(IdentityOpError::BadSignature(_))
        ));
    }

    #[test]
    fn refuses_a_jwk_that_is_not_p256() {
        let store = MemoryStore::new();
        let mut jwk = p256_jwk();
        jwk.crv = "P-384".to_string();
        let signed = registration(&MlDsaSigningProvider::generate(), jwk, 100);
        assert!(matches!(
            check_register_credential_key(&store, &signed),
            Err(IdentityOpError::Invalid(_))
        ));
    }

    #[test]
    fn same_key_is_a_no_op_and_rotation_needs_a_later_registered_at() {
        let store = MemoryStore::new();
        let issuer = MlDsaSigningProvider::generate();
        let first = registration(&issuer, p256_jwk(), 100);
        apply_register_credential_key(&store, &first).unwrap();
        let replay = registration(&issuer, first.jwk.clone(), 200);
        assert_eq!(
            check_register_credential_key(&store, &replay),
            Ok(Change::AlreadyApplied)
        );
        let backdated = registration(&issuer, p256_jwk(), 100);
        assert!(matches!(
            check_register_credential_key(&store, &backdated),
            Err(IdentityOpError::Conflict(_))
        ));
        let rotated = registration(&issuer, p256_jwk(), 300);
        apply_register_credential_key(&store, &rotated).unwrap();
        assert_eq!(
            store.read_issuer_credential_key(&rotated.did).unwrap().jwk,
            rotated.jwk
        );
    }
}
