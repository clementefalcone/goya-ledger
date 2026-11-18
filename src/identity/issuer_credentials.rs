use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::credential_ops::issue_message;
use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
use crate::identity::signing::{EcdsaP256SigningProvider, SigningProvider};
use crate::storage::traits::Credential;

pub const CREDENTIAL_VALIDITY_SECS: u64 = 365 * 24 * 3600;
const ANCHOR_ID_PREFIX: &str = "sd-jwt:";
const THUMBPRINT_MEMBERS: [&str; 6] = ["crv", "e", "kty", "n", "x", "y"];

pub struct StatusListEntry {
    pub list_id: String,
    pub index: usize,
}

pub struct CredentialDraft {
    pub issuer_url: String,
    pub vct: String,
    pub holder_jwk: serde_json::Value,
    pub claims: Vec<(String, serde_json::Value)>,
    pub status: Option<StatusListEntry>,
}

pub struct IssuedCredential {
    pub compact: String,
    pub vct: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub fn jwk_thumbprint(jwk: &serde_json::Value) -> String {
    let required_members: serde_json::Map<String, serde_json::Value> = THUMBPRINT_MEMBERS
        .iter()
        .filter_map(|member| Some((member.to_string(), jwk.get(*member)?.clone())))
        .collect();
    let canonical = serde_json::to_vec(&required_members).unwrap_or_default();
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        hash_with(HashAlgorithm::Sha256, &canonical),
    )
}

pub fn issue_holder_credential(
    credential_key: &EcdsaP256SigningProvider,
    draft: &CredentialDraft,
    issued_at: u64,
) -> Result<IssuedCredential, String> {
    let expires_at = issued_at + CREDENTIAL_VALIDITY_SECS;
    let status = draft.status.as_ref().map(|entry| {
        serde_json::json!({
            "status_list": {
                "idx": entry.index,
                "uri": format!("{}/status-lists/{}", draft.issuer_url, entry.list_id),
            }
        })
    });
    let claims = VcClaims {
        iss: draft.issuer_url.clone(),
        sub: jwk_thumbprint(&draft.holder_jwk),
        iat: issued_at,
        exp: expires_at,
        vct: draft.vct.clone(),
        claims: draft.claims.clone(),
        cnf: Some(serde_json::json!({ "jwk": draft.holder_jwk })),
        status,
    };
    Ok(IssuedCredential {
        compact: issue_sd_jwt_vc(&claims, credential_key)?.compact,
        vct: draft.vct.clone(),
        issued_at,
        expires_at,
    })
}

pub fn issuer_jwt_commitment(sd_jwt_vc: &str) -> String {
    let issuer_jwt = sd_jwt_vc.split('~').next().unwrap_or_default();
    hex::encode(hash_with(HashAlgorithm::Sha256, issuer_jwt.as_bytes()))
}

pub fn anchor_id(sd_jwt_vc: &str) -> String {
    format!("{ANCHOR_ID_PREFIX}{}", issuer_jwt_commitment(sd_jwt_vc))
}

pub fn sign_anchor(
    did_key: &dyn SigningProvider,
    issuer_did: &str,
    issued: &IssuedCredential,
) -> Result<Credential, String> {
    let id = anchor_id(&issued.compact);
    let unsigned = Credential {
        id: id.clone(),
        issuer_did: issuer_did.to_string(),
        subject_did: id,
        cred_type: issued.vct.clone(),
        issued_at: issued.issued_at,
        expires_at: issued.expires_at,
        revoked_at: None,
        claims: serde_json::Value::Null,
        signature: String::new(),
        status: "active".to_string(),
        claims_commitment: Some(issuer_jwt_commitment(&issued.compact)),
        claims_salt: None,
    };
    let signature = did_key
        .sign(issue_message(&unsigned).as_bytes())
        .map_err(|e| format!("DID key of {issuer_did} could not sign the anchor: {e}"))?;
    Ok(Credential {
        signature: hex::encode(signature),
        ..unsigned
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did::did_from_pubkey_hex;
    use crate::identity::operations::is_signed_by;
    use crate::identity::sd_jwt::verify_sd_jwt_vc;
    use crate::identity::signing::MlDsaSigningProvider;

    fn draft(holder_jwk: serde_json::Value) -> CredentialDraft {
        CredentialDraft {
            issuer_url: "https://node.example/api/v1/issuers/did:goya:a".to_string(),
            vct: "urn:eudi:pid:1".to_string(),
            holder_jwk,
            claims: vec![
                ("given_name".to_string(), serde_json::json!("Ada")),
                ("family_name".to_string(), serde_json::json!("Lovelace")),
            ],
            status: Some(StatusListEntry {
                list_id: "main".to_string(),
                index: 7,
            }),
        }
    }

    #[test]
    fn jwk_thumbprint_matches_rfc_7638_example() {
        let rsa_jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        });
        assert_eq!(
            jwk_thumbprint(&rsa_jwk),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn holder_credential_verifies_and_carries_binding_status_and_disclosures() {
        let credential_key = EcdsaP256SigningProvider::generate();
        let holder_jwk = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "AQ" });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let issued =
            issue_holder_credential(&credential_key, &draft(holder_jwk.clone()), now).unwrap();
        let verified =
            verify_sd_jwt_vc(&issued.compact, &hex::encode(credential_key.public_key())).unwrap();
        assert_eq!(verified.vct, "urn:eudi:pid:1");
        assert_eq!(verified.exp, now + CREDENTIAL_VALIDITY_SECS);
        assert_eq!(verified.cnf.unwrap()["jwk"], holder_jwk);
        assert_eq!(
            verified.status.unwrap(),
            serde_json::json!({ "status_list": { "idx": 7, "uri": "https://node.example/api/v1/issuers/did:goya:a/status-lists/main" } })
        );
        assert_eq!(verified.disclosed_claims.len(), 2);
    }

    #[test]
    fn anchor_commits_to_the_issuer_jwt_and_is_signed_by_the_did_key() {
        let did_key = MlDsaSigningProvider::generate();
        let public_key = hex::encode(did_key.public_key());
        let did = did_from_pubkey_hex(&public_key);
        let issued = IssuedCredential {
            compact: "header.payload.signature~disclosure~".to_string(),
            vct: "urn:eudi:pid:1".to_string(),
            issued_at: 10,
            expires_at: 20,
        };
        let anchor = sign_anchor(&did_key, &did, &issued).unwrap();
        let commitment = hex::encode(hash_with(
            HashAlgorithm::Sha256,
            b"header.payload.signature",
        ));
        assert_eq!(anchor.id, format!("sd-jwt:{commitment}"));
        assert_eq!(anchor.id, anchor_id("header.payload.signature~other~"));
        assert_eq!(
            anchor.claims_commitment.as_deref(),
            Some(commitment.as_str())
        );
        assert!(is_signed_by(
            &public_key,
            &issue_message(&anchor),
            &anchor.signature
        ));
    }
}
