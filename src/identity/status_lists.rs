use crate::identity::issuer_keys::{https_url_path, issuer_path, sec1_public_key_hex};
use crate::identity::operations::{Change, IdentityOpError};
use crate::identity::signing::SigningAlgorithm;
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, IssuerStatusList};

pub const STATUS_LIST_MAX_BYTES: usize = 64 * 1024;
const STATUS_LIST_ID_MAX_CHARS: usize = 64;
const STATUS_LIST_BITS: [u64; 4] = [1, 2, 4, 8];

pub fn status_list_path(did: &str, list_id: &str) -> String {
    format!("{}/status-lists/{list_id}", issuer_path(did))
}

pub fn is_status_list_id(list_id: &str) -> bool {
    (1..=STATUS_LIST_ID_MAX_CHARS).contains(&list_id.len())
        && list_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub fn is_own_status_list_uri(uri: &str, did: &str) -> bool {
    https_url_path(uri)
        .and_then(|path| path.strip_prefix(&format!("{}/status-lists/", issuer_path(did))))
        .is_some_and(is_status_list_id)
}

fn invalid(reason: String) -> IdentityOpError {
    IdentityOpError::Invalid(reason)
}

fn decode_base64url(segment: &str) -> Option<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, segment).ok()
}

fn decode_json_segment(segment: &str, name: &str) -> Result<serde_json::Value, IdentityOpError> {
    decode_base64url(segment)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| invalid(format!("status list JWT {name} is not base64url JSON")))
}

struct CompactJwt<'a> {
    header: serde_json::Value,
    payload: serde_json::Value,
    signing_input: &'a str,
    signature: &'a str,
}

fn split_compact_jwt(jwt: &str) -> Result<CompactJwt<'_>, IdentityOpError> {
    let (signing_input, signature) = jwt
        .rsplit_once('.')
        .ok_or_else(|| invalid("status list JWT is not header.payload.signature".to_string()))?;
    let (header, payload) = signing_input
        .split_once('.')
        .filter(|(_, payload)| !payload.contains('.'))
        .ok_or_else(|| invalid("status list JWT is not header.payload.signature".to_string()))?;
    Ok(CompactJwt {
        header: decode_json_segment(header, "header")?,
        payload: decode_json_segment(payload, "payload")?,
        signing_input,
        signature,
    })
}

fn require_header(header: &serde_json::Value) -> Result<(), IdentityOpError> {
    let (typ, alg) = (header["typ"].as_str(), header["alg"].as_str());
    if typ != Some("statuslist+jwt") || alg != Some("ES256") {
        return Err(invalid(format!(
            "status list JWT header must have typ statuslist+jwt and alg ES256, got typ {typ:?} alg {alg:?}"
        )));
    }
    Ok(())
}

fn require_issuer_key_signature(
    store: &dyn BlockStore,
    did: &str,
    jwt: &CompactJwt<'_>,
) -> Result<(), IdentityOpError> {
    let registration = store
        .read_issuer_credential_key(did)
        .map_err(|_| IdentityOpError::NotFound(format!("credential key of issuer {did}")))?;
    let credential_key_hex = sec1_public_key_hex(&registration.jwk).ok_or_else(|| {
        invalid(format!(
            "registered credential key of {did} is not a P-256 JWK"
        ))
    })?;
    let is_signed = decode_base64url(jwt.signature).is_some_and(|signature| {
        crate::signature::verify_signature(
            SigningAlgorithm::EcdsaP256,
            &credential_key_hex,
            jwt.signing_input.as_bytes(),
            &hex::encode(signature),
        )
    });
    if !is_signed {
        return Err(IdentityOpError::BadSignature(format!(
            "status list JWT is not signed with ES256 by the registered credential key of {did}"
        )));
    }
    Ok(())
}

fn require_url_path(
    payload: &serde_json::Value,
    claim: &str,
    expected_path: &str,
) -> Result<(), IdentityOpError> {
    let value = payload[claim].as_str().unwrap_or_default();
    if https_url_path(value) != Some(expected_path) {
        return Err(invalid(format!(
            "status list JWT {claim} {value:?} is not https://{{host}}{expected_path}"
        )));
    }
    Ok(())
}

fn require_status_list_claim(payload: &serde_json::Value) -> Result<(), IdentityOpError> {
    let bits = payload["status_list"]["bits"].as_u64();
    if !bits.is_some_and(|bits| STATUS_LIST_BITS.contains(&bits)) {
        return Err(invalid(format!(
            "status_list.bits must be one of {STATUS_LIST_BITS:?}, got {bits:?}"
        )));
    }
    let is_encoded_list = payload["status_list"]["lst"]
        .as_str()
        .and_then(decode_base64url)
        .is_some_and(|bytes| !bytes.is_empty());
    if !is_encoded_list {
        return Err(invalid(
            "status_list.lst must be a non-empty base64url string".to_string(),
        ));
    }
    Ok(())
}

fn issued_at(payload: &serde_json::Value) -> Result<u64, IdentityOpError> {
    payload["iat"]
        .as_u64()
        .ok_or_else(|| invalid("status list JWT iat must be a unix time".to_string()))
}

fn stored_issued_at(stored: &IssuerStatusList) -> Result<u64, IdentityOpError> {
    issued_at(&split_compact_jwt(&stored.jwt)?.payload)
}

pub fn check_publish_status_list(
    store: &dyn BlockStore,
    status_list: &IssuerStatusList,
) -> Result<Change, IdentityOpError> {
    let IssuerStatusList { did, list_id, jwt } = status_list;
    if !is_status_list_id(list_id) {
        return Err(invalid(format!(
            "list_id {list_id:?} must be 1-{STATUS_LIST_ID_MAX_CHARS} characters of A-Z a-z 0-9 _ -"
        )));
    }
    if jwt.len() > STATUS_LIST_MAX_BYTES {
        return Err(invalid(format!(
            "status list JWT is {} bytes, limit {STATUS_LIST_MAX_BYTES}",
            jwt.len()
        )));
    }
    let token = split_compact_jwt(jwt)?;
    require_header(&token.header)?;
    require_issuer_key_signature(store, did, &token)?;
    require_url_path(&token.payload, "iss", &issuer_path(did))?;
    require_url_path(&token.payload, "sub", &status_list_path(did, list_id))?;
    let iat = issued_at(&token.payload)?;
    require_status_list_claim(&token.payload)?;
    let Ok(current) = store.read_issuer_status_list(did, list_id) else {
        return Ok(Change::Write);
    };
    if current.jwt == *jwt {
        return Ok(Change::AlreadyApplied);
    }
    let current_iat = stored_issued_at(&current)?;
    if iat <= current_iat {
        return Err(IdentityOpError::Conflict(format!(
            "status list {list_id} of {did} already has iat {current_iat}; a new list needs a later iat"
        )));
    }
    Ok(Change::Write)
}

pub fn apply_publish_status_list(
    store: &dyn BlockStore,
    status_list: &IssuerStatusList,
) -> StorageResult<()> {
    if check_publish_status_list(store, status_list)? == Change::AlreadyApplied {
        return Ok(());
    }
    store.write_issuer_status_list(status_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_list_id_allows_only_url_safe_characters_up_to_64() {
        assert!(is_status_list_id("revocations_2026-01"));
        assert!(is_status_list_id(&"a".repeat(64)));
        assert!(!is_status_list_id(""));
        assert!(!is_status_list_id(&"a".repeat(65)));
        assert!(!is_status_list_id("a/b"));
        assert!(!is_status_list_id("a.b"));
    }

    #[test]
    fn own_status_list_uri_names_a_list_of_the_same_issuer() {
        let own = "https://node.example/api/v1/issuers/did:goya:a/status-lists/main";
        assert!(is_own_status_list_uri(own, "did:goya:a"));
        assert!(!is_own_status_list_uri(own, "did:goya:b"));
        assert!(!is_own_status_list_uri(
            "http://node.example/api/v1/issuers/did:goya:a/status-lists/main",
            "did:goya:a"
        ));
        assert!(!is_own_status_list_uri(
            "https://node.example/api/v1/issuers/did:goya:a/status-lists/",
            "did:goya:a"
        ));
        assert!(!is_own_status_list_uri(
            "https://node.example/api/v1/issuers/did:goya:a/status-lists/main/../x",
            "did:goya:a"
        ));
    }
}
