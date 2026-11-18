use crate::identity::issuer_keys::{https_url_path, issuer_path, sec1_public_key_hex};
use crate::identity::operations::{Change, IdentityOpError};
use crate::identity::sd_jwt::sign_compact_jwt;
use crate::identity::signing::{EcdsaP256SigningProvider, SigningAlgorithm};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, IssuerStatusList};
use std::io::{Read, Write};

pub const STATUS_LIST_MAX_BYTES: usize = 64 * 1024;
pub const STATUS_LIST_ENTRIES: usize = 16_384;
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
    if !is_signed_with(jwt, &credential_key_hex) {
        return Err(IdentityOpError::BadSignature(format!(
            "status list JWT is not signed with ES256 by the registered credential key of {did}"
        )));
    }
    Ok(())
}

fn is_signed_with(jwt: &CompactJwt<'_>, credential_key_hex: &str) -> bool {
    decode_base64url(jwt.signature).is_some_and(|signature| {
        crate::signature::verify_signature(
            SigningAlgorithm::EcdsaP256,
            credential_key_hex,
            jwt.signing_input.as_bytes(),
            &hex::encode(signature),
        )
    })
}

pub fn encode_status_list(revoked_indices: &[usize]) -> Result<String, IdentityOpError> {
    let mut statuses = vec![0u8; STATUS_LIST_ENTRIES / 8];
    for &index in revoked_indices {
        let byte = statuses.get_mut(index / 8).ok_or_else(|| {
            invalid(format!(
                "status index {index} is outside the list of {STATUS_LIST_ENTRIES} entries"
            ))
        })?;
        *byte |= 1 << (index % 8);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(&statuses)
        .and_then(|()| encoder.finish())
        .map(|compressed| {
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                compressed,
            )
        })
        .map_err(|e| invalid(format!("status list compression failed: {e}")))
}

pub fn is_status_set(lst: &str, index: usize) -> Result<bool, IdentityOpError> {
    let compressed = decode_base64url(lst)
        .ok_or_else(|| invalid("status_list.lst is not base64url".to_string()))?;
    let mut statuses = Vec::new();
    flate2::read::ZlibDecoder::new(compressed.as_slice())
        .take(STATUS_LIST_MAX_BYTES as u64)
        .read_to_end(&mut statuses)
        .map_err(|e| invalid(format!("status_list.lst is not zlib data: {e}")))?;
    let byte = statuses.get(index / 8).ok_or_else(|| {
        invalid(format!(
            "status index {index} is outside the list of {} entries",
            statuses.len() * 8
        ))
    })?;
    Ok(byte & (1 << (index % 8)) != 0)
}

pub struct StatusListDraft<'a> {
    pub issuer_url: &'a str,
    pub list_id: &'a str,
    pub revoked_indices: &'a [usize],
    pub issued_at: u64,
}

pub fn sign_status_list_jwt(
    credential_key: &EcdsaP256SigningProvider,
    draft: &StatusListDraft<'_>,
) -> Result<String, IdentityOpError> {
    let payload = serde_json::json!({
        "iss": draft.issuer_url,
        "sub": format!("{}/status-lists/{}", draft.issuer_url, draft.list_id),
        "iat": draft.issued_at,
        "status_list": { "bits": 1, "lst": encode_status_list(draft.revoked_indices)? },
    });
    let header = serde_json::json!({ "typ": "statuslist+jwt", "alg": "ES256" });
    sign_compact_jwt(credential_key, &header, &payload).map_err(invalid)
}

pub fn read_status(
    jwt: &str,
    credential_key_hex: &str,
    index: usize,
) -> Result<bool, IdentityOpError> {
    let token = split_compact_jwt(jwt)?;
    require_header(&token.header)?;
    if !is_signed_with(&token, credential_key_hex) {
        return Err(IdentityOpError::BadSignature(
            "status list JWT is not signed with ES256 by the given credential key".to_string(),
        ));
    }
    require_status_list_claim(&token.payload)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| invalid(format!("system clock is before the unix epoch: {e}")))?
        .as_secs();
    require_unexpired(jwt, now)?;
    if token.payload["status_list"]["bits"].as_u64() != Some(1) {
        return Err(invalid(format!(
            "only 1-bit status lists are read, got bits {}",
            token.payload["status_list"]["bits"]
        )));
    }
    is_status_set(
        token.payload["status_list"]["lst"]
            .as_str()
            .unwrap_or_default(),
        index,
    )
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

pub fn require_unexpired(jwt: &str, now: u64) -> Result<(), IdentityOpError> {
    let payload = split_compact_jwt(jwt)?.payload;
    let Some(exp) = payload.get("exp") else {
        return Ok(());
    };
    if !exp.as_u64().is_some_and(|exp| exp > now) {
        return Err(invalid(format!(
            "status list JWT exp {exp} is not a unix time after now ({now})"
        )));
    }
    Ok(())
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
    fn status_bits_are_read_least_significant_first_as_in_the_token_status_list_example() {
        let example = "eNrbuRgAAhcBXQ";
        let expected = [
            true, false, false, true, true, true, false, true, true, true, false, false, false,
            true, false, true,
        ];
        for (index, is_revoked) in expected.into_iter().enumerate() {
            assert_eq!(
                is_status_set(example, index).unwrap(),
                is_revoked,
                "{index}"
            );
        }
        assert!(is_status_set(example, 16).is_err());
    }

    #[test]
    fn encoded_status_list_sets_exactly_the_revoked_indices() {
        let last = STATUS_LIST_ENTRIES - 1;
        let lst = encode_status_list(&[3, 7, last]).unwrap();
        let revoked: Vec<usize> = (0..STATUS_LIST_ENTRIES)
            .filter(|&index| is_status_set(&lst, index).unwrap())
            .collect();
        assert_eq!(revoked, vec![3, 7, last]);
        assert!(encode_status_list(&[STATUS_LIST_ENTRIES]).is_err());
    }

    #[test]
    fn status_is_read_only_from_a_list_signed_by_the_given_key() {
        use crate::identity::signing::SigningProvider;
        let credential_key = EcdsaP256SigningProvider::generate();
        let draft = StatusListDraft {
            issuer_url: "https://node.example/api/v1/issuers/did:goya:a",
            list_id: "main",
            revoked_indices: &[5],
            issued_at: 100,
        };
        let jwt = sign_status_list_jwt(&credential_key, &draft).unwrap();
        let key_hex = hex::encode(credential_key.public_key());
        assert!(read_status(&jwt, &key_hex, 5).unwrap());
        assert!(!read_status(&jwt, &key_hex, 4).unwrap());
        let other_key_hex = hex::encode(EcdsaP256SigningProvider::generate().public_key());
        assert!(matches!(
            read_status(&jwt, &other_key_hex, 5),
            Err(IdentityOpError::BadSignature(_))
        ));
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
