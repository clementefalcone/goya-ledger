use crate::crypto::hasher::hash_sha3_512;

pub fn did_from_pubkey_hex(pubkey_hex: &str) -> String {
    let raw = hex::decode(pubkey_hex).unwrap_or_else(|_| pubkey_hex.as_bytes().to_vec());
    let digest = hash_sha3_512(&raw);
    format!("did:goya:{}", hex::encode(digest))
}

pub fn did_matches_pubkey(did: &str, pubkey_hex: &str) -> bool {
    !pubkey_hex.is_empty() && did == did_from_pubkey_hex(pubkey_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_uses_sha3_512() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        let did = did_from_pubkey_hex(pubkey_hex);
        assert!(did.starts_with("did:goya:"));
        let suffix = did.strip_prefix("did:goya:").unwrap();
        assert_eq!(suffix.len(), 128);
    }

    #[test]
    fn canonical_did_matches_pubkey() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        let did = did_from_pubkey_hex(pubkey_hex);
        assert!(did_matches_pubkey(&did, pubkey_hex));
    }

    #[test]
    fn canonical_did_rejects_wrong_pubkey() {
        let pubkey_hex = "aabbccdd11223344ffffffffffffffff";
        let did = did_from_pubkey_hex(pubkey_hex);
        let wrong_key = "1111111111111111ffffffffffffffff";
        assert!(!did_matches_pubkey(&did, wrong_key));
    }

    #[test]
    fn canonical_did_rejects_empty_pubkey() {
        let did = "did:goya:0000";
        assert!(!did_matches_pubkey(did, ""));
    }

    #[test]
    fn canonical_did_deterministic() {
        let key = "606024501eda68c20bd7b65841d0c580aaaaaa";
        assert_eq!(did_from_pubkey_hex(key), did_from_pubkey_hex(key));
    }
}
