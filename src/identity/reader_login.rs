use crate::identity::signing::SigningAlgorithm;
use crate::storage::traits::{IdentityRecord, VaultEntryKind};

pub const READER_PUBLIC_KEY_HEX_CHARS: usize = 64;

pub fn is_reader_public_key(text: &str) -> bool {
    text.len() == READER_PUBLIC_KEY_HEX_CHARS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn reader_login_message(nonce: &str) -> String {
    format!("identity:read:{nonce}")
}

pub fn active_reader_key<'a>(record: &'a IdentityRecord, entry_id: &str) -> Option<&'a str> {
    record
        .vault_entries
        .iter()
        .find(|entry| {
            entry.entry_id == entry_id
                && entry.kind == VaultEntryKind::Reader
                && entry.revoked_at.is_none()
        })
        .map(|entry| entry.sealed_key.as_str())
}

pub fn is_signed_by_reader(
    record: &IdentityRecord,
    entry_id: &str,
    nonce: &str,
    signature_hex: &str,
) -> bool {
    active_reader_key(record, entry_id).is_some_and(|public_key| {
        crate::signature::verify_signature(
            SigningAlgorithm::Ed25519,
            public_key,
            reader_login_message(nonce).as_bytes(),
            signature_hex,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
    use crate::storage::traits::VaultEntry;

    fn reader_entry(entry_id: &str, public_key: &str, kind: VaultEntryKind) -> VaultEntry {
        VaultEntry {
            entry_id: entry_id.to_string(),
            kind,
            label: "iPhone".to_string(),
            sealed_key: public_key.to_string(),
            added_at: 1,
            revoked_at: None,
        }
    }

    fn record_with(entries: Vec<VaultEntry>) -> IdentityRecord {
        IdentityRecord {
            did: "did:goya:owner".to_string(),
            public_key: "00".to_string(),
            created_at: 1,
            updated_at: 1,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: Some("MlDsa65".to_string()),
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: entries,
        }
    }

    fn sign(reader: &SoftwareSigningProvider, nonce: &str) -> String {
        hex::encode(reader.sign(reader_login_message(nonce).as_bytes()).unwrap())
    }

    #[test]
    fn active_reader_signs_the_read_challenge() {
        let reader = SoftwareSigningProvider::generate();
        let record = record_with(vec![reader_entry(
            "aa01",
            &hex::encode(reader.public_key()),
            VaultEntryKind::Reader,
        )]);
        assert!(is_signed_by_reader(
            &record,
            "aa01",
            "n1",
            &sign(&reader, "n1")
        ));
        assert!(!is_signed_by_reader(
            &record,
            "aa01",
            "n2",
            &sign(&reader, "n1")
        ));
    }

    #[test]
    fn revoked_or_device_entries_cannot_read() {
        let reader = SoftwareSigningProvider::generate();
        let public_key = hex::encode(reader.public_key());
        let revoked = VaultEntry {
            revoked_at: Some(5),
            ..reader_entry("aa01", &public_key, VaultEntryKind::Reader)
        };
        let device = reader_entry("bb02", &public_key, VaultEntryKind::Device);
        let record = record_with(vec![revoked, device]);
        assert!(!is_signed_by_reader(
            &record,
            "aa01",
            "n1",
            &sign(&reader, "n1")
        ));
        assert!(!is_signed_by_reader(
            &record,
            "bb02",
            "n1",
            &sign(&reader, "n1")
        ));
    }

    #[test]
    fn another_key_cannot_sign_for_a_reader() {
        let reader = SoftwareSigningProvider::generate();
        let thief = SoftwareSigningProvider::generate();
        let record = record_with(vec![reader_entry(
            "aa01",
            &hex::encode(reader.public_key()),
            VaultEntryKind::Reader,
        )]);
        assert!(!is_signed_by_reader(
            &record,
            "aa01",
            "n1",
            &sign(&thief, "n1")
        ));
    }

    #[test]
    fn reader_public_key_is_64_lowercase_hex() {
        assert!(is_reader_public_key(&"ab".repeat(32)));
        assert!(!is_reader_public_key(&"AB".repeat(32)));
        assert!(!is_reader_public_key(&"ab".repeat(31)));
        assert!(!is_reader_public_key(r#"{"kdf":"hkdf"}"#));
    }
}
