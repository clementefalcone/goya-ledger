use crate::identity::did::did_from_pubkey_hex;
use crate::storage::errors::StorageResult;
use crate::storage::traits::BlockStore;

const NEW_DID_SUFFIX_LEN: usize = 128;

fn is_legacy_did(did: &str) -> bool {
    let suffix = did.strip_prefix("did:goya:").unwrap_or("");
    !suffix.is_empty() && suffix.len() != NEW_DID_SUFFIX_LEN
}

pub struct MigrationResult {
    pub migrated: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

pub fn migrate_legacy_dids(store: &dyn BlockStore) -> StorageResult<MigrationResult> {
    let identities = store.list_identities()?;
    let mut result = MigrationResult {
        migrated: 0,
        skipped: 0,
        errors: Vec::new(),
    };

    for record in &identities {
        if !is_legacy_did(&record.did) {
            result.skipped += 1;
            continue;
        }

        if record.public_key.is_empty() {
            result
                .errors
                .push(format!("{}: no public key, cannot re-derive", record.did));
            continue;
        }

        let new_did = did_from_pubkey_hex(&record.public_key);

        if store.read_identity(&new_did).is_ok() {
            result.skipped += 1;
            continue;
        }

        let mut migrated = record.clone();
        migrated.did = new_did.clone();
        migrated.migrated_from = Some(record.did.clone());
        migrated.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Err(e) = store.write_identity(&migrated) {
            result.errors.push(format!("{}: {e}", record.did));
            continue;
        }

        if let Some(anchor) = &record.civil_anchor {
            let _ = store.write_civil_anchor(anchor, &new_did);
        }

        log::info!("migrated {} → {}", record.did, new_did);
        result.migrated += 1;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::traits::IdentityRecord;
    use crate::storage::MemoryStore;

    fn legacy_record(pubkey: &str) -> IdentityRecord {
        IdentityRecord {
            did: format!("did:goya:{}", &pubkey[..16.min(pubkey.len())]),
            public_key: pubkey.to_string(),
            created_at: 1000,
            updated_at: 1000,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: Vec::new(),
        }
    }

    #[test]
    fn migrates_legacy_did_to_sha3_512() {
        let store = MemoryStore::new();
        let rec = legacy_record("aabbccdd11223344ffffffffffffffff");
        store.write_identity(&rec).unwrap();

        let result = migrate_legacy_dids(&store).unwrap();
        assert_eq!(result.migrated, 1);
        assert_eq!(result.skipped, 0);

        let new_did = did_from_pubkey_hex("aabbccdd11223344ffffffffffffffff");
        let migrated = store.read_identity(&new_did).unwrap();
        assert_eq!(migrated.migrated_from, Some(rec.did));
        assert_eq!(migrated.public_key, rec.public_key);
    }

    #[test]
    fn skips_already_migrated() {
        let store = MemoryStore::new();
        let new_did = did_from_pubkey_hex("aabbccdd11223344ffffffffffffffff");
        let rec = IdentityRecord {
            did: new_did,
            public_key: "aabbccdd11223344ffffffffffffffff".to_string(),
            created_at: 1000,
            updated_at: 1000,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: Vec::new(),
        };
        store.write_identity(&rec).unwrap();

        let result = migrate_legacy_dids(&store).unwrap();
        assert_eq!(result.migrated, 0);
        assert_eq!(result.skipped, 1);
    }

    #[test]
    fn skips_empty_pubkey() {
        let store = MemoryStore::new();
        let rec = IdentityRecord {
            did: "did:goya:abcd1234".to_string(),
            public_key: String::new(),
            created_at: 1000,
            updated_at: 1000,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: Vec::new(),
        };
        store.write_identity(&rec).unwrap();

        let result = migrate_legacy_dids(&store).unwrap();
        assert_eq!(result.migrated, 0);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn migrates_civil_anchor() {
        let store = MemoryStore::new();
        let anchor = crate::identity::did::civil_anchor_hash("RUT", "12345678-9");
        let mut rec = legacy_record("aabbccdd11223344ffffffffffffffff");
        rec.civil_anchor = Some(anchor.clone());
        store.write_identity(&rec).unwrap();

        migrate_legacy_dids(&store).unwrap();

        let new_did = did_from_pubkey_hex("aabbccdd11223344ffffffffffffffff");
        let resolved = store.resolve_by_civil_anchor(&anchor).unwrap();
        assert_eq!(resolved, new_did);
    }

    #[test]
    fn no_duplicate_if_new_did_already_exists() {
        let store = MemoryStore::new();
        let pubkey = "aabbccdd11223344ffffffffffffffff";
        let legacy = legacy_record(pubkey);
        store.write_identity(&legacy).unwrap();

        let new_did = did_from_pubkey_hex(pubkey);
        let existing = IdentityRecord {
            did: new_did,
            public_key: pubkey.to_string(),
            created_at: 500,
            updated_at: 500,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: Vec::new(),
        };
        store.write_identity(&existing).unwrap();

        let result = migrate_legacy_dids(&store).unwrap();
        assert_eq!(result.migrated, 0);
        assert_eq!(result.skipped, 2);
    }

    #[test]
    fn is_legacy_did_detection() {
        assert!(is_legacy_did("did:goya:aabbccdd11223344"));
        assert!(!is_legacy_did(&format!("did:goya:{}", "ab".repeat(64))));
        assert!(!is_legacy_did("did:goya:"));
    }
}
