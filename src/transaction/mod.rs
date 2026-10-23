pub mod endorsed;
pub mod executor;
pub mod mempool;
pub mod mvcc;
pub mod parallel;
pub mod proposal;
pub mod rwset;

use crate::identity::{operations, vault_entries};
use crate::storage::errors::StorageResult;
use crate::storage::traits::{BlockStore, Transaction, TxPayload};

pub fn apply_tx_payload(store: &dyn BlockStore, tx: &Transaction) -> StorageResult<()> {
    match &tx.payload {
        Some(TxPayload::RegisterIdentity {
            record,
            civil_anchor,
            owner_signature,
        }) => operations::apply_register(
            store,
            record,
            civil_anchor.as_deref(),
            owner_signature.as_deref(),
        ),
        Some(TxPayload::RevokeIdentity {
            did,
            revoked_at,
            owner_signature,
        }) => operations::apply_revoke(store, did, *revoked_at, owner_signature),
        Some(TxPayload::RotateIdentity {
            did,
            new_public_key,
            recovery_public_key,
            new_recovery_commitment,
            rotated_at,
            recovery_signature,
            new_key_signature,
        }) => operations::apply_rotate(
            store,
            &operations::RotateRequest {
                did,
                new_public_key,
                recovery_public_key,
                new_recovery_commitment,
                recovery_signature,
                new_key_signature,
            },
            *rotated_at,
        ),
        Some(TxPayload::AddVaultEntry {
            did,
            entry,
            owner_signature,
        }) => vault_entries::apply_add_vault_entry(
            store,
            &vault_entries::AddVaultEntryRequest {
                did,
                entry,
                owner_signature,
            },
        ),
        Some(TxPayload::RevokeVaultEntry {
            did,
            entry_id,
            revoked_at,
            owner_signature,
        }) => vault_entries::apply_revoke_vault_entry(
            store,
            &vault_entries::RevokeVaultEntryRequest {
                did,
                entry_id,
                revoked_at: *revoked_at,
                owner_signature,
            },
        ),
        Some(TxPayload::Notarize { entry }) => store.write_notarization(entry),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::did::did_from_pubkey_hex;
    use crate::identity::operations::{register_message, revoke_message, rotate_message};
    use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use crate::identity::vault_entries::{add_vault_entry_message, revoke_vault_entry_message};
    use crate::storage::traits::{IdentityRecord, VaultEntry, VaultEntryKind};
    use crate::storage::MemoryStore;

    fn sign(provider: &MlDsaSigningProvider, message: &str) -> String {
        hex::encode(provider.sign(message.as_bytes()).unwrap())
    }

    fn identity_of(provider: &MlDsaSigningProvider) -> (String, String) {
        let public_key = hex::encode(provider.public_key());
        (did_from_pubkey_hex(&public_key), public_key)
    }

    fn tx_with(payload: TxPayload) -> Transaction {
        Transaction {
            id: "identity-op".to_string(),
            block_height: 1,
            timestamp: 100,
            input_did: String::new(),
            output_recipient: String::new(),
            amount: 0,
            state: "confirmed".to_string(),
            fee: 0,
            payload: Some(payload),
        }
    }

    fn register_tx(provider: &MlDsaSigningProvider) -> Transaction {
        register_tx_with_recovery(provider, None)
    }

    fn register_tx_with_recovery(
        provider: &MlDsaSigningProvider,
        recovery_commitment: Option<&str>,
    ) -> Transaction {
        let (did, public_key) = identity_of(provider);
        tx_with(TxPayload::RegisterIdentity {
            record: IdentityRecord {
                did: did.clone(),
                public_key,
                created_at: 100,
                updated_at: 100,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: None,
                civil_anchor: None,
                recovery_commitment: recovery_commitment.map(str::to_string),
                vault_entries: Vec::new(),
            },
            civil_anchor: None,
            owner_signature: Some(sign(provider, &register_message(&did, recovery_commitment))),
        })
    }

    fn apply_on_both(nodes: [&MemoryStore; 2], tx: &Transaction) {
        for node in nodes {
            apply_tx_payload(node, tx).unwrap();
        }
    }

    #[test]
    fn revocation_in_a_block_reaches_every_node() {
        let (node_a, node_b) = (MemoryStore::new(), MemoryStore::new());
        let owner = MlDsaSigningProvider::generate();
        let (did, _) = identity_of(&owner);
        apply_on_both([&node_a, &node_b], &register_tx(&owner));

        let revoke = tx_with(TxPayload::RevokeIdentity {
            did: did.clone(),
            revoked_at: 200,
            owner_signature: sign(&owner, &revoke_message(&did)),
        });
        apply_on_both([&node_a, &node_b], &revoke);

        let on_a = node_a.read_identity(&did).unwrap();
        let on_b = node_b.read_identity(&did).unwrap();
        assert_eq!(on_b.status, "revoked");
        assert_eq!(on_a, on_b);
    }

    #[test]
    fn rotation_in_a_block_reaches_every_node_and_kills_old_key() {
        let (node_a, node_b) = (MemoryStore::new(), MemoryStore::new());
        let owner = MlDsaSigningProvider::generate();
        let recovery = MlDsaSigningProvider::generate();
        let successor = MlDsaSigningProvider::generate();
        let next = MlDsaSigningProvider::generate();
        let (did, _) = identity_of(&owner);
        let (recovery_did, recovery_public_key) = identity_of(&recovery);
        let (_, new_public_key) = identity_of(&successor);
        let (next_did, _) = identity_of(&next);
        apply_on_both(
            [&node_a, &node_b],
            &register_tx_with_recovery(&owner, Some(&recovery_did)),
        );

        let message = rotate_message(&did, &new_public_key, &next_did);
        let rotate = tx_with(TxPayload::RotateIdentity {
            did: did.clone(),
            new_public_key: new_public_key.clone(),
            recovery_public_key,
            new_recovery_commitment: next_did,
            rotated_at: 300,
            recovery_signature: sign(&recovery, &message),
            new_key_signature: sign(&successor, &message),
        });
        apply_on_both([&node_a, &node_b], &rotate);

        let on_b = node_b.read_identity(&did).unwrap();
        assert_eq!(on_b.public_key, new_public_key);
        assert_eq!(node_a.read_identity(&did).unwrap(), on_b);
        let stolen_key_revocation = tx_with(TxPayload::RevokeIdentity {
            did: did.clone(),
            revoked_at: 400,
            owner_signature: sign(&owner, &revoke_message(&did)),
        });
        assert!(apply_tx_payload(&node_b, &stolen_key_revocation).is_err());
    }

    #[test]
    fn forged_revocation_in_a_block_is_rejected_by_receiving_node() {
        let node = MemoryStore::new();
        let owner = MlDsaSigningProvider::generate();
        let thief = MlDsaSigningProvider::generate();
        let (did, _) = identity_of(&owner);
        apply_tx_payload(&node, &register_tx(&owner)).unwrap();

        let forged = tx_with(TxPayload::RevokeIdentity {
            did: did.clone(),
            revoked_at: 200,
            owner_signature: sign(&thief, &revoke_message(&did)),
        });
        assert!(apply_tx_payload(&node, &forged).is_err());
        assert_eq!(node.read_identity(&did).unwrap().status, "active");
    }

    #[test]
    fn forged_registration_in_a_block_is_rejected_by_receiving_node() {
        let node = MemoryStore::new();
        let owner = MlDsaSigningProvider::generate();
        let attacker = MlDsaSigningProvider::generate();
        let (did, _) = identity_of(&owner);
        let mut tx = register_tx(&owner);
        if let Some(TxPayload::RegisterIdentity {
            owner_signature, ..
        }) = &mut tx.payload
        {
            *owner_signature = Some(sign(&attacker, &register_message(&did, None)));
        }
        assert!(apply_tx_payload(&node, &tx).is_err());
        assert!(node.read_identity(&did).is_err());
    }

    fn phone_copy() -> VaultEntry {
        VaultEntry {
            entry_id: "0378ffe5".to_string(),
            kind: VaultEntryKind::Device,
            label: "iPhone".to_string(),
            sealed_key: r#"{"kdf":"hkdf","ciphertext":"aa"}"#.to_string(),
            added_at: 150,
            revoked_at: None,
        }
    }

    #[test]
    fn vault_copy_in_a_block_reaches_every_node() {
        let (node_a, node_b) = (MemoryStore::new(), MemoryStore::new());
        let owner = MlDsaSigningProvider::generate();
        let (did, _) = identity_of(&owner);
        apply_on_both([&node_a, &node_b], &register_tx(&owner));

        let add = tx_with(TxPayload::AddVaultEntry {
            did: did.clone(),
            entry: phone_copy(),
            owner_signature: sign(&owner, &add_vault_entry_message(&did, &phone_copy())),
        });
        apply_on_both([&node_a, &node_b], &add);
        let revoke = tx_with(TxPayload::RevokeVaultEntry {
            did: did.clone(),
            entry_id: phone_copy().entry_id,
            revoked_at: 250,
            owner_signature: sign(&owner, &revoke_vault_entry_message(&did, "0378ffe5")),
        });
        apply_on_both([&node_a, &node_b], &revoke);

        let on_b = node_b.read_identity(&did).unwrap();
        assert_eq!(on_b.vault_entries[0].revoked_at, Some(250));
        assert_eq!(node_a.read_identity(&did).unwrap(), on_b);
    }

    #[test]
    fn forged_vault_copy_in_a_block_is_rejected_by_receiving_node() {
        let node = MemoryStore::new();
        let owner = MlDsaSigningProvider::generate();
        let thief = MlDsaSigningProvider::generate();
        let (did, _) = identity_of(&owner);
        apply_tx_payload(&node, &register_tx(&owner)).unwrap();

        let forged = tx_with(TxPayload::AddVaultEntry {
            did: did.clone(),
            entry: phone_copy(),
            owner_signature: sign(&thief, &add_vault_entry_message(&did, &phone_copy())),
        });
        assert!(apply_tx_payload(&node, &forged).is_err());
        assert!(node.read_identity(&did).unwrap().vault_entries.is_empty());
    }
}
