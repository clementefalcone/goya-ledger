pub mod endorsed;
pub mod executor;
pub mod mempool;
pub mod mvcc;
pub mod parallel;
pub mod proposal;
pub mod rwset;

use crate::storage::errors::{StorageError, StorageResult};
use crate::storage::traits::{BlockStore, Transaction, TxPayload};

pub fn apply_tx_payload(store: &dyn BlockStore, tx: &Transaction) -> StorageResult<()> {
    match &tx.payload {
        Some(TxPayload::RegisterIdentity {
            record,
            civil_anchor,
        }) => {
            if let Some(anchor) = civil_anchor {
                if store.resolve_by_civil_anchor(anchor).is_ok() {
                    return Err(StorageError::Other(format!(
                        "civil anchor already registered: {anchor}"
                    )));
                }
            }
            store.write_identity(record)?;
            if let Some(anchor) = civil_anchor {
                store.write_civil_anchor(anchor, &record.did)?;
            }
            Ok(())
        }
        Some(TxPayload::Notarize { entry }) => store.write_notarization(entry),
        _ => Ok(()),
    }
}
