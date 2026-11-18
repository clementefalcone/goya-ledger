//! DID-to-PIN association store.

use std::collections::HashMap;
use std::sync::RwLock;

use super::generator::{Pin, PinError};

/// Persistent mapping from DID to hashed PIN.
pub trait PinStore: Send + Sync {
    /// Store a hashed PIN for a DID. Overwrites any previous PIN.
    fn set(&self, did: &str, pin_hash: &str) -> Result<(), PinError>;

    /// Retrieve the stored hash for a DID, if any.
    fn get_hash(&self, did: &str) -> Result<Option<String>, PinError>;

    /// Verify a plaintext PIN against the stored hash for a DID.
    fn verify(&self, did: &str, plain_pin: &str) -> Result<(), PinError>;

    /// Remove the PIN for a DID. Returns true if a PIN was removed.
    fn remove(&self, did: &str) -> Result<bool, PinError>;
}

pub const MAX_FAILED_ATTEMPTS: u8 = 5;

struct PinRecord {
    hash: String,
    failed_attempts: u8,
}

/// In-memory implementation backed by a `HashMap`.
pub struct MemoryPinStore {
    data: RwLock<HashMap<String, PinRecord>>,
}

impl MemoryPinStore {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryPinStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PinStore for MemoryPinStore {
    fn set(&self, did: &str, pin_hash: &str) -> Result<(), PinError> {
        let mut map = self
            .data
            .write()
            .map_err(|e| PinError::HashError(format!("lock poisoned: {e}")))?;
        map.insert(
            did.to_string(),
            PinRecord {
                hash: pin_hash.to_string(),
                failed_attempts: 0,
            },
        );
        Ok(())
    }

    fn get_hash(&self, did: &str) -> Result<Option<String>, PinError> {
        let map = self
            .data
            .read()
            .map_err(|e| PinError::HashError(format!("lock poisoned: {e}")))?;
        Ok(map.get(did).map(|record| record.hash.clone()))
    }

    fn verify(&self, did: &str, plain_pin: &str) -> Result<(), PinError> {
        let mut map = self
            .data
            .write()
            .map_err(|e| PinError::HashError(format!("lock poisoned: {e}")))?;
        let record = map
            .get_mut(did)
            .ok_or_else(|| PinError::HashError(format!("no PIN registered for DID: {did}")))?;
        match Pin::verify(plain_pin, &record.hash) {
            Ok(()) => {
                record.failed_attempts = 0;
                Ok(())
            }
            Err(PinError::VerifyFailed) => {
                record.failed_attempts += 1;
                if record.failed_attempts >= MAX_FAILED_ATTEMPTS {
                    map.remove(did);
                }
                Err(PinError::VerifyFailed)
            }
            Err(e) => Err(e),
        }
    }

    fn remove(&self, did: &str) -> Result<bool, PinError> {
        let mut map = self
            .data
            .write()
            .map_err(|e| PinError::HashError(format!("lock poisoned: {e}")))?;
        Ok(map.remove(did).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_verify_pin() {
        let store = MemoryPinStore::new();
        let pin = Pin::generate(4).unwrap();
        let hash = pin.hash().unwrap();

        store.set("did:goya:alice", &hash).unwrap();
        assert!(store.verify("did:goya:alice", pin.as_str()).is_ok());
    }

    #[test]
    fn verify_wrong_pin_fails() {
        let store = MemoryPinStore::new();
        let pin = Pin::generate(6).unwrap();
        let hash = pin.hash().unwrap();

        store.set("did:goya:bob", &hash).unwrap();
        let result = store.verify("did:goya:bob", "000000");
        if pin.as_str() != "000000" {
            assert!(result.is_err());
        }
    }

    #[test]
    fn verify_unknown_did_fails() {
        let store = MemoryPinStore::new();
        let result = store.verify("did:goya:unknown", "1234");
        assert!(result.is_err());
    }

    #[test]
    fn overwrite_pin() {
        let store = MemoryPinStore::new();
        let pin1 = Pin::generate(4).unwrap();
        let pin2 = Pin::generate(4).unwrap();

        store.set("did:goya:carol", &pin1.hash().unwrap()).unwrap();
        store.set("did:goya:carol", &pin2.hash().unwrap()).unwrap();

        assert!(store.verify("did:goya:carol", pin2.as_str()).is_ok());
    }

    #[test]
    fn remove_pin() {
        let store = MemoryPinStore::new();
        let pin = Pin::generate(4).unwrap();
        store.set("did:goya:dave", &pin.hash().unwrap()).unwrap();

        assert!(store.remove("did:goya:dave").unwrap());
        assert!(!store.remove("did:goya:dave").unwrap());
        assert!(store.verify("did:goya:dave", pin.as_str()).is_err());
    }

    fn wrong_pin_for(pin: &Pin) -> String {
        if pin.as_str() == "0000" {
            "1111"
        } else {
            "0000"
        }
        .to_string()
    }

    #[test]
    fn five_wrong_pins_void_the_pin() {
        let store = MemoryPinStore::new();
        let pin = Pin::generate(4).unwrap();
        store.set("did:goya:erin", &pin.hash().unwrap()).unwrap();

        for _ in 0..MAX_FAILED_ATTEMPTS {
            assert!(store.verify("did:goya:erin", &wrong_pin_for(&pin)).is_err());
        }
        assert!(store.verify("did:goya:erin", pin.as_str()).is_err());
        assert!(store.get_hash("did:goya:erin").unwrap().is_none());
    }

    #[test]
    fn right_pin_resets_the_failed_attempts() {
        let store = MemoryPinStore::new();
        let pin = Pin::generate(4).unwrap();
        store.set("did:goya:frank", &pin.hash().unwrap()).unwrap();

        for _ in 0..2 {
            for _ in 1..MAX_FAILED_ATTEMPTS {
                assert!(store
                    .verify("did:goya:frank", &wrong_pin_for(&pin))
                    .is_err());
            }
            assert!(store.verify("did:goya:frank", pin.as_str()).is_ok());
        }
    }

    #[test]
    fn new_pin_starts_with_no_failed_attempts() {
        let store = MemoryPinStore::new();
        let old_pin = Pin::generate(4).unwrap();
        store
            .set("did:goya:gina", &old_pin.hash().unwrap())
            .unwrap();
        for _ in 1..MAX_FAILED_ATTEMPTS {
            assert!(store
                .verify("did:goya:gina", &wrong_pin_for(&old_pin))
                .is_err());
        }

        let new_pin = Pin::generate(4).unwrap();
        store
            .set("did:goya:gina", &new_pin.hash().unwrap())
            .unwrap();
        assert!(store
            .verify("did:goya:gina", &wrong_pin_for(&new_pin))
            .is_err());
        assert!(store.verify("did:goya:gina", new_pin.as_str()).is_ok());
    }

    #[test]
    fn get_hash_returns_none_for_unknown() {
        let store = MemoryPinStore::new();
        assert!(store.get_hash("did:goya:nobody").unwrap().is_none());
    }
}
