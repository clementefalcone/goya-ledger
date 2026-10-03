//! RocksDB storage adapter implementation
//!
//! Implements the BlockStore trait using RocksDB with dedicated Column Families:
//!
//! | CF name       | Key schema            | Value          |
//! |---------------|-----------------------|----------------|
//! | `blocks`      | zero-padded height    | JSON Block     |
//! | `transactions`| tx_id                 | JSON Tx        |
//! | `identities`  | DID string            | JSON Identity  |
//! | `credentials` | cred_id string        | JSON Credential|
//! | `meta`        | well-known byte keys  | raw bytes      |

use rocksdb::{
    ColumnFamilyDescriptor, DBWithThreadMode, Direction, IteratorMode, MultiThreaded, Options,
    WriteBatch,
};

type RocksDB = DBWithThreadMode<MultiThreaded>;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use super::errors::{StorageError, StorageResult};
use super::traits::{Block, BlockStore, Credential, IdentityRecord, Transaction};
use super::world_state::{VersionedValue, WorldState};
use crate::chaincode::{ChaincodeError, ChaincodePackageStore};
use crate::endorsement::org::Organization;
use crate::endorsement::registry::OrgRegistry;
use crate::private_data::{sha256, PrivateDataStore};

const CF_BLOCKS: &str = "blocks";
const CF_TRANSACTIONS: &str = "transactions";
const CF_IDENTITIES: &str = "identities";
const CF_CREDENTIALS: &str = "credentials";
const CF_META: &str = "meta";
/// Secondary index: `{012-padded-height}:{tx_id}` → `""` (empty)
const CF_TX_BY_BLOCK: &str = "tx_by_block";
/// Secondary index: `{subject_did}:{cred_id}` → `""` (empty)
const CF_CRED_BY_SUBJECT: &str = "cred_by_subject";
/// Organizations registry
const CF_ORGANIZATIONS: &str = "organizations";
/// Certificate Revocation List: key = msp_id, value = JSON Vec<String> (serials)
const CF_CRL: &str = "crl";
/// World state: key = arbitrary string key, value = JSON VersionedValue
const CF_WORLD_STATE: &str = "world_state";
/// Chaincode packages: key = `{chaincode_id}:{version}`, value = raw Wasm bytes
const CF_CHAINCODE_PACKAGES: &str = "chaincode_packages";
/// ACL entries: key = resource string, value = JSON AclEntry
const CF_ACLS: &str = "acls";
/// Channel config history: key = `{channel_id}:{version:012}`, value = JSON ChannelConfig
const CF_CHANNEL_CONFIGS: &str = "channel_configs";
/// Key-level endorsement policies: key = state key string, value = JSON endorsement policy expression
const CF_KEY_ENDORSEMENT_POLICIES: &str = "key_endorsement_policies";
/// Endorsement policies: key = resource_id, value = JSON EndorsementPolicy
const CF_ENDORSEMENT_POLICIES: &str = "endorsement_policies";
/// Private data collection definitions: key = collection name, value = JSON PrivateDataCollection
const CF_COLLECTIONS: &str = "collections";
/// Chaincode definitions: key = `{chaincode_id}:{version}`, value = JSON ChaincodeDefinition
const CF_CHAINCODE_DEFINITIONS: &str = "chaincode_definitions";
/// Key history: key = `{state_key}\x00{version:012}`, value = JSON HistoryEntry
const CF_KEY_HISTORY: &str = "key_history";
/// Audit log: key = `{timestamp}:{trace_id}`, value = JSON AuditEntry
const CF_AUDIT_LOG: &str = "audit_log";
/// Sandbox reports: key = `{chaincode_id}:{version}`, value = JSON SandboxReport
const CF_SANDBOX_REPORTS: &str = "sandbox_reports";
/// Legal oracle records: key = record id, value = JSON OracleRecord
const CF_ORACLE_RECORDS: &str = "oracle_records";
/// Governance proposals: key = `{id:012}`, value = JSON Proposal
const CF_GOVERNANCE_PROPOSALS: &str = "governance_proposals";
/// Governance votes: key = `{proposal_id:012}:{voter}`, value = JSON Vote
const CF_GOVERNANCE_VOTES: &str = "governance_votes";
/// Vault: key = DID, value = encrypted wallet JSON (opaque blob)
const CF_VAULT: &str = "vault";
const CF_SCOPES: &str = "scopes";
const CF_ASSEMBLIES: &str = "assemblies";
const CF_SESSIONS: &str = "sessions";
const CF_ACTAS: &str = "actas";
const CF_ASSETS: &str = "assets";
const CF_ASSET_EVENTS: &str = "asset_events";
const CF_ASSET_TOKENS: &str = "asset_tokens";
const CF_COMPLIANCE_RULES: &str = "compliance_rules";
const CF_COMPLIANCE_RESULTS: &str = "compliance_results";
const CF_ALIASES: &str = "aliases";
const CF_INFERENCE_CLAIMS: &str = "inference_claims";
const CF_INVITATIONS: &str = "invitations";
/// Notarizations (Proof of Existence): key = id, value = JSON NotarizationEntry
/// Secondary index: `hash:{content_hash}` → id
const CF_NOTARIZATIONS: &str = "notarizations";
/// Ownership transfers: key = `{content_hash}:{timestamp}`, value = JSON OwnershipTransfer
const CF_OWNERSHIP_TRANSFERS: &str = "ownership_transfers";
const CF_LEXCONTRACTS: &str = "lexcontracts";
const CF_CIVIL_ANCHORS: &str = "civil_anchors";

const META_LATEST_HEIGHT: &[u8] = b"latest_height";

const ALL_CFS: &[&str] = &[
    CF_BLOCKS,
    CF_TRANSACTIONS,
    CF_IDENTITIES,
    CF_CREDENTIALS,
    CF_META,
    CF_TX_BY_BLOCK,
    CF_CRED_BY_SUBJECT,
    CF_ORGANIZATIONS,
    CF_CRL,
    CF_WORLD_STATE,
    CF_CHAINCODE_PACKAGES,
    CF_ACLS,
    CF_CHANNEL_CONFIGS,
    CF_KEY_ENDORSEMENT_POLICIES,
    CF_KEY_HISTORY,
    CF_ENDORSEMENT_POLICIES,
    CF_COLLECTIONS,
    CF_CHAINCODE_DEFINITIONS,
    CF_AUDIT_LOG,
    CF_SANDBOX_REPORTS,
    CF_ORACLE_RECORDS,
    CF_GOVERNANCE_PROPOSALS,
    CF_GOVERNANCE_VOTES,
    CF_VAULT,
    CF_SCOPES,
    CF_ASSEMBLIES,
    CF_SESSIONS,
    CF_ACTAS,
    CF_ASSETS,
    CF_ASSET_EVENTS,
    CF_ASSET_TOKENS,
    CF_COMPLIANCE_RULES,
    CF_COMPLIANCE_RESULTS,
    CF_ALIASES,
    CF_INFERENCE_CLAIMS,
    CF_INVITATIONS,
    CF_NOTARIZATIONS,
    CF_OWNERSHIP_TRANSFERS,
    CF_LEXCONTRACTS,
    CF_CIVIL_ANCHORS,
];

/// RocksDB-backed block store using Column Families for data isolation
pub struct RocksDbBlockStore {
    pub(crate) db: RocksDB,
}

impl RocksDbBlockStore {
    /// Open (or create) a RocksDB database at the given path.
    ///
    /// All five column families are created automatically when missing,
    /// so this works on both new and existing databases.
    pub fn new(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Static CFs plus any already on disk (e.g. `private_*` from PrivateDataStore::ensure_private_cf).
        // Opening without listing existing CFs causes: "Column families not opened: private_...".
        let mut cf_names: BTreeSet<String> = ALL_CFS.iter().map(|s| (*s).to_string()).collect();
        if let Ok(existing) = RocksDB::list_cf(&opts, path) {
            for name in existing {
                cf_names.insert(name);
            }
        }

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, Options::default()))
            .collect();

        let db = RocksDB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;

        Ok(RocksDbBlockStore { db })
    }

    /// Flush the WAL (Write-Ahead Log) to ensure all pending writes are
    /// persisted to SST files on disk. Call this before shutdown to prevent
    /// data loss.
    pub fn flush_wal(&self) -> StorageResult<()> {
        self.db
            .flush_wal(true)
            .map_err(|e| StorageError::RocksDbError(format!("WAL flush failed: {e}")))?;
        // Also flush memtables to SST files for full durability.
        self.db
            .flush()
            .map_err(|e| StorageError::RocksDbError(format!("memtable flush failed: {e}")))?;
        Ok(())
    }

    #[allow(dead_code)]
    /// Open (or create) a per-channel RocksDB database.
    ///
    /// The database is placed at `<base_path>/channels/<channel_id>`, so each
    /// channel gets its own isolated set of column families.
    ///
    /// `channel_id` must be a non-empty string containing only alphanumeric
    /// characters, hyphens, or underscores to avoid path-traversal issues.
    pub fn create_channel_store(
        channel_id: &str,
        base_path: &Path,
    ) -> StorageResult<RocksDbBlockStore> {
        if channel_id.is_empty()
            || !channel_id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(StorageError::InvalidChannelId(channel_id.to_string()));
        }
        let channel_path = base_path.join("channels").join(channel_id);
        RocksDbBlockStore::new(channel_path)
    }

    // ── Column Family handle helpers ──────────────────────────────────────────

    fn cf_blocks(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_BLOCKS.to_string()))
    }

    fn cf_transactions(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_TRANSACTIONS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_TRANSACTIONS.to_string()))
    }

    fn cf_identities(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_IDENTITIES)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_IDENTITIES.to_string()))
    }

    fn cf_civil_anchors(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CIVIL_ANCHORS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CIVIL_ANCHORS.to_string()))
    }

    fn cf_credentials(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CREDENTIALS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CREDENTIALS.to_string()))
    }

    fn cf_meta(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_META)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_META.to_string()))
    }

    fn cf_tx_by_block(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_TX_BY_BLOCK)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_TX_BY_BLOCK.to_string()))
    }

    fn cf_cred_by_subject(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CRED_BY_SUBJECT)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CRED_BY_SUBJECT.to_string()))
    }

    fn cf_organizations(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_ORGANIZATIONS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_ORGANIZATIONS.to_string()))
    }

    fn cf_crl(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CRL)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CRL.to_string()))
    }

    fn cf_world_state(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_WORLD_STATE)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_WORLD_STATE.to_string()))
    }

    fn cf_chaincode_packages(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CHAINCODE_PACKAGES)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CHAINCODE_PACKAGES.to_string()))
    }

    fn cf_acls(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_ACLS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_ACLS.to_string()))
    }

    fn cf_channel_configs(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CHANNEL_CONFIGS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CHANNEL_CONFIGS.to_string()))
    }

    pub(crate) fn cf_key_endorsement_policies(
        &self,
    ) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_KEY_ENDORSEMENT_POLICIES)
            .ok_or_else(|| {
                StorageError::ColumnFamilyNotFound(CF_KEY_ENDORSEMENT_POLICIES.to_string())
            })
    }

    pub(crate) fn cf_key_history(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_KEY_HISTORY)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_KEY_HISTORY.to_string()))
    }

    // ── Key encoders ─────────────────────────────────────────────────────────

    /// Zero-padded decimal height gives lexicographic == numeric ordering.
    fn block_key(height: u64) -> Vec<u8> {
        format!("{height:012}").into_bytes()
    }

    /// Secondary-index key: `{012-padded-height}:{tx_id}`.
    ///
    /// The fixed-width height prefix keeps all entries for a block contiguous
    /// and in numeric order, enabling a simple prefix range scan.
    fn tx_block_index_key(height: u64, tx_id: &str) -> Vec<u8> {
        format!("{height:012}:{tx_id}").into_bytes()
    }

    /// The prefix used to scan all index entries for `height`.
    fn tx_block_prefix(height: u64) -> Vec<u8> {
        format!("{height:012}:").into_bytes()
    }

    /// Secondary-index key for the subject-DID index: `{subject_did}\x00{cred_id}`.
    ///
    /// `\x00` is used as separator because DID characters and cred IDs never
    /// contain a NUL byte, making the prefix scan unambiguous.
    fn cred_subject_index_key(subject_did: &str, cred_id: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(subject_did.len() + 1 + cred_id.len());
        key.extend_from_slice(subject_did.as_bytes());
        key.push(0x00);
        key.extend_from_slice(cred_id.as_bytes());
        key
    }

    /// Prefix used to scan all index entries for `subject_did`.
    fn cred_subject_prefix(subject_did: &str) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(subject_did.len() + 1);
        prefix.extend_from_slice(subject_did.as_bytes());
        prefix.push(0x00);
        prefix
    }

    #[allow(dead_code)]
    /// Key-history entry key: `{state_key}\x00{version:012}`.
    fn history_key(state_key: &str, version: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(state_key.len() + 1 + 12);
        key.extend_from_slice(state_key.as_bytes());
        key.push(0x00);
        key.extend_from_slice(format!("{version:012}").as_bytes());
        key
    }

    /// Prefix for scanning all history entries of a given key.
    fn history_prefix(state_key: &str) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(state_key.len() + 1);
        prefix.extend_from_slice(state_key.as_bytes());
        prefix.push(0x00);
        prefix
    }

    // ── Key history ──────────────────────────────────────────────────────────

    #[allow(dead_code)]
    /// Write a single history entry for a world-state key.
    pub fn write_history_entry(
        &self,
        state_key: &str,
        entry: &crate::storage::traits::HistoryEntry,
    ) -> StorageResult<()> {
        let cf = self.cf_key_history()?;
        let key = Self::history_key(state_key, entry.version);
        let value = serde_json::to_vec(entry)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    /// Read all history entries for a world-state key, ordered by version.
    pub fn get_history(
        &self,
        state_key: &str,
    ) -> StorageResult<Vec<crate::storage::traits::HistoryEntry>> {
        let cf = self.cf_key_history()?;
        let prefix = Self::history_prefix(state_key);
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&prefix, Direction::Forward));

        let mut entries = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            if !k.starts_with(&prefix) {
                break;
            }
            let entry: crate::storage::traits::HistoryEntry = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    // ── World state ───────────────────────────────────────────────────────────

    /// Write `data` under `key` in the world state CF.
    ///
    /// If the key already exists the version is incremented; if it is new the
    /// version starts at 1.  Returns the new version number.
    pub fn world_state_put(&self, key: &str, data: &[u8]) -> StorageResult<u64> {
        let cf = self.cf_world_state()?;
        let new_version = match self
            .db
            .get_cf(&cf, key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => {
                let existing: VersionedValue = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                existing.version + 1
            }
            None => 1,
        };
        let vv = VersionedValue {
            version: new_version,
            data: data.to_vec(),
        };
        let encoded =
            serde_json::to_vec(&vv).map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &encoded)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(new_version)
    }

    /// Read the current `VersionedValue` for `key`, or `None` if absent.
    pub fn world_state_get(&self, key: &str) -> StorageResult<Option<VersionedValue>> {
        let cf = self.cf_world_state()?;
        match self
            .db
            .get_cf(&cf, key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => {
                let vv: VersionedValue = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                Ok(Some(vv))
            }
            None => Ok(None),
        }
    }
}

impl BlockStore for RocksDbBlockStore {
    fn write_block(&self, block: &Block) -> StorageResult<()> {
        let value = serde_json::to_vec(block)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let current_latest = self.get_latest_height().unwrap_or(0);
        let cf_b = self.cf_blocks()?;
        let cf_m = self.cf_meta()?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_b, Self::block_key(block.height), &value);
        if block.height >= current_latest {
            batch.put_cf(&cf_m, META_LATEST_HEIGHT, block.height.to_le_bytes());
        }
        self.db
            .write(batch)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_block(&self, height: u64) -> StorageResult<Block> {
        let key = Self::block_key(height);
        match self
            .db
            .get_cf(&self.cf_blocks()?, &key)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(format!("block:{height}"))),
        }
    }

    fn write_transaction(&self, tx: &Transaction) -> StorageResult<()> {
        let value =
            serde_json::to_vec(tx).map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&self.cf_transactions()?, tx.id.as_bytes(), &value);
        batch.put_cf(
            &self.cf_tx_by_block()?,
            Self::tx_block_index_key(tx.block_height, &tx.id),
            b"",
        );
        self.db
            .write(batch)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_transaction(&self, tx_id: &str) -> StorageResult<Transaction> {
        match self
            .db
            .get_cf(&self.cf_transactions()?, tx_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(format!("tx:{tx_id}"))),
        }
    }

    fn write_identity(&self, identity: &IdentityRecord) -> StorageResult<()> {
        let value = serde_json::to_vec(identity)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&self.cf_identities()?, identity.did.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_identity(&self, did: &str) -> StorageResult<IdentityRecord> {
        match self
            .db
            .get_cf(&self.cf_identities()?, did.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::IdentityNotFound(did.to_string())),
        }
    }

    fn list_identities(&self) -> StorageResult<Vec<IdentityRecord>> {
        let cf = self.cf_identities()?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();
        for item in iter {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let rec: IdentityRecord = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            results.push(rec);
        }
        Ok(results)
    }

    fn write_civil_anchor(&self, anchor_hash: &str, did: &str) -> StorageResult<()> {
        self.db
            .put_cf(
                &self.cf_civil_anchors()?,
                anchor_hash.as_bytes(),
                did.as_bytes(),
            )
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn resolve_by_civil_anchor(&self, anchor_hash: &str) -> StorageResult<String> {
        match self
            .db
            .get_cf(&self.cf_civil_anchors()?, anchor_hash.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => String::from_utf8(bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(format!(
                "civil_anchor:{anchor_hash}"
            ))),
        }
    }

    fn write_credential(&self, credential: &Credential) -> StorageResult<()> {
        let value = serde_json::to_vec(credential)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&self.cf_credentials()?, credential.id.as_bytes(), &value);
        batch.put_cf(
            &self.cf_cred_by_subject()?,
            Self::cred_subject_index_key(&credential.subject_did, &credential.id),
            b"",
        );
        self.db
            .write(batch)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_credential(&self, cred_id: &str) -> StorageResult<Credential> {
        match self
            .db
            .get_cf(&self.cf_credentials()?, cred_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::CredentialNotFound(cred_id.to_string())),
        }
    }

    fn list_credentials(&self) -> StorageResult<Vec<Credential>> {
        let cf = self.cf_credentials()?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();
        for item in iter {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let rec: Credential = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            results.push(rec);
        }
        Ok(results)
    }

    fn write_batch(&self, blocks: &[Block], txs: &[Transaction]) -> StorageResult<()> {
        if blocks.is_empty() && txs.is_empty() {
            return Err(StorageError::BatchOperationFailed(
                "Empty batch".to_string(),
            ));
        }

        let current_latest = self.get_latest_height().unwrap_or(0);
        let mut new_latest = current_latest;

        let cf_b = self.cf_blocks()?;
        let cf_t = self.cf_transactions()?;
        let cf_m = self.cf_meta()?;
        let cf_idx = self.cf_tx_by_block()?;

        let mut batch = WriteBatch::default();

        for block in blocks {
            let value = serde_json::to_vec(block)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            batch.put_cf(&cf_b, Self::block_key(block.height), &value);
            if block.height > new_latest {
                new_latest = block.height;
            }
        }

        for tx in txs {
            let value = serde_json::to_vec(tx)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            batch.put_cf(&cf_t, tx.id.as_bytes(), &value);
            batch.put_cf(
                &cf_idx,
                Self::tx_block_index_key(tx.block_height, &tx.id),
                b"",
            );
        }

        if new_latest > current_latest {
            batch.put_cf(&cf_m, META_LATEST_HEIGHT, new_latest.to_le_bytes());
        }

        self.db
            .write(batch)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn get_latest_height(&self) -> StorageResult<u64> {
        match self
            .db
            .get_cf(&self.cf_meta()?, META_LATEST_HEIGHT)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => {
                let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                    StorageError::DataCorrupted("latest_height is not 8 bytes".to_string())
                })?;
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0),
        }
    }

    fn block_exists(&self, height: u64) -> StorageResult<bool> {
        self.db
            .get_cf(&self.cf_blocks()?, Self::block_key(height))
            .map(|v| v.is_some())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn transactions_by_block_height(&self, height: u64) -> StorageResult<Vec<Transaction>> {
        let prefix = Self::tx_block_prefix(height);
        let cf_idx = self.cf_tx_by_block()?;
        let cf_t = self.cf_transactions()?;

        let iter = self
            .db
            .iterator_cf(&cf_idx, IteratorMode::From(&prefix, Direction::Forward));

        let mut txs = Vec::new();
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;

            // Stop once we've passed all keys with this height prefix.
            if !key.starts_with(&prefix) {
                break;
            }

            // Extract tx_id: everything after `{012}:`
            let tx_id = std::str::from_utf8(&key[prefix.len()..])
                .map_err(|e| StorageError::DataCorrupted(e.to_string()))?;

            let tx_bytes = self
                .db
                .get_cf(&cf_t, tx_id.as_bytes())
                .map_err(|e| StorageError::RocksDbError(e.to_string()))?
                .ok_or_else(|| StorageError::KeyNotFound(format!("tx:{tx_id}")))?;

            let tx: Transaction = serde_json::from_slice(&tx_bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            txs.push(tx);
        }

        Ok(txs)
    }

    fn credentials_by_subject_did(&self, subject_did: &str) -> StorageResult<Vec<Credential>> {
        let prefix = Self::cred_subject_prefix(subject_did);
        let cf_idx = self.cf_cred_by_subject()?;
        let cf_c = self.cf_credentials()?;

        let iter = self
            .db
            .iterator_cf(&cf_idx, IteratorMode::From(&prefix, Direction::Forward));

        let mut creds = Vec::new();
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;

            if !key.starts_with(&prefix) {
                break;
            }

            // Extract cred_id: everything after `{subject_did}\x00`
            let cred_id = std::str::from_utf8(&key[prefix.len()..])
                .map_err(|e| StorageError::DataCorrupted(e.to_string()))?;

            let cred_bytes = self
                .db
                .get_cf(&cf_c, cred_id.as_bytes())
                .map_err(|e| StorageError::RocksDbError(e.to_string()))?
                .ok_or_else(|| StorageError::KeyNotFound(format!("cred:{cred_id}")))?;

            let cred: Credential = serde_json::from_slice(&cred_bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            creds.push(cred);
        }

        Ok(creds)
    }

    fn mark_tx_seen(&self, tx_id: &str, timestamp: u64) -> StorageResult<()> {
        let cf = self.cf_meta()?;
        let key = format!("seen_tx:{tx_id}");
        self.db
            .put_cf(&cf, key.as_bytes(), timestamp.to_be_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn is_tx_seen(&self, tx_id: &str) -> StorageResult<bool> {
        let cf = self.cf_meta()?;
        let key = format!("seen_tx:{tx_id}");
        let exists = self
            .db
            .get_cf(&cf, key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .is_some();
        Ok(exists)
    }

    fn load_seen_txs(&self) -> StorageResult<Vec<(String, u64)>> {
        let cf = self.cf_meta()?;
        let prefix = b"seen_tx:";
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(prefix, Direction::Forward));

        let mut result = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            let tx_id = std::str::from_utf8(&key[prefix.len()..])
                .map_err(|e| StorageError::DataCorrupted(e.to_string()))?
                .to_string();
            let ts = if value.len() == 8 {
                u64::from_be_bytes(value[..8].try_into().expect("guarded by len == 8 check"))
            } else {
                0
            };
            result.push((tx_id, ts));
        }
        Ok(result)
    }

    fn cleanup_seen_txs(&self, max_age_secs: u64) -> StorageResult<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entries = self.load_seen_txs()?;
        let cf = self.cf_meta()?;
        let mut removed = 0u64;
        for (tx_id, ts) in entries {
            if now.saturating_sub(ts) > max_age_secs {
                let key = format!("seen_tx:{tx_id}");
                self.db
                    .delete_cf(&cf, key.as_bytes())
                    .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    // ── Governance persistence ─────────────────────────────────────────────

    fn write_proposal(
        &self,
        proposal: &crate::governance::proposals::Proposal,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_GOVERNANCE_PROPOSALS)
            .ok_or_else(|| StorageError::RocksDbError("missing governance_proposals CF".into()))?;
        let key = format!("{:012}", proposal.id);
        let value = serde_json::to_vec(proposal)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_proposal(&self, id: u64) -> StorageResult<crate::governance::proposals::Proposal> {
        let cf = self
            .db
            .cf_handle(CF_GOVERNANCE_PROPOSALS)
            .ok_or_else(|| StorageError::RocksDbError("missing governance_proposals CF".into()))?;
        let key = format!("{id:012}");
        match self
            .db
            .get_cf(&cf, key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(format!("PROPOSAL:{key}"))),
        }
    }

    fn list_proposals(&self) -> StorageResult<Vec<crate::governance::proposals::Proposal>> {
        let cf = self
            .db
            .cf_handle(CF_GOVERNANCE_PROPOSALS)
            .ok_or_else(|| StorageError::RocksDbError("missing governance_proposals CF".into()))?;
        let mut proposals = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (_, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let p: crate::governance::proposals::Proposal = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            proposals.push(p);
        }
        Ok(proposals)
    }

    fn write_vote(&self, vote: &crate::governance::voting::Vote) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_GOVERNANCE_VOTES)
            .ok_or_else(|| StorageError::RocksDbError("missing governance_votes CF".into()))?;
        let key = format!("{:012}:{}", vote.proposal_id, vote.voter);
        let value = serde_json::to_vec(vote)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn list_votes(&self, proposal_id: u64) -> StorageResult<Vec<crate::governance::voting::Vote>> {
        let cf = self
            .db
            .cf_handle(CF_GOVERNANCE_VOTES)
            .ok_or_else(|| StorageError::RocksDbError("missing governance_votes CF".into()))?;
        let prefix = format!("{proposal_id:012}:");
        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(prefix.as_bytes(), Direction::Forward),
        );
        let mut votes = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let v: crate::governance::voting::Vote = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            votes.push(v);
        }
        Ok(votes)
    }

    fn write_vault(&self, did: &str, encrypted_wallet: &serde_json::Value) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_VAULT)
            .ok_or_else(|| StorageError::RocksDbError("missing vault CF".into()))?;
        let json = serde_json::to_vec(encrypted_wallet)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, did.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn read_vault(&self, did: &str) -> StorageResult<serde_json::Value> {
        let cf = self
            .db
            .cf_handle(CF_VAULT)
            .ok_or_else(|| StorageError::RocksDbError("missing vault CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, did.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("vault:{did}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }

    fn write_vault_recovery(&self, blind_index: &str, did: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_VAULT)
            .ok_or_else(|| StorageError::RocksDbError("missing vault CF".into()))?;
        let key = format!("recovery:{blind_index}");
        self.db
            .put_cf(&cf, key.as_bytes(), did.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn read_vault_by_recovery(&self, blind_index: &str) -> StorageResult<String> {
        let cf = self
            .db
            .cf_handle(CF_VAULT)
            .ok_or_else(|| StorageError::RocksDbError("missing vault CF".into()))?;
        let key = format!("recovery:{blind_index}");
        let data = self
            .db
            .get_cf(&cf, key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound("vault recovery entry not found".into()))?;
        String::from_utf8(data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }

    // ── Governance entities ─────────────────────────────────────────────

    fn write_scope(&self, scope: &super::traits::Scope) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_SCOPES)
            .ok_or_else(|| StorageError::RocksDbError("missing scopes CF".into()))?;
        let json = serde_json::to_vec(scope)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, scope.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_scope(&self, id: &str) -> StorageResult<super::traits::Scope> {
        let cf = self
            .db
            .cf_handle(CF_SCOPES)
            .ok_or_else(|| StorageError::RocksDbError("missing scopes CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("scope:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_scopes(&self) -> StorageResult<Vec<super::traits::Scope>> {
        let cf = self
            .db
            .cf_handle(CF_SCOPES)
            .ok_or_else(|| StorageError::RocksDbError("missing scopes CF".into()))?;
        let mut result = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let scope: super::traits::Scope = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            result.push(scope);
        }
        Ok(result)
    }
    fn delete_scope(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_SCOPES)
            .ok_or_else(|| StorageError::RocksDbError("missing scopes CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn write_assembly(&self, assembly: &super::traits::Assembly) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSEMBLIES)
            .ok_or_else(|| StorageError::RocksDbError("missing assemblies CF".into()))?;
        let json = serde_json::to_vec(assembly)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, assembly.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_assembly(&self, id: &str) -> StorageResult<super::traits::Assembly> {
        let cf = self
            .db
            .cf_handle(CF_ASSEMBLIES)
            .ok_or_else(|| StorageError::RocksDbError("missing assemblies CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("assembly:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_assemblies(&self) -> StorageResult<Vec<super::traits::Assembly>> {
        let cf = self
            .db
            .cf_handle(CF_ASSEMBLIES)
            .ok_or_else(|| StorageError::RocksDbError("missing assemblies CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            result.push(
                serde_json::from_slice(&v)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?,
            );
        }
        Ok(result)
    }
    fn list_assemblies_by_scope(
        &self,
        scope_id: &str,
    ) -> StorageResult<Vec<super::traits::Assembly>> {
        Ok(self
            .list_assemblies()?
            .into_iter()
            .filter(|a| a.scope_id == scope_id)
            .collect())
    }

    fn delete_assembly(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSEMBLIES)
            .ok_or_else(|| StorageError::RocksDbError("missing assemblies CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn write_session(&self, session: &super::traits::Session) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_SESSIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing sessions CF".into()))?;
        let json = serde_json::to_vec(session)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, session.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_session(&self, id: &str) -> StorageResult<super::traits::Session> {
        let cf = self
            .db
            .cf_handle(CF_SESSIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing sessions CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("session:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_sessions_by_assembly(
        &self,
        assembly_id: &str,
    ) -> StorageResult<Vec<super::traits::Session>> {
        let cf = self
            .db
            .cf_handle(CF_SESSIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing sessions CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let s: super::traits::Session = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if s.assembly_id == assembly_id {
                result.push(s);
            }
        }
        Ok(result)
    }

    fn delete_session(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_SESSIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing sessions CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn write_acta(&self, acta: &super::traits::Acta) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ACTAS)
            .ok_or_else(|| StorageError::RocksDbError("missing actas CF".into()))?;
        let json = serde_json::to_vec(acta)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, acta.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_acta(&self, id: &str) -> StorageResult<super::traits::Acta> {
        let cf = self
            .db
            .cf_handle(CF_ACTAS)
            .ok_or_else(|| StorageError::RocksDbError("missing actas CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("acta:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn delete_acta(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ACTAS)
            .ok_or_else(|| StorageError::RocksDbError("missing actas CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn list_actas(&self) -> StorageResult<Vec<super::traits::Acta>> {
        let cf = self
            .db
            .cf_handle(CF_ACTAS)
            .ok_or_else(|| StorageError::RocksDbError("missing actas CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            result.push(
                serde_json::from_slice(&v)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?,
            );
        }
        Ok(result)
    }

    // ── Asset Registry ──────────────────────────────────────────────────

    fn write_asset(&self, asset: &crate::registry::types::Asset) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSETS)
            .ok_or_else(|| StorageError::RocksDbError("missing assets CF".into()))?;
        let json = serde_json::to_vec(asset)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, asset.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_asset(&self, id: &str) -> StorageResult<crate::registry::types::Asset> {
        let cf = self
            .db
            .cf_handle(CF_ASSETS)
            .ok_or_else(|| StorageError::RocksDbError("missing assets CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("asset:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_assets(&self) -> StorageResult<Vec<crate::registry::types::Asset>> {
        let cf = self
            .db
            .cf_handle(CF_ASSETS)
            .ok_or_else(|| StorageError::RocksDbError("missing assets CF".into()))?;
        let mut r = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            r.push(
                serde_json::from_slice(&v)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?,
            );
        }
        Ok(r)
    }
    fn delete_asset(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSETS)
            .ok_or_else(|| StorageError::RocksDbError("missing assets CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn write_asset_event(&self, event: &crate::registry::types::AssetEvent) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_EVENTS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_events CF".into()))?;
        let json = serde_json::to_vec(event)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, event.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_asset_event(&self, id: &str) -> StorageResult<crate::registry::types::AssetEvent> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_EVENTS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_events CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("asset_event:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_asset_events(
        &self,
        asset_id: &str,
    ) -> StorageResult<Vec<crate::registry::types::AssetEvent>> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_EVENTS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_events CF".into()))?;
        let mut r = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let e: crate::registry::types::AssetEvent = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if e.asset_id == asset_id {
                r.push(e);
            }
        }
        Ok(r)
    }

    // ── RWA Tokenization ────────────────────────────────────────────────

    fn write_asset_token(
        &self,
        token: &crate::registry::tokenization::AssetToken,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_TOKENS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_tokens CF".into()))?;
        let json = serde_json::to_vec(token)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, token.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_asset_token(
        &self,
        id: &str,
    ) -> StorageResult<crate::registry::tokenization::AssetToken> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_TOKENS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_tokens CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("token:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_asset_tokens(&self) -> StorageResult<Vec<crate::registry::tokenization::AssetToken>> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_TOKENS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_tokens CF".into()))?;
        let mut r = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            r.push(
                serde_json::from_slice(&v)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?,
            );
        }
        Ok(r)
    }
    fn delete_asset_token(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ASSET_TOKENS)
            .ok_or_else(|| StorageError::RocksDbError("missing asset_tokens CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    // ── Compliance Automation ───────────────────────────────────────────

    fn write_compliance_rule(
        &self,
        rule: &crate::registry::compliance::ComplianceRule,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_COMPLIANCE_RULES)
            .ok_or_else(|| StorageError::RocksDbError("missing compliance_rules CF".into()))?;
        let json = serde_json::to_vec(rule)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, rule.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn read_compliance_rule(
        &self,
        id: &str,
    ) -> StorageResult<crate::registry::compliance::ComplianceRule> {
        let cf = self
            .db
            .cf_handle(CF_COMPLIANCE_RULES)
            .ok_or_else(|| StorageError::RocksDbError("missing compliance_rules CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("rule:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }
    fn list_compliance_rules(
        &self,
    ) -> StorageResult<Vec<crate::registry::compliance::ComplianceRule>> {
        let cf = self
            .db
            .cf_handle(CF_COMPLIANCE_RULES)
            .ok_or_else(|| StorageError::RocksDbError("missing compliance_rules CF".into()))?;
        let mut r = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            r.push(
                serde_json::from_slice(&v)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?,
            );
        }
        Ok(r)
    }
    fn delete_compliance_rule(&self, id: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_COMPLIANCE_RULES)
            .ok_or_else(|| StorageError::RocksDbError("missing compliance_rules CF".into()))?;
        self.db
            .delete_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn write_compliance_result(
        &self,
        result: &crate::registry::compliance::ComplianceResult,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_COMPLIANCE_RESULTS)
            .ok_or_else(|| StorageError::RocksDbError("missing compliance_results CF".into()))?;
        let json = serde_json::to_vec(result)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, result.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
    fn list_compliance_results(
        &self,
        asset_id: &str,
    ) -> StorageResult<Vec<crate::registry::compliance::ComplianceResult>> {
        let cf = self
            .db
            .cf_handle(CF_COMPLIANCE_RESULTS)
            .ok_or_else(|| StorageError::RocksDbError("missing compliance_results CF".into()))?;
        let mut r = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let res: crate::registry::compliance::ComplianceResult = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if res.asset_id == asset_id {
                r.push(res);
            }
        }
        Ok(r)
    }

    // ── Alias Registry ──────────────────────────────────────────────────

    fn write_alias(&self, entry: &super::traits::AliasEntry) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ALIASES)
            .ok_or_else(|| StorageError::RocksDbError("missing aliases CF".into()))?;
        let json = serde_json::to_vec(entry)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, entry.commitment.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        // Secondary index: did → commitment (for reverse lookup)
        let did_key = format!("did:{}", entry.did);
        self.db
            .put_cf(&cf, did_key.as_bytes(), entry.commitment.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn read_alias(&self, commitment: &str) -> StorageResult<super::traits::AliasEntry> {
        let cf = self
            .db
            .cf_handle(CF_ALIASES)
            .ok_or_else(|| StorageError::RocksDbError("missing aliases CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, commitment.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("alias:{commitment}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }

    fn read_alias_by_did(&self, did: &str) -> StorageResult<super::traits::AliasEntry> {
        let cf = self
            .db
            .cf_handle(CF_ALIASES)
            .ok_or_else(|| StorageError::RocksDbError("missing aliases CF".into()))?;
        let did_key = format!("did:{did}");
        let commitment_bytes = self
            .db
            .get_cf(&cf, did_key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("alias for DID:{did}")))?;
        let commitment = String::from_utf8(commitment_bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
        self.read_alias(&commitment)
    }

    fn delete_alias(&self, commitment: &str) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_ALIASES)
            .ok_or_else(|| StorageError::RocksDbError("missing aliases CF".into()))?;
        // Remove secondary index first
        if let Ok(entry) = self.read_alias(commitment) {
            let did_key = format!("did:{}", entry.did);
            let _ = self.db.delete_cf(&cf, did_key.as_bytes());
        }
        self.db
            .delete_cf(&cf, commitment.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    // ── Inference Claims ────────────────────────────────────────────────

    fn write_inference_claim(&self, claim: &super::traits::InferenceClaim) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_INFERENCE_CLAIMS)
            .ok_or_else(|| StorageError::RocksDbError("missing inference_claims CF".into()))?;
        let json = serde_json::to_vec(claim)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, claim.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        // Secondary index: oracle:{oracle_id}:{claim_id} → claim_id
        let oracle_key = format!("oracle:{}:{}", claim.oracle_id, claim.id);
        self.db
            .put_cf(&cf, oracle_key.as_bytes(), claim.id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        // Secondary index: model:{model_hash}:{claim_id} → claim_id
        let model_key = format!("model:{}:{}", claim.model_hash, claim.id);
        self.db
            .put_cf(&cf, model_key.as_bytes(), claim.id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn read_inference_claim(&self, id: &str) -> StorageResult<super::traits::InferenceClaim> {
        let cf = self
            .db
            .cf_handle(CF_INFERENCE_CLAIMS)
            .ok_or_else(|| StorageError::RocksDbError("missing inference_claims CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("inference_claim:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }

    fn list_inference_claims(
        &self,
        status: Option<&super::traits::ClaimStatus>,
        oracle_id: Option<&str>,
        model_hash: Option<&str>,
    ) -> StorageResult<Vec<super::traits::InferenceClaim>> {
        let cf = self
            .db
            .cf_handle(CF_INFERENCE_CLAIMS)
            .ok_or_else(|| StorageError::RocksDbError("missing inference_claims CF".into()))?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            // Skip secondary index keys (they start with "oracle:" or "model:")
            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("oracle:") || key_str.starts_with("model:") {
                continue;
            }
            let claim: super::traits::InferenceClaim = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if status.is_none_or(|s| &claim.status == s)
                && oracle_id.is_none_or(|o| claim.oracle_id == o)
                && model_hash.is_none_or(|m| claim.model_hash == m)
            {
                results.push(claim);
            }
        }
        Ok(results)
    }

    fn write_inference_challenge(
        &self,
        challenge: &super::traits::InferenceChallenge,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_INFERENCE_CLAIMS)
            .ok_or_else(|| StorageError::RocksDbError("missing inference_claims CF".into()))?;
        let key = format!("challenge:{}", challenge.id);
        let json = serde_json::to_vec(challenge)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        // Secondary: claim_challenge:{claim_id}:{challenge_id} → challenge_id
        let claim_key = format!("claim_challenge:{}:{}", challenge.claim_id, challenge.id);
        self.db
            .put_cf(&cf, claim_key.as_bytes(), challenge.id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn list_challenges_by_claim(
        &self,
        claim_id: &str,
    ) -> StorageResult<Vec<super::traits::InferenceChallenge>> {
        let cf = self
            .db
            .cf_handle(CF_INFERENCE_CLAIMS)
            .ok_or_else(|| StorageError::RocksDbError("missing inference_claims CF".into()))?;
        let prefix = format!("claim_challenge:{claim_id}:");
        let iter = self.db.prefix_iterator_cf(&cf, prefix.as_bytes());
        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with(&prefix) {
                break;
            }
            let challenge_id = String::from_utf8(value.to_vec())
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            let ch_key = format!("challenge:{challenge_id}");
            if let Some(data) = self
                .db
                .get_cf(&cf, ch_key.as_bytes())
                .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            {
                let challenge: super::traits::InferenceChallenge = serde_json::from_slice(&data)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                results.push(challenge);
            }
        }
        Ok(results)
    }

    // ── Invitations ─────────────────────────────────────────────────────

    fn write_invitation(&self, invitation: &super::traits::Invitation) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_INVITATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing invitations CF".into()))?;
        let json = serde_json::to_vec(invitation)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, invitation.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_invitation(&self, id: &str) -> StorageResult<super::traits::Invitation> {
        let cf = self
            .db
            .cf_handle(CF_INVITATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing invitations CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("invitation:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }

    fn list_invitations_by_commitment(
        &self,
        to_commitment: &str,
    ) -> StorageResult<Vec<super::traits::Invitation>> {
        let cf = self
            .db
            .cf_handle(CF_INVITATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing invitations CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let inv: super::traits::Invitation = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if inv.to_commitment == to_commitment {
                result.push(inv);
            }
        }
        Ok(result)
    }

    fn list_invitations_by_sender(
        &self,
        from_did: &str,
    ) -> StorageResult<Vec<super::traits::Invitation>> {
        let cf = self
            .db
            .cf_handle(CF_INVITATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing invitations CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (_, v) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let inv: super::traits::Invitation = serde_json::from_slice(&v)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if inv.from_did == from_did {
                result.push(inv);
            }
        }
        Ok(result)
    }

    // ── Notarization (Proof of Existence) ──────────────────────────────

    fn write_notarization(&self, entry: &super::traits::NotarizationEntry) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_NOTARIZATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing notarizations CF".into()))?;
        let json = serde_json::to_vec(entry)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        // Primary key: id → full entry
        self.db
            .put_cf(&cf, entry.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        // Secondary index: hash:{content_hash} → id (for verify-by-hash lookup)
        let hash_key = format!("hash:{}", entry.content_hash);
        self.db
            .put_cf(&cf, hash_key.as_bytes(), entry.id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn read_notarization(&self, id: &str) -> StorageResult<super::traits::NotarizationEntry> {
        let cf = self
            .db
            .cf_handle(CF_NOTARIZATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing notarizations CF".into()))?;
        let data = self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| StorageError::KeyNotFound(format!("notarization:{id}")))?;
        serde_json::from_slice(&data).map_err(|e| StorageError::DeserializationError(e.to_string()))
    }

    fn read_notarization_by_hash(
        &self,
        content_hash: &str,
    ) -> StorageResult<super::traits::NotarizationEntry> {
        let cf = self
            .db
            .cf_handle(CF_NOTARIZATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing notarizations CF".into()))?;
        let hash_key = format!("hash:{content_hash}");
        let id_bytes = self
            .db
            .get_cf(&cf, hash_key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .ok_or_else(|| {
                StorageError::KeyNotFound(format!("notarization:hash:{content_hash}"))
            })?;
        let id = String::from_utf8(id_bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
        self.read_notarization(&id)
    }

    fn list_notarizations(
        &self,
        signer: Option<&str>,
    ) -> StorageResult<Vec<super::traits::NotarizationEntry>> {
        let cf = self
            .db
            .cf_handle(CF_NOTARIZATIONS)
            .ok_or_else(|| StorageError::RocksDbError("missing notarizations CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (key, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            // Skip secondary index keys
            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("hash:") {
                continue;
            }
            let entry: super::traits::NotarizationEntry = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if signer.is_none_or(|s| entry.signer == s) {
                result.push(entry);
            }
        }
        result.sort_by_key(|b| std::cmp::Reverse(b.notarized_at));
        Ok(result)
    }

    // ── Ownership Transfers ─────────────────────────────────────────────

    fn write_ownership_transfer(
        &self,
        transfer: &super::traits::OwnershipTransfer,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_OWNERSHIP_TRANSFERS)
            .ok_or_else(|| StorageError::RocksDbError("missing ownership_transfers CF".into()))?;
        let key = format!("{}:{:012}", transfer.content_hash, transfer.transferred_at);
        let value = serde_json::to_vec(transfer)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn read_ownership_transfers(
        &self,
        content_hash: &str,
    ) -> StorageResult<Vec<super::traits::OwnershipTransfer>> {
        let cf = self
            .db
            .cf_handle(CF_OWNERSHIP_TRANSFERS)
            .ok_or_else(|| StorageError::RocksDbError("missing ownership_transfers CF".into()))?;
        let prefix = format!("{content_hash}:");
        let mut result = Vec::new();
        for item in self.db.prefix_iterator_cf(&cf, prefix.as_bytes()) {
            let (key, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let key_str = String::from_utf8_lossy(&key);
            match key_str.starts_with(&prefix) {
                true => {
                    let transfer: super::traits::OwnershipTransfer = serde_json::from_slice(&value)
                        .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                    result.push(transfer);
                }
                false => break,
            }
        }
        result.sort_by_key(|t| t.transferred_at);
        Ok(result)
    }

    fn write_lexcontract(
        &self,
        contract: &crate::lexchain::types::LexContract,
    ) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_LEXCONTRACTS)
            .ok_or_else(|| StorageError::RocksDbError("missing lexcontracts CF".into()))?;
        let json = serde_json::to_vec(contract)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, contract.id.as_bytes(), &json)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_lexcontract(&self, id: &str) -> StorageResult<crate::lexchain::types::LexContract> {
        let cf = self
            .db
            .cf_handle(CF_LEXCONTRACTS)
            .ok_or_else(|| StorageError::RocksDbError("missing lexcontracts CF".into()))?;
        match self
            .db
            .get_cf(&cf, id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(format!("lexcontract:{id}"))),
        }
    }

    fn list_lexcontracts(&self) -> StorageResult<Vec<crate::lexchain::types::LexContract>> {
        let cf = self
            .db
            .cf_handle(CF_LEXCONTRACTS)
            .ok_or_else(|| StorageError::RocksDbError("missing lexcontracts CF".into()))?;
        let mut result = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (_, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let contract: crate::lexchain::types::LexContract = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            result.push(contract);
        }
        Ok(result)
    }
}

impl OrgRegistry for RocksDbBlockStore {
    fn register_org(&self, org: &Organization) -> StorageResult<()> {
        let cf = self.cf_organizations()?;
        let value =
            serde_json::to_vec(org).map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, org.org_id.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn get_org(&self, org_id: &str) -> StorageResult<Organization> {
        let cf = self.cf_organizations()?;
        match self
            .db
            .get_cf(&cf, org_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(org_id.to_string())),
        }
    }

    fn list_orgs(&self) -> StorageResult<Vec<Organization>> {
        let cf = self.cf_organizations()?;
        let mut orgs = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (_, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let org: Organization = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            orgs.push(org);
        }
        Ok(orgs)
    }

    fn remove_org(&self, org_id: &str) -> StorageResult<()> {
        let cf = self.cf_organizations()?;
        // Verify it exists first
        if self
            .db
            .get_cf(&cf, org_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
            .is_none()
        {
            return Err(StorageError::KeyNotFound(org_id.to_string()));
        }
        self.db
            .delete_cf(&cf, org_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
}

impl crate::msp::CrlStore for RocksDbBlockStore {
    fn write_crl(&self, msp_id: &str, serials: &[String]) -> StorageResult<()> {
        let cf = self.cf_crl()?;
        let value = serde_json::to_vec(serials)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, msp_id.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn read_crl(&self, msp_id: &str) -> StorageResult<Vec<String>> {
        let cf = self.cf_crl()?;
        match self
            .db
            .get_cf(&cf, msp_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Ok(Vec::new()),
        }
    }
}

impl WorldState for RocksDbBlockStore {
    fn get(&self, key: &str) -> StorageResult<Option<VersionedValue>> {
        self.world_state_get(key)
    }

    fn put(&self, key: &str, data: &[u8]) -> StorageResult<u64> {
        self.world_state_put(key, data)
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let cf = self.cf_world_state()?;
        self.db
            .delete_cf(&cf, key.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn get_range(&self, start: &str, end: &str) -> StorageResult<Vec<(String, VersionedValue)>> {
        let cf = self.cf_world_state()?;
        let mut result = Vec::new();
        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(start.as_bytes(), Direction::Forward),
        );
        for item in iter {
            let (raw_key, raw_value) =
                item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let k = String::from_utf8(raw_key.to_vec())
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            if k.as_str() >= end {
                break;
            }
            let vv: VersionedValue = serde_json::from_slice(&raw_value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            result.push((k, vv));
        }
        Ok(result)
    }

    fn get_history(&self, key: &str) -> StorageResult<Vec<crate::storage::traits::HistoryEntry>> {
        self.get_history(key)
    }
}

// ── Chaincode package storage ─────────────────────────────────────────────────

impl RocksDbBlockStore {
    /// Compose the CF key as `{chaincode_id}:{version}`.
    fn package_key(chaincode_id: &str, version: &str) -> Vec<u8> {
        format!("{chaincode_id}:{version}").into_bytes()
    }

    /// Store raw Wasm bytes for a chaincode package.
    pub fn store_package(
        &self,
        chaincode_id: &str,
        version: &str,
        wasm_bytes: &[u8],
    ) -> StorageResult<()> {
        let cf = self.cf_chaincode_packages()?;
        self.db
            .put_cf(&cf, Self::package_key(chaincode_id, version), wasm_bytes)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    /// Retrieve raw Wasm bytes for a chaincode package, or `None` if not found.
    pub fn get_package(&self, chaincode_id: &str, version: &str) -> StorageResult<Option<Vec<u8>>> {
        let cf = self.cf_chaincode_packages()?;
        self.db
            .get_cf(&cf, Self::package_key(chaincode_id, version))
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
}

// ── ChaincodePackageStore impl ────────────────────────────────────────────────

impl ChaincodePackageStore for RocksDbBlockStore {
    fn store_package(
        &self,
        chaincode_id: &str,
        version: &str,
        wasm_bytes: &[u8],
    ) -> Result<(), ChaincodeError> {
        self.store_package(chaincode_id, version, wasm_bytes)
            .map_err(|e| ChaincodeError::Storage(e.to_string()))
    }

    fn get_package(
        &self,
        chaincode_id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, ChaincodeError> {
        self.get_package(chaincode_id, version)
            .map_err(|e| ChaincodeError::Storage(e.to_string()))
    }
}

// ── PrivateDataStore impl ─────────────────────────────────────────────────────

impl RocksDbBlockStore {
    /// CF name for a private data collection: `private_{collection_name}`.
    fn private_cf_name(collection_name: &str) -> String {
        format!("private_{collection_name}")
    }

    /// Ensure the side CF for `collection_name` exists, creating it if needed.
    fn ensure_private_cf(&self, collection_name: &str) -> StorageResult<()> {
        let cf_name = Self::private_cf_name(collection_name);
        if self.db.cf_handle(&cf_name).is_none() {
            self.db
                .create_cf(&cf_name, &Options::default())
                .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        }
        Ok(())
    }
}

impl PrivateDataStore for RocksDbBlockStore {
    fn put_private_data(
        &self,
        collection_name: &str,
        key: &str,
        value: &[u8],
    ) -> StorageResult<[u8; 32]> {
        self.ensure_private_cf(collection_name)?;
        let cf_name = Self::private_cf_name(collection_name);
        let cf = self
            .db
            .cf_handle(&cf_name)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(cf_name.clone()))?;
        let hash = sha256(value);
        self.db
            .put_cf(&cf, key.as_bytes(), value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(hash)
    }

    fn get_private_data(&self, collection_name: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.ensure_private_cf(collection_name)?;
        let cf_name = Self::private_cf_name(collection_name);
        let cf = self
            .db
            .cf_handle(&cf_name)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(cf_name.clone()))?;
        self.db
            .get_cf(&cf, key.as_bytes())
            .map(|opt| opt.map(|b| b.to_vec()))
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
}

impl crate::acl::AclProvider for RocksDbBlockStore {
    fn set_acl(&self, resource: &str, policy_ref: &str) -> StorageResult<()> {
        let cf = self.cf_acls()?;
        let entry = crate::acl::AclEntry::new(resource, policy_ref);
        let bytes = serde_json::to_vec(&entry)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, resource.as_bytes(), bytes)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn get_acl(&self, resource: &str) -> StorageResult<Option<crate::acl::AclEntry>> {
        let cf = self.cf_acls()?;
        match self.db.get_cf(&cf, resource.as_bytes()) {
            Ok(Some(bytes)) => {
                let entry = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::RocksDbError(e.to_string())),
        }
    }

    fn list_acls(&self) -> StorageResult<Vec<crate::acl::AclEntry>> {
        let cf = self.cf_acls()?;
        let mut entries = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (_, value) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let entry: crate::acl::AclEntry = serde_json::from_slice(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn remove_acl(&self, resource: &str) -> StorageResult<()> {
        let cf = self.cf_acls()?;
        self.db
            .delete_cf(&cf, resource.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }
}

impl RocksDbBlockStore {
    #[allow(dead_code)]
    /// Persist a [`ChannelConfig`] snapshot.
    ///
    /// Key format: `{channel_id}:{version:012}` — zero-padded so lexicographic
    /// order matches numeric order, enabling cheap prefix range scans.
    pub fn write_channel_config(
        &self,
        channel_id: &str,
        config: &crate::channel::config::ChannelConfig,
    ) -> StorageResult<()> {
        let cf = self.cf_channel_configs()?;
        let key = format!("{channel_id}:{:012}", config.version);
        let value = serde_json::to_vec(config)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    #[allow(dead_code)]
    /// Read a specific version of a channel's config. Returns `None` if not found.
    pub fn read_channel_config(
        &self,
        channel_id: &str,
        version: u64,
    ) -> StorageResult<Option<crate::channel::config::ChannelConfig>> {
        let cf = self.cf_channel_configs()?;
        let key = format!("{channel_id}:{version:012}");
        match self.db.get_cf(&cf, key.as_bytes()) {
            Ok(Some(bytes)) => {
                let config = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(config))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::RocksDbError(e.to_string())),
        }
    }

    #[allow(dead_code)]
    /// List all stored version numbers for `channel_id` in ascending order.
    pub fn list_channel_versions(&self, channel_id: &str) -> StorageResult<Vec<u64>> {
        let cf = self.cf_channel_configs()?;
        let prefix = format!("{channel_id}:");
        let iter = self.db.iterator_cf(
            &cf,
            IteratorMode::From(prefix.as_bytes(), Direction::Forward),
        );
        let mut versions = Vec::new();
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let key_str = std::str::from_utf8(&key)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            if !key_str.starts_with(&prefix) {
                break;
            }
            let version_str = &key_str[prefix.len()..];
            let version: u64 = version_str.parse().map_err(|e: std::num::ParseIntError| {
                StorageError::SerializationError(e.to_string())
            })?;
            versions.push(version);
        }
        Ok(versions)
    }
}

// ── CF helpers for new persistent stores ─────────────────────────────────────

impl RocksDbBlockStore {
    fn cf_endorsement_policies(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_ENDORSEMENT_POLICIES)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_ENDORSEMENT_POLICIES.to_string()))
    }

    fn cf_collections(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_COLLECTIONS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_COLLECTIONS.to_string()))
    }

    fn cf_chaincode_definitions(&self) -> StorageResult<Arc<rocksdb::BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(CF_CHAINCODE_DEFINITIONS)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(CF_CHAINCODE_DEFINITIONS.to_string()))
    }
}

// ── PolicyStore ──────────────────────────────────────────────────────────────

impl crate::endorsement::policy_store::PolicyStore for RocksDbBlockStore {
    fn set_policy(
        &self,
        resource_id: &str,
        policy: &crate::endorsement::policy::EndorsementPolicy,
    ) -> StorageResult<()> {
        let cf = self.cf_endorsement_policies()?;
        let value = serde_json::to_vec(policy)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, resource_id.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))
    }

    fn get_policy(
        &self,
        resource_id: &str,
    ) -> StorageResult<crate::endorsement::policy::EndorsementPolicy> {
        let cf = self.cf_endorsement_policies()?;
        match self
            .db
            .get_cf(&cf, resource_id.as_bytes())
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::DeserializationError(e.to_string())),
            None => Err(StorageError::KeyNotFound(resource_id.to_string())),
        }
    }
}

// ── CollectionRegistry ───────────────────────────────────────────────────────

impl crate::private_data::CollectionRegistry for RocksDbBlockStore {
    fn register(
        &self,
        collection: crate::private_data::PrivateDataCollection,
    ) -> Result<(), crate::private_data::PrivateDataError> {
        let cf = self
            .cf_collections()
            .map_err(|e| crate::private_data::PrivateDataError::InvalidCollection(e.to_string()))?;
        let value = serde_json::to_vec(&collection)
            .map_err(|e| crate::private_data::PrivateDataError::InvalidCollection(e.to_string()))?;
        self.db
            .put_cf(&cf, collection.name.as_bytes(), &value)
            .map_err(|e| crate::private_data::PrivateDataError::InvalidCollection(e.to_string()))
    }

    fn get(&self, name: &str) -> Option<crate::private_data::PrivateDataCollection> {
        let cf = self.cf_collections().ok()?;
        let bytes = self.db.get_cf(&cf, name.as_bytes()).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    fn list(&self) -> Vec<crate::private_data::PrivateDataCollection> {
        let cf = match self.cf_collections() {
            Ok(cf) => cf,
            Err(_) => return Vec::new(),
        };
        let mut result = Vec::new();
        for (_, value) in self.db.iterator_cf(&cf, IteratorMode::Start).flatten() {
            if let Ok(col) = serde_json::from_slice(&value) {
                result.push(col);
            }
        }
        result
    }
}

// ── ChaincodeDefinitionStore ─────────────────────────────────────────────────

impl crate::chaincode::ChaincodeDefinitionStore for RocksDbBlockStore {
    fn upsert_definition(
        &self,
        def: crate::chaincode::definition::ChaincodeDefinition,
    ) -> Result<(), crate::chaincode::ChaincodeError> {
        let cf = self
            .cf_chaincode_definitions()
            .map_err(|e| crate::chaincode::ChaincodeError::Execution(e.to_string()))?;
        let key = format!("{}:{}", def.chaincode_id, def.version);
        let value = serde_json::to_vec(&def)
            .map_err(|e| crate::chaincode::ChaincodeError::Execution(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| crate::chaincode::ChaincodeError::Execution(e.to_string()))
    }

    fn get_definition(
        &self,
        chaincode_id: &str,
        version: &str,
    ) -> Result<
        Option<crate::chaincode::definition::ChaincodeDefinition>,
        crate::chaincode::ChaincodeError,
    > {
        let cf = self
            .cf_chaincode_definitions()
            .map_err(|e| crate::chaincode::ChaincodeError::Execution(e.to_string()))?;
        let key = format!("{chaincode_id}:{version}");
        match self
            .db
            .get_cf(&cf, key.as_bytes())
            .map_err(|e| crate::chaincode::ChaincodeError::Execution(e.to_string()))?
        {
            Some(bytes) => {
                let def = serde_json::from_slice(&bytes)
                    .map_err(|e| crate::chaincode::ChaincodeError::Execution(e.to_string()))?;
                Ok(Some(def))
            }
            None => Ok(None),
        }
    }
}

// ── AuditStore on RocksDB ────────────────────────────────────────────────────

impl crate::audit::AuditStore for RocksDbBlockStore {
    fn append(&self, entry: &crate::audit::AuditEntry) -> StorageResult<()> {
        let cf = self
            .db
            .cf_handle(CF_AUDIT_LOG)
            .ok_or_else(|| StorageError::RocksDbError("missing audit_log CF".to_string()))?;
        let key = format!("{}:{}", entry.timestamp, entry.trace_id);
        let value = serde_json::to_vec(entry)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key.as_bytes(), &value)
            .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        Ok(())
    }

    fn query(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        org_id: Option<&str>,
        action: Option<&crate::audit::AuditAction>,
        limit: usize,
    ) -> StorageResult<Vec<crate::audit::AuditEntry>> {
        let cf = self
            .db
            .cf_handle(CF_AUDIT_LOG)
            .ok_or_else(|| StorageError::RocksDbError("missing audit_log CF".to_string()))?;

        let mode = match from {
            Some(f) => IteratorMode::From(f.as_bytes(), Direction::Forward),
            None => IteratorMode::Start,
        };

        let mut results = Vec::new();
        for item in self.db.iterator_cf(&cf, mode) {
            let (key_bytes, val_bytes) =
                item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let key_str = String::from_utf8_lossy(&key_bytes);
            // Key format: "{timestamp}:{trace_id}" — extract timestamp prefix
            let ts = key_str.split(':').next().unwrap_or("");
            if let Some(t) = to {
                if ts > t {
                    break;
                }
            }
            let entry: crate::audit::AuditEntry = serde_json::from_slice(&val_bytes)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            if let Some(org) = org_id {
                if entry.org_id != org {
                    continue;
                }
            }
            if let Some(act) = action {
                if &entry.action != act {
                    continue;
                }
            }
            results.push(entry);
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    fn purge_expired(
        &self,
        policy: &crate::audit_retention::AuditRetentionPolicy,
        now_secs: u64,
    ) -> StorageResult<usize> {
        if !policy.auto_purge_enabled || policy.max_retention_secs == 0 {
            return Ok(0);
        }
        let cf = self
            .db
            .cf_handle(CF_AUDIT_LOG)
            .ok_or_else(|| StorageError::RocksDbError("missing audit_log CF".to_string()))?;

        let mut to_delete = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (key_bytes, val_bytes) =
                item.map_err(|e| StorageError::RocksDbError(e.to_string()))?;
            let ts = serde_json::from_slice::<crate::audit::AuditEntry>(&val_bytes)
                .ok()
                .and_then(|e| {
                    chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                        .map(|dt| dt.timestamp() as u64)
                        .ok()
                })
                .unwrap_or(0);
            if policy.is_purgeable(ts, now_secs) {
                to_delete.push(key_bytes.to_vec());
            }
        }

        let count = to_delete.len();
        for key in &to_delete {
            self.db
                .delete_cf(&cf, key)
                .map_err(|e| StorageError::RocksDbError(e.to_string()))?;
        }
        Ok(count)
    }
}

// ── SandboxReportStore on RocksDB ────────────────────────────────────────────

impl crate::chaincode::sandbox::SandboxReportStore for RocksDbBlockStore {
    fn store_report(&self, report: &crate::chaincode::sandbox::SandboxReport) {
        let cf = match self.db.cf_handle(CF_SANDBOX_REPORTS) {
            Some(cf) => cf,
            None => return,
        };
        let key = format!("{}:{}", report.chaincode_id, report.version);
        if let Ok(value) = serde_json::to_vec(report) {
            let _ = self.db.put_cf(&cf, key.as_bytes(), &value);
        }
    }

    fn get_report(
        &self,
        chaincode_id: &str,
        version: &str,
    ) -> Option<crate::chaincode::sandbox::SandboxReport> {
        let cf = self.db.cf_handle(CF_SANDBOX_REPORTS)?;
        let key = format!("{chaincode_id}:{version}");
        let bytes = self.db.get_cf(&cf, key.as_bytes()).ok()??;
        serde_json::from_slice(&bytes).ok()
    }
}

// ── OracleRecordStore on RocksDB ─────────────────────────────────────────────

impl crate::legal_oracle::OracleRecordStore for RocksDbBlockStore {
    fn store(
        &self,
        record: &crate::legal_oracle::OracleRecord,
    ) -> Result<(), crate::legal_oracle::OracleError> {
        let cf = self.db.cf_handle(CF_ORACLE_RECORDS).ok_or_else(|| {
            crate::legal_oracle::OracleError::Storage("missing oracle_records CF".to_string())
        })?;
        let value = serde_json::to_vec(record)
            .map_err(|e| crate::legal_oracle::OracleError::Storage(e.to_string()))?;
        self.db
            .put_cf(&cf, record.id.as_bytes(), &value)
            .map_err(|e| crate::legal_oracle::OracleError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get(
        &self,
        id: &str,
    ) -> Result<Option<crate::legal_oracle::OracleRecord>, crate::legal_oracle::OracleError> {
        let cf = self.db.cf_handle(CF_ORACLE_RECORDS).ok_or_else(|| {
            crate::legal_oracle::OracleError::Storage("missing oracle_records CF".to_string())
        })?;
        match self.db.get_cf(&cf, id.as_bytes()) {
            Ok(Some(bytes)) => {
                let record = serde_json::from_slice(&bytes)
                    .map_err(|e| crate::legal_oracle::OracleError::Storage(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(crate::legal_oracle::OracleError::Storage(e.to_string())),
        }
    }

    fn list(
        &self,
        source: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::legal_oracle::OracleRecord>, crate::legal_oracle::OracleError> {
        let cf = self.db.cf_handle(CF_ORACLE_RECORDS).ok_or_else(|| {
            crate::legal_oracle::OracleError::Storage("missing oracle_records CF".to_string())
        })?;
        let mut results = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (_key, val) =
                item.map_err(|e| crate::legal_oracle::OracleError::Storage(e.to_string()))?;
            let record: crate::legal_oracle::OracleRecord = serde_json::from_slice(&val)
                .map_err(|e| crate::legal_oracle::OracleError::Storage(e.to_string()))?;
            if source.is_none_or(|s| record.source == s) {
                results.push(record);
            }
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AclProvider;
    use crate::msp::CrlStore;
    use tempfile::TempDir;

    fn tmp_store() -> (RocksDbBlockStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = RocksDbBlockStore::new(dir.path()).unwrap();
        (store, dir)
    }

    // ── create_channel_store tests ────────────────────────────────────────────

    #[test]
    fn create_channel_store_opens_at_channels_subdir() {
        let base = TempDir::new().unwrap();
        let store = RocksDbBlockStore::create_channel_store("ch-01", base.path());
        assert!(store.is_ok());
        let expected = base.path().join("channels").join("ch-01");
        assert!(expected.exists());
    }

    #[test]
    fn create_channel_store_two_channels_are_isolated() {
        let base = TempDir::new().unwrap();
        let _s1 = RocksDbBlockStore::create_channel_store("alpha", base.path()).unwrap();
        let _s2 = RocksDbBlockStore::create_channel_store("beta", base.path()).unwrap();
        assert!(base.path().join("channels").join("alpha").exists());
        assert!(base.path().join("channels").join("beta").exists());
    }

    #[test]
    fn create_channel_store_rejects_empty_id() {
        let base = TempDir::new().unwrap();
        let err = RocksDbBlockStore::create_channel_store("", base.path())
            .err()
            .expect("expected InvalidChannelId error");
        assert!(matches!(err, StorageError::InvalidChannelId(_)));
    }

    #[test]
    fn create_channel_store_rejects_path_traversal() {
        let base = TempDir::new().unwrap();
        let err = RocksDbBlockStore::create_channel_store("../evil", base.path())
            .err()
            .expect("expected InvalidChannelId error");
        assert!(matches!(err, StorageError::InvalidChannelId(_)));
    }

    #[test]
    fn create_channel_store_rejects_slash_in_id() {
        let base = TempDir::new().unwrap();
        let err = RocksDbBlockStore::create_channel_store("a/b", base.path())
            .err()
            .expect("expected InvalidChannelId error");
        assert!(matches!(err, StorageError::InvalidChannelId(_)));
    }

    #[test]
    fn create_channel_store_accepts_alphanumeric_hyphen_underscore() {
        let base = TempDir::new().unwrap();
        assert!(RocksDbBlockStore::create_channel_store("Channel_01-test", base.path()).is_ok());
    }

    #[test]
    fn create_channel_store_is_functional_store() {
        let base = TempDir::new().unwrap();
        let store = RocksDbBlockStore::create_channel_store("ch-functional", base.path()).unwrap();
        // get_latest_height returns 0 on an empty store
        assert!(store.get_latest_height().is_ok());
    }

    fn sample_block(height: u64) -> Block {
        Block {
            height,
            timestamp: 1_000,
            parent_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            transactions: vec!["tx1".to_string()],
            proposer: "proposer1".to_string(),
            signature: vec![2u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        }
    }

    fn sample_tx(id: &str) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: 1,
            timestamp: 1_000,
            input_did: "did:goya:input".to_string(),
            output_recipient: "did:goya:output".to_string(),
            amount: 100,
            state: "confirmed".to_string(),
            fee: 0,
            payload: None,
        }
    }

    // ── Key encoding ─────────────────────────────────────────────────────────

    #[test]
    fn block_key_is_zero_padded() {
        assert_eq!(RocksDbBlockStore::block_key(1), b"000000000001");
        assert_eq!(RocksDbBlockStore::block_key(123456), b"000000123456");
    }

    #[test]
    fn block_key_lexicographic_order_matches_numeric() {
        let k1 = RocksDbBlockStore::block_key(9);
        let k2 = RocksDbBlockStore::block_key(10);
        assert!(k1 < k2, "lexicographic order must match numeric order");
    }

    // ── Column Family presence ────────────────────────────────────────────────

    #[test]
    fn all_column_families_exist_after_open() {
        let (store, _dir) = tmp_store();
        assert!(store.cf_blocks().is_ok());
        assert!(store.cf_transactions().is_ok());
        assert!(store.cf_identities().is_ok());
        assert!(store.cf_credentials().is_ok());
        assert!(store.cf_meta().is_ok());
    }

    #[test]
    fn reopening_existing_db_preserves_data() {
        let dir = TempDir::new().unwrap();
        {
            let store = RocksDbBlockStore::new(dir.path()).unwrap();
            store.write_block(&sample_block(1)).unwrap();
        }
        // Re-open same path
        let store2 = RocksDbBlockStore::new(dir.path()).unwrap();
        assert!(store2.block_exists(1).unwrap());
        assert_eq!(store2.get_latest_height().unwrap(), 1);
    }

    // ── Block operations ─────────────────────────────────────────────────────

    #[test]
    fn write_and_read_block_roundtrip() {
        let (store, _dir) = tmp_store();
        store.write_block(&sample_block(1)).unwrap();
        let block = store.read_block(1).unwrap();
        assert_eq!(block.height, 1);
        assert_eq!(block.proposer, "proposer1");
    }

    #[test]
    fn read_block_not_found() {
        let (store, _dir) = tmp_store();
        assert!(store.read_block(999).is_err());
    }

    #[test]
    fn block_exists_after_write() {
        let (store, _dir) = tmp_store();
        assert!(!store.block_exists(5).unwrap());
        store.write_block(&sample_block(5)).unwrap();
        assert!(store.block_exists(5).unwrap());
    }

    #[test]
    fn latest_height_tracks_writes() {
        let (store, _dir) = tmp_store();
        assert_eq!(store.get_latest_height().unwrap(), 0);
        store.write_block(&sample_block(3)).unwrap();
        assert_eq!(store.get_latest_height().unwrap(), 3);
        store.write_block(&sample_block(7)).unwrap();
        assert_eq!(store.get_latest_height().unwrap(), 7);
        // Writing an older block does not decrease latest
        store.write_block(&sample_block(2)).unwrap();
        assert_eq!(store.get_latest_height().unwrap(), 7);
    }

    // ── Transaction operations ───────────────────────────────────────────────

    #[test]
    fn write_and_read_transaction_roundtrip() {
        let (store, _dir) = tmp_store();
        store.write_transaction(&sample_tx("tx123")).unwrap();
        let tx = store.read_transaction("tx123").unwrap();
        assert_eq!(tx.id, "tx123");
        assert_eq!(tx.amount, 100);
    }

    #[test]
    fn transaction_stored_in_own_cf_not_visible_as_block() {
        let (store, _dir) = tmp_store();
        store
            .write_transaction(&sample_tx("tx-cf-isolation"))
            .unwrap();
        // height 0 should not exist (tx keys are strings, block keys are numbers)
        assert!(!store.block_exists(0).unwrap());
    }

    // ── Identity operations ──────────────────────────────────────────────────

    #[test]
    fn write_and_read_identity_roundtrip() {
        let (store, _dir) = tmp_store();
        let identity = IdentityRecord {
            did: "did:goya:123".to_string(),
            public_key: String::new(),
            created_at: 1_000,
            updated_at: 2_000,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
        };
        store.write_identity(&identity).unwrap();
        let loaded = store.read_identity("did:goya:123").unwrap();
        assert_eq!(loaded.did, "did:goya:123");
        assert_eq!(loaded.status, "active");
    }

    #[test]
    fn read_identity_not_found_returns_identity_error() {
        let (store, _dir) = tmp_store();
        let err = store.read_identity("did:goya:ghost").unwrap_err();
        assert!(matches!(err, StorageError::IdentityNotFound(_)));
    }

    // ── Credential operations ────────────────────────────────────────────────

    #[test]
    fn write_and_read_credential_roundtrip() {
        let (store, _dir) = tmp_store();
        let cred = Credential {
            id: "cred-1".to_string(),
            issuer_did: "did:goya:issuer".to_string(),
            subject_did: "did:goya:subject".to_string(),
            cred_type: "eid".to_string(),
            issued_at: 1_000,
            expires_at: 2_000,
            revoked_at: None,
            ..Default::default()
        };
        store.write_credential(&cred).unwrap();
        let loaded = store.read_credential("cred-1").unwrap();
        assert_eq!(loaded.id, "cred-1");
        assert_eq!(loaded.cred_type, "eid");
    }

    #[test]
    fn read_credential_not_found_returns_credential_error() {
        let (store, _dir) = tmp_store();
        let err = store.read_credential("ghost").unwrap_err();
        assert!(matches!(err, StorageError::CredentialNotFound(_)));
    }

    // ── Batch operations ─────────────────────────────────────────────────────

    #[test]
    fn write_batch_empty_fails() {
        let (store, _dir) = tmp_store();
        assert!(store.write_batch(&[], &[]).is_err());
    }

    #[test]
    fn write_batch_atomically_stores_blocks_and_txs() {
        let (store, _dir) = tmp_store();
        let blocks = vec![sample_block(10), sample_block(11)];
        let txs = vec![sample_tx("batch-tx-1")];
        store.write_batch(&blocks, &txs).unwrap();
        assert!(store.block_exists(10).unwrap());
        assert!(store.block_exists(11).unwrap());
        assert_eq!(
            store.read_transaction("batch-tx-1").unwrap().id,
            "batch-tx-1"
        );
        assert_eq!(store.get_latest_height().unwrap(), 11);
    }

    #[test]
    fn write_batch_txs_only_does_not_update_latest_height() {
        let (store, _dir) = tmp_store();
        store.write_block(&sample_block(5)).unwrap();
        store.write_batch(&[], &[sample_tx("only-tx")]).unwrap();
        // Latest height unchanged — no blocks in batch
        assert_eq!(store.get_latest_height().unwrap(), 5);
    }

    // ── Secondary index: tx_by_block_height ───────────────────────────────────

    fn tx_at_height(id: &str, height: u64) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: height,
            timestamp: 1_000,
            input_did: "did:goya:in".to_string(),
            output_recipient: "did:goya:out".to_string(),
            amount: 1,
            state: "confirmed".to_string(),
            fee: 0,
            payload: None,
        }
    }

    #[test]
    fn index_key_format_is_correct() {
        let key = RocksDbBlockStore::tx_block_index_key(7, "abc");
        assert_eq!(key, b"000000000007:abc");
        let prefix = RocksDbBlockStore::tx_block_prefix(7);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn transactions_by_block_height_returns_empty_for_unknown_height() {
        let (store, _dir) = tmp_store();
        let txs = store.transactions_by_block_height(99).unwrap();
        assert!(txs.is_empty());
    }

    #[test]
    fn write_transaction_is_queryable_by_block_height() {
        let (store, _dir) = tmp_store();
        store.write_transaction(&tx_at_height("tx-a", 5)).unwrap();
        store.write_transaction(&tx_at_height("tx-b", 5)).unwrap();
        store.write_transaction(&tx_at_height("tx-c", 6)).unwrap();

        let block5 = store.transactions_by_block_height(5).unwrap();
        let ids: Vec<&str> = block5.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"tx-a"));
        assert!(ids.contains(&"tx-b"));

        let block6 = store.transactions_by_block_height(6).unwrap();
        assert_eq!(block6.len(), 1);
        assert_eq!(block6[0].id, "tx-c");
    }

    #[test]
    fn write_batch_indexes_transactions_by_block_height() {
        let (store, _dir) = tmp_store();
        let txs = vec![tx_at_height("btx-1", 10), tx_at_height("btx-2", 10)];
        store.write_batch(&[sample_block(10)], &txs).unwrap();

        let result = store.transactions_by_block_height(10).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn index_does_not_cross_height_boundaries() {
        let (store, _dir) = tmp_store();
        // heights 9 and 10 have similar decimal prefix — confirm no bleed-over
        store.write_transaction(&tx_at_height("tx-9", 9)).unwrap();
        store.write_transaction(&tx_at_height("tx-10", 10)).unwrap();

        assert_eq!(store.transactions_by_block_height(9).unwrap().len(), 1);
        assert_eq!(store.transactions_by_block_height(10).unwrap().len(), 1);
    }

    // ── Secondary index: cred_by_subject_did ─────────────────────────────────

    fn cred_for_subject(id: &str, subject_did: &str) -> Credential {
        Credential {
            id: id.to_string(),
            issuer_did: "did:goya:issuer".to_string(),
            subject_did: subject_did.to_string(),
            cred_type: "eid".to_string(),
            issued_at: 1_000,
            expires_at: 9_999,
            revoked_at: None,
            ..Default::default()
        }
    }

    #[test]
    fn cred_subject_index_key_format_is_correct() {
        let key = RocksDbBlockStore::cred_subject_index_key("did:goya:alice", "cred-1");
        let prefix = RocksDbBlockStore::cred_subject_prefix("did:goya:alice");
        assert!(key.starts_with(&prefix));
        // cred_id follows the NUL separator
        assert_eq!(&key[prefix.len()..], b"cred-1");
    }

    #[test]
    fn credentials_by_subject_did_returns_empty_for_unknown_subject() {
        let (store, _dir) = tmp_store();
        assert!(store
            .credentials_by_subject_did("did:goya:ghost")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn write_credential_is_queryable_by_subject_did() {
        let (store, _dir) = tmp_store();
        store
            .write_credential(&cred_for_subject("cred-1", "did:goya:alice"))
            .unwrap();
        store
            .write_credential(&cred_for_subject("cred-2", "did:goya:alice"))
            .unwrap();
        store
            .write_credential(&cred_for_subject("cred-3", "did:goya:bob"))
            .unwrap();

        let alice = store.credentials_by_subject_did("did:goya:alice").unwrap();
        let ids: Vec<&str> = alice.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"cred-1"));
        assert!(ids.contains(&"cred-2"));

        let bob = store.credentials_by_subject_did("did:goya:bob").unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].id, "cred-3");
    }

    #[test]
    fn cred_subject_index_does_not_cross_subject_boundaries() {
        let (store, _dir) = tmp_store();
        // "did:goya:ali" is a prefix of "did:goya:alice" — confirm no bleed-over
        store
            .write_credential(&cred_for_subject("cred-a", "did:goya:ali"))
            .unwrap();
        store
            .write_credential(&cred_for_subject("cred-b", "did:goya:alice"))
            .unwrap();

        assert_eq!(
            store
                .credentials_by_subject_did("did:goya:ali")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .credentials_by_subject_did("did:goya:alice")
                .unwrap()
                .len(),
            1
        );
    }

    // ── OrgRegistry (RocksDB) ─────────────────────────────────────────────────

    fn make_org(id: &str) -> Organization {
        Organization::new(
            id,
            format!("{id}MSP"),
            vec![format!("did:goya:{id}:admin")],
            vec![],
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn org_write_read_roundtrip() {
        let (store, _dir) = tmp_store();
        let org = make_org("org1");
        OrgRegistry::register_org(&store, &org).unwrap();
        let retrieved = OrgRegistry::get_org(&store, "org1").unwrap();
        assert_eq!(retrieved.org_id, "org1");
        assert_eq!(retrieved.msp_id, "org1MSP");
    }

    #[test]
    fn org_list() {
        let (store, _dir) = tmp_store();
        OrgRegistry::register_org(&store, &make_org("org1")).unwrap();
        OrgRegistry::register_org(&store, &make_org("org2")).unwrap();
        let orgs = OrgRegistry::list_orgs(&store).unwrap();
        assert_eq!(orgs.len(), 2);
    }

    #[test]
    fn org_remove() {
        let (store, _dir) = tmp_store();
        OrgRegistry::register_org(&store, &make_org("org1")).unwrap();
        OrgRegistry::remove_org(&store, "org1").unwrap();
        assert!(OrgRegistry::get_org(&store, "org1").is_err());
    }

    // ── CRL tests ─────────────────────────────────────────────────────────────

    #[test]
    fn crl_write_read_roundtrip() {
        let (store, _dir) = tmp_store();
        let serials = vec!["serial-001".to_string(), "serial-002".to_string()];
        CrlStore::write_crl(&store, "Org1MSP", &serials).unwrap();
        let loaded = CrlStore::read_crl(&store, "Org1MSP").unwrap();
        assert_eq!(loaded, serials);
    }

    #[test]
    fn crl_read_missing_returns_empty() {
        let (store, _dir) = tmp_store();
        let serials = CrlStore::read_crl(&store, "UnknownMSP").unwrap();
        assert!(serials.is_empty());
    }

    #[test]
    fn crl_overwrite_replaces_serials() {
        let (store, _dir) = tmp_store();
        CrlStore::write_crl(&store, "Org1MSP", &["s1".to_string()]).unwrap();
        CrlStore::write_crl(&store, "Org1MSP", &["s1".to_string(), "s2".to_string()]).unwrap();
        let loaded = CrlStore::read_crl(&store, "Org1MSP").unwrap();
        assert_eq!(loaded.len(), 2);
    }

    // ── World state ───────────────────────────────────────────────────────────

    #[test]
    fn world_state_put_new_key_starts_at_version_1() {
        let (store, _dir) = tmp_store();
        let ver = store.world_state_put("asset1", b"value_a").unwrap();
        assert_eq!(ver, 1);
        let vv = store.world_state_get("asset1").unwrap().unwrap();
        assert_eq!(vv.version, 1);
        assert_eq!(vv.data, b"value_a");
    }

    #[test]
    fn world_state_put_again_increments_version() {
        let (store, _dir) = tmp_store();
        store.world_state_put("asset1", b"value_a").unwrap();
        let ver2 = store.world_state_put("asset1", b"value_b").unwrap();
        assert_eq!(ver2, 2);
        let vv = store.world_state_get("asset1").unwrap().unwrap();
        assert_eq!(vv.version, 2);
        assert_eq!(vv.data, b"value_b");
    }

    #[test]
    fn world_state_get_absent_key_returns_none() {
        let (store, _dir) = tmp_store();
        assert!(store.world_state_get("missing").unwrap().is_none());
    }

    #[test]
    fn world_state_multiple_keys_are_independent() {
        let (store, _dir) = tmp_store();
        store.world_state_put("k1", b"a").unwrap();
        store.world_state_put("k1", b"b").unwrap(); // version 2
        store.world_state_put("k2", b"x").unwrap(); // version 1

        let v1 = store.world_state_get("k1").unwrap().unwrap();
        let v2 = store.world_state_get("k2").unwrap().unwrap();
        assert_eq!(v1.version, 2);
        assert_eq!(v2.version, 1);
    }

    // ── PrivateDataStore tests ────────────────────────────────────────────────

    #[test]
    fn private_data_put_returns_sha256_hash() {
        let (store, _dir) = tmp_store();
        let value = b"secret data";
        let hash = store.put_private_data("mycol", "key1", value).unwrap();
        assert_eq!(hash, sha256(value));
    }

    #[test]
    fn private_data_get_returns_original_value() {
        let (store, _dir) = tmp_store();
        let value = b"private payload";
        store.put_private_data("mycol", "key1", value).unwrap();
        let got = store.get_private_data("mycol", "key1").unwrap();
        assert_eq!(got, Some(value.to_vec()));
    }

    #[test]
    fn private_data_hash_matches_sha256_of_value() {
        let (store, _dir) = tmp_store();
        let value = b"on-chain integrity";
        let hash = store.put_private_data("col", "k", value).unwrap();
        // caller would embed `hash` in TX data field; verify it matches
        assert_eq!(hash, sha256(value));
        let stored = store.get_private_data("col", "k").unwrap().unwrap();
        assert_eq!(sha256(&stored), hash);
    }

    #[test]
    fn private_data_get_returns_none_for_missing_key() {
        let (store, _dir) = tmp_store();
        let got = store.get_private_data("col", "nonexistent").unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn private_data_collections_are_isolated() {
        let (store, _dir) = tmp_store();
        store.put_private_data("col1", "k", b"alpha").unwrap();
        store.put_private_data("col2", "k", b"beta").unwrap();
        assert_eq!(
            store.get_private_data("col1", "k").unwrap(),
            Some(b"alpha".to_vec())
        );
        assert_eq!(
            store.get_private_data("col2", "k").unwrap(),
            Some(b"beta".to_vec())
        );
    }

    // ── chaincode package tests ───────────────────────────────────────────────

    #[test]
    fn store_and_get_package_roundtrip() {
        let (store, _dir) = tmp_store();
        let wasm = vec![0u8; 100 * 1024]; // 100 KB
        store.store_package("my_cc", "1.0", &wasm).unwrap();
        let retrieved = store.get_package("my_cc", "1.0").unwrap();
        assert_eq!(retrieved, Some(wasm));
    }

    #[test]
    fn get_missing_package_returns_none() {
        let (store, _dir) = tmp_store();
        let result = store.get_package("missing_cc", "0.1").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn different_versions_stored_independently() {
        let (store, _dir) = tmp_store();
        let wasm_v1 = vec![1u8; 64];
        let wasm_v2 = vec![2u8; 64];
        store.store_package("cc", "1.0", &wasm_v1).unwrap();
        store.store_package("cc", "2.0", &wasm_v2).unwrap();
        assert_eq!(store.get_package("cc", "1.0").unwrap(), Some(wasm_v1));
        assert_eq!(store.get_package("cc", "2.0").unwrap(), Some(wasm_v2));
    }

    // ── AclProvider tests ────────────────────────────────────────────────────

    #[test]
    fn acl_write_read_roundtrip() {
        let (store, _dir) = tmp_store();
        store.set_acl("peer/ChaincodeInvoke", "OrgPolicy").unwrap();
        let entry = store
            .get_acl("peer/ChaincodeInvoke")
            .unwrap()
            .expect("entry");
        assert_eq!(entry.resource, "peer/ChaincodeInvoke");
        assert_eq!(entry.policy_ref, "OrgPolicy");
    }

    #[test]
    fn acl_get_missing_returns_none() {
        let (store, _dir) = tmp_store();
        assert!(store.get_acl("nonexistent").unwrap().is_none());
    }

    #[test]
    fn acl_list_and_remove() {
        let (store, _dir) = tmp_store();
        store.set_acl("peer/BlockEvents", "PolicyA").unwrap();
        store.set_acl("peer/ChaincodeInvoke", "PolicyB").unwrap();
        let mut list = store.list_acls().unwrap();
        list.sort_by(|a, b| a.resource.cmp(&b.resource));
        assert_eq!(list.len(), 2);
        store.remove_acl("peer/BlockEvents").unwrap();
        assert_eq!(store.list_acls().unwrap().len(), 1);
        assert!(store.get_acl("peer/BlockEvents").unwrap().is_none());
    }

    // ── channel_configs tests ────────────────────────────────────────────────

    fn sample_channel_config(version: u64) -> crate::channel::config::ChannelConfig {
        use crate::channel::config::ChannelConfig;
        ChannelConfig {
            version,
            member_orgs: vec!["org1".to_string()],
            ..ChannelConfig::default()
        }
    }

    #[test]
    fn channel_config_write_read_roundtrip() {
        let (store, _dir) = tmp_store();
        let cfg = sample_channel_config(0);
        store.write_channel_config("ch1", &cfg).unwrap();
        let restored = store
            .read_channel_config("ch1", 0)
            .unwrap()
            .expect("config");
        assert_eq!(cfg, restored);
    }

    #[test]
    fn channel_config_read_missing_returns_none() {
        let (store, _dir) = tmp_store();
        assert!(store.read_channel_config("ch1", 99).unwrap().is_none());
    }

    #[test]
    fn channel_config_list_versions() {
        let (store, _dir) = tmp_store();
        store
            .write_channel_config("ch1", &sample_channel_config(0))
            .unwrap();
        store
            .write_channel_config("ch1", &sample_channel_config(1))
            .unwrap();
        store
            .write_channel_config("ch1", &sample_channel_config(2))
            .unwrap();
        // Different channel — must not appear in ch1 results.
        store
            .write_channel_config("ch2", &sample_channel_config(0))
            .unwrap();

        let versions = store.list_channel_versions("ch1").unwrap();
        assert_eq!(versions, vec![0, 1, 2]);
    }

    // ── CF key_endorsement_policies ──────────────────────────────────────────

    #[test]
    fn cf_key_endorsement_policies_handle_is_present() {
        let (store, _dir) = tmp_store();
        assert!(store.cf_key_endorsement_policies().is_ok());
    }

    #[test]
    fn key_endorsement_policies_cf_is_distinct_from_world_state() {
        // The CF name constants must differ — they map to independent key spaces.
        assert_ne!(CF_KEY_ENDORSEMENT_POLICIES, CF_WORLD_STATE);
    }

    #[test]
    fn key_endorsement_policies_roundtrip_via_raw_put_get() {
        let (store, _dir) = tmp_store();
        let cf = store.cf_key_endorsement_policies().unwrap();
        let key = b"asset:color";
        let value = br#"{"rule":"OR('Org1MSP.member')"}"#;
        store.db.put_cf(&cf, key, value).unwrap();
        let got = store
            .db
            .get_cf(&cf, key)
            .unwrap()
            .expect("value must exist");
        assert_eq!(got, value);
    }

    #[test]
    fn key_endorsement_policies_missing_key_returns_none() {
        let (store, _dir) = tmp_store();
        let cf = store.cf_key_endorsement_policies().unwrap();
        let got = store.db.get_cf(&cf, b"nonexistent").unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn cf_key_history_handle_is_present() {
        let (store, _dir) = tmp_store();
        assert!(store.cf_key_history().is_ok());
    }

    #[test]
    fn write_and_read_key_history_three_versions() {
        use crate::storage::traits::HistoryEntry;

        let (store, _dir) = tmp_store();

        let entries = vec![
            HistoryEntry {
                version: 1,
                data: b"v1".to_vec(),
                tx_id: "tx1".into(),
                timestamp: 100,
                is_delete: false,
            },
            HistoryEntry {
                version: 2,
                data: b"v2".to_vec(),
                tx_id: "tx2".into(),
                timestamp: 200,
                is_delete: false,
            },
            HistoryEntry {
                version: 3,
                data: vec![],
                tx_id: "tx3".into(),
                timestamp: 300,
                is_delete: true,
            },
        ];

        for entry in &entries {
            store.write_history_entry("mykey", entry).unwrap();
        }

        let history = store.get_history("mykey").unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[0].data, b"v1");
        assert_eq!(history[1].version, 2);
        assert!(history[2].is_delete);
        assert_eq!(history[2].data, Vec::<u8>::new());
    }

    #[test]
    fn key_history_isolation_between_keys() {
        use crate::storage::traits::HistoryEntry;

        let (store, _dir) = tmp_store();

        store
            .write_history_entry(
                "alpha",
                &HistoryEntry {
                    version: 1,
                    data: b"a1".to_vec(),
                    tx_id: "t1".into(),
                    timestamp: 10,
                    is_delete: false,
                },
            )
            .unwrap();
        store
            .write_history_entry(
                "beta",
                &HistoryEntry {
                    version: 1,
                    data: b"b1".to_vec(),
                    tx_id: "t2".into(),
                    timestamp: 20,
                    is_delete: false,
                },
            )
            .unwrap();

        let alpha_history = store.get_history("alpha").unwrap();
        assert_eq!(alpha_history.len(), 1);
        assert_eq!(alpha_history[0].data, b"a1");

        let beta_history = store.get_history("beta").unwrap();
        assert_eq!(beta_history.len(), 1);
        assert_eq!(beta_history[0].data, b"b1");
    }

    #[test]
    fn key_history_empty_returns_empty_vec() {
        let (store, _dir) = tmp_store();
        let history = store.get_history("nonexistent").unwrap();
        assert!(history.is_empty());
    }

    // ── flush_wal tests ──────────────────────────────────────────────────────

    #[test]
    fn flush_wal_succeeds_on_empty_db() {
        let (store, _dir) = tmp_store();
        assert!(store.flush_wal().is_ok());
    }

    #[test]
    fn flush_wal_persists_pending_writes() {
        let (store, dir) = tmp_store();
        let block = sample_block(0);
        store.write_block(&block).unwrap();

        // Flush WAL
        store.flush_wal().unwrap();

        // Reopen and verify data survived
        drop(store);
        let store2 = RocksDbBlockStore::new(dir.path()).unwrap();
        assert!(store2.block_exists(0).unwrap());
    }

    #[test]
    fn rocksdb_audit_purge_expired() {
        use crate::audit::{AuditAction, AuditEntry, AuditStore};
        let (store, _dir) = tmp_store();

        let old_entry = AuditEntry {
            timestamp: "2020-01-01T00:00:00Z".to_string(),
            action: AuditAction::HttpRequest,
            method: "GET".to_string(),
            path: "/old".to_string(),
            org_id: "org1".to_string(),
            source_ip: "127.0.0.1".to_string(),
            status_code: 200,
            trace_id: "t1".to_string(),
            duration_ms: 0,
            metadata: None,
            previous_hash: String::new(),
            entry_hash: String::new(),
        };
        let new_entry = AuditEntry {
            timestamp: "2026-07-01T00:00:00Z".to_string(),
            trace_id: "t2".to_string(),
            path: "/new".to_string(),
            ..old_entry.clone()
        };

        store.append(&old_entry).unwrap();
        store.append(&new_entry).unwrap();

        let policy = crate::audit_retention::AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 2 * 365 * 24 * 3600,
            auto_purge_enabled: true,
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .timestamp() as u64;

        let purged = AuditStore::purge_expired(&store, &policy, now).unwrap();
        assert_eq!(purged, 1);

        let remaining = store.query(None, None, None, None, 100).unwrap();
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].path.contains("/new"));
    }

    #[test]
    fn rocksdb_audit_purge_disabled_noop() {
        use crate::audit::{AuditAction, AuditEntry, AuditStore};
        let (store, _dir) = tmp_store();

        let entry = AuditEntry {
            timestamp: "2020-01-01T00:00:00Z".to_string(),
            action: AuditAction::HttpRequest,
            method: "GET".to_string(),
            path: "/x".to_string(),
            org_id: "org1".to_string(),
            source_ip: "127.0.0.1".to_string(),
            status_code: 200,
            trace_id: "t1".to_string(),
            duration_ms: 0,
            metadata: None,
            previous_hash: String::new(),
            entry_hash: String::new(),
        };
        store.append(&entry).unwrap();

        let policy = crate::audit_retention::AuditRetentionPolicy {
            min_retention_secs: 365 * 24 * 3600,
            max_retention_secs: 2 * 365 * 24 * 3600,
            auto_purge_enabled: false,
        };
        let purged = AuditStore::purge_expired(&store, &policy, 2_000_000_000).unwrap();
        assert_eq!(purged, 0);
    }
}
