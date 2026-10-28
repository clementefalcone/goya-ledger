use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
pub type StoreMap = Arc<RwLock<HashMap<String, Arc<dyn BlockStore>>>>;

use crate::acl::AclProvider;
use crate::airdrop::AirdropManager;
use crate::billing::BillingManager;
use crate::cache::BalanceCache;
use crate::chaincode::{ChaincodeDefinitionStore, ChaincodePackageStore};
use crate::channel::config::ChannelConfig;
use crate::checkpoint::CheckpointManager;
use crate::discovery::service::DiscoveryService;
use crate::endorsement::policy_store::PolicyStore;
use crate::endorsement::registry::OrgRegistry;
use crate::events::EventBus;
use crate::gateway::Gateway;
use crate::governance::params::ParamRegistry;
use crate::governance::proposals::ProposalStore;
use crate::governance::voting::VoteStore;
use crate::metrics::MetricsCollector;
use crate::mining::MiningService;
use crate::msp::CrlStore;
use crate::network::Node;
use crate::ordering::OrderingBackend;
use crate::pin::store::PinStore;
use crate::privacy::PrivateClaimsStore;
use crate::private_data::{CollectionRegistry, PrivateDataStore};
use crate::smart_contracts::ContractManager;
use crate::staking::StakingManager;
use crate::storage::traits::BlockStore;
use crate::tokenomics::economics::EconomicsState;
use crate::tokenomics::storage_deposit::DepositLedger;
use crate::transaction_validation::TransactionValidator;

/// Shared application state for the HTTP API layer.
#[derive(Clone)]
pub struct AppState {
    pub node: Option<Arc<Node>>,
    pub balance_cache: Arc<BalanceCache>,
    pub billing_manager: Arc<BillingManager>,
    pub contract_manager: Arc<RwLock<ContractManager>>,
    pub staking_manager: Arc<StakingManager>,
    pub airdrop_manager: Arc<AirdropManager>,
    pub checkpoint_manager: Option<Arc<Mutex<CheckpointManager>>>,
    pub transaction_validator: Arc<Mutex<TransactionValidator>>,
    pub metrics: Arc<MetricsCollector>,
    /// Per-channel storage layer. Key `"default"` holds the main store.
    /// Wrapped in `RwLock` so channels can be added at runtime via `POST /channels`.
    pub store: StoreMap,
    /// Organization registry for endorsement policies.
    pub org_registry: Option<Arc<dyn OrgRegistry>>,
    /// Endorsement policy store.
    pub policy_store: Option<Arc<dyn PolicyStore>>,
    /// Certificate Revocation List store.
    pub crl_store: Option<Arc<dyn CrlStore>>,
    /// Private data side-store (one per node, shared across channels).
    pub private_data_store: Option<Arc<dyn PrivateDataStore>>,
    /// Registry of private data collection definitions.
    pub collection_registry: Option<Arc<dyn CollectionRegistry>>,
    /// Chaincode Wasm package store.
    pub chaincode_package_store: Option<Arc<dyn ChaincodePackageStore>>,
    /// Chaincode lifecycle definition store.
    pub chaincode_definition_store: Option<Arc<dyn ChaincodeDefinitionStore>>,
    /// Fabric Gateway — orchestrates endorse → order → commit.
    pub gateway: Option<Arc<Gateway>>,
    /// Service Discovery — peer registry and endorsement plan computation.
    pub discovery_service: Option<Arc<DiscoveryService>>,
    /// Event bus — fan-out channel for block and transaction events.
    pub event_bus: Arc<EventBus>,
    /// Per-channel config history. Key = channel_id; value = ordered list of configs (index 0 = genesis).
    pub channel_configs: Arc<RwLock<HashMap<String, Vec<ChannelConfig>>>>,
    /// ACL provider — maps resource names to endorsement policy references.
    pub acl_provider: Option<Arc<dyn AclProvider>>,
    /// Ordering backend — solo (default) or raft.
    pub ordering_backend: Option<Arc<dyn OrderingBackend>>,
    /// World state for snapshots and state queries.
    pub world_state: Option<Arc<dyn crate::storage::world_state::WorldState>>,
    /// Audit trail — immutable log of all API requests.
    pub audit_store: Option<Arc<dyn crate::audit::AuditStore>>,
    /// Governance — proposal store.
    pub proposal_store: Option<Arc<ProposalStore>>,
    /// Governance — vote store.
    pub vote_store: Option<Arc<VoteStore>>,
    /// Governance — protocol parameter registry.
    pub param_registry: Option<Arc<ParamRegistry>>,
    /// PIN store — DID-to-hashed-PIN mappings.
    pub pin_store: Option<Arc<dyn PinStore>>,
    /// Oracle registry — price feeds and oracle node management.
    pub oracle_registry: Arc<std::sync::Mutex<crate::oracle_system::OracleRegistry>>,
    /// Contact form submissions.
    pub contact_store: Arc<crate::api::handlers::contact::ContactStore>,
    /// Chaincode sandbox validation reports.
    pub sandbox_report_store: Arc<dyn crate::chaincode::sandbox::SandboxReportStore>,
    /// Legal oracle record store.
    pub legal_oracle_store: Arc<dyn crate::legal_oracle::OracleRecordStore>,
    /// Legal oracle service.
    pub legal_oracle: Arc<std::sync::Mutex<crate::legal_oracle::legal::LegalOracle>>,
    /// Mining service backed by BlockStore (new path).
    pub mining_service: Option<Arc<MiningService>>,
    /// Node signing provider (ML-DSA-65 by default).
    pub signing_provider: Option<Arc<dyn crate::identity::signing::SigningProvider>>,
    /// New transaction pool backed by storage::Transaction.
    pub tx_pool: Arc<Mutex<crate::transaction::mempool::TransactionPool>>,
    /// HMAC secret for vault recovery blind indexing (NIST SP 800-185).
    /// Recovery is disabled when this is `None`.
    pub vault_recovery_secret: Option<Vec<u8>>,
    pub pairwise_secret: Option<Vec<u8>>,
    /// Per-IP rate limiter for vault recovery attempts.
    pub vault_rate_limiter: Arc<crate::api::handlers::vault::RecoveryRateLimiter>,
    /// Cross-chain bridge engine.
    pub bridge_engine: Arc<crate::bridge::protocol::BridgeEngine>,
    /// Pluggable proof verifier for zkML inference claims.
    pub proof_verifier: Arc<dyn crate::inference::proof::ProofVerifier>,
    /// RFC 3161 Time Stamping Authority provider.
    pub tsa_provider: Option<Arc<crate::tsa::TsaProvider>>,
    /// Registration Authority store (Ley 19.799 Art. 15).
    pub ra_store: Option<Arc<crate::identity::ra::RaStore>>,
    /// External identity verification provider (eIDAS Art. 26(b)).
    pub identity_verifier: Option<Arc<dyn crate::identity::ra::IdentityVerificationProvider>>,
    /// OCSP responder (RFC 6960).
    pub ocsp_responder: Option<Arc<crate::msp::ocsp::OcspResponder>>,
    /// Certificate lifecycle manager (revoke→CRL, suspend, expiry monitoring).
    pub lifecycle_manager: Option<Arc<crate::pki_lifecycle::LifecycleManager>>,
    /// LexChain contract store.
    pub lexchain_store: crate::lexchain::store::LexChainStore,
    pub economics_state: Arc<Mutex<EconomicsState>>,
    pub deposit_ledger: Arc<DepositLedger>,
    pub private_claims: Arc<PrivateClaimsStore>,
}

impl AppState {
    /// Create an AppState with all memory-backed defaults for testing.
    ///
    /// All `Option` fields are `None`, all stores use in-memory implementations.
    /// Callers can override specific fields after construction.
    pub fn test_default() -> Self {
        use crate::storage::MemoryStore;

        let default_store: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
        let mut store_map = HashMap::new();
        store_map.insert("default".to_string(), default_store);

        Self {
            node: None,
            balance_cache: Arc::new(BalanceCache::new()),
            billing_manager: Arc::new(BillingManager::new()),
            contract_manager: Arc::new(RwLock::new(ContractManager::new())),
            staking_manager: Arc::new(StakingManager::new(None, None, None)),
            airdrop_manager: Arc::new(AirdropManager::new(100, 10, "test-wallet".to_string())),
            checkpoint_manager: None,
            transaction_validator: Arc::new(Mutex::new(TransactionValidator::with_defaults())),
            metrics: Arc::new(MetricsCollector::new()),
            store: Arc::new(RwLock::new(store_map)),
            org_registry: None,
            policy_store: None,
            crl_store: None,
            private_data_store: None,
            collection_registry: None,
            chaincode_package_store: None,
            chaincode_definition_store: None,
            gateway: None,
            discovery_service: None,
            event_bus: Arc::new(EventBus::new()),
            channel_configs: Arc::new(RwLock::new(HashMap::new())),
            acl_provider: None,
            ordering_backend: None,
            world_state: None,
            audit_store: Some(Arc::new(crate::audit::MemoryAuditStore::new())),
            proposal_store: None,
            vote_store: None,
            param_registry: None,
            pin_store: None,
            oracle_registry: Arc::new(std::sync::Mutex::new(
                crate::oracle_system::OracleRegistry::new(66, 5000),
            )),
            contact_store: Arc::new(crate::api::handlers::contact::ContactStore::new()),
            sandbox_report_store: Arc::new(
                crate::chaincode::sandbox::MemorySandboxReportStore::new(),
            ),
            legal_oracle_store: Arc::new(crate::legal_oracle::MemoryOracleRecordStore::new()),
            legal_oracle: Arc::new(std::sync::Mutex::new(
                crate::legal_oracle::legal::LegalOracle::new(300),
            )),
            mining_service: None,
            signing_provider: None,
            tx_pool: Arc::new(Mutex::new(
                crate::transaction::mempool::TransactionPool::new(),
            )),
            vault_recovery_secret: None,
            pairwise_secret: None,
            vault_rate_limiter: Arc::new(crate::api::handlers::vault::RecoveryRateLimiter::new()),
            bridge_engine: Arc::new(crate::bridge::protocol::BridgeEngine::new()),
            proof_verifier: Arc::new(crate::inference::proof::MultiVerifier::new()),
            tsa_provider: None,
            ra_store: None,
            identity_verifier: None,
            ocsp_responder: None,
            lifecycle_manager: None,
            lexchain_store: crate::lexchain::store::LexChainStore::new(),
            economics_state: Arc::new(Mutex::new(EconomicsState::default())),
            deposit_ledger: Arc::new(DepositLedger::new()),
            private_claims: Arc::new(PrivateClaimsStore::new()),
        }
    }
}
