#![allow(dead_code)]
mod acl;
mod airdrop;
mod api;
mod api_legacy;
mod app_state;
mod audit;
mod audit_retention;
mod billing;
mod block_creation;
mod bridge;
mod cache;
mod chaincode;
mod channel;
mod checkpoint;
mod compliance;
mod consensus;
mod crypto;
mod discovery;
mod document;
mod endorsement;
mod events;
#[cfg(feature = "evm")]
mod evm_compat;
mod forensic;
mod forensic_pentest;
mod gateway;
mod governance;
mod identity;
mod inference;
mod intelligence;
mod legal_oracle;
mod lexchain;
mod metrics;
mod middleware;
mod mining;
mod msp;
mod network;
mod network_security;
mod oracle_connector;
mod oracle_demo;
mod oracle_system;
mod ordering;
mod pin;
mod pki;
mod pki_ceremony;
mod pki_chain;
mod pki_lifecycle;
mod pki_policy;
mod privacy;
mod private_data;
mod registry;
mod regulatory;
mod signature;
mod smart_contracts;
mod staking;
mod storage;
mod stress;
mod time_source;
mod tls;
mod tokenomics;
mod transaction;
mod transaction_validation;
mod tsa;
mod tsl;
mod tsl_client;

use actix_cors::Cors;
use actix_web::middleware::Compress;
use actix_web::{web, App, HttpServer};
use airdrop::AirdropManager;
use api::routes::{ApiRoutes, LightRoutes};
use api_legacy::config_routes;
use app_state::AppState;
use billing::BillingManager;
use cache::BalanceCache;
use metrics::MetricsCollector;
use middleware::RateLimitMiddleware;
use network::{parse_peer_allowlist, Node};
use rust_bc::light_client::mode::NodeMode;
use staking::StakingManager;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
#[cfg(feature = "rocksdb-storage")]
use storage::BlockStore;
#[cfg(feature = "rocksdb-storage")]
use storage::RocksDbBlockStore;
use tls::{
    load_client_config_from_env, load_tls_config_from_env, reload_tls_config,
    tls_reload_params_from_env,
};
use transaction_validation::TransactionValidator;

/**
 * Función principal - Inicia el servidor API
 */
fn main() -> std::io::Result<()> {
    // Actix route registration creates deeply nested generic types whose
    // async state machine exceeds the default 8 MB stack in debug builds.
    // We use a 16 MB stack (enough for release) and Box::pin the large
    // sub-futures so that they live on the heap instead of the stack.
    let builder = std::thread::Builder::new()
        .name("main-rt".into())
        .stack_size(16 * 1024 * 1024);
    let handle = builder
        .spawn(|| actix_rt::System::new().block_on(async_main()))
        .expect("failed to spawn main runtime thread");
    handle.join().unwrap()
}

async fn async_main() -> std::io::Result<()> {
    // Box::pin moves the enormous state machine (1200+ lines of locals and
    // await points) from the thread stack to the heap, preventing stack
    // overflow in unoptimized debug builds.
    Box::pin(async_main_inner()).await
}

async fn async_main_inner() -> std::io::Result<()> {
    // Structured logging via tracing-subscriber.
    // LOG_FORMAT=json → JSON output (production, Docker, ELK/Loki).
    // Default        → human-readable text (development).
    // RUST_LOG       → filter levels (e.g. RUST_LOG=debug).
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    // Install the TLS CryptoProvider early, before any TLS config is built.
    // When TLS_PQC_KEM=true this enables X25519+ML-KEM-768 hybrid key exchange.
    tls::install_crypto_provider();

    let args: Vec<String> = env::args().collect();
    let api_port = args
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| {
            env::var("API_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080)
        });
    let p2p_port = args
        .get(2)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| {
            env::var("P2P_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8081)
        });
    let db_name = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| env::var("DB_NAME").unwrap_or_else(|_| "blockchain".to_string()));

    // Network ID: "mainnet" o "testnet" (default: "mainnet")
    let network_id = env::var("NETWORK_ID").unwrap_or_else(|_| "mainnet".to_string());

    // Bootstrap nodes: lista separada por comas (ej: "127.0.0.1:8081,127.0.0.1:8083")
    let bootstrap_nodes_str = env::var("BOOTSTRAP_NODES").unwrap_or_default();
    let bootstrap_nodes: Vec<String> = if bootstrap_nodes_str.is_empty() {
        Vec::new()
    } else {
        bootstrap_nodes_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Seed nodes: lista separada por comas (siempre se intentan, incluso sin bootstrap)
    // Estas son nodos conocidos que siempre están disponibles para discovery
    let seed_nodes_str = env::var("SEED_NODES").unwrap_or_default();
    let seed_nodes: Vec<String> = if seed_nodes_str.is_empty() {
        Vec::new()
    } else {
        seed_nodes_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let peer_allowlist = env::var("PEER_ALLOWLIST")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| parse_peer_allowlist(&s))
        .map(Arc::new);

    // Auto-discovery: intervalo en segundos (default: 120 = 2 minutos)
    let auto_discovery_interval = env::var("AUTO_DISCOVERY_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120);

    // Auto-discovery: máximo número de conexiones por ciclo (default: 5)
    let auto_discovery_max_connections = env::var("AUTO_DISCOVERY_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(5);

    // Auto-discovery: delay inicial en segundos (default: 30)
    let auto_discovery_initial_delay = env::var("AUTO_DISCOVERY_INITIAL_DELAY")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);

    let checkpoints_dir = format!("{db_name}_checkpoints");

    println!("🚀 Iniciando Blockchain API Server...");
    println!("📊 Storage: BlockStore (legacy removed)");
    println!("🌐 Puerto API: {api_port}");
    println!("📡 Puerto P2P: {p2p_port}");
    println!("🌍 Network ID: {network_id}");
    if !bootstrap_nodes.is_empty() {
        println!("🔗 Bootstrap nodes: {}", bootstrap_nodes.join(", "));
    }
    if !seed_nodes.is_empty() {
        println!("🌱 Seed nodes: {}", seed_nodes.join(", "));
    }
    if let Some(ref allow) = peer_allowlist {
        println!(
            "🔒 PEER_ALLOWLIST activo ({} dirección/es P2P entrantes permitidas)",
            allow.len()
        );
    }
    println!(
        "🔍 Auto-discovery: intervalo {auto_discovery_interval}s, max conexiones {auto_discovery_max_connections}, delay inicial {auto_discovery_initial_delay}s"
    );

    let balance_cache = Arc::new(BalanceCache::new());
    let billing_manager = Arc::new(BillingManager::new());

    // Los contratos se mantienen en memoria (ContractManager)
    // Se reconstruyen desde blockchain si es necesario
    let contract_manager = smart_contracts::ContractManager::new();
    let contract_manager = Arc::new(RwLock::new(contract_manager));

    // Inicializar CheckpointManager (protección anti-51%) - ANTES de crear Node
    let checkpoint_interval = env::var("CHECKPOINT_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);
    let max_reorg_depth = env::var("MAX_REORG_DEPTH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);

    let checkpoint_manager = match crate::checkpoint::CheckpointManager::new(
        &checkpoints_dir,
        Some(checkpoint_interval),
        Some(max_reorg_depth),
    ) {
        Ok(manager) => {
            let count = manager.checkpoint_count();
            if count > 0 {
                println!("✅ CheckpointManager inicializado: {count} checkpoints cargados");
            } else {
                println!("✅ CheckpointManager inicializado (sin checkpoints previos)");
            }
            Some(Arc::new(Mutex::new(manager)))
        }
        Err(e) => {
            eprintln!("⚠️  Error al inicializar CheckpointManager: {e}");
            None
        }
    };

    // Inicializar TransactionValidator (store attached later for persistence)
    let transaction_validator = Arc::new(Mutex::new(TransactionValidator::with_defaults()));

    let node_address = SocketAddr::from(([0, 0, 0, 0], p2p_port));
    let mut node_arc = Node::new(
        node_address,
        Some(network_id.clone()),
        Some(bootstrap_nodes.clone()),
        Some(seed_nodes.clone()),
        peer_allowlist.clone(),
    );
    node_arc.set_contract_manager(contract_manager.clone());
    if let Some(ref checkpoint_mgr) = checkpoint_manager {
        node_arc.set_checkpoint_manager(checkpoint_mgr.clone());
    }
    node_arc.set_transaction_validator(transaction_validator.clone());

    // Configurar TLS para conexiones P2P salientes
    let tls_client_cfg = match load_client_config_from_env() {
        Ok(Some(cfg)) => {
            println!("🔐 TLS P2P saliente habilitado");
            Some(Arc::new(cfg))
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("❌ Error al cargar ClientConfig TLS P2P: {e}");
            return Err(std::io::Error::other(e.to_string()));
        }
    };
    if let Some(ref cfg) = tls_client_cfg {
        node_arc.set_tls_connector(tokio_rustls::TlsConnector::from(Arc::clone(cfg)));
    }

    // Clonar los recursos compartidos antes de crear el Arc
    let shared_peers = node_arc.peers.clone();
    let shared_contract_sync_metrics = node_arc.contract_sync_metrics.clone();
    let shared_pending_broadcasts = node_arc.pending_contract_broadcasts.clone();
    let shared_recent_receipts = node_arc.recent_contract_receipts.clone();
    let shared_rate_limits = node_arc.contract_rate_limits.clone();
    let shared_failed_peers = node_arc.failed_peers.clone();

    let node_arc = Arc::new(node_arc);

    // Crear segunda instancia para el servidor P2P que comparte los mismos recursos
    let mut node_for_server = Node::new(
        node_address,
        Some(network_id.clone()),
        Some(bootstrap_nodes.clone()),
        Some(seed_nodes.clone()),
        peer_allowlist.clone(),
    );
    node_for_server.set_contract_manager(contract_manager.clone());
    if let Some(ref checkpoint_mgr) = checkpoint_manager {
        node_for_server.set_checkpoint_manager(checkpoint_mgr.clone());
    }
    node_for_server.set_transaction_validator(transaction_validator.clone());
    if let Some(ref cfg) = tls_client_cfg {
        node_for_server.set_tls_connector(tokio_rustls::TlsConnector::from(Arc::clone(cfg)));
    }
    // Configure TLS acceptor for incoming P2P connections
    if let Ok(Some(server_cfg)) = load_tls_config_from_env() {
        node_for_server.set_tls_acceptor(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg)));
    }
    // Compartir los mismos recursos compartidos
    // BFT event channel — created early so node_for_server can route incoming BFT messages.
    let (bft_tx, bft_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::consensus::controller::BftEvent>();
    node_for_server.bft_tx = Some(bft_tx.clone());
    node_for_server.peers = shared_peers;
    node_for_server.contract_sync_metrics = shared_contract_sync_metrics;
    node_for_server.pending_contract_broadcasts = shared_pending_broadcasts;
    node_for_server.recent_contract_receipts = shared_recent_receipts;
    node_for_server.contract_rate_limits = shared_rate_limits;
    node_for_server.failed_peers = shared_failed_peers;

    // Crear StakingManager
    // Min stake: 1000 tokens (configurable vía MIN_STAKE env var)
    let min_stake = env::var("MIN_STAKE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1000);

    // Unstaking period: 7 días (configurable vía UNSTAKING_PERIOD env var, en segundos)
    let unstaking_period = env::var("UNSTAKING_PERIOD")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(604800); // 7 días

    // Slash percentage: 5% (configurable vía SLASH_PERCENTAGE env var)
    let slash_percentage = env::var("SLASH_PERCENTAGE")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(5);

    let staking_manager = Arc::new(StakingManager::new(
        Some(min_stake),
        Some(unstaking_period),
        Some(slash_percentage),
    ));

    // Inicializar AirdropManager
    let max_eligible_nodes = env::var("AIRDROP_MAX_NODES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(500);

    let airdrop_amount_per_node = env::var("AIRDROP_AMOUNT_PER_NODE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1000);

    let airdrop_wallet = env::var("AIRDROP_WALLET").unwrap_or_else(|_| "AIRDROP".to_string());

    let airdrop_manager = Arc::new(AirdropManager::new(
        max_eligible_nodes,
        airdrop_amount_per_node,
        airdrop_wallet.clone(),
    ));

    // Inicializar MetricsCollector
    let metrics_collector = Arc::new(MetricsCollector::new());

    // FIPS 140-3 power-up self-tests — verify crypto correctness before accepting requests.
    crate::identity::signing::run_crypto_self_tests()
        .expect("FATAL: cryptographic self-tests failed — node cannot start");
    crate::crypto::hasher::run_hash_self_tests()
        .expect("FATAL: hash self-tests failed — node cannot start");
    let hash_algo = crate::crypto::hasher::configured_algorithm();
    log::info!("Cryptographic self-tests passed (Ed25519, ML-DSA-65, SHA-256, SHA3-256)");
    log::info!("Hash algorithm: {hash_algo}");

    let signing_provider: Arc<dyn crate::identity::signing::SigningProvider> = {
        use crate::identity::signing::SigningProvider as _;
        let algo = std::env::var("SIGNING_ALGORITHM").unwrap_or_default();
        let key_dir = std::env::var("STORAGE_PATH").unwrap_or_else(|_| "/app/data".into());
        match algo.to_lowercase().as_str() {
            "" | "ml-dsa-65" | "mldsa65" => {
                let key_path = std::path::Path::new(&key_dir).join("signing_key_mldsa65.bin");
                let provider = if key_path.exists() {
                    let data = std::fs::read(&key_path).expect("failed to read signing key");
                    let pk_len = 1952;
                    crate::identity::signing::MlDsaSigningProvider::from_keys(
                        &data[..pk_len],
                        &data[pk_len..],
                    )
                    .expect("failed to load ML-DSA-65 key from disk")
                } else {
                    let provider = crate::identity::signing::MlDsaSigningProvider::generate();
                    let key_bytes = provider.export_key_bytes();
                    if let Some(parent) = key_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    std::fs::write(&key_path, &key_bytes)
                        .expect("failed to persist ML-DSA-65 signing key");
                    log::info!("ML-DSA-65 signing key persisted to {}", key_path.display());
                    provider
                };
                log::info!(
                    "Signing algorithm: ML-DSA-65 (FIPS 204, post-quantum) | pubkey_len={} bytes",
                    provider.public_key().len()
                );
                Arc::new(provider)
            }
            "ed25519" => {
                log::warn!("SIGNING_ALGORITHM=ed25519 is deprecated — defaulting to ML-DSA-65 in future releases");
                let provider = crate::identity::signing::SoftwareSigningProvider::generate();
                log::info!(
                    "Signing algorithm: Ed25519 | pubkey_len={} bytes",
                    provider.public_key().len()
                );
                Arc::new(provider)
            }
            "ecdsa-p256" | "es256" | "p256" => {
                let provider = crate::identity::signing::EcdsaP256SigningProvider::generate();
                log::info!(
                    "Signing algorithm: ECDSA P-256 (ES256) | pubkey_len={} bytes",
                    provider.public_key().len()
                );
                Arc::new(provider)
            }
            other => {
                panic!(
                    "FATAL: Unknown SIGNING_ALGORITHM='{other}'. Accepted values: ml-dsa-65, ed25519, ecdsa-p256"
                );
            }
        }
    };

    let trusted_signer_count = crate::ordering::configure_trusted_block_signers(
        &env::var("TRUSTED_BLOCK_SIGNERS").unwrap_or_default(),
    )
    .unwrap_or_else(|e| panic!("FATAL: invalid TRUSTED_BLOCK_SIGNERS: {e}"));
    log::info!("Trusted block signers: {trusted_signer_count} peer key(s) plus this node");

    // Ordering backend: "raft" or "solo" (default)
    //
    // When ORDERING_BACKEND=raft, also reads:
    //   RAFT_NODE_ID  — this node's raft ID (default: 1)
    //   RAFT_PEERS    — comma-separated `id:host:port` (e.g. "1:orderer1:8087,2:orderer2:8087")
    #[cfg(feature = "raft-ordering")]
    let mut shared_raft_node: Option<Arc<Mutex<crate::ordering::raft_node::RaftNode>>> = None;
    #[cfg(feature = "raft-ordering")]
    let mut raft_peer_map: Option<crate::ordering::raft_transport::PeerMap> = None;

    let ordering_backend: Option<Arc<dyn ordering::OrderingBackend>> = {
        let backend_name = env::var("ORDERING_BACKEND").unwrap_or_else(|_| "solo".to_string());
        match backend_name.as_str() {
            #[cfg(feature = "raft-ordering")]
            "raft" => {
                let raft_id: u64 = env::var("RAFT_NODE_ID")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);
                let peer_map_raw =
                    env::var("RAFT_PEERS").unwrap_or_else(|_| format!("{raft_id}:127.0.0.1:8087"));
                let parsed_map = crate::ordering::raft_transport::parse_raft_peers(&peer_map_raw);
                let raft_voter_ids: Vec<u64> = parsed_map.keys().copied().collect();

                let voters = if raft_voter_ids.is_empty() {
                    vec![raft_id]
                } else {
                    raft_voter_ids
                };
                // Use persistent Raft storage when STORAGE_BACKEND=rocksdb.
                let raft_result = if env::var("STORAGE_BACKEND").unwrap_or_default() == "rocksdb" {
                    let raft_path = std::path::PathBuf::from(
                        env::var("STORAGE_PATH").unwrap_or_else(|_| "./data/blocks".to_string()),
                    )
                    .join("raft");
                    ordering::raft_service::RaftOrderingService::new_persistent(
                        raft_id, voters, 100, 2000, &raft_path,
                    )
                } else {
                    ordering::raft_service::RaftOrderingService::new(raft_id, voters, 100, 2000)
                };
                match raft_result {
                    Ok(svc) => {
                        log::info!(
                            "Ordering backend: Raft (node_id={raft_id}, peers={peer_map_raw})"
                        );
                        let svc = svc.with_signing_provider(signing_provider.clone());
                        let raft_arc = svc.raft_node.clone();
                        shared_raft_node = Some(raft_arc.clone());
                        raft_peer_map = Some(Arc::new(Mutex::new(parsed_map)));

                        // Use the same RaftOrderingService for the gateway —
                        // shares the RaftNode with the tick loop and P2P handler.
                        Some(Arc::new(svc))
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to create Raft ordering service: {e}. Falling back to solo."
                        );
                        Some(Arc::new(
                            ordering::service::OrderingService::new()
                                .with_signing_provider(signing_provider.clone()),
                        ))
                    }
                }
            }
            _ => {
                log::info!("Ordering backend: Solo");
                Some(Arc::new(
                    ordering::service::OrderingService::new()
                        .with_signing_provider(signing_provider.clone()),
                ))
            }
        }
    };

    // Initialize scaffold services — use RocksDB-backed impls when STORAGE_BACKEND=rocksdb.
    let storage_backend_env = env::var("STORAGE_BACKEND").unwrap_or_default();
    #[cfg(feature = "rocksdb-storage")]
    let shared_rocksdb: Option<Arc<RocksDbBlockStore>> = if storage_backend_env == "rocksdb" {
        let path = env::var("STORAGE_PATH").unwrap_or_else(|_| "./data/blocks".to_string());
        match RocksDbBlockStore::new(&path) {
            Ok(store) => {
                // Run schema migrations before serving requests.
                match storage::migrations::run_pending(&store) {
                    Ok(n) if n > 0 => log::info!("{n} schema migration(s) applied"),
                    Err(e) => {
                        log::error!("Schema migration failed: {e}");
                        return Err(std::io::Error::other(format!("migration failed: {e}")));
                    }
                    _ => {}
                }
                match crate::identity::migration::migrate_legacy_dids(&store) {
                    Ok(r) if r.migrated > 0 => {
                        log::info!("Migrated {} legacy DID(s) to SHA3-512", r.migrated);
                    }
                    Ok(r) if !r.errors.is_empty() => {
                        log::warn!("DID migration: {} error(s)", r.errors.len());
                    }
                    Err(e) => log::warn!("DID migration skipped: {e}"),
                    _ => {}
                }
                log::info!("Storage backend: RocksDB at {path}");
                Some(Arc::new(store))
            }
            Err(e) => {
                log::error!("STORAGE_BACKEND=rocksdb but failed to open RocksDB at {path}: {e}");
                return Err(std::io::Error::other(format!(
                    "RocksDB failed to open at {path}: {e}"
                )));
            }
        }
    } else {
        None
    };
    #[cfg(not(feature = "rocksdb-storage"))]
    let shared_rocksdb: Option<Arc<storage::MemoryStore>> = {
        let _ = &storage_backend_env;
        if storage_backend_env == "rocksdb" {
            log::warn!("STORAGE_BACKEND=rocksdb but 'rocksdb-storage' feature not compiled. Using memory store.");
        }
        None
    };

    // Attach persistent store to TransactionValidator for replay prevention
    #[cfg(feature = "rocksdb-storage")]
    if let Some(ref db) = shared_rocksdb {
        let mut tv = transaction_validator
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Ok(entries) = db.load_seen_txs() {
            let count = entries.len();
            for (tx_id, ts) in entries {
                tv.seen_transaction_ids.insert(tx_id, ts);
            }
            if count > 0 {
                log::info!("Loaded {count} seen transaction IDs from RocksDB");
            }
        }
        tv.store = Some(db.clone());
    }

    if shared_rocksdb.is_some() {
        log::info!("Services: persistent (RocksDB) — orgs, policies, ACLs, CRL, chaincode, collections, private data, seen tx IDs");
    } else {
        log::info!("Services: in-memory — data will be lost on restart");
    }

    let org_registry: Arc<dyn crate::endorsement::registry::OrgRegistry> = {
        #[cfg(feature = "rocksdb-storage")]
        if let Some(ref db) = shared_rocksdb {
            db.clone()
        } else {
            Arc::new(crate::endorsement::registry::MemoryOrgRegistry::new())
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        Arc::new(crate::endorsement::registry::MemoryOrgRegistry::new())
    };
    let policy_store: Arc<dyn crate::endorsement::policy_store::PolicyStore> = {
        #[cfg(feature = "rocksdb-storage")]
        if let Some(ref db) = shared_rocksdb {
            db.clone()
        } else {
            Arc::new(crate::endorsement::policy_store::MemoryPolicyStore::new())
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        Arc::new(crate::endorsement::policy_store::MemoryPolicyStore::new())
    };
    let discovery_service = Arc::new(
        crate::discovery::service::DiscoveryService::new(
            org_registry.clone(),
            policy_store.clone(),
        )
        .with_metrics(metrics_collector.clone()),
    );
    let world_state: Arc<dyn storage::world_state::WorldState> = {
        let state_db = env::var("STATE_DB").unwrap_or_default();
        if state_db == "couchdb" {
            let couchdb_url =
                env::var("COUCHDB_URL").unwrap_or_else(|_| "http://localhost:5984".to_string());
            let couchdb_db = env::var("COUCHDB_DB").unwrap_or_else(|_| "world_state".to_string());
            match storage::couchdb::CouchDbWorldState::new(&couchdb_url, &couchdb_db) {
                Ok(ws) => {
                    log::info!("World state backend: CouchDB at {couchdb_url}/{couchdb_db}");
                    Arc::new(ws)
                }
                Err(e) => {
                    log::error!(
                        "Failed to connect to CouchDB: {e}. Falling back to MemoryWorldState."
                    );
                    Arc::new(storage::MemoryWorldState::new())
                }
            }
        } else {
            log::info!("World state backend: MemoryWorldState");
            Arc::new(storage::MemoryWorldState::new())
        }
    };
    let chaincode_package_store: Arc<dyn crate::chaincode::ChaincodePackageStore> = {
        #[cfg(feature = "rocksdb-storage")]
        if let Some(ref db) = shared_rocksdb {
            db.clone()
        } else {
            Arc::new(crate::chaincode::MemoryChaincodePackageStore::new())
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        Arc::new(crate::chaincode::MemoryChaincodePackageStore::new())
    };
    let ordering_service_for_gateway: Arc<dyn ordering::OrderingBackend> =
        ordering_backend.clone().unwrap_or_else(|| {
            Arc::new(
                ordering::service::OrderingService::new()
                    .with_signing_provider(signing_provider.clone()),
            )
        });
    let gateway_store: Arc<dyn storage::BlockStore> = {
        #[cfg(feature = "rocksdb-storage")]
        if let Some(ref db) = shared_rocksdb {
            db.clone()
        } else {
            Arc::new(storage::MemoryStore::new())
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        Arc::new(storage::MemoryStore::new())
    };
    let mut gateway = crate::gateway::Gateway::new(
        org_registry.clone(),
        policy_store.clone(),
        ordering_service_for_gateway,
        gateway_store.clone(),
    );
    gateway.world_state = Some(world_state.clone());
    gateway.discovery_service = Some(discovery_service.clone());
    gateway.p2p_node = Some(node_arc.clone());
    let event_bus = Arc::new(events::EventBus::new());
    gateway.event_bus = Some(event_bus.clone());

    // CSIRT/SIEM webhook: forward security events to external endpoint.
    if let Some(webhook_config) = events::webhook::WebhookConfig::from_env() {
        let webhook_rx = event_bus.subscribe();
        events::webhook::spawn_webhook_notifier(webhook_config, webhook_rx);
    }

    // Wire endorsement resources into the P2P server node so it can handle
    // ProposalRequest messages (simulate chaincode + sign rwset).
    node_for_server.chaincode_store = Some(chaincode_package_store.clone());
    node_for_server.world_state = Some(world_state.clone());
    node_for_server.signing_provider = Some(signing_provider.clone());
    // Wire the gateway store into the server node for pull-based state sync
    // (StateRequest handler reads blocks from this store).
    node_for_server.store = Some(gateway_store.clone());
    // Wire Raft node into the P2P server for RaftMessage handling.
    #[cfg(feature = "raft-ordering")]
    if let Some(ref raft) = shared_raft_node {
        node_for_server.raft_node = Some(raft.clone());
    }
    // Wire private data resources for PrivateDataPush handling.
    let private_data_store: Arc<dyn crate::private_data::PrivateDataStore> = {
        #[cfg(feature = "rocksdb-storage")]
        if let Some(ref db) = shared_rocksdb {
            db.clone()
        } else {
            Arc::new(crate::private_data::MemoryPrivateDataStore::new())
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        Arc::new(crate::private_data::MemoryPrivateDataStore::new())
    };
    let collection_registry: Arc<dyn crate::private_data::CollectionRegistry> = {
        #[cfg(feature = "rocksdb-storage")]
        if let Some(ref db) = shared_rocksdb {
            db.clone()
        } else {
            Arc::new(crate::private_data::MemoryCollectionRegistry::new())
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        Arc::new(crate::private_data::MemoryCollectionRegistry::new())
    };
    node_for_server.private_data_store = Some(private_data_store.clone());
    node_for_server.collection_registry = Some(collection_registry.clone());

    // Hydrate governance stores from persistent storage
    let proposal_store = {
        let ps = Arc::new(governance::proposals::ProposalStore::new());
        match gateway_store.list_proposals() {
            Ok(proposals) => {
                let count = proposals.len();
                for p in proposals {
                    ps.load_proposal(p);
                }
                if count > 0 {
                    log::info!("Hydrated {count} governance proposals from store");
                }
            }
            Err(e) => log::warn!("Failed to load proposals from store: {e}"),
        }
        ps
    };
    let vote_store = {
        let vs = Arc::new(governance::voting::VoteStore::new());
        // Load votes for all known proposals
        if let Ok(proposals) = gateway_store.list_proposals() {
            let mut total = 0usize;
            for p in &proposals {
                if let Ok(votes) = gateway_store.list_votes(p.id) {
                    for v in votes {
                        vs.load_vote(v);
                        total += 1;
                    }
                }
            }
            if total > 0 {
                log::info!("Hydrated {total} governance votes from store");
            }
        }
        vs
    };

    let economics_state = std::sync::Arc::new(std::sync::Mutex::new(
        crate::tokenomics::economics::EconomicsState::default(),
    ));

    let app_state = AppState {
        node: Some(node_arc.clone()),
        balance_cache: balance_cache.clone(),
        billing_manager: billing_manager.clone(),
        contract_manager: contract_manager.clone(),
        staking_manager: staking_manager.clone(),
        airdrop_manager: airdrop_manager.clone(),
        checkpoint_manager: checkpoint_manager.clone(),
        transaction_validator: transaction_validator.clone(),
        metrics: metrics_collector.clone(),
        store: {
            // Use the same store instance as the gateway so queries and commits
            // operate on the same data.
            let default_store: Arc<dyn storage::BlockStore> = gateway_store.clone();
            // Write genesis block for the default channel if store is empty.
            if !default_store.block_exists(0).unwrap_or(true) {
                let genesis_config = crate::channel::config::ChannelConfig::default();
                let genesis =
                    crate::channel::genesis::create_genesis_block("default", &genesis_config);
                if let Err(e) = default_store.write_block(&genesis) {
                    log::error!("Failed to write default channel genesis block: {e}");
                } else {
                    log::info!("Default channel genesis block written (height=0)");
                }
            }
            let mut store_map = std::collections::HashMap::new();
            store_map.insert("default".to_string(), default_store);
            std::sync::Arc::new(std::sync::RwLock::new(store_map))
        },
        org_registry: Some(org_registry),
        policy_store: Some(policy_store),
        crl_store: Some({
            #[cfg(feature = "rocksdb-storage")]
            if let Some(ref db) = shared_rocksdb {
                db.clone() as Arc<dyn crate::msp::CrlStore>
            } else {
                Arc::new(crate::msp::MemoryCrlStore::new()) as Arc<dyn crate::msp::CrlStore>
            }
            #[cfg(not(feature = "rocksdb-storage"))]
            {
                Arc::new(crate::msp::MemoryCrlStore::new()) as Arc<dyn crate::msp::CrlStore>
            }
        }),
        private_data_store: Some(private_data_store.clone()),
        collection_registry: Some(collection_registry.clone()),
        chaincode_package_store: Some(chaincode_package_store.clone()),
        chaincode_definition_store: Some({
            #[cfg(feature = "rocksdb-storage")]
            if let Some(ref db) = shared_rocksdb {
                db.clone() as Arc<dyn crate::chaincode::ChaincodeDefinitionStore>
            } else {
                Arc::new(crate::chaincode::MemoryChaincodeDefinitionStore::new())
                    as Arc<dyn crate::chaincode::ChaincodeDefinitionStore>
            }
            #[cfg(not(feature = "rocksdb-storage"))]
            {
                Arc::new(crate::chaincode::MemoryChaincodeDefinitionStore::new())
                    as Arc<dyn crate::chaincode::ChaincodeDefinitionStore>
            }
        }),
        gateway: Some(Arc::new(gateway)),
        discovery_service: Some(discovery_service),
        event_bus: event_bus.clone(),
        channel_configs: std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::new(),
        )),
        acl_provider: Some({
            #[cfg(feature = "rocksdb-storage")]
            if let Some(ref db) = shared_rocksdb {
                db.clone() as Arc<dyn crate::acl::AclProvider>
            } else {
                Arc::new(crate::acl::MemoryAclProvider::new()) as Arc<dyn crate::acl::AclProvider>
            }
            #[cfg(not(feature = "rocksdb-storage"))]
            {
                Arc::new(crate::acl::MemoryAclProvider::new()) as Arc<dyn crate::acl::AclProvider>
            }
        }),
        ordering_backend,
        world_state: Some(world_state.clone()),
        audit_store: Some({
            #[cfg(feature = "rocksdb-storage")]
            if let Some(ref db) = shared_rocksdb {
                db.clone() as Arc<dyn crate::audit::AuditStore>
            } else {
                Arc::new(crate::audit::MemoryAuditStore::new()) as Arc<dyn crate::audit::AuditStore>
            }
            #[cfg(not(feature = "rocksdb-storage"))]
            {
                Arc::new(crate::audit::MemoryAuditStore::new()) as Arc<dyn crate::audit::AuditStore>
            }
        }),
        proposal_store: Some(proposal_store),
        vote_store: Some(vote_store),
        param_registry: Some({
            let reg = Arc::new(governance::params::ParamRegistry::with_defaults());
            // Override voting period from env for demo/testnet (default: 17280 blocks ~3 days)
            if let Ok(vp) = std::env::var("GOVERNANCE_VOTING_PERIOD") {
                if let Ok(blocks) = vp.parse::<u64>() {
                    reg.set(
                        governance::params::keys::VOTING_PERIOD_BLOCKS,
                        governance::params::ParamValue::U64(blocks),
                    );
                    log::info!("Governance voting period set to {blocks} blocks (from env)");
                }
            }
            reg
        }),
        pin_store: Some(Arc::new(pin::store::MemoryPinStore::new())),
        oracle_registry: Arc::new(std::sync::Mutex::new(oracle_system::OracleRegistry::new(
            66, 300_000,
        ))),
        contact_store: Arc::new(api::handlers::contact::ContactStore::new()),
        sandbox_report_store: Arc::new(chaincode::sandbox::MemorySandboxReportStore::new()),
        legal_oracle_store: Arc::new(legal_oracle::MemoryOracleRecordStore::new()),
        legal_oracle: Arc::new(std::sync::Mutex::new(
            legal_oracle::legal::LegalOracle::new(300),
        )),
        mining_service: Some(Arc::new(
            mining::MiningService::new(gateway_store.clone(), mining::MiningConfig::default())
                .with_signer(signing_provider.clone())
                .with_economics(economics_state.clone()),
        )),
        signing_provider: Some(signing_provider.clone()),
        tx_pool: Arc::new(std::sync::Mutex::new(
            transaction::mempool::TransactionPool::new(),
        )),
        vault_recovery_secret: std::env::var("VAULT_RECOVERY_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| hex::decode(s.as_str()).unwrap_or_else(|_| s.into_bytes())),
        vault_rate_limiter: Arc::new(crate::api::handlers::vault::RecoveryRateLimiter::new()),
        bridge_engine: Arc::new(crate::bridge::protocol::BridgeEngine::new()),
        proof_verifier: Arc::new(inference::proof::MultiVerifier::new()),
        tsa_provider: {
            let pk_hex = hex::encode(signing_provider.public_key());
            let tsa_did = crate::identity::did::did_from_pubkey_hex(&pk_hex);
            let mut tsa = crate::tsa::TsaProvider::new(signing_provider.clone(), tsa_did);
            let ntp = Arc::new(crate::time_source::NtpTimeSource::new(5));
            let _ = crate::time_source::check_ntp_sync(&ntp);
            tsa = tsa.with_time_source(ntp);
            log::info!("TSA provider initialized (RFC 3161)");
            Some(Arc::new(tsa))
        },
        ra_store: {
            let store = Arc::new(crate::identity::ra::RaStore::new());
            log::info!("RA store initialized (Ley 19.799 Art. 15)");
            Some(store)
        },
        identity_verifier: {
            if let Ok(uuid) = std::env::var("SMART_ID_UUID") {
                let name =
                    std::env::var("SMART_ID_NAME").unwrap_or_else(|_| "Goya Ledger".to_string());
                let verifier: Arc<dyn crate::identity::ra::IdentityVerificationProvider> =
                    if uuid == "demo" {
                        log::info!("Identity verifier: Smart-ID (demo)");
                        Arc::new(crate::identity::ra::SmartIdVerifier::demo(name))
                    } else {
                        log::info!("Identity verifier: Smart-ID (production)");
                        Arc::new(crate::identity::ra::SmartIdVerifier::new(uuid, name))
                    };
                Some(verifier)
            } else {
                log::info!("Identity verifier: simulated (set SMART_ID_UUID to enable Smart-ID)");
                Some(Arc::new(crate::identity::ra::SimulatedIdentityVerifier))
            }
        },
        ocsp_responder: {
            let responder = crate::msp::ocsp::OcspResponder::new(
                signing_provider.clone(),
                crate::identity::did::did_from_pubkey_hex(&hex::encode(
                    signing_provider.public_key(),
                )),
            );
            log::info!("OCSP responder initialized (RFC 6960)");
            Some(Arc::new(responder))
        },
        lifecycle_manager: {
            let lm = crate::pki_lifecycle::LifecycleManager::new(7, 30);
            log::info!("Certificate lifecycle manager initialized");
            Some(Arc::new(lm))
        },
        lexchain_store: crate::lexchain::store::LexChainStore::with_backend(gateway_store.clone()),
        economics_state: economics_state.clone(),
        deposit_ledger: std::sync::Arc::new(
            crate::tokenomics::storage_deposit::DepositLedger::new(),
        ),
        private_claims: std::sync::Arc::new(crate::privacy::PrivateClaimsStore::new()),
    };
    log::info!("LexChain engine initialized");

    // Log vault recovery secret fingerprint for rotation verification.
    app_state.vault_recovery_secret.as_ref().inspect(|secret| {
        pqc_crypto_module::api::sha3_256(secret)
            .inspect(|hash| {
                log::info!(
                    "Vault recovery secret fingerprint: {}...",
                    &hash.to_hex()[..16]
                );
            })
            .ok();
    });

    // Telemetry adapter: polls external APIs and ingests into Asset Registry.
    // Activated by TELEMETRY_SOURCE_URL env var.
    if let Some(adapter_config) = registry::adapter::AdapterConfig::from_env() {
        registry::adapter::spawn_telemetry_poller(adapter_config, gateway_store.clone());
    }

    // Oracle demo feed: simulated price data for sandbox demos.
    let demo_config = oracle_demo::DemoFeedConfig::from_env();
    oracle_demo::spawn_demo_feed(demo_config, app_state.oracle_registry.clone());

    // Oracle external connector: real price feeds from HTTP APIs.
    // Activated by ORACLE_SOURCES env var (comma-separated URLs).
    if let Some(connector_config) = oracle_connector::ConnectorConfig::from_env() {
        let symbol = std::env::var("ORACLE_CONNECTOR_SYMBOL").unwrap_or_else(|_| "BTC/USD".into());
        log::info!(
            "Oracle external connector enabled: {} source(s) for {symbol}",
            connector_config.sources.len()
        );
        oracle_connector::spawn_oracle_poller(
            connector_config,
            app_state.oracle_registry.clone(),
            symbol,
        );
    }

    println!("🌐 Servidor API iniciado en http://127.0.0.1:{api_port}");
    println!("📡 Servidor P2P iniciado en 127.0.0.1:{p2p_port}");
    println!("📚 Documentación de API:");
    println!("   GET  /api/v1/blocks (gateway envelope)");
    println!("   GET  /api/v1/blocks/index/{{index}}");
    println!("   GET  /api/v1/blocks/{{hash}}");
    println!("   POST /api/v1/blocks (gateway envelope)");
    println!("   POST /api/v1/transactions (gateway envelope)");
    println!("   GET  /api/v1/mempool (gateway envelope)");
    println!("   GET  /api/v1/wallets/{{address}}");
    println!("   GET  /api/v1/chain/verify (gateway envelope)");
    println!("   GET  /api/v1/chain/info (gateway envelope)");
    println!("   GET  /api/v1/health   (gateway envelope)");
    println!("   GET  /api/v1/version (gateway envelope)");
    println!("   GET  /api/v1/openapi.json");
    println!("\n💡 Presiona Ctrl+C para detener el servidor\n");

    // Clonar node_arc para conectar a bootstrap nodes después de iniciar
    let node_for_bootstrap = node_arc.clone();
    let bootstrap_nodes_clone = bootstrap_nodes.clone();

    // Start pull-based state sync loop (catches up from peers with higher block height).
    let pull_sync_handle =
        node_for_server.start_pull_sync_loop(crate::network::gossip::PULL_INTERVAL_MS);

    // Start Raft tick loop if raft backend is configured.
    #[cfg(feature = "raft-ordering")]
    if let (Some(raft), Some(peer_map)) = (&shared_raft_node, &raft_peer_map) {
        let _raft_tick_handle = crate::ordering::raft_transport::start_raft_tick_loop(
            raft.clone(),
            peer_map.clone(),
            node_arc.clone(),
            100, // tick every 100ms
        );
        log::info!("Raft tick loop started (100ms interval)");
    }

    // Private data TTL purge loop — expires entries whose blocks_to_live window has closed.
    {
        let pd_store = private_data_store.clone();
        let gw_store = gateway_store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let current_height = gw_store.get_latest_height().unwrap_or(0);
                if current_height > 0 {
                    pd_store.purge_expired(current_height);
                }
            }
        });
    }

    let server_handle = tokio::spawn(async move {
        if let Err(e) = node_for_server.start_server(p2p_port).await {
            eprintln!("Error en servidor P2P: {e}");
        }
    });

    // Conectar a bootstrap nodes después de un breve delay
    if !bootstrap_nodes_clone.is_empty() {
        tokio::spawn(async move {
            // Esperar a que el servidor esté listo
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            node_for_bootstrap.connect_to_bootstrap_nodes().await;
        });
    }

    // ── BFT consensus + auto-mine loop ─────────────────────────────────
    let bft_enabled = std::env::var("BFT_VALIDATORS")
        .ok()
        .filter(|v| !v.is_empty());

    if let Some(ref validator_csv) = bft_enabled {
        let validators: Vec<String> = validator_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let node_id = std::env::var("BFT_NODE_ID").unwrap_or_else(|_| format!("node-{p2p_port}"));

        // Parse validator public keys for real ML-DSA-65 signature verification.
        let bft_verifier = match std::env::var("BFT_VALIDATOR_KEYS") {
            Ok(keys_csv) => {
                let registry =
                    crate::consensus::bft::validator_registry::ValidatorRegistry::from_env_str(
                        &keys_csv,
                    )
                    .unwrap_or_else(|e| panic!("BFT_VALIDATOR_KEYS invalid: {e}"));
                log::info!("BFT: loaded {} validator public keys", registry.len());
                crate::consensus::bft::validator_registry::RegistryVerifier::new(
                    std::sync::Arc::new(registry),
                )
            }
            Err(_) => {
                panic!("BFT_VALIDATOR_KEYS must be set when BFT_VALIDATORS is configured. \
                        Format: id1:<hex_pk>,id2:<hex_pk>,... (ML-DSA-65 public keys, 1952 bytes each)");
            }
        };

        log::info!(
            "BFT consensus enabled: {} validators, node_id={node_id}",
            validators.len()
        );
        let bft_node = node_arc.clone();
        let bft_store = gateway_store.clone();
        let bft_signer = signing_provider.clone();
        let bft_mining = app_state
            .mining_service
            .clone()
            .expect("MiningService required for BFT");
        let bft_pool = app_state.tx_pool.clone();
        tokio::spawn(async move {
            crate::consensus::controller::run_bft_loop(
                node_id,
                validators,
                bft_rx,
                bft_node,
                bft_store,
                bft_signer,
                bft_mining,
                bft_pool,
                bft_verifier,
            )
            .await;
        });
    }

    // Solo mode auto-mine (only when BFT is not active).
    if bft_enabled.is_none() {
        let mine_interval_secs: u64 = std::env::var("BLOCK_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let mine_store = gateway_store.clone();
        let mine_tx_pool = app_state.tx_pool.clone();
        let mine_mining = app_state.mining_service.clone();
        let mine_node = node_arc.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(mine_interval_secs));
            loop {
                interval.tick().await;
                let Some(ref mining_service) = mine_mining else {
                    continue;
                };
                let txs = {
                    let mut pool = mine_tx_pool.lock().unwrap_or_else(|e| e.into_inner());
                    pool.drain_for_block(50)
                };
                if txs.is_empty() {
                    continue;
                }
                let tx_count = txs.len();
                match mining_service.mine_block("auto-miner", txs) {
                    Ok(height) => {
                        log::info!("⛏ Auto-mined block {height} with {tx_count} tx(s)");
                        if let Ok(block) = mine_store.read_block(height) {
                            let node = mine_node.clone();
                            tokio::spawn(async move {
                                node.broadcast_ordered_block(&block).await;
                            });
                        }
                    }
                    Err(e) => log::error!("Auto-mine failed: {e}"),
                }
            }
        });
        log::info!("Solo auto-mine loop started (interval=5s)");
    }

    let rate_limit_config = middleware::RateLimitConfig {
        requests_per_minute: std::env::var("RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100),
        requests_per_hour: std::env::var("RATE_LIMIT_PER_HOUR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000),
        requests_per_second: std::env::var("RATE_LIMIT_PER_SECOND")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20),
    };

    // Parámetros de recarga TLS (para SIGHUP)
    let tls_reload_params = tls_reload_params_from_env();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let api_bind = format!("{bind_addr}:{api_port}");
    let node_mode = NodeMode::from_env();
    log::info!("Node mode: {node_mode}");

    let http_keep_alive_secs: u64 = std::env::var("HTTP_KEEP_ALIVE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(75);
    let http_request_timeout_secs: u64 = std::env::var("HTTP_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    // Configurar límite de tamaño para JSON (256KB por defecto, aumentamos a 1MB)
    let json_config = web::JsonConfig::default()
        .limit(1_048_576) // 1MB
        .error_handler(|err, _req| {
            log::debug!("[JSON ERROR] Error al deserializar JSON: {err:?}");
            actix_web::error::ErrorBadRequest(format!("JSON deserialization error: {err}"))
        });

    let audit_store_for_mw: Arc<dyn crate::audit::AuditStore> = app_state
        .audit_store
        .clone()
        .unwrap_or_else(|| Arc::new(crate::audit::MemoryAuditStore::new()));

    let nonce_store = web::Data::new(crate::api::handlers::oid4vci::NonceStore::new());
    let status_list_store = web::Data::new(crate::api::handlers::oid4vci::StatusListStore::new());
    {
        let seed = crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            b"goya-oid4vci-es256-issuer-key-v1",
        );
        let provider = crate::identity::signing::EcdsaP256SigningProvider::from_bytes(&seed)
            .expect("deterministic ES256 key");
        status_list_store.set_signing_provider(std::sync::Arc::new(provider));
    }
    let credential_offer_store =
        web::Data::new(crate::api::handlers::oid4vci::CredentialOfferStore::new());
    let vp_request_store = web::Data::new(crate::api::handlers::oid4vp::VpRequestStore::new());
    let auth_store = web::Data::new(crate::api::handlers::oid4vci::AuthorizationStore::new());

    #[cfg(feature = "evm")]
    let evm_state = web::Data::new(crate::api::handlers::evm::EvmState::new());

    let server = HttpServer::new(move || {
        let cors_policy = crate::api::cors::CorsPolicy::from_env();
        let cors = if cors_policy.allowed_origins.contains(&"*".to_string()) {
            Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600)
        } else {
            let mut c = Cors::default();
            for origin in &cors_policy.allowed_origins {
                c = c.allowed_origin(origin);
            }
            c.allow_any_method()
                .allow_any_header()
                .supports_credentials()
                .max_age(3600)
        };

        let app = App::new()
            .wrap(cors)
            .wrap(Compress::default())
            .wrap(crate::api::middleware::AuditMiddleware {
                store: audit_store_for_mw.clone(),
            })
            .wrap(RateLimitMiddleware::new(rate_limit_config.clone()))
            .wrap(crate::api::middleware::TlsIdentityMiddleware)
            .wrap(crate::api::middleware::InputValidationMiddleware::default())
            .app_data(web::Data::new(app_state.clone()))
            .app_data(nonce_store.clone())
            .app_data(status_list_store.clone())
            .app_data(credential_offer_store.clone())
            .app_data(vp_request_store.clone())
            .app_data(auth_store.clone());
        #[cfg(feature = "evm")]
        let app = app.app_data(evm_state.clone());
        app.app_data(json_config.clone())
            .app_data(web::PayloadConfig::default().limit(10_485_760)) // 10MB max for raw payloads (chaincode)
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                log::debug!("[JSON] Deserialization error on {}: {err:?}", _req.path());
                actix_web::error::ErrorBadRequest(format!("JSON error: {err}"))
            }))
            .configure(|cfg: &mut web::ServiceConfig| {
                match node_mode {
                    NodeMode::Full => {
                        config_routes(cfg);
                        ApiRoutes::configure_metrics(cfg);
                    }
                    NodeMode::Light => LightRoutes::configure(cfg),
                }
            })
    })
    .on_connect(|conn, ext| {
        // Extract peer certificates from mTLS handshake into connection extensions.
        // Actix passes the underlying TLS stream; we extract the rustls ServerConnection
        // and read the peer cert chain.
        use std::any::Any;
        if let Some(tls_stream) = (conn as &dyn Any)
            .downcast_ref::<actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>>()
        {
            let server_conn = tls_stream.get_ref().1;
            if let Some(certs) = server_conn.peer_certificates() {
                let der_certs: Vec<Vec<u8>> = certs.iter().map(|c| c.as_ref().to_vec()).collect();
                if !der_certs.is_empty() {
                    ext.insert(crate::api::middleware::PeerCertificates(der_certs));
                }
            }
        }
    })
    .keep_alive(std::time::Duration::from_secs(http_keep_alive_secs))
    .client_request_timeout(std::time::Duration::from_secs(http_request_timeout_secs));

    log::info!(
        "HTTP keep-alive: {http_keep_alive_secs}s, request timeout: {http_request_timeout_secs}s"
    );

    // --- Production environment guards ---
    let env_mode = std::env::var("RUST_BC_ENV").unwrap_or_default();
    let acl_mode = std::env::var("ACL_MODE").unwrap_or_else(|_| "permissive".to_string());

    if env_mode == "production" && acl_mode == "permissive" {
        log::warn!(
            "ACL_MODE=permissive in production — X-Org-Id/X-Msp-Role headers are spoofable. \
             Set ACL_MODE=strict with mTLS for production use."
        );
    }

    let tls_result = load_tls_config_from_env();

    if env_mode == "production" {
        match &tls_result {
            Ok(None) => panic!(
                "FATAL: TLS_CERT_PATH and TLS_KEY_PATH must be set in production. \
                 Set RUST_BC_ENV=development to run without TLS."
            ),
            Err(e) => panic!("FATAL: TLS configuration error in production: {e}"),
            Ok(Some(_)) => {}
        }
    }

    let api_handle = match tls_result {
        Ok(Some(tls_config)) => {
            println!("TLS habilitado en {api_bind}");
            server.bind_rustls_0_23(&api_bind, tls_config)?
        }
        Ok(None) => {
            log::warn!("TLS no configurado — API en texto plano en {api_bind}");
            server.bind(&api_bind)?
        }
        Err(e) => {
            eprintln!("Error al cargar configuracion TLS: {e}");
            return Err(std::io::Error::other(e.to_string()));
        }
    }
    .workers(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8),
    )
    .run();

    // Tarea SIGHUP: recarga certificados TLS y detiene el servidor si los nuevos son válidos
    {
        let sighup_server_handle = api_handle.handle();
        let params = tls_reload_params.clone();
        tokio::spawn(async move {
            let mut sig =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("No se pudo registrar SIGHUP: {e}");
                        return;
                    }
                };
            loop {
                sig.recv().await;
                log::info!("SIGHUP recibido — verificando certificados TLS...");
                match &params {
                    None => log::info!("TLS no configurado; SIGHUP ignorado."),
                    Some(p) => match reload_tls_config(p) {
                        Ok(_) => {
                            log::info!(
                                "Certificados TLS OK. Deteniendo servidor para aplicar cambios..."
                            );
                            sighup_server_handle.stop(true).await;
                            break;
                        }
                        Err(e) => {
                            log::error!(
                                "Error al recargar certificados TLS: {e}. Servidor sin cambios."
                            );
                        }
                    },
                }
            }
        });
    }

    // Tarea periódica de recarga TLS (opcional: TLS_RELOAD_INTERVAL en segundos)
    if let Some(interval_secs) = env::var("TLS_RELOAD_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
    {
        let reload_server_handle = api_handle.handle();
        let params = tls_reload_params.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            ticker.tick().await; // saltar el tick inicial inmediato
            loop {
                ticker.tick().await;
                log::info!(
                    "Recarga TLS periódica (intervalo {interval_secs}s) — verificando certificados..."
                );
                match &params {
                    None => log::debug!("TLS no configurado; recarga periódica omitida."),
                    Some(p) => match reload_tls_config(p) {
                        Ok(_) => {
                            log::info!(
                                "Certificados TLS OK. Deteniendo servidor para aplicar cambios..."
                            );
                            reload_server_handle.stop(true).await;
                            break;
                        }
                        Err(e) => {
                            log::error!(
                                "Error en recarga TLS periódica: {e}. Servidor sin cambios."
                            );
                        }
                    },
                }
            }
        });
        log::info!("Recarga TLS automática habilitada cada {interval_secs} segundos.");
    }

    // Tarea periódica para limpiar peers desconectados (cada 60 segundos)
    let node_for_cleanup = node_arc.clone();
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            node_for_cleanup.cleanup_disconnected_peers().await;
        }
    });

    // Tarea periódica para auto-discovery de peers
    let node_for_discovery = node_arc.clone();
    let discovery_interval_secs = auto_discovery_interval;
    let discovery_max_connections = auto_discovery_max_connections;
    let discovery_initial_delay_secs = auto_discovery_initial_delay;
    let discovery_handle = tokio::spawn(async move {
        // Esperar delay inicial para que los bootstrap nodes se conecten
        tokio::time::sleep(tokio::time::Duration::from_secs(
            discovery_initial_delay_secs,
        ))
        .await;

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(discovery_interval_secs));
        loop {
            interval.tick().await;

            // auto_discover_and_connect ya maneja:
            // 1. Reconexión a bootstrap si no hay peers (en discover_peers)
            // 2. Conexión a bootstrap si hay pocos peers (< 3)
            node_for_discovery
                .auto_discover_and_connect(discovery_max_connections)
                .await;
        }
    });

    // Anti-entropy: periodically sync with peers to recover from missed gossip
    let node_for_antientropy = node_arc.clone();
    let antientropy_handle = tokio::spawn(async move {
        // Wait for network to stabilize
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = node_for_antientropy.sync_with_all_peers().await {
                log::debug!("Anti-entropy sync: {e}");
            }
        }
    });

    // ── Graceful shutdown ─────────────────────────────────────────────────────
    //
    // Wait for the API server to finish OR a termination signal (Ctrl-C /
    // SIGTERM).  On signal we:
    //   1. Stop accepting new HTTP connections and drain in-flight requests.
    //   2. Abort ALL background tasks.
    //   3. Flush RocksDB WAL + memtables to ensure all writes are persisted.
    //   4. Log each phase for operator visibility.
    let http_server_handle = api_handle.handle();

    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
    };

    tokio::select! {
        result = api_handle => {
            result?;
        }
        _ = shutdown_signal => {
            let shutdown_start = std::time::Instant::now();
            log::info!("Shutdown signal received — stopping gracefully (15s max)...");

            // 1. Stop HTTP server (drain in-flight requests).
            http_server_handle.stop(true).await;
            log::info!("[shutdown] HTTP server stopped ({:.1}s)", shutdown_start.elapsed().as_secs_f64());

            // 2. Abort ALL background tasks.
            cleanup_handle.abort();
            discovery_handle.abort();
            server_handle.abort();
            pull_sync_handle.abort();
            antientropy_handle.abort();
            log::info!("[shutdown] Background tasks aborted ({:.1}s)", shutdown_start.elapsed().as_secs_f64());

            // 3. Flush RocksDB WAL + memtables.
            #[cfg(feature = "rocksdb-storage")]
            if let Some(ref db) = shared_rocksdb {
                match db.flush_wal() {
                    Ok(()) => log::info!("[shutdown] RocksDB WAL + memtables flushed"),
                    Err(e) => log::error!("[shutdown] RocksDB flush failed: {e}"),
                }
            }

            log::info!(
                "[shutdown] Complete in {:.1}s",
                shutdown_start.elapsed().as_secs_f64()
            );
        }
    }

    Ok(())
}
