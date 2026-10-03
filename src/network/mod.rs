pub mod gossip;

// Type alias for the gossip block sender to reduce type complexity.
type GossipBlockTx = Option<
    Arc<tokio::sync::mpsc::UnboundedSender<(crate::storage::traits::Block, Option<String>)>>,
>;

// Conditional type alias for Raft node handle.
#[cfg(feature = "raft-ordering")]
type RaftNodeHandle = Option<Arc<Mutex<crate::ordering::raft_node::RaftNode>>>;
#[cfg(not(feature = "raft-ordering"))]
type RaftNodeHandle = Option<Arc<()>>; // Arc<()> is not Copy, so .clone() is valid

// Standard library
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

// External crates
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// Crate modules
use crate::checkpoint::CheckpointManager;
use crate::network_security::NetworkSecurityManager;
use crate::ordering::NodeRole;
use crate::smart_contracts::{ContractManager, SmartContract};
use crate::transaction_validation::TransactionValidator;

// ── Configurable buffer sizes (env var override) ─────────────────────────────

/// Buffer for `send_and_wait` P2P responses.  Default 256 KB.
fn p2p_response_buffer_size() -> usize {
    std::env::var("P2P_RESPONSE_BUFFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 * 1024 * 1024) // 4 MB (was 256 KB)
}

/// Buffer for the per-connection message handler.  Default 1 MB.
fn p2p_handler_buffer_size() -> usize {
    std::env::var("P2P_HANDLER_BUFFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024 * 1024) // 1 MB (was 64 KB)
}

/// Buffer for pull-based state sync responses.  Default 4 MB.
fn p2p_sync_buffer_size() -> usize {
    std::env::var("P2P_SYNC_BUFFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 * 1024 * 1024)
}

/// Abstracts over plain TCP and TLS peer streams.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

/**
 * Tipos de mensajes en la red P2P
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum Message {
    Ping,
    Pong,
    GetPeers,
    Peers(Vec<String>),
    Version {
        version: String,
        block_count: usize,
        latest_hash: String,
        p2p_address: Option<String>, // Dirección P2P del nodo que envía el mensaje
        network_id: Option<String>,  // Network ID para separar testnet/mainnet
    },
    // Mensajes de contratos
    GetContracts,
    GetContractsSince {
        timestamp: u64,
    },
    Contracts(Vec<SmartContract>),
    NewContract(SmartContract),
    UpdateContract(SmartContract),
    /// Peer sends an endorsed transaction to the orderer.
    SubmitTransaction(crate::storage::traits::Transaction),
    /// Orderer broadcasts an ordered block to peers.
    OrderedBlock(crate::storage::traits::Block),
    /// Raft consensus message (protobuf-serialized via prost).
    RaftMessage(Vec<u8>),
    /// Gossip alive message for peer liveness detection.
    Alive(gossip::AliveMessage),
    /// Pull-based state sync: request blocks starting from `from_height`.
    StateRequest {
        from_height: u64,
    },
    /// Pull-based state sync: response with a batch of blocks.
    StateResponse {
        blocks: Vec<crate::storage::traits::Block>,
    },
    /// Endorsement request: peer simulates chaincode and returns a signed rwset.
    ProposalRequest {
        /// Unique ID to correlate request with response.
        request_id: String,
        /// Chaincode to simulate.
        chaincode_id: String,
        /// Function to invoke (e.g. "invoke", "query").
        function: String,
        /// Channel context.
        channel_id: String,
        /// The transaction proposal from the client.
        proposal: crate::transaction::proposal::TransactionProposal,
    },
    /// Endorsement response: simulation result + signed endorsement.
    ProposalResponse {
        /// Correlates with the originating `ProposalRequest`.
        request_id: String,
        /// The read-write set produced by simulation.
        rwset: crate::transaction::rwset::ReadWriteSet,
        /// This peer's endorsement (org_id + signature over rwset hash).
        endorsement: crate::endorsement::types::Endorsement,
        /// Chaincode return value (empty if void).
        result: Vec<u8>,
    },
    /// Push private data to a member peer for replication.
    PrivateDataPush {
        /// Collection name.
        collection: String,
        /// Data key within the collection.
        key: String,
        /// The private data bytes.
        value: Vec<u8>,
        /// Org ID of the sender (receiver validates membership).
        sender_org: String,
    },
    /// Acknowledgement that private data was stored by the receiving peer.
    PrivateDataAck {
        /// Collection name (for correlation).
        collection: String,
        /// Data key (for correlation).
        key: String,
        /// Whether the peer accepted and stored the data.
        accepted: bool,
    },

    // ── BFT consensus messages ──────────────────────────────────────────────
    /// Leader broadcasts a block proposal for a BFT round.
    BftProposal {
        round: u64,
        block_hash: [u8; 32],
        leader_id: String,
        /// Serialized block data (the full proposed block).
        block_data: Vec<u8>,
        /// Serialized justify_qc (leader's high_qc). Empty if none.
        #[serde(default)]
        justify_qc: Vec<u8>,
    },
    /// Validator vote for a BFT phase (Prepare / PreCommit / Commit).
    BftVote(crate::consensus::bft::types::VoteMessage),
    /// A formed quorum certificate broadcast to peers.
    BftQuorumCertificate(crate::consensus::bft::types::QuorumCertificate),
    /// View change: validator signals round timeout and proposes advancing.
    BftViewChange {
        /// The round that timed out.
        timed_out_round: u64,
        /// The new round being proposed.
        new_round: u64,
        /// Validator sending the view change.
        voter_id: String,
        /// Highest commit QC this validator has seen (proof of progress).
        highest_qc: Option<crate::consensus::bft::types::QuorumCertificate>,
    },
}

/**
 * Nodo en la red P2P
 */
/**
 * Métricas de sincronización de contratos
 */
#[derive(Debug, Clone, Default)]
pub struct ContractSyncMetrics {
    pub last_sync_timestamp: u64,
}

#[derive(Clone)]
pub struct Node {
    #[allow(dead_code)]
    pub address: SocketAddr,
    pub peers: Arc<Mutex<HashSet<String>>>,
    pub contract_manager: Option<Arc<RwLock<ContractManager>>>,
    pub checkpoint_manager: Option<Arc<Mutex<CheckpointManager>>>,
    pub transaction_validator: Option<Arc<Mutex<TransactionValidator>>>,
    pub listening: bool,
    pub contract_sync_metrics: Arc<Mutex<HashMap<String, ContractSyncMetrics>>>,
    pub pending_contract_broadcasts: Arc<Mutex<Vec<(String, SmartContract)>>>,
    // Tracking de contratos recibidos recientemente para prevenir loops
    pub recent_contract_receipts: Arc<Mutex<HashMap<String, (u64, String)>>>, // (contract_address, timestamp, source_peer)
    // Rate limiting para contratos por peer
    pub contract_rate_limits: Arc<Mutex<HashMap<String, (u64, usize)>>>, // (peer_address, (timestamp, count))
    // Network ID para separar testnet/mainnet
    pub network_id: String,
    // Bootstrap nodes para auto-conexión
    pub bootstrap_nodes: Vec<String>,
    // Seed nodes hardcodeadas (siempre se intentan, incluso sin bootstrap)
    pub seed_nodes: Vec<String>,
    // Peers fallidos con timestamp para retry
    pub failed_peers: Arc<Mutex<HashMap<String, (u64, u32)>>>, // (peer_address, (timestamp, attempt_count))
    /// Si está definido, solo se aceptan conexiones entrantes cuya dirección remota esté en el conjunto (`PEER_ALLOWLIST`).
    pub peer_allowlist: Option<Arc<HashSet<String>>>,
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
    pub tls_connector: Option<Arc<TlsConnector>>,
    /// Role of this node in the network (peer / orderer / both).
    pub role: NodeRole,
    /// Ordering service (present when role is Orderer or PeerAndOrderer).
    pub ordering_service: Option<Arc<crate::ordering::service::OrderingService>>,
    /// New storage layer (present when STORAGE_BACKEND is configured).
    pub store: Option<Arc<dyn crate::storage::traits::BlockStore>>,
    /// Sender side of the push-gossip channel for newly accepted blocks.
    pub gossip_block_tx: GossipBlockTx,
    /// BFT event channel — routes incoming BFT messages to the consensus controller.
    pub bft_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::consensus::controller::BftEvent>>,
    /// Gossip membership table for alive-based liveness tracking.
    pub membership: gossip::MembershipTable,
    /// Organization ID of this node (used in alive messages and endorsements).
    pub org_id: String,
    /// Chaincode package store for loading Wasm during endorsement simulation.
    pub chaincode_store: Option<Arc<dyn crate::chaincode::ChaincodePackageStore>>,
    /// World state for chaincode simulation.
    pub world_state: Option<Arc<dyn crate::storage::world_state::WorldState>>,
    /// Signing provider for producing endorsements.
    pub signing_provider: Option<Arc<dyn crate::identity::signing::SigningProvider>>,
    /// Raft node for delivering inbound consensus messages.
    pub raft_node: RaftNodeHandle,
    /// Private data store for receiving replicated private data from peers.
    pub private_data_store: Option<Arc<dyn crate::private_data::PrivateDataStore>>,
    /// Collection registry for validating membership on private data push.
    pub collection_registry: Option<Arc<dyn crate::private_data::CollectionRegistry>>,
    #[allow(dead_code)]
    /// Monotonically increasing alive sequence counter.
    pub alive_sequence: Arc<Mutex<u64>>,
    /// P2P-level security: peer scoring, reputation, per-peer rate limiting.
    pub network_security: Arc<Mutex<NetworkSecurityManager>>,
    /// Anchor peers for cross-org gossip discovery (parsed from `ANCHOR_PEERS` env).
    pub anchor_peers: Vec<gossip::AnchorPeer>,
    /// Externally reachable address (from `P2P_EXTERNAL_ADDRESS` env, e.g. `node1:8081`).
    /// Falls back to `self.address` when unset.
    pub announce_address: Option<String>,
}

/// Parsea `PEER_ALLOWLIST` (coma-separada, cada token `IP:puerto` o `[IPv6]:puerto`).
/// Devuelve `None` si no hay ninguna dirección válida (lista deshabilitada o vacía tras parseo).
pub fn parse_peer_allowlist(env_value: &str) -> Option<HashSet<String>> {
    let mut set = HashSet::new();
    for token in env_value.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<SocketAddr>() {
            Ok(addr) => {
                set.insert(addr.to_string());
            }
            Err(_) => {
                eprintln!("⚠️  PEER_ALLOWLIST: entrada ignorada (no es dirección válida): {t:?}");
            }
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

/// Number of random peers to forward a newly received block to (push-gossip fanout).
const GOSSIP_FANOUT: usize = 3;

/// Opens a TCP connection (optionally wrapped in TLS) without requiring a `Node` reference.
async fn open_peer_stream(
    address: &str,
    tls_connector: Option<&TlsConnector>,
) -> Result<Box<dyn AsyncStream>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect(address).await?;
    match tls_connector {
        Some(connector) => {
            let name = parse_server_name(address)?;
            let tls = connector.connect(name, tcp).await?;
            Ok(Box::new(tls))
        }
        None => Ok(Box::new(tcp)),
    }
}

/// Background task that re-gossips accepted blocks to up to `GOSSIP_FANOUT` random peers,
/// excluding the peer that originally sent the block.
async fn gossip_loop(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<(crate::storage::traits::Block, Option<String>)>,
    peers: Arc<Mutex<HashSet<String>>>,
    tls_connector: Option<Arc<TlsConnector>>,
) {
    use pqc_crypto_module::legacy::rng::SliceRandom as _;
    while let Some((block, source)) = rx.recv().await {
        let all_peers: Vec<String> = peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect();
        let candidates: Vec<String> = all_peers
            .into_iter()
            .filter(|p| source.as_deref() != Some(p.as_str()))
            .collect();
        let n = GOSSIP_FANOUT.min(candidates.len());
        if n == 0 {
            continue;
        }
        let chosen: Vec<String> = candidates
            .choose_multiple(&mut rand::thread_rng(), n)
            .cloned()
            .collect();
        let msg_json = match serde_json::to_string(&Message::OrderedBlock(block)) {
            Ok(j) => j,
            Err(_) => continue,
        };
        for addr in chosen {
            let mut sent = false;
            for attempt in 0..2 {
                if let Ok(mut stream) = open_peer_stream(&addr, tls_connector.as_deref()).await {
                    if tokio::io::AsyncWriteExt::write_all(&mut stream, msg_json.as_bytes())
                        .await
                        .is_ok()
                    {
                        sent = true;
                        break;
                    }
                }
                if attempt == 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                }
            }
            if !sent {
                log::warn!("gossip: failed to send block to {addr} after 2 attempts");
            }
        }
    }
}

fn parse_server_name(
    address: &str,
) -> Result<ServerName<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let host = address.rsplit_once(':').map(|(h, _)| h).unwrap_or(address);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name '{host}': {e}").into())
}

impl Node {
    /**
     * Crea un nuevo nodo
     * @param address - Dirección del nodo
     * @param blockchain - Blockchain compartida
     * @param network_id - Network ID para separar testnet/mainnet (default: "mainnet")
     * @param bootstrap_nodes - Lista de bootstrap nodes para auto-conexión
     * @param seed_nodes - Lista de seed nodes (siempre se intentan, incluso sin bootstrap)
     */
    pub fn new(
        address: SocketAddr,
        network_id: Option<String>,
        bootstrap_nodes: Option<Vec<String>>,
        seed_nodes: Option<Vec<String>>,
        peer_allowlist: Option<Arc<HashSet<String>>>,
    ) -> Node {
        Node::with_role(
            address,
            network_id,
            bootstrap_nodes,
            seed_nodes,
            peer_allowlist,
            NodeRole::from_env(),
        )
    }

    pub fn with_role(
        address: SocketAddr,
        network_id: Option<String>,
        bootstrap_nodes: Option<Vec<String>>,
        seed_nodes: Option<Vec<String>>,
        peer_allowlist: Option<Arc<HashSet<String>>>,
        role: NodeRole,
    ) -> Node {
        Node {
            address,
            peers: Arc::new(Mutex::new(HashSet::new())),
            contract_manager: None,
            checkpoint_manager: None,
            transaction_validator: None,
            listening: false,
            contract_sync_metrics: Arc::new(Mutex::new(HashMap::new())),
            pending_contract_broadcasts: Arc::new(Mutex::new(Vec::new())),
            recent_contract_receipts: Arc::new(Mutex::new(HashMap::new())),
            contract_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            network_id: network_id.unwrap_or_else(|| "mainnet".to_string()),
            bootstrap_nodes: bootstrap_nodes.unwrap_or_default(),
            seed_nodes: seed_nodes.unwrap_or_default(),
            failed_peers: Arc::new(Mutex::new(HashMap::new())),
            peer_allowlist,
            tls_acceptor: None,
            tls_connector: None,
            role,
            ordering_service: None,
            store: None,
            gossip_block_tx: None,
            bft_tx: None,
            membership: gossip::MembershipTable::new(gossip::ALIVE_TIMEOUT_MS),
            org_id: std::env::var("ORG_ID").unwrap_or_else(|_| "default".to_string()),
            alive_sequence: Arc::new(Mutex::new(0)),
            network_security: Arc::new(Mutex::new(NetworkSecurityManager::with_defaults())),
            anchor_peers: std::env::var("ANCHOR_PEERS")
                .map(|v| gossip::parse_anchor_peers(&v))
                .unwrap_or_default(),
            announce_address: std::env::var("P2P_EXTERNAL_ADDRESS").ok(),
            chaincode_store: None,
            world_state: None,
            signing_provider: None,
            raft_node: None,
            private_data_store: None,
            collection_registry: None,
        }
    }

    /// Returns the address to announce to peers. Uses `P2P_EXTERNAL_ADDRESS` if set,
    /// otherwise falls back to `self.address`.
    pub fn p2p_address(&self) -> String {
        self.announce_address
            .clone()
            .unwrap_or_else(|| self.address.to_string())
    }

    /**
     * Configura el contract manager para el nodo
     */
    pub fn set_contract_manager(&mut self, contract_manager: Arc<RwLock<ContractManager>>) {
        self.contract_manager = Some(contract_manager);
    }

    /**
     * Configura el checkpoint manager para el nodo
     */
    pub fn set_checkpoint_manager(&mut self, checkpoint_manager: Arc<Mutex<CheckpointManager>>) {
        self.checkpoint_manager = Some(checkpoint_manager);
    }

    /**
     * Configura el transaction validator para el nodo
     */
    pub fn set_transaction_validator(
        &mut self,
        transaction_validator: Arc<Mutex<TransactionValidator>>,
    ) {
        self.transaction_validator = Some(transaction_validator);
    }

    pub fn set_tls_acceptor(&mut self, acceptor: TlsAcceptor) {
        self.tls_acceptor = Some(Arc::new(acceptor));
    }

    pub fn set_tls_connector(&mut self, connector: TlsConnector) {
        self.tls_connector = Some(Arc::new(connector));
    }

    /// Opens a TCP connection and optionally wraps it in TLS.
    async fn open_stream(
        &self,
        address: &str,
    ) -> Result<Box<dyn AsyncStream>, Box<dyn std::error::Error + Send + Sync>> {
        open_peer_stream(address, self.tls_connector.as_deref()).await
    }

    /// Send a message to a peer and wait for a response on the same TCP stream.
    ///
    /// Opens a new connection, writes the serialized message, then reads the
    /// peer's response with the given timeout.  Returns `Err` on network
    /// failure, serialization error, or timeout.
    pub async fn send_and_wait(
        &self,
        peer_address: &str,
        message: Message,
        timeout: std::time::Duration,
    ) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = self.open_stream(peer_address).await?;

        // Write request
        let request_json = serde_json::to_string(&message)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        stream
            .write_all(request_json.as_bytes())
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        stream
            .flush()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        // Read response with timeout — accumulate TCP chunks until valid JSON or EOF.
        let mut accum = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("no response from {peer_address} within {timeout:?}"),
                )));
            }
            let n = match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
                Ok(Ok(0)) if accum.is_empty() => {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("peer {peer_address} closed connection without responding"),
                    )));
                }
                Ok(Ok(0)) => break, // EOF after partial data — try parse below
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(Box::new(e)),
                Err(_) => {
                    if accum.is_empty() {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("no response from {peer_address} within {timeout:?}"),
                        )));
                    }
                    break; // timeout after partial data — try parse
                }
            };
            accum.extend_from_slice(&buf[..n]);
            if let Ok(msg) = serde_json::from_slice::<Message>(&accum) {
                return Ok(msg);
            }
        }

        let response: Message = serde_json::from_slice(&accum)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(response)
    }

    /**
     * Inicia el servidor P2P
     */
    pub async fn start_server(&mut self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{port}");
        let listener = TcpListener::bind(&addr).await?;
        self.listening = true;

        println!("🌐 Servidor P2P iniciado en {addr}");

        // Clonar recursos compartidos antes del loop
        let peers = self.peers.clone();
        let contract_manager = self.contract_manager.clone();
        let checkpoint_manager = self.checkpoint_manager.clone();
        let transaction_validator = self.transaction_validator.clone();
        let my_p2p_address = self.p2p_address();
        let recent_receipts = self.recent_contract_receipts.clone();
        let rate_limits = self.contract_rate_limits.clone();
        let pending_broadcasts = self.pending_contract_broadcasts.clone();
        let network_id = self.network_id.clone();
        let peer_allowlist = self.peer_allowlist.clone();
        let tls_acceptor = self.tls_acceptor.clone();
        let role = self.role;
        let ordering_service = self.ordering_service.clone();
        let store = self.store.clone();
        let membership = self.membership.clone();
        let chaincode_store = self.chaincode_store.clone();
        let world_state = self.world_state.clone();
        let signing_provider = self.signing_provider.clone();
        let node_org_id = self.org_id.clone();
        let raft_node = self.raft_node.clone();
        let private_data_store = self.private_data_store.clone();
        let collection_registry = self.collection_registry.clone();
        let net_security = self.network_security.clone();

        // Push-gossip channel: newly accepted blocks are sent here and forwarded
        // to GOSSIP_FANOUT random peers by the background gossip task.
        let (gossip_tx, gossip_rx) = tokio::sync::mpsc::unbounded_channel::<(
            crate::storage::traits::Block,
            Option<String>,
        )>();
        let gossip_tx = Arc::new(gossip_tx);
        self.gossip_block_tx = Some(gossip_tx.clone());
        {
            let gossip_peers = peers.clone();
            let gossip_tls = self.tls_connector.clone();
            tokio::spawn(gossip_loop(gossip_rx, gossip_peers, gossip_tls));
        }

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let peer_key = peer_addr.to_string();
                    if let Some(ref allowed) = peer_allowlist {
                        if !allowed.contains(&peer_key) {
                            eprintln!(
                                "🚫 Conexión P2P rechazada (no está en PEER_ALLOWLIST): {peer_key}"
                            );
                            drop(stream);
                            continue;
                        }
                    }
                    println!("📡 Nueva conexión desde: {peer_addr}");
                    let peers_clone = peers.clone();
                    let contract_manager_clone = contract_manager.clone();
                    let checkpoint_manager_clone = checkpoint_manager.clone();
                    let transaction_validator_clone = transaction_validator.clone();
                    let my_p2p_address_clone = my_p2p_address.clone();
                    let recent_receipts_clone = recent_receipts.clone();
                    let rate_limits_clone = rate_limits.clone();
                    let pending_broadcasts_clone = pending_broadcasts.clone();
                    let network_id_clone = network_id.clone();
                    let tls_acceptor_clone = tls_acceptor.clone();
                    let ordering_service_clone = ordering_service.clone();
                    let store_clone = store.clone();
                    let gossip_tx_clone = gossip_tx.clone();
                    let membership_clone = membership.clone();
                    let chaincode_store_clone = chaincode_store.clone();
                    let world_state_clone = world_state.clone();
                    let signing_provider_clone = signing_provider.clone();
                    let node_org_id_clone = node_org_id.clone();
                    let raft_node_clone = raft_node.clone();
                    let private_data_store_clone = private_data_store.clone();
                    let collection_registry_clone = collection_registry.clone();
                    let net_security_clone = net_security.clone();
                    let bft_tx_clone = self.bft_tx.clone();

                    tokio::spawn(async move {
                        let boxed: Box<dyn AsyncStream> = if let Some(acceptor) = tls_acceptor_clone
                        {
                            match acceptor.accept(stream).await {
                                Ok(tls) => Box::new(tls),
                                Err(e) => {
                                    eprintln!("TLS handshake error from {peer_addr}: {e}");
                                    return;
                                }
                            }
                        } else {
                            Box::new(stream)
                        };
                        if let Err(e) = Self::handle_connection(
                            boxed,
                            peer_addr,
                            peers_clone,
                            contract_manager_clone,
                            checkpoint_manager_clone,
                            transaction_validator_clone,
                            Some(my_p2p_address_clone),
                            recent_receipts_clone,
                            rate_limits_clone,
                            pending_broadcasts_clone,
                            Some(network_id_clone),
                            role,
                            ordering_service_clone,
                            store_clone,
                            Some(gossip_tx_clone),
                            membership_clone,
                            chaincode_store_clone,
                            world_state_clone,
                            signing_provider_clone,
                            node_org_id_clone,
                            raft_node_clone,
                            private_data_store_clone,
                            collection_registry_clone,
                            net_security_clone,
                            bft_tx_clone,
                        )
                        .await
                        {
                            eprintln!("Error manejando conexión: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error aceptando conexión: {e}");
                }
            }
        }
    }

    /**
     * Maneja una conexión entrante
     */
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        mut stream: Box<dyn AsyncStream>,
        peer_addr: SocketAddr,
        peers: Arc<Mutex<HashSet<String>>>,
        contract_manager: Option<Arc<RwLock<ContractManager>>>,
        checkpoint_manager: Option<Arc<Mutex<CheckpointManager>>>,
        transaction_validator: Option<Arc<Mutex<TransactionValidator>>>,
        my_p2p_address: Option<String>,
        recent_receipts: Arc<Mutex<HashMap<String, (u64, String)>>>,
        rate_limits: Arc<Mutex<HashMap<String, (u64, usize)>>>,
        pending_broadcasts: Arc<Mutex<Vec<(String, SmartContract)>>>,
        network_id: Option<String>,
        role: NodeRole,
        ordering_service: Option<Arc<crate::ordering::service::OrderingService>>,
        store: Option<Arc<dyn crate::storage::traits::BlockStore>>,
        gossip_block_tx: GossipBlockTx,
        membership: gossip::MembershipTable,
        chaincode_store: Option<Arc<dyn crate::chaincode::ChaincodePackageStore>>,
        world_state: Option<Arc<dyn crate::storage::world_state::WorldState>>,
        signing_provider: Option<Arc<dyn crate::identity::signing::SigningProvider>>,
        node_org_id: String,
        raft_node: RaftNodeHandle,
        private_data_store: Option<Arc<dyn crate::private_data::PrivateDataStore>>,
        collection_registry: Option<Arc<dyn crate::private_data::CollectionRegistry>>,
        net_security: Arc<Mutex<NetworkSecurityManager>>,
        bft_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::consensus::controller::BftEvent>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let peer_addr_str = format!("{}:{}", peer_addr.ip(), peer_addr.port());
        let mut buffer = vec![0u8; p2p_handler_buffer_size()];
        let mut first_message = true;

        // Register peer with NetworkSecurityManager
        {
            let mut sec = net_security.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = sec.register_peer(peer_addr_str.clone()) {
                log::warn!("P2P connection rejected for {peer_addr_str}: {e}");
                return Err(e.into());
            }
        }

        // Limpiar rate limit antiguo (más de 1 minuto)
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut limits = rate_limits.lock().unwrap_or_else(|e| e.into_inner());
            limits.retain(|_, (ts, _)| now - *ts < 60);
        }

        // Procesar contratos pendientes para este peer
        {
            let mut pending = pending_broadcasts.lock().unwrap_or_else(|e| e.into_inner());
            let mut to_remove = Vec::new();
            for (i, (peer, _contract)) in pending.iter().enumerate() {
                if peer == &peer_addr_str {
                    // Marcar para remover (el contrato ya fue procesado)
                    to_remove.push(i);
                }
            }
            // Remover en orden inverso para mantener índices válidos
            for i in to_remove.into_iter().rev() {
                pending.remove(i);
            }
        }

        let connection_result: Result<(), Box<dyn std::error::Error>> = async {
        let mut accum = Vec::new();
        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                // EOF — try to parse whatever we accumulated before exiting.
                if !accum.is_empty() {
                    log::info!("P2P EOF with {} accumulated bytes from {peer_addr_str}", accum.len());
                    let msg_str = String::from_utf8_lossy(&accum);
                    if let Ok(message) = serde_json::from_str::<Message>(&msg_str) {
                        let _ = Self::process_message(
                            message,
                            &peers,
                            contract_manager.clone(),
                            checkpoint_manager.clone(),
                            transaction_validator.clone(),
                            my_p2p_address.clone(),
                            Some(peer_addr_str.clone()),
                            recent_receipts.clone(),
                            rate_limits.clone(),
                            network_id.clone(),
                            role,
                            ordering_service.clone(),
                            store.clone(),
                            gossip_block_tx.clone(),
                            Some(&membership),
                            chaincode_store.clone(),
                            world_state.clone(),
                            signing_provider.clone(),
                            &node_org_id,
                            raft_node.clone(),
                            private_data_store.clone(),
                            collection_registry.clone(),
                            bft_tx.as_ref(),
                        )
                        .await;
                    }
                }
                break;
            }

            // Per-peer rate limiting and reputation check
            {
                let mut sec = net_security.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = sec.check_rate_limit(&peer_addr_str, n) {
                    log::warn!("P2P rate limit for {peer_addr_str}: {e}");
                    break;
                }
            }

            // Accumulate chunks until we have a complete JSON message.
            accum.extend_from_slice(&buffer[..n]);
            let message_str = String::from_utf8_lossy(&accum);
            if let Ok(message) = serde_json::from_str::<Message>(&message_str) {
            accum.clear();
                // Si es el primer mensaje y es Version, validar network_id y responder
                if first_message {
                    if let Message::Version {
                        p2p_address,
                        network_id: their_network_id,
                        ..
                    } = &message
                    {
                        // Validar Network ID - rechazar si no coincide
                        if let (Some(their_id), Some(my_id)) = (their_network_id, &network_id) {
                            if *their_id != **my_id {
                                eprintln!("❌ Network ID mismatch: expected '{my_id}', got '{their_id}'. Rejecting connection.");
                                // Enviar mensaje de error antes de cerrar (aunque el cliente puede no procesarlo)
                                // Cerrar el stream inmediatamente para que el cliente detecte el rechazo
                                return Err(format!(
                                    "Network ID mismatch: expected '{my_id}', got '{their_id}'"
                                )
                                .into());
                            }
                        }

                        // Use the peer's declared address if it's routable (not 0.0.0.0).
                        // Fall back to socket IP + declared port otherwise.
                        {
                            let declared = p2p_address.as_deref().unwrap_or("");
                            let usable = if declared.starts_with("0.0.0.0") || declared.is_empty() {
                                let port = declared.rsplit(':').next()
                                    .and_then(|p| p.parse::<u16>().ok())
                                    .unwrap_or(8081);
                                format!("{}:{}", peer_addr.ip(), port)
                            } else {
                                declared.to_string()
                            };
                            let mut peers_guard = peers.lock().unwrap_or_else(|e| e.into_inner());
                            peers_guard.insert(usable.clone());
                            println!("📡 Peer agregado desde conexión entrante: {usable}");
                        }
                        first_message = false;
                    }
                }

                let response = Self::process_message(
                    message,
                    &peers,
                    contract_manager.clone(),
                    checkpoint_manager.clone(),
                    transaction_validator.clone(),
                    my_p2p_address.clone(),
                    Some(peer_addr_str.clone()),
                    recent_receipts.clone(),
                    rate_limits.clone(),
                    network_id.clone(),
                    role,
                    ordering_service.clone(),
                    store.clone(),
                    gossip_block_tx.clone(),
                    Some(&membership),
                    chaincode_store.clone(),
                    world_state.clone(),
                    signing_provider.clone(),
                    &node_org_id,
                    raft_node.clone(),
                    private_data_store.clone(),
                    collection_registry.clone(),
                    bft_tx.as_ref(),
                )
                .await?;

                if let Some(response_msg) = response {
                    let response_json = serde_json::to_string(&response_msg)?;
                    stream.write_all(response_json.as_bytes()).await?;
                }

                // Record valid message for reputation
                {
                    let mut sec = net_security.lock().unwrap_or_else(|e| e.into_inner());
                    sec.record_valid_message(&peer_addr_str, n);
                }
            } else {
                // Failed to deserialize — penalize peer reputation
                let mut sec = net_security.lock().unwrap_or_else(|e| e.into_inner());
                sec.record_invalid_message(&peer_addr_str, 10);
                if sec.peer_scores.get(&peer_addr_str).is_some_and(|s| s.is_banned()) {
                    log::warn!("P2P peer {peer_addr_str} banned after invalid messages");
                    break;
                }
            }
        }
        Ok(())
        }.await;

        // Always unregister peer on disconnect
        {
            let mut sec = net_security.lock().unwrap_or_else(|e| e.into_inner());
            sec.unregister_peer(&peer_addr_str);
        }

        connection_result
    }

    /**
     * Procesa un mensaje recibido
     */
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn process_message(
        message: Message,
        peers: &Arc<Mutex<HashSet<String>>>,
        contract_manager: Option<Arc<RwLock<ContractManager>>>,
        _checkpoint_manager: Option<Arc<Mutex<CheckpointManager>>>,
        _transaction_validator: Option<Arc<Mutex<TransactionValidator>>>,
        my_p2p_address: Option<String>,
        source_peer: Option<String>,
        recent_receipts: Arc<Mutex<HashMap<String, (u64, String)>>>,
        rate_limits: Arc<Mutex<HashMap<String, (u64, usize)>>>,
        network_id: Option<String>,
        role: NodeRole,
        ordering_service: Option<Arc<crate::ordering::service::OrderingService>>,
        store: Option<Arc<dyn crate::storage::traits::BlockStore>>,
        _gossip_block_tx: GossipBlockTx,
        membership: Option<&gossip::MembershipTable>,
        chaincode_store: Option<Arc<dyn crate::chaincode::ChaincodePackageStore>>,
        world_state: Option<Arc<dyn crate::storage::world_state::WorldState>>,
        signing_provider: Option<Arc<dyn crate::identity::signing::SigningProvider>>,
        node_org_id: &str,
        _raft_node: RaftNodeHandle,
        private_data_store: Option<Arc<dyn crate::private_data::PrivateDataStore>>,
        collection_registry: Option<Arc<dyn crate::private_data::CollectionRegistry>>,
        bft_tx: Option<&tokio::sync::mpsc::UnboundedSender<crate::consensus::controller::BftEvent>>,
    ) -> Result<Option<Message>, Box<dyn std::error::Error>> {
        match message {
            Message::Ping => Ok(Some(Message::Pong)),

            Message::GetPeers => {
                let peers = peers.lock().unwrap_or_else(|e| e.into_inner());
                let peer_list: Vec<String> = peers.iter().cloned().collect();
                Ok(Some(Message::Peers(peer_list)))
            }

            Message::Peers(peer_list) => {
                let mut peers = peers.lock().unwrap_or_else(|e| e.into_inner());
                for peer in peer_list {
                    if !peer.is_empty()
                        && !peer.starts_with("0.0.0.0")
                        && my_p2p_address.as_deref() != Some(peer.as_str())
                    {
                        peers.insert(peer);
                    }
                }
                Ok(None)
            }

            Message::Version {
                block_count: their_count,
                latest_hash: _their_hash,
                p2p_address,
                network_id: their_network_id,
                ..
            } => {
                // Validar Network ID - rechazar si no coincide
                if let (Some(their_id), Some(my_id)) = (their_network_id, &network_id) {
                    if *their_id != **my_id {
                        return Err(format!(
                            "Network ID mismatch: expected '{my_id}', got '{their_id}'"
                        )
                        .into());
                    }
                }

                // Si el peer envió su dirección P2P, agregarlo a nuestra lista
                // (skip 0.0.0.0 / empty — same filter as handle_connection)
                if let Some(ref addr) = p2p_address {
                    if !addr.is_empty() && !addr.starts_with("0.0.0.0") {
                        let mut peers_guard = peers.lock().unwrap_or_else(|e| e.into_inner());
                        peers_guard.insert(addr.clone());
                    }
                }

                let (my_count, my_hash) = if let Some(s) = &store {
                    let h = s.get_latest_height().unwrap_or(0);
                    let hash = s
                        .read_block(h)
                        .ok()
                        .map(|b| hex::encode(b.parent_hash))
                        .unwrap_or_default();
                    ((h + 1) as usize, hash)
                } else {
                    (0, String::new())
                };

                let _ = their_count;

                Ok(Some(Message::Version {
                    version: "1.0.0".to_string(),
                    block_count: my_count,
                    latest_hash: my_hash,
                    p2p_address: my_p2p_address,
                    network_id: network_id.clone(),
                }))
            }

            Message::Pong => Ok(None),

            // Mensajes de contratos
            Message::GetContracts => {
                if let Some(cm) = &contract_manager {
                    let cm_guard = cm.read().unwrap_or_else(|e| e.into_inner());
                    let contracts: Vec<SmartContract> = cm_guard
                        .get_all_contracts()
                        .iter()
                        .map(|c| (*c).clone())
                        .collect();
                    Ok(Some(Message::Contracts(contracts)))
                } else {
                    Ok(Some(Message::Contracts(Vec::new())))
                }
            }

            Message::GetContractsSince { timestamp } => {
                if let Some(cm) = &contract_manager {
                    let cm_guard = cm.read().unwrap_or_else(|e| e.into_inner());
                    let contracts: Vec<SmartContract> = cm_guard
                        .get_all_contracts()
                        .iter()
                        .filter(|c| {
                            c.updated_at > timestamp
                                || (c.updated_at == timestamp && c.update_sequence > 0)
                        })
                        .map(|c| (*c).clone())
                        .collect();
                    Ok(Some(Message::Contracts(contracts)))
                } else {
                    Ok(Some(Message::Contracts(Vec::new())))
                }
            }

            Message::Contracts(contracts) => {
                if let Some(cm) = &contract_manager {
                    let mut cm_guard = cm.write().unwrap_or_else(|e| e.into_inner());
                    let mut synced = 0;
                    let mut errors = 0;

                    for contract in contracts {
                        // Validar integridad del contrato
                        if !contract.validate_integrity() {
                            eprintln!(
                                "⚠️  Contrato recibido tiene hash de integridad inválido: {}",
                                contract.address
                            );
                            errors += 1;
                            continue;
                        }

                        // Verificar si el contrato ya existe
                        if cm_guard.get_contract(&contract.address).is_none() {
                            // Contrato nuevo, agregarlo
                            if cm_guard.deploy_contract(contract.clone()).is_ok() {
                                synced += 1;
                            }
                        } else {
                            // Contrato existe, verificar si necesita actualización
                            if let Some(existing) = cm_guard.get_contract(&contract.address) {
                                // Validar que el owner no haya cambiado ilegalmente
                                if contract.owner != existing.owner {
                                    eprintln!("⚠️  Intento de actualizar contrato con owner diferente rechazado: {}", contract.address);
                                    errors += 1;
                                    continue;
                                }

                                // Comparar por updated_at y update_sequence para resolver race conditions
                                let should_update = contract.updated_at > existing.updated_at
                                    || (contract.updated_at == existing.updated_at
                                        && contract.update_sequence > existing.update_sequence);

                                if should_update {
                                    // Actualizar el contrato
                                    if let Some(existing_mut) =
                                        cm_guard.get_contract_mut(&contract.address)
                                    {
                                        *existing_mut = contract.clone();
                                        synced += 1;
                                    }
                                }
                            }
                        }
                    }

                    if synced > 0 {
                        println!("✅ {synced} contratos sincronizados desde peer");
                    }
                    if errors > 0 {
                        println!("⚠️  {errors} contratos rechazados por validación");
                    }
                }
                Ok(None)
            }

            Message::NewContract(contract) => {
                // Validar tamaño del contrato (máximo 1MB)
                let contract_size = serde_json::to_string(&contract).unwrap_or_default().len();
                if contract_size > 1_000_000 {
                    eprintln!(
                        "⚠️  Contrato recibido excede tamaño máximo ({} bytes): {}",
                        contract_size, contract.address
                    );
                    return Ok(None);
                }

                // Rate limiting: máximo 10 contratos por minuto por peer
                if let Some(ref peer) = source_peer {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mut limits = rate_limits.lock().unwrap_or_else(|e| e.into_inner());
                    let (last_ts, count) = limits.entry(peer.clone()).or_insert((now, 0));

                    if now - *last_ts < 60 {
                        if *count >= 10 {
                            eprintln!("⚠️  Rate limit excedido para peer {peer}: {count} contratos en último minuto");
                            return Ok(None);
                        }
                        *count += 1;
                    } else {
                        *last_ts = now;
                        *count = 1;
                    }
                }

                // Prevenir loops: verificar si recibimos este contrato recientemente del mismo peer
                if let Some(ref peer) = source_peer {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mut receipts = recent_receipts.lock().unwrap_or_else(|e| e.into_inner());

                    // Limpiar entradas antiguas (más de 5 minutos)
                    receipts.retain(|_, (ts, _)| now - *ts < 300);

                    if let Some((ts, prev_peer)) = receipts.get(&contract.address) {
                        if *prev_peer == *peer && now - *ts < 60 {
                            println!("ℹ️  Contrato {} recibido recientemente del mismo peer {}, ignorando para prevenir loop", contract.address, peer);
                            return Ok(None);
                        }
                    }

                    receipts.insert(contract.address.clone(), (now, peer.clone()));
                }

                if let Some(cm) = &contract_manager {
                    // Validar integridad del contrato
                    if !contract.validate_integrity() {
                        eprintln!(
                            "⚠️  Contrato recibido tiene hash de integridad inválido: {}",
                            contract.address
                        );
                        return Ok(None);
                    }

                    let mut cm_guard = cm.write().unwrap_or_else(|e| e.into_inner());

                    // Verificar si el contrato ya existe
                    if cm_guard.get_contract(&contract.address).is_none() {
                        // Contrato nuevo, agregarlo
                        if cm_guard.deploy_contract(contract.clone()).is_ok() {
                            println!(
                                "✅ Nuevo contrato recibido y agregado: {} ({})",
                                contract.name, contract.address
                            );
                        } else {
                            println!("⚠️  Error al agregar contrato recibido");
                        }
                    } else {
                        println!("ℹ️  Contrato ya existe en nuestra red");
                    }
                }
                Ok(None)
            }

            Message::UpdateContract(contract) => {
                println!(
                    "📥 Mensaje UpdateContract recibido para contrato: {} ({})",
                    contract.name, contract.address
                );

                // Validar tamaño del contrato (máximo 1MB)
                let contract_size = serde_json::to_string(&contract).unwrap_or_default().len();
                if contract_size > 1_000_000 {
                    eprintln!(
                        "⚠️  Actualización de contrato excede tamaño máximo ({} bytes): {}",
                        contract_size, contract.address
                    );
                    return Ok(None);
                }

                // Rate limiting: máximo 20 actualizaciones por minuto por peer
                if let Some(ref peer) = source_peer {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mut limits = rate_limits.lock().unwrap_or_else(|e| e.into_inner());
                    let (last_ts, count) = limits.entry(peer.clone()).or_insert((now, 0));

                    if now - *last_ts < 60 {
                        if *count >= 20 {
                            eprintln!("⚠️  Rate limit excedido para peer {peer}: {count} actualizaciones en último minuto");
                            return Ok(None);
                        }
                        *count += 1;
                    } else {
                        *last_ts = now;
                        *count = 1;
                    }
                }

                // Prevenir loops: verificar si recibimos esta actualización recientemente del mismo peer
                if let Some(ref peer) = source_peer {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let mut receipts = recent_receipts.lock().unwrap_or_else(|e| e.into_inner());

                    // Limpiar entradas antiguas (más de 5 minutos)
                    receipts.retain(|_, (ts, _)| now - *ts < 300);

                    let receipt_key = format!(
                        "{}:{}:{}",
                        contract.address, contract.updated_at, contract.update_sequence
                    );
                    if let Some((ts, prev_peer)) = receipts.get(&receipt_key) {
                        if *prev_peer == *peer && now - *ts < 30 {
                            println!("ℹ️  Actualización de contrato {} recibida recientemente del mismo peer {}, ignorando para prevenir loop", contract.address, peer);
                            return Ok(None);
                        }
                    }

                    receipts.insert(receipt_key, (now, peer.clone()));
                }

                if let Some(cm) = &contract_manager {
                    // Validar integridad del contrato
                    if !contract.validate_integrity() {
                        eprintln!(
                            "⚠️  Contrato recibido tiene hash de integridad inválido: {}",
                            contract.address
                        );
                        return Ok(None);
                    }

                    let mut cm_guard = cm.write().unwrap_or_else(|e| e.into_inner());

                    if let Some(existing_mut) = cm_guard.get_contract_mut(&contract.address) {
                        // Validar que el owner no haya cambiado ilegalmente
                        if contract.owner != existing_mut.owner {
                            eprintln!("⚠️  Intento de actualizar contrato con owner diferente rechazado: {}", contract.address);
                            return Ok(None);
                        }

                        // Comparar por updated_at y update_sequence para resolver race conditions
                        let should_update = contract.updated_at > existing_mut.updated_at
                            || (contract.updated_at == existing_mut.updated_at
                                && contract.update_sequence > existing_mut.update_sequence);

                        println!("🔍 Comparando actualización: nuestro updated_at={}, sequence={}, recibido updated_at={}, sequence={}, should_update={}", 
                            existing_mut.updated_at, existing_mut.update_sequence,
                            contract.updated_at, contract.update_sequence, should_update);

                        if should_update {
                            let old_balance = existing_mut.get_balance(
                                contract
                                    .state
                                    .balances
                                    .keys()
                                    .next()
                                    .unwrap_or(&String::new()),
                            );
                            *existing_mut = contract.clone();
                            let new_balance = existing_mut.get_balance(
                                contract
                                    .state
                                    .balances
                                    .keys()
                                    .next()
                                    .unwrap_or(&String::new()),
                            );

                            println!("✅ Contrato actualizado desde peer: {} ({}), balance cambió de {} a {}", 
                                contract.name, contract.address, old_balance, new_balance);
                        } else {
                            println!("ℹ️  Contrato recibido es más antiguo o igual, ignorando actualización");
                        }
                    } else {
                        // Contrato no existe, agregarlo como nuevo (validar integridad ya hecho arriba)
                        println!("ℹ️  Contrato no existe localmente, agregándolo como nuevo");
                        if cm_guard.deploy_contract(contract.clone()).is_ok() {
                            println!(
                                "✅ Contrato recibido (no existía) y agregado: {} ({})",
                                contract.name, contract.address
                            );
                        }
                    }
                }
                Ok(None)
            }

            Message::SubmitTransaction(tx) => {
                if matches!(role, NodeRole::Orderer | NodeRole::PeerAndOrderer) {
                    if let Some(svc) = &ordering_service {
                        let _ = svc.submit_tx(tx);
                    }
                }
                Ok(None)
            }

            Message::OrderedBlock(block) => {
                if matches!(role, NodeRole::Peer | NodeRole::PeerAndOrderer) {
                    if let Some(s) = &store {
                        let trusted_signers =
                            crate::ordering::trusted_block_signers(signing_provider.as_deref());
                        if let Err(e) = commit_incoming_block(s.as_ref(), &block, &trusted_signers)
                        {
                            log::warn!("ordered block rejected: {e}");
                            return Ok(None);
                        }
                    }
                }
                Ok(None)
            }

            Message::RaftMessage(_data) => {
                #[cfg(feature = "raft-ordering")]
                {
                    // Decode protobuf and deliver to the local Raft node.
                    if let Some(ref raft) = _raft_node {
                        match crate::ordering::raft_transport::decode_raft_msg(&_data) {
                            Ok(raft_msg) => {
                                let mut node = raft.lock().unwrap_or_else(|e| e.into_inner());
                                if let Err(e) = node.step(raft_msg) {
                                    eprintln!("RaftMessage step error: {e}");
                                }
                            }
                            Err(e) => {
                                eprintln!("RaftMessage decode error: {e}");
                            }
                        }
                    }
                }
                Ok(None)
            }

            Message::Alive(alive) => {
                if let Some(table) = membership {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    table.record_alive_full(
                        &alive.peer_address,
                        &alive.org_id,
                        alive.sequence,
                        now_ms,
                        alive.latest_height,
                    );
                }
                Ok(None)
            }

            Message::StateRequest { from_height } => {
                // Respond with blocks starting at from_height, up to STATE_BATCH_SIZE.
                if let Some(ref blk_store) = store {
                    let latest = blk_store.get_latest_height().unwrap_or(0);
                    let mut blocks = Vec::new();
                    for h in from_height..=latest {
                        if blocks.len() >= gossip::STATE_BATCH_SIZE {
                            break;
                        }
                        if let Ok(block) = blk_store.read_block(h) {
                            blocks.push(block);
                        }
                    }
                    if blocks.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(Message::StateResponse { blocks }))
                    }
                } else {
                    Ok(None)
                }
            }

            Message::StateResponse { .. } => {
                // Responses are read directly by start_pull_sync_loop() on the
                // same TCP stream. Ignore unsolicited responses.
                Ok(None)
            }

            Message::ProposalRequest {
                request_id,
                chaincode_id,
                function,
                channel_id: _,
                proposal: _,
            } => {
                // Peer-side endorsement: simulate chaincode and return signed rwset.
                let cc_store = match &chaincode_store {
                    Some(s) => s,
                    None => {
                        eprintln!("ProposalRequest rejected: no chaincode store configured");
                        return Ok(None);
                    }
                };
                let ws = match &world_state {
                    Some(s) => s,
                    None => {
                        eprintln!("ProposalRequest rejected: no world state configured");
                        return Ok(None);
                    }
                };
                let signer = match &signing_provider {
                    Some(s) => s,
                    None => {
                        eprintln!("ProposalRequest rejected: no signing provider configured");
                        return Ok(None);
                    }
                };

                // 1. Load chaincode Wasm package (latest version)
                let wasm_bytes = match cc_store.get_package(&chaincode_id, "latest") {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => {
                        eprintln!("ProposalRequest rejected: chaincode '{chaincode_id}' not found");
                        return Ok(None);
                    }
                    Err(e) => {
                        eprintln!("ProposalRequest error loading chaincode '{chaincode_id}': {e}");
                        return Ok(None);
                    }
                };

                // 2. Create executor and simulate
                let executor =
                    match crate::chaincode::executor::WasmExecutor::new(&wasm_bytes, 1_000_000) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("ProposalRequest error creating executor: {e}");
                            return Ok(None);
                        }
                    };

                let (result, rwset) = match executor.simulate(Arc::clone(ws), &function) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("ProposalRequest simulation failed: {e}");
                        return Ok(None);
                    }
                };

                // 3. Sign the rwset hash
                let rwset_bytes = serde_json::to_vec(&rwset).unwrap_or_default();
                let payload_hash: [u8; 32] = {
                    use pqc_crypto_module::legacy::sha256::Digest;
                    let mut hasher = pqc_crypto_module::legacy::sha256::Sha256::new();
                    hasher.update(&rwset_bytes);
                    hasher.finalize().into()
                };

                let signature = match signer.sign(&payload_hash) {
                    Ok(sig) => sig,
                    Err(e) => {
                        eprintln!("ProposalRequest signing failed: {e}");
                        return Ok(None);
                    }
                };

                // 4. Build endorsement
                let pub_key = signer.public_key();
                let signer_did = crate::identity::did::did_from_pubkey_hex(&hex::encode(&pub_key));
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let endorsement = crate::endorsement::types::Endorsement {
                    signer_did,
                    org_id: node_org_id.to_string(),
                    signature,
                    signature_algorithm: Default::default(),
                    payload_hash,
                    timestamp,
                };

                Ok(Some(Message::ProposalResponse {
                    request_id,
                    rwset,
                    endorsement,
                    result,
                }))
            }

            Message::ProposalResponse { .. } => {
                // Responses are read directly by send_and_wait() on the same
                // TCP stream, so they never arrive here in normal operation.
                // Ignore unsolicited responses.
                Ok(None)
            }

            Message::PrivateDataPush {
                collection,
                key,
                value,
                sender_org,
            } => {
                // Validate membership and store private data from peer.
                let accepted = if let (Some(reg), Some(pd_store)) =
                    (&collection_registry, &private_data_store)
                {
                    if let Some(col) = reg.get(&collection) {
                        if col.is_member(&sender_org) {
                            match pd_store.put_private_data(&collection, &key, &value) {
                                Ok(_hash) => true,
                                Err(e) => {
                                    eprintln!(
                                        "[private-data] store error for {collection}/{key}: {e}"
                                    );
                                    false
                                }
                            }
                        } else {
                            eprintln!(
                                "[private-data] rejected: org '{sender_org}' not member of '{collection}'"
                            );
                            false
                        }
                    } else {
                        eprintln!("[private-data] rejected: unknown collection '{collection}'");
                        false
                    }
                } else {
                    eprintln!(
                        "[private-data] rejected: no collection registry or private data store"
                    );
                    false
                };

                Ok(Some(Message::PrivateDataAck {
                    collection,
                    key,
                    accepted,
                }))
            }

            Message::PrivateDataAck { .. } => {
                // Acks are read directly by the dissemination logic via
                // send_and_wait(). Ignore unsolicited acks.
                Ok(None)
            }

            Message::BftProposal {
                round,
                block_hash,
                leader_id,
                block_data,
                justify_qc,
            } => {
                log::info!(
                    "BFT: received proposal round={round} leader={leader_id} data_len={} jqc_len={}",
                    block_data.len(),
                    justify_qc.len()
                );
                if let Some(tx) = bft_tx {
                    if let Ok(block) = serde_json::from_slice(&block_data) {
                        let Some(s) = &store else {
                            log::warn!("BFT: proposal round={round} rejected: no local store");
                            return Ok(None);
                        };
                        let trusted_signers =
                            crate::ordering::trusted_block_signers(signing_provider.as_deref());
                        if let Err(e) =
                            validate_bft_proposal(&block, &block_hash, s.as_ref(), &trusted_signers)
                        {
                            log::warn!("BFT: proposal round={round} rejected: {e}");
                            return Ok(None);
                        }
                        let jqc = if justify_qc.is_empty() {
                            None
                        } else {
                            serde_json::from_slice(&justify_qc).ok()
                        };
                        let _ = tx.send(crate::consensus::controller::BftEvent::Proposal {
                            round,
                            block_hash,
                            leader_id,
                            block,
                            justify_qc: jqc,
                        });
                    } else {
                        log::warn!("BFT: failed to deserialize block_data");
                    }
                } else {
                    log::warn!("BFT: proposal received but bft_tx is None");
                }
                Ok(None)
            }
            Message::BftVote(ref vote) => {
                log::info!(
                    "BFT: received vote phase={:?} voter={} round={}",
                    vote.phase,
                    vote.voter_id,
                    vote.round
                );
                if let Some(tx) = bft_tx {
                    let _ = tx.send(crate::consensus::controller::BftEvent::Vote(vote.clone()));
                }
                Ok(None)
            }
            Message::BftQuorumCertificate(_) | Message::BftViewChange { .. } => {
                log::debug!("BFT QC/ViewChange received — not yet handled");
                Ok(None)
            }
        }
    }

    /**
     * Conecta a un peer
     */
    pub async fn connect_to_peer(&self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = self.open_stream(address).await.map_err(|e| {
            Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
        })?;

        let version_msg = {
            let (block_count, latest_hash) = if let Some(s) = &self.store {
                let h = s.get_latest_height().unwrap_or(0);
                let hash = s
                    .read_block(h)
                    .ok()
                    .map(|b| hex::encode(b.parent_hash))
                    .unwrap_or_default();
                ((h + 1) as usize, hash)
            } else {
                (0, String::new())
            };
            let p2p_addr = self.p2p_address();
            Message::Version {
                version: "1.0.0".to_string(),
                block_count,
                latest_hash,
                p2p_address: Some(p2p_addr),
                network_id: Some(self.network_id.clone()),
            }
        };

        let msg_json = serde_json::to_string(&version_msg)?;
        stream.write_all(msg_json.as_bytes()).await?;

        let mut buffer = vec![0u8; p2p_response_buffer_size()];
        let n = match stream.read(&mut buffer).await {
            Ok(0) => {
                // Conexión cerrada sin respuesta - probablemente rechazada por el servidor
                return Err(
                    "Connection closed by peer (likely Network ID mismatch or rejection)".into(),
                );
            }
            Ok(n) => n,
            Err(e) => {
                // Error al leer - conexión probablemente cerrada
                return Err(format!(
                    "Error reading response from peer: {e} (connection may have been rejected)"
                )
                .into());
            }
        };

        let response_str = String::from_utf8_lossy(&buffer[..n]);

        if let Ok(Message::Version {
            block_count: their_count,
            latest_hash: _their_hash,
            p2p_address,
            network_id: their_network_id,
            ..
        }) = serde_json::from_str(&response_str)
        {
            // Validar Network ID PRIMERO - rechazar conexión si no coincide (ANTES de agregar a peers)
            if let Some(their_id) = their_network_id {
                if their_id != self.network_id {
                    return Err(format!(
                        "Network ID mismatch: expected '{}', got '{}'. Rejecting connection.",
                        self.network_id, their_id
                    )
                    .into());
                }
            } else {
                // Si el peer no envía network_id, asumimos compatibilidad (backward compatibility)
                println!("⚠️  Peer {address} no envió network_id, asumiendo compatibilidad");
            }

            // Always use the address we connected to — the peer's declared
            // address may be 0.0.0.0 (behind NAT/container).
            let peer_p2p_addr = address.to_string();
            let _ = p2p_address; // ignored — not reachable from outside

            {
                let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
                peers.insert(peer_p2p_addr.clone());
                println!("📡 Peer agregado en connect_to_peer: {peer_p2p_addr}");
            }

            let my_count = self
                .store
                .as_ref()
                .and_then(|s| s.get_latest_height().ok())
                .map(|h| (h + 1) as usize)
                .unwrap_or(0);

            // State sync via StateRequest if peer has more blocks
            if their_count > my_count {
                println!(
                    "📥 Requesting state sync from {address} (them: {their_count}, us: {my_count})"
                );
                self.request_state_sync(address, my_count as u64).await?;
            }

            // Sincronizar contratos
            if self.contract_manager.is_some() {
                println!("📋 Sincronizando contratos desde {address}...");
                if let Err(e) = self.request_contracts(address).await {
                    eprintln!("⚠️  Error sincronizando contratos desde {address}: {e}");
                }
            }
        } else {
            // Si no recibimos Version válido, aún así agregar el peer
            let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers.insert(address.to_string());
        }

        println!("✅ Conectado a peer: {address}");
        Ok(())
    }

    /**
     * Sincroniza con todos los peers conectados
     */
    pub async fn sync_with_all_peers(&self) -> Result<(), Box<dyn std::error::Error>> {
        let peers: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        for peer_addr in peers.iter() {
            if let Err(e) = self.sync_with_peer(peer_addr).await {
                eprintln!("Error sincronizando con {peer_addr}: {e}");
            }
        }

        Ok(())
    }

    /**
     * Verifica si un peer está conectado enviando un ping
     */
    async fn ping_peer(&self, address: &str) -> bool {
        if let Ok(mut stream) = self.open_stream(address).await {
            let ping_msg = Message::Ping;
            if let Ok(msg_json) = serde_json::to_string(&ping_msg) {
                if stream.write_all(msg_json.as_bytes()).await.is_ok() {
                    let mut buffer = [0; 256];
                    match tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        stream.read(&mut buffer),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            if let Ok(Message::Pong) = serde_json::from_slice(&buffer[..n]) {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        false
    }

    #[allow(dead_code)]
    /// Connect to anchor peers before general discovery.
    ///
    /// Anchor peers serve as cross-org entry points: each org publishes one
    /// or more anchors so that peers from different orgs can discover each other.
    /// This runs before `connect_to_bootstrap_nodes`.
    pub async fn connect_to_anchor_peers(&self) {
        if self.anchor_peers.is_empty() {
            return;
        }

        let my_addr = self.p2p_address();
        let mut connected = 0;

        for anchor in &self.anchor_peers {
            if anchor.peer_address == my_addr {
                continue;
            }
            match self.connect_to_peer(&anchor.peer_address).await {
                Ok(_) => {
                    eprintln!(
                        "[gossip] connected to anchor peer {} (org={})",
                        anchor.peer_address, anchor.org_id
                    );
                    connected += 1;
                }
                Err(e) => {
                    eprintln!(
                        "[gossip] failed to connect to anchor peer {} (org={}): {}",
                        anchor.peer_address, anchor.org_id, e
                    );
                }
            }
        }

        if connected > 0 {
            eprintln!(
                "[gossip] connected to {}/{} anchor peers",
                connected,
                self.anchor_peers.len()
            );
        }
    }

    /**
     * Conecta automáticamente a los bootstrap nodes
     */
    pub async fn connect_to_bootstrap_nodes(&self) {
        if self.bootstrap_nodes.is_empty() {
            return;
        }

        println!("🔗 Intentando conectar a bootstrap nodes...");
        let mut connected = 0;
        let mut failed = 0;

        for bootstrap_addr in &self.bootstrap_nodes {
            // Evitar conectarse a sí mismo
            let my_addr = self.p2p_address();
            if bootstrap_addr == &my_addr {
                continue;
            }

            match self.connect_to_peer(bootstrap_addr).await {
                Ok(_) => {
                    println!("✅ Conectado a bootstrap node: {bootstrap_addr}");
                    connected += 1;
                }
                Err(e) => {
                    println!("⚠️  No se pudo conectar a bootstrap node {bootstrap_addr}: {e}");
                    failed += 1;
                }
            }

            // Pequeño delay entre conexiones
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        if connected > 0 {
            println!(
                "✅ Conectado a {}/{} bootstrap nodes",
                connected,
                self.bootstrap_nodes.len()
            );
        } else if failed > 0 {
            println!("⚠️  No se pudo conectar a ningún bootstrap node (esto es normal si es el primer nodo)");
        }
    }

    /**
     * Pide la lista de peers a un peer específico
     * @param address - Dirección del peer al que pedir la lista
     * @returns Lista de peers o error
     */
    pub async fn request_peers_from_peer(
        &self,
        address: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut stream = self.open_stream(address).await.map_err(|e| {
            Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
        })?;

        let get_peers_msg = Message::GetPeers;
        let msg_json = serde_json::to_string(&get_peers_msg)?;
        stream.write_all(msg_json.as_bytes()).await?;

        let mut buffer = vec![0u8; p2p_response_buffer_size()];
        let n = match stream.read(&mut buffer).await {
            Ok(0) => return Err("Connection closed by peer".into()),
            Ok(n) => n,
            Err(e) => return Err(format!("Error reading response: {e}").into()),
        };

        let response_str = String::from_utf8_lossy(&buffer[..n]);

        if let Ok(Message::Peers(peer_list)) = serde_json::from_str(&response_str) {
            Ok(peer_list)
        } else {
            Err("Invalid response from peer".into())
        }
    }

    /**
     * Intenta conectar a bootstrap nodes y seed nodes
     * @param force - Si es true, intenta conectar incluso si ya hay peers (útil para descubrir más)
     * @returns true si conectó a al menos un node
     */
    pub async fn try_bootstrap_reconnect(&self, force: bool) -> bool {
        // Obtener información sobre peers actuales (soltar lock antes de await)
        let (has_peers, current_peers) = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            let has = !peers_guard.is_empty();
            let current: HashSet<String> = peers_guard.iter().cloned().collect();
            (has, current)
        };

        // Si ya hay peers y no es forzado, no hacer nada
        if has_peers && !force {
            return false;
        }

        // Combinar bootstrap nodes y seed nodes
        let mut all_nodes: Vec<String> = Vec::new();
        all_nodes.extend_from_slice(&self.bootstrap_nodes);
        all_nodes.extend_from_slice(&self.seed_nodes);

        if all_nodes.is_empty() {
            return false;
        }

        let log_msg = if has_peers {
            "🔄 Intentando conectar a bootstrap/seed nodes para descubrir más peers..."
        } else {
            "🔄 Sin peers conectados, intentando conectar a bootstrap/seed nodes..."
        };
        println!("{log_msg}");

        let mut connected = 0;

        for node_addr in &all_nodes {
            // Evitar conectarse a sí mismo
            let my_addr = self.p2p_address();
            if node_addr == &my_addr {
                continue;
            }

            // Si ya estamos conectados a este node, saltarlo
            if current_peers.contains(node_addr) {
                continue;
            }

            match self.connect_to_peer(node_addr).await {
                Ok(_) => {
                    // Determinar si es bootstrap o seed para el log
                    let node_type = if self.bootstrap_nodes.contains(node_addr) {
                        "bootstrap"
                    } else {
                        "seed"
                    };
                    println!("✅ Conectado a {node_type} node: {node_addr}");
                    connected += 1;
                    // Si no es forzado, con uno es suficiente
                    if !force {
                        break;
                    }
                }
                Err(_) => {
                    // Silenciosamente ignorar errores
                }
            }

            // Pequeño delay entre intentos
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        connected > 0
    }

    /**
     * Descubre nuevos peers pidiendo la lista a todos los peers conectados
     * @returns Número de nuevos peers descubiertos
     */
    pub async fn discover_peers(&self) -> usize {
        let current_peers: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        // Si no hay peers, intentar conectar a bootstrap/seed nodes primero
        if current_peers.is_empty() {
            // Combinar bootstrap y seed nodes para verificar si hay alguno disponible
            let has_any_nodes = !self.bootstrap_nodes.is_empty() || !self.seed_nodes.is_empty();

            if has_any_nodes {
                if self.try_bootstrap_reconnect(false).await {
                    // Si reconectamos, esperar un momento y obtener la nueva lista
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
                    if peers_guard.is_empty() {
                        return 0;
                    }
                    // Continuar con el discovery normal
                } else {
                    return 0;
                }
            } else {
                // Sin bootstrap ni seed nodes, no hay forma de descubrir
                return 0;
            }
        }

        // Re-obtener lista actualizada después de posible reconexión
        let current_peers: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        let mut discovered_peers = HashSet::new();
        let my_addr = self.p2p_address();

        // Pedir peers a cada peer conectado
        for peer_addr in &current_peers {
            match self.request_peers_from_peer(peer_addr).await {
                Ok(peer_list) => {
                    for discovered_peer in peer_list {
                        // Evitar agregarnos a nosotros mismos
                        if discovered_peer != my_addr {
                            discovered_peers.insert(discovered_peer);
                        }
                    }
                }
                Err(e) => {
                    // Silenciosamente ignorar errores (peer puede estar desconectado)
                    eprintln!("⚠️  Error obteniendo peers de {peer_addr}: {e}");
                }
            }

            // Pequeño delay entre requests
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }

        // Agregar nuevos peers descubiertos a nuestra lista (sin conectar aún)
        // Límite máximo de 200 peers para evitar crecimiento indefinido
        const MAX_PEERS: usize = 200;
        let mut new_peers_count = 0;
        {
            let mut peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            let current_count = peers_guard.len();

            for discovered_peer in discovered_peers {
                if !peers_guard.contains(&discovered_peer) {
                    // Si ya tenemos el máximo, no agregar más
                    if current_count + new_peers_count >= MAX_PEERS {
                        break;
                    }
                    peers_guard.insert(discovered_peer.clone());
                    new_peers_count += 1;
                }
            }
        }

        if new_peers_count > 0 {
            println!("🔍 Descubiertos {new_peers_count} nuevos peers");
        }

        new_peers_count
    }

    /**
     * Auto-descubre peers y se conecta automáticamente a los nuevos
     * @param max_new_connections - Máximo número de nuevas conexiones a establecer (default: 5)
     */
    pub async fn auto_discover_and_connect(&self, max_new_connections: usize) {
        // Si tenemos pocos peers (menos de 3), intentar conectar a bootstrap/seed nodes también
        // Esto ayuda a descubrir más peers incluso si ya tenemos algunos
        let (peer_count, has_any_nodes) = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            let count = peers_guard.len();
            let has_nodes = !self.bootstrap_nodes.is_empty() || !self.seed_nodes.is_empty();
            (count, has_nodes)
        };

        if peer_count < 3 && has_any_nodes {
            // Intentar conectar a bootstrap/seed nodes para descubrir más (force=true)
            self.try_bootstrap_reconnect(true).await;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        // Primero descubrir nuevos peers
        let _ = self.discover_peers().await;

        // Limpiar peers fallidos antiguos (más de 10 minutos) y con muchos intentos (más de 5)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        {
            let mut failed = self.failed_peers.lock().unwrap_or_else(|e| e.into_inner());
            failed.retain(|_, (ts, attempts)| {
                let age = now.saturating_sub(*ts);
                // Mantener si tiene menos de 10 minutos y menos de 5 intentos
                age < 600 && *attempts < 5
            });
        }

        // Obtener lista de peers actuales
        let all_peers: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        let my_addr = self.p2p_address();
        let mut connected_count = 0;
        let mut new_peers_to_try: Vec<String> = Vec::new();

        // Separar peers nuevos descubiertos de peers fallidos para retry
        {
            let failed = self.failed_peers.lock().unwrap_or_else(|e| e.into_inner());
            for peer_addr in &all_peers {
                if peer_addr == &my_addr {
                    continue;
                }

                // Verificar si es un peer fallido que podemos reintentar
                if let Some((failed_ts, attempts)) = failed.get(peer_addr) {
                    let age = now.saturating_sub(*failed_ts);
                    // Reintentar si han pasado al menos 2 minutos y tiene menos de 5 intentos
                    if age >= 120 && *attempts < 5 {
                        new_peers_to_try.push(peer_addr.clone());
                    }
                } else {
                    // Peer nuevo o no fallido, agregar a la lista
                    new_peers_to_try.push(peer_addr.clone());
                }
            }
        }

        // Limitar número de peers a intentar
        let peers_to_try: Vec<String> = new_peers_to_try
            .into_iter()
            .take(max_new_connections)
            .collect();

        // Intentar conectar a los peers
        for peer_addr in peers_to_try {
            // Verificar si ya estamos conectados (ping rápido con timeout más corto)
            let is_connected = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                self.ping_peer(&peer_addr),
            )
            .await
            .unwrap_or(false);

            if !is_connected {
                // No está conectado, intentar conectar
                match self.connect_to_peer(&peer_addr).await {
                    Ok(_) => {
                        println!("✅ Auto-conectado a peer: {peer_addr}");
                        connected_count += 1;

                        // Remover de peers fallidos si estaba ahí
                        let mut failed =
                            self.failed_peers.lock().unwrap_or_else(|e| e.into_inner());
                        failed.remove(&peer_addr);
                    }
                    Err(e) => {
                        // Registrar como peer fallido
                        let mut failed =
                            self.failed_peers.lock().unwrap_or_else(|e| e.into_inner());
                        let entry = failed.entry(peer_addr.clone()).or_insert((now, 0));
                        entry.1 += 1;
                        eprintln!(
                            "⚠️  No se pudo auto-conectar a {} (intento {}): {}",
                            peer_addr, entry.1, e
                        );
                    }
                }
            }

            // Delay entre conexiones
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        if connected_count > 0 {
            println!("✅ Auto-conectado a {connected_count} peers");
        }
    }

    /**
     * Limpia peers desconectados verificando su conectividad
     */
    pub async fn cleanup_disconnected_peers(&self) {
        let peers_to_check: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        let mut disconnected = Vec::new();

        for peer_addr in peers_to_check.iter() {
            if !self.ping_peer(peer_addr).await {
                println!("🔌 Peer desconectado detectado: {peer_addr}");
                disconnected.push(peer_addr.clone());
            }
        }

        if !disconnected.is_empty() {
            let mut peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            for peer in disconnected {
                peers_guard.remove(&peer);
                println!("🗑️  Peer removido de la lista: {peer}");
            }
        }
    }

    /**
     * Sincroniza con un peer específico
     */
    pub async fn sync_with_peer(&self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let my_height = self
            .store
            .as_ref()
            .and_then(|s| s.get_latest_height().ok())
            .unwrap_or(0);
        self.request_state_sync(address, my_height).await
    }

    /// Pull-based state sync: request blocks from `from_height` via `StateRequest`.
    async fn request_state_sync(
        &self,
        address: &str,
        from_height: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let msg = Message::StateRequest { from_height };
        let resp = self
            .send_and_wait(address, msg, std::time::Duration::from_secs(30))
            .await
            .map_err(|e| -> Box<dyn std::error::Error> {
                Box::new(std::io::Error::other(e.to_string()))
            })?;
        if let Message::StateResponse { blocks } = resp {
            if let Some(s) = &self.store {
                let trusted_signers =
                    crate::ordering::trusted_block_signers(self.signing_provider.as_deref());
                for block in &blocks {
                    if let Err(e) = commit_incoming_block(s.as_ref(), block, &trusted_signers) {
                        log::warn!("state sync from {address} stopped: {e}");
                        break;
                    }
                }
                println!(
                    "✅ State sync from {address}: {} blocks written",
                    blocks.len()
                );
            }
        }
        Ok(())
    }

    /// Broadcast a committed DLT block to all connected peers.
    ///
    /// Peers that receive `OrderedBlock` persist it to their local store,
    /// keeping the ledger in sync without pull-based state sync.
    /// Broadcast any serializable Message to all connected peers.
    pub async fn broadcast_message(&self, msg: &Message) {
        let my_addr = self.p2p_address();
        let peers: Vec<String> = {
            let guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            guard.iter().filter(|p| **p != my_addr).cloned().collect()
        };
        let msg_json = match serde_json::to_string(msg) {
            Ok(j) => j,
            Err(_) => return,
        };
        log::info!(
            "P2P broadcast {} bytes to {} peer(s): {:?}",
            msg_json.len(),
            peers.len(),
            peers
        );
        for peer_addr in &peers {
            let addr = peer_addr.clone();
            match self.open_stream(&addr).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(msg_json.as_bytes()).await {
                        log::warn!("P2P broadcast write to {addr} failed: {e}");
                    }
                }
                Err(e) => {
                    log::warn!("P2P broadcast connect to {addr} failed: {e}");
                }
            }
        }
    }

    pub async fn broadcast_ordered_block(&self, block: &crate::storage::traits::Block) {
        let my_addr = self.p2p_address();
        let peers: Vec<String> = {
            let guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            guard.iter().filter(|p| **p != my_addr).cloned().collect()
        };
        log::info!(
            "Broadcasting block {} to {} peer(s): {:?}",
            block.height,
            peers.len(),
            peers
        );
        let msg = Message::OrderedBlock(block.clone());
        for peer_addr in &peers {
            let msg_json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    log::warn!("Failed to serialize block for {peer_addr}: {e}");
                    continue;
                }
            };
            let addr = peer_addr.clone();
            match self.open_stream(&addr).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(msg_json.as_bytes()).await {
                        log::warn!("Failed to write block to {addr}: {e}");
                    } else {
                        log::info!(
                            "Sent block {} to {addr} ({} bytes)",
                            block.height,
                            msg_json.len()
                        );
                    }
                }
                Err(e) => {
                    log::warn!("Failed to connect to {addr} for block broadcast: {e}");
                }
            }
        }
    }

    /**
     * Solicita contratos a un peer (sincronización completa)
     */
    pub async fn request_contracts(&self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();
        let mut stream = self.open_stream(address).await.map_err(|e| {
            Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
        })?;

        // Intentar sincronización incremental primero
        let last_sync = {
            let metrics = self
                .contract_sync_metrics
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            metrics
                .get(address)
                .map(|m| m.last_sync_timestamp)
                .unwrap_or(0)
        };

        let get_contracts_msg = if last_sync > 0 {
            Message::GetContractsSince {
                timestamp: last_sync,
            }
        } else {
            Message::GetContracts
        };

        let msg_json = serde_json::to_string(&get_contracts_msg)?;
        stream.write_all(msg_json.as_bytes()).await?;

        let mut buffer = [0; 8192]; // Buffer más grande para contratos
        let n = stream.read(&mut buffer).await?;
        let response_str = String::from_utf8_lossy(&buffer[..n]);

        if let Ok(Message::Contracts(contracts)) = serde_json::from_str(&response_str) {
            if let Some(cm) = &self.contract_manager {
                let mut cm_guard = cm.write().unwrap_or_else(|e| e.into_inner());
                let mut synced = 0;
                let mut errors = 0;

                for contract in contracts {
                    // Validar integridad
                    if !contract.validate_integrity() {
                        eprintln!(
                            "⚠️  Contrato recibido tiene hash de integridad inválido: {}",
                            contract.address
                        );
                        errors += 1;
                        continue;
                    }

                    // Verificar si el contrato ya existe
                    if cm_guard.get_contract(&contract.address).is_none() {
                        // Contrato nuevo, agregarlo
                        if cm_guard.deploy_contract(contract.clone()).is_ok() {
                            synced += 1;
                        }
                    } else {
                        // Contrato existe, verificar si necesita actualización
                        if let Some(existing) = cm_guard.get_contract(&contract.address) {
                            // Validar owner
                            if contract.owner != existing.owner {
                                eprintln!("⚠️  Intento de actualizar contrato con owner diferente rechazado: {}", contract.address);
                                errors += 1;
                                continue;
                            }

                            // Comparar por updated_at y update_sequence
                            let should_update = contract.updated_at > existing.updated_at
                                || (contract.updated_at == existing.updated_at
                                    && contract.update_sequence > existing.update_sequence);

                            if should_update {
                                // Actualizar el contrato
                                if let Some(existing_mut) =
                                    cm_guard.get_contract_mut(&contract.address)
                                {
                                    *existing_mut = contract.clone();
                                    synced += 1;
                                }
                            }
                        }
                    }
                }

                // Actualizar métricas
                let duration_ms = start_time.elapsed().as_millis() as u64;
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                {
                    let mut metrics = self
                        .contract_sync_metrics
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    metrics.insert(
                        address.to_string(),
                        ContractSyncMetrics {
                            last_sync_timestamp: timestamp,
                        },
                    );
                }

                if synced > 0 {
                    println!(
                        "✅ {synced} contratos sincronizados desde {address} ({duration_ms}ms, {errors} errores)"
                    );
                } else if errors > 0 {
                    println!("⚠️  {errors} contratos rechazados desde {address} por validación");
                } else {
                    println!("ℹ️  No hay contratos nuevos para sincronizar desde {address}");
                }
            }
        } else {
            println!("⚠️  Respuesta inválida al solicitar contratos desde {address}");
        }

        Ok(())
    }

    /**
     * Envía un nuevo contrato a todos los peers con reintentos
     */
    pub async fn broadcast_contract(&self, contract: &SmartContract) {
        let peers: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        for peer_addr in peers.iter() {
            let mut retries = 3;
            let mut success = false;

            while retries > 0 && !success {
                let result = self.send_contract_to_peer(peer_addr, contract).await;
                match result {
                    Ok(_) => {
                        success = true;
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        retries -= 1;
                        if retries > 0 {
                            let delay_ms = 100 * (4 - retries); // Backoff exponencial: 100ms, 200ms, 300ms
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        } else {
                            eprintln!(
                                "Error enviando contrato a {peer_addr} después de 3 intentos: {error_msg}"
                            );
                            // Agregar a cola de pendientes (memoria)
                            let mut pending = self
                                .pending_contract_broadcasts
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            pending.push((peer_addr.clone(), contract.clone()));
                        }
                    }
                }
            }
        }
    }

    /**
     * Envía un contrato a un peer específico
     */
    async fn send_contract_to_peer(
        &self,
        address: &str,
        contract: &SmartContract,
    ) -> Result<(), String> {
        let mut stream = self
            .open_stream(address)
            .await
            .map_err(|e| format!("Error conectando: {e}"))?;
        let msg = Message::NewContract(contract.clone());
        let msg_json =
            serde_json::to_string(&msg).map_err(|e| format!("Error serializando: {e}"))?;
        stream
            .write_all(msg_json.as_bytes())
            .await
            .map_err(|e| format!("Error escribiendo: {e}"))?;

        // Esperar un poco para que el peer procese el mensaje (similar a bloques)
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Ok(())
    }

    /**
     * Envía una actualización de contrato a todos los peers con reintentos
     */
    pub async fn broadcast_contract_update(&self, contract: &SmartContract) {
        let peers: Vec<String> = {
            let peers_guard = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers_guard.iter().cloned().collect()
        };

        if peers.is_empty() {
            println!(
                "⚠️  No hay peers conectados para broadcast de actualización de contrato: {}",
                contract.address
            );
            return;
        }

        println!(
            "📤 Broadcast de actualización de contrato {} a {} peers: {:?}",
            contract.address,
            peers.len(),
            peers
        );

        for peer_addr in peers.iter() {
            println!(
                "📤 Enviando actualización de contrato {} a peer: {}",
                contract.address, peer_addr
            );
            let mut retries = 3;
            let mut success = false;

            while retries > 0 && !success {
                let result = self.send_contract_update_to_peer(peer_addr, contract).await;
                match result {
                    Ok(_) => {
                        println!(
                            "✅ Actualización de contrato {} enviada exitosamente a {}",
                            contract.address, peer_addr
                        );
                        success = true;
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        retries -= 1;
                        if retries > 0 {
                            let delay_ms = 100 * (4 - retries); // Backoff exponencial: 100ms, 200ms, 300ms
                            println!(
                                "⚠️  Error enviando a {} (intento {}): {}, reintentando en {}ms",
                                peer_addr,
                                4 - retries,
                                error_msg,
                                delay_ms
                            );
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        } else {
                            eprintln!("❌ Error enviando actualización de contrato a {peer_addr} después de 3 intentos: {error_msg}");
                            // Agregar a cola de pendientes (memoria)
                            let mut pending = self
                                .pending_contract_broadcasts
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            pending.push((peer_addr.clone(), contract.clone()));
                        }
                    }
                }
            }
        }

        println!(
            "✅ Broadcast de actualización de contrato {} completado",
            contract.address
        );
    }

    /**
     * Envía una actualización de contrato a un peer específico
     */
    async fn send_contract_update_to_peer(
        &self,
        address: &str,
        contract: &SmartContract,
    ) -> Result<(), String> {
        println!(
            "📤 Conectando a {} para enviar UpdateContract de {}",
            address, contract.address
        );
        let mut stream = self
            .open_stream(address)
            .await
            .map_err(|e| format!("Error conectando a {address}: {e}"))?;
        let msg = Message::UpdateContract(contract.clone());
        let msg_json = serde_json::to_string(&msg)
            .map_err(|e| format!("Error serializando UpdateContract: {e}"))?;

        println!(
            "📤 Enviando UpdateContract de {} a {} (tamaño: {} bytes)",
            contract.address,
            address,
            msg_json.len()
        );
        stream
            .write_all(msg_json.as_bytes())
            .await
            .map_err(|e| format!("Error escribiendo UpdateContract a {address}: {e}"))?;

        // Esperar un poco para que el peer procese el mensaje (similar a bloques)
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Ok(())
    }

    #[allow(dead_code)]
    /// Spawn the alive broadcast + suspect sweep loop.
    ///
    /// Every `alive_interval_ms` the node:
    /// 1. Broadcasts an `Alive` message to all connected peers.
    /// 2. Sweeps the membership table and marks silent peers as suspect.
    ///
    /// The returned `JoinHandle` can be used to abort the loop on shutdown.
    pub fn start_alive_loop(&self, alive_interval_ms: u64) -> tokio::task::JoinHandle<()> {
        let node = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(alive_interval_ms));
            loop {
                interval.tick().await;

                // Bump sequence number.
                let seq = {
                    let mut seq_guard = node
                        .alive_sequence
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    *seq_guard += 1;
                    *seq_guard
                };

                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                // Include local height for anti-entropy gap detection.
                let local_height = node
                    .store
                    .as_ref()
                    .and_then(|s| s.get_latest_height().ok())
                    .unwrap_or(0);

                // Build alive message (signature left zeroed — real signing in a future subtask).
                let alive = gossip::AliveMessage::with_height(
                    node.address.to_string(),
                    &node.org_id,
                    now_ms / 1000,
                    seq,
                    vec![0u8; 64],
                    local_height,
                );

                let msg = Message::Alive(alive);
                let Ok(json) = serde_json::to_string(&msg) else {
                    continue;
                };

                // Broadcast to all peers.
                let peers: Vec<String> = {
                    let g = node.peers.lock().unwrap_or_else(|e| e.into_inner());
                    g.iter().cloned().collect()
                };
                for peer_addr in &peers {
                    if let Ok(mut stream) = node.open_stream(peer_addr).await {
                        let _ =
                            tokio::io::AsyncWriteExt::write_all(&mut stream, json.as_bytes()).await;
                    }
                }

                // Sweep for suspects.
                let suspects = node.membership.sweep_suspects(now_ms);
                for s in &suspects {
                    eprintln!(
                        "[gossip] peer {} marked as suspect (no alive for {}ms)",
                        s, node.membership.timeout_ms
                    );
                }
            }
        })
    }

    /// Spawn the pull-based state sync loop.
    ///
    /// Every `pull_interval_ms` the node asks each peer for blocks it is missing
    /// (via `StateRequest`), receives a `StateResponse`, and writes them to the store.
    pub fn start_pull_sync_loop(&self, pull_interval_ms: u64) -> tokio::task::JoinHandle<()> {
        let node = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(pull_interval_ms));
            loop {
                interval.tick().await;

                let store = match &node.store {
                    Some(s) => s.clone(),
                    None => continue,
                };

                // Determine local height.
                let local_height = store.get_latest_height().unwrap_or(0);

                let peers: Vec<String> = {
                    let g = node.peers.lock().unwrap_or_else(|e| e.into_inner());
                    g.iter().cloned().collect()
                };

                for peer_addr in &peers {
                    // Send StateRequest.
                    let req = Message::StateRequest {
                        from_height: local_height + 1,
                    };
                    let Ok(json) = serde_json::to_string(&req) else {
                        continue;
                    };

                    let mut stream = match node.open_stream(peer_addr).await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    if tokio::io::AsyncWriteExt::write_all(&mut stream, json.as_bytes())
                        .await
                        .is_err()
                    {
                        continue;
                    }

                    // Read response.
                    let mut buf = vec![0u8; p2p_sync_buffer_size()];
                    let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => continue,
                    };

                    let resp: Message = match serde_json::from_slice(&buf[..n]) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    if let Message::StateResponse { blocks } = resp {
                        let trusted_signers = crate::ordering::trusted_block_signers(
                            node.signing_provider.as_deref(),
                        );
                        for block in blocks.iter().take(gossip::STATE_BATCH_SIZE) {
                            if let Err(e) =
                                commit_incoming_block(store.as_ref(), block, &trusted_signers)
                            {
                                log::warn!("pull sync from {peer_addr} stopped: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        })
    }
}

fn validate_bft_proposal(
    block: &crate::storage::traits::Block,
    proposed_hash: &[u8; 32],
    store: &dyn crate::storage::traits::BlockStore,
    trusted_signers: &[String],
) -> Result<(), String> {
    if crate::mining::block_hash(block) != *proposed_hash {
        return Err(format!(
            "proposed hash does not match block {}",
            block.height
        ));
    }
    crate::ordering::validate_incoming_block(block, store, trusted_signers)
}

fn commit_incoming_block(
    store: &dyn crate::storage::traits::BlockStore,
    block: &crate::storage::traits::Block,
    trusted_signers: &[String],
) -> Result<(), String> {
    let is_known = store
        .block_exists(block.height)
        .map_err(|e| format!("failed to check local block {}: {e}", block.height))?;
    if is_known {
        return Ok(());
    }
    crate::ordering::validate_incoming_block(block, store, trusted_signers)?;
    store
        .write_block(block)
        .map_err(|e| format!("failed to write block {}: {e}", block.height))?;
    for tx in &block.transaction_data {
        let mut committed_tx = tx.clone();
        if let Err(e) = crate::transaction::apply_tx_payload(store, tx) {
            log::warn!("tx {} payload rejected: {e}", tx.id);
            committed_tx.state = "invalid_payload".to_string();
        }
        store
            .write_transaction(&committed_tx)
            .map_err(|e| format!("failed to write tx {}: {e}", tx.id))?;
    }
    Ok(())
}

#[cfg(test)]
mod peer_allowlist_tests {
    use super::parse_peer_allowlist;

    #[test]
    fn parse_peer_allowlist_accepts_comma_separated_addrs() {
        let s = "127.0.0.1:8081, 192.168.1.1:9090";
        let set = parse_peer_allowlist(s).expect("valid");
        assert!(set.contains("127.0.0.1:8081"));
        assert!(set.contains("192.168.1.1:9090"));
    }

    #[test]
    fn parse_peer_allowlist_empty_returns_none() {
        assert!(parse_peer_allowlist("").is_none());
        assert!(parse_peer_allowlist("   , , ").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const TEST_CERT_PEM: &str = include_str!("../../tests/fixtures/test_cert.pem");
    const TEST_KEY_PEM: &str = include_str!("../../tests/fixtures/test_key.pem");

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn parse_peer_allowlist_valid_addresses() {
        let result = parse_peer_allowlist("127.0.0.1:8000,127.0.0.1:8001");
        assert!(result.is_some());
        let set = result.unwrap();
        assert!(set.contains("127.0.0.1:8000"));
        assert!(set.contains("127.0.0.1:8001"));
    }

    #[test]
    fn parse_peer_allowlist_empty_returns_none() {
        assert!(parse_peer_allowlist("").is_none());
        assert!(parse_peer_allowlist("   ").is_none());
    }

    #[test]
    fn parse_peer_allowlist_invalid_entries_skipped() {
        let result = parse_peer_allowlist("127.0.0.1:8000,not-an-addr,127.0.0.1:8001");
        let set = result.unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn set_tls_acceptor_stores_acceptor() {
        use crate::tls::build_server_config;
        let cert = write_temp(TEST_CERT_PEM);
        let key = write_temp(TEST_KEY_PEM);
        let server_config = build_server_config(cert.path(), key.path()).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut node = Node::new("127.0.0.1:9999".parse().unwrap(), None, None, None, None);
        node.set_tls_acceptor(acceptor);
        assert!(node.tls_acceptor.is_some());
    }

    #[test]
    fn parse_server_name_ip() {
        let name = parse_server_name("127.0.0.1:8000").unwrap();
        assert!(matches!(name, ServerName::IpAddress(_)));
    }

    #[test]
    fn parse_server_name_dns() {
        let name = parse_server_name("localhost:8000").unwrap();
        assert!(matches!(name, ServerName::DnsName(_)));
    }

    fn make_node(role: NodeRole) -> Node {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Node::with_role(addr, None, None, None, None, role)
    }

    #[test]
    fn node_role_peer() {
        let node = make_node(NodeRole::Peer);
        assert_eq!(node.role, NodeRole::Peer);
    }

    #[test]
    fn node_role_orderer() {
        let node = make_node(NodeRole::Orderer);
        assert_eq!(node.role, NodeRole::Orderer);
    }

    fn make_storage_tx() -> crate::storage::traits::Transaction {
        crate::storage::traits::Transaction {
            id: "tx-test".to_string(),
            block_height: 1,
            timestamp: 42,
            input_did: "did:goya:alice".to_string(),
            output_recipient: "did:goya:bob".to_string(),
            amount: 10,
            state: "pending".to_string(),
            fee: 0,
            payload: None,
        }
    }

    #[test]
    fn submit_transaction_serde_roundtrip() {
        let msg = Message::SubmitTransaction(make_storage_tx());
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::SubmitTransaction(tx) = decoded {
            assert_eq!(tx.id, "tx-test");
        } else {
            panic!("wrong variant");
        }
    }

    type ProcessMsgArgs = (
        Arc<Mutex<HashSet<String>>>,
        Arc<Mutex<HashMap<String, (u64, String)>>>,
        Arc<Mutex<HashMap<String, (u64, usize)>>>,
    );

    fn empty_process_message_args() -> ProcessMsgArgs {
        (
            Arc::new(Mutex::new(HashSet::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
        )
    }

    #[tokio::test]
    async fn orderer_submit_transaction_increases_pending_count() {
        let svc = Arc::new(crate::ordering::service::OrderingService::with_config(
            100, 2000,
        ));
        let (peers, receipts, rates) = empty_process_message_args();
        let tx = make_storage_tx();

        Node::process_message(
            Message::SubmitTransaction(tx),
            &peers,
            None,
            None,
            None,
            None,
            None,
            receipts,
            rates,
            None,
            NodeRole::Orderer,
            Some(svc.clone()),
            None,
            None,      // gossip_block_tx
            None,      // membership
            None,      // chaincode_store
            None,      // world_state
            None,      // signing_provider
            "default", // node_org_id
            None,      // raft_node
            None,      // private_data_store
            None,      // collection_registry
            None,      // bft_tx
        )
        .await
        .unwrap();

        assert_eq!(svc.pending_count(), 1);
    }

    async fn deliver_ordered_block(
        block: crate::storage::traits::Block,
        signing_provider: Arc<dyn crate::identity::signing::SigningProvider>,
    ) -> Arc<dyn crate::storage::traits::BlockStore> {
        let store: Arc<dyn crate::storage::traits::BlockStore> =
            Arc::new(crate::storage::MemoryStore::new());
        let (peers, receipts, rates) = empty_process_message_args();
        Node::process_message(
            Message::OrderedBlock(block),
            &peers,
            None,
            None,
            None,
            None,
            None,
            receipts,
            rates,
            None,
            NodeRole::Peer,
            None,
            Some(store.clone()),
            None,
            None,
            None,
            None,
            Some(signing_provider),
            "default",
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        store
    }

    fn transaction(
        id: &str,
        payload: Option<crate::storage::traits::TxPayload>,
    ) -> crate::storage::traits::Transaction {
        crate::storage::traits::Transaction {
            id: id.to_string(),
            block_height: 7,
            timestamp: 0,
            input_did: "did:goya:alice".to_string(),
            output_recipient: "did:goya:bob".to_string(),
            amount: 1,
            state: "pending".to_string(),
            fee: 0,
            payload,
        }
    }

    fn block_with(
        tx: crate::storage::traits::Transaction,
        signing_provider: Arc<dyn crate::identity::signing::SigningProvider>,
    ) -> crate::storage::traits::Block {
        let svc = crate::ordering::service::OrderingService::with_config(10, 500)
            .with_signing_provider(signing_provider);
        svc.submit_tx(tx).unwrap();
        svc.cut_block(7, [0u8; 32], "ord").unwrap().unwrap()
    }

    fn block_signed_by(
        signing_provider: Arc<dyn crate::identity::signing::SigningProvider>,
    ) -> crate::storage::traits::Block {
        block_with(transaction("tx-1", None), signing_provider)
    }

    fn trusted_provider() -> Arc<dyn crate::identity::signing::SigningProvider> {
        Arc::new(crate::identity::signing::SoftwareSigningProvider::generate())
    }

    #[tokio::test]
    async fn peer_ordered_block_from_trusted_signer_writes_to_store() {
        let signer = trusted_provider();
        let store = deliver_ordered_block(block_signed_by(signer.clone()), signer).await;
        assert_eq!(store.read_block(7).unwrap().height, 7);
        assert!(store.read_transaction("tx-1").is_ok());
    }

    #[tokio::test]
    async fn peer_ordered_block_replicates_notarization_from_transaction() {
        let entry = crate::storage::traits::NotarizationEntry {
            id: "nota-1".to_string(),
            content_hash: "a".repeat(64),
            signer: "did:goya:alice".to_string(),
            metadata: None,
            notarized_at: 1_700_000_000,
            block_height: 7,
            signature: "ff".repeat(32),
            public_key: "aa".repeat(32),
            cades_der: None,
            signature_algorithm: Default::default(),
            signature_level: crate::signature::SignatureLevel::Simple,
            biometric_evidence: vec![],
            signer_proof: None,
        };
        let payload = crate::storage::traits::TxPayload::Notarize {
            entry: Box::new(entry.clone()),
        };
        let signer = trusted_provider();
        let block = block_with(
            transaction("notarize:nota-1", Some(payload)),
            signer.clone(),
        );
        let store = deliver_ordered_block(block, signer).await;
        assert_eq!(store.read_notarization("nota-1").unwrap(), entry);
    }

    #[tokio::test]
    async fn peer_ordered_block_with_tampered_data_is_rejected() {
        let signer = trusted_provider();
        let mut block = block_signed_by(signer.clone());
        block.transaction_data[0].amount = 1_000_000;
        let store = deliver_ordered_block(block, signer).await;
        assert!(!store.block_exists(7).unwrap());
        assert!(store.read_transaction("tx-1").is_err());
    }

    #[tokio::test]
    async fn peer_ordered_block_from_untrusted_signer_is_rejected() {
        let block = block_signed_by(trusted_provider());
        let store = deliver_ordered_block(block, trusted_provider()).await;
        assert!(!store.block_exists(7).unwrap());
    }

    #[test]
    fn ordered_block_serde_roundtrip() {
        let block = crate::storage::traits::Block {
            height: 5,
            timestamp: 100,
            parent_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            transactions: vec!["tx-test".to_string()],
            proposer: "orderer1".to_string(),
            signature: vec![0u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        };
        let msg = Message::OrderedBlock(block);
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::OrderedBlock(b) = decoded {
            assert_eq!(b.height, 5);
            assert_eq!(b.transactions, vec!["tx-test"]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn raft_message_serde_roundtrip() {
        let payload = vec![1u8, 2, 3, 42];
        let msg = Message::RaftMessage(payload.clone());
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::RaftMessage(data) = decoded {
            assert_eq!(data, payload);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn state_request_serde_roundtrip() {
        let msg = Message::StateRequest { from_height: 42 };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::StateRequest { from_height } = decoded {
            assert_eq!(from_height, 42);
        } else {
            panic!("expected StateRequest");
        }
    }

    #[test]
    fn state_response_serde_roundtrip() {
        let block = crate::storage::traits::Block {
            height: 10,
            timestamp: 999,
            parent_hash: [1u8; 32],
            merkle_root: [2u8; 32],
            transactions: vec!["tx1".to_string()],
            proposer: "peer0".to_string(),
            signature: vec![3u8; 64],
            signature_algorithm: Default::default(),
            endorsements: vec![],
            secondary_signature: None,
            secondary_signature_algorithm: None,
            hash_algorithm: Default::default(),
            orderer_signature: None,
            commit_qc: None,
            transaction_data: vec![],
        };
        let msg = Message::StateResponse {
            blocks: vec![block],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::StateResponse { blocks } = decoded {
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].height, 10);
            assert_eq!(blocks[0].proposer, "peer0");
        } else {
            panic!("expected StateResponse");
        }
    }
}
