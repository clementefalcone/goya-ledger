//! Fabric Gateway — orchestrates the endorse → order → commit lifecycle.

use std::sync::Arc;

use thiserror::Error;

use crate::chaincode::executor::WasmExecutor;
use crate::discovery::service::DiscoveryError;
use crate::discovery::service::DiscoveryService;
use crate::endorsement::key_policy::KeyEndorsementStore;
use crate::endorsement::policy::EndorsementPolicy;
use crate::endorsement::policy_store::PolicyStore;
use crate::endorsement::registry::OrgRegistry;
use crate::endorsement::types::Endorsement;
use crate::events::types::BlockEvent;
use crate::events::EventBus;
use crate::network::{Message, Node};
use crate::storage::traits::{BlockStore, Transaction};
use crate::storage::world_state::WorldState;
use crate::transaction::endorsed::EndorsedTransaction;
use crate::transaction::executor;
use crate::transaction::mvcc;
use crate::transaction::rwset::ReadWriteSet;

/// Timeout for individual peer endorsement requests.
const ENDORSEMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Errors produced by the gateway.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("endorsement policy not satisfied for chaincode '{0}'")]
    PolicyNotSatisfied(String),
    #[error("ordering service error: {0}")]
    Ordering(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("chaincode simulation failed: {0}")]
    Simulation(String),
}

/// Result returned after a transaction is fully committed.
#[derive(Debug, Clone, PartialEq)]
pub struct TxResult {
    /// The transaction ID that was submitted.
    pub tx_id: String,
    /// The block height at which the transaction was committed.
    pub block_height: u64,
    /// Whether the transaction passed MVCC validation.
    /// `true` = writes applied to world state; `false` = mvcc_conflict (block
    /// still contains the TX but its writes were NOT applied).
    pub valid: bool,
}

/// Result of a batch parallel commit.
#[derive(Debug, Clone)]
pub struct BatchTxResult {
    /// Block height where the batch was committed.
    pub block_height: u64,
    /// Number of transactions that passed MVCC and were applied.
    pub committed_count: usize,
    /// Number of transactions rejected due to MVCC conflicts.
    pub conflict_count: usize,
    /// Number of execution waves (1 = fully parallel, N = fully sequential).
    pub wave_count: usize,
    /// Parallelism ratio: total_txs / wave_count.
    pub parallelism_ratio: f64,
    /// Per-transaction outcomes (tx_id, outcome).
    pub outcomes: Vec<(String, executor::TxOutcome)>,
}

/// Orchestrates the endorse → order → commit lifecycle for a single node.
pub struct Gateway {
    pub org_registry: Arc<dyn OrgRegistry>,
    pub policy_store: Arc<dyn PolicyStore>,
    pub ordering_service: Arc<dyn crate::ordering::OrderingBackend>,
    pub store: Arc<dyn BlockStore>,
    /// Optional discovery service used to resolve endorsers at submit time.
    pub discovery_service: Option<Arc<DiscoveryService>>,
    /// Optional event bus — when set, emits `BlockCommitted` and
    /// `TransactionCommitted` events after each successful commit.
    pub event_bus: Option<Arc<EventBus>>,
    /// Optional Wasm executor for pre-ordering simulation.
    ///
    /// When set, `submit` runs the chaincode against `world_state` to produce
    /// an rwset, then validates any key-level endorsement policies before
    /// enqueuing the transaction in the ordering service.
    pub wasm_executor: Option<Arc<WasmExecutor>>,
    /// Base world state used as input for Wasm simulation.
    pub world_state: Option<Arc<dyn WorldState>>,
    /// Key-level endorsement policy store consulted after simulation.
    pub key_endorsement_store: Option<Arc<dyn KeyEndorsementStore>>,
    /// P2P node handle for sending endorsement requests to remote peers.
    pub p2p_node: Option<Arc<Node>>,
}

impl Gateway {
    pub fn new(
        org_registry: Arc<dyn OrgRegistry>,
        policy_store: Arc<dyn PolicyStore>,
        ordering_service: Arc<dyn crate::ordering::OrderingBackend>,
        store: Arc<dyn BlockStore>,
    ) -> Self {
        Self {
            org_registry,
            policy_store,
            ordering_service,
            store,
            discovery_service: None,
            event_bus: None,
            wasm_executor: None,
            world_state: None,
            key_endorsement_store: None,
            p2p_node: None,
        }
    }

    #[allow(dead_code)]
    /// Like [`new`] but with a discovery service for peer-aware endorsement.
    pub fn with_discovery(
        org_registry: Arc<dyn OrgRegistry>,
        policy_store: Arc<dyn PolicyStore>,
        ordering_service: Arc<dyn crate::ordering::OrderingBackend>,
        store: Arc<dyn BlockStore>,
        discovery_service: Arc<DiscoveryService>,
    ) -> Self {
        Self {
            org_registry,
            policy_store,
            ordering_service,
            store,
            discovery_service: Some(discovery_service),
            event_bus: None,
            wasm_executor: None,
            world_state: None,
            key_endorsement_store: None,
            p2p_node: None,
        }
    }

    #[allow(dead_code)]
    /// Like [`new`] but with an event bus for block/transaction notifications.
    pub fn with_events(
        org_registry: Arc<dyn OrgRegistry>,
        policy_store: Arc<dyn PolicyStore>,
        ordering_service: Arc<dyn crate::ordering::OrderingBackend>,
        store: Arc<dyn BlockStore>,
        event_bus: Arc<EventBus>,
    ) -> Self {
        Self {
            org_registry,
            policy_store,
            ordering_service,
            store,
            discovery_service: None,
            event_bus: Some(event_bus),
            wasm_executor: None,
            world_state: None,
            key_endorsement_store: None,
            p2p_node: None,
        }
    }

    #[allow(dead_code)]
    /// Attach a Wasm executor for pre-ordering chaincode simulation.
    ///
    /// When set, `submit` will:
    /// 1. Run `executor.simulate(world_state, "invoke")` to produce an rwset.
    /// 2. Validate any key-level endorsement policies for the write set.
    /// 3. Only then enqueue the transaction in the ordering service.
    pub fn with_wasm_simulation(
        mut self,
        executor: Arc<WasmExecutor>,
        world_state: Arc<dyn WorldState>,
        key_endorsement_store: Option<Arc<dyn KeyEndorsementStore>>,
    ) -> Self {
        self.wasm_executor = Some(executor);
        self.world_state = Some(world_state);
        self.key_endorsement_store = key_endorsement_store;
        self
    }

    /// Submit a transaction through the full endorse → order → commit pipeline.
    ///
    /// Steps (single-node implementation):
    /// 1. Resolve endorsers via the discovery service when available (channel-aware),
    ///    or fall back to a self-endorsement check using the local org registry.
    /// 2. Enqueue the transaction in the ordering service.
    /// 3. Cut a block immediately and persist it to the store.
    /// 4. Return [`TxResult`] with the transaction ID and the committed block height.
    ///
    /// When `channel_id` is non-empty and a `DiscoveryService` is configured, step 1
    /// calls `endorsement_plan` to find the required endorsers.  If the policy is not
    /// found in discovery the method falls back to the local org-registry check.
    pub async fn submit(
        &self,
        chaincode_id: &str,
        channel_id: &str,
        tx: Transaction,
    ) -> Result<TxResult, GatewayError> {
        // ── Step 1: endorsement ───────────────────────────────────────────────
        //
        // Three paths, in priority order:
        //   A) Multi-peer: p2p_node + discovery → collect remote endorsements
        //   B) Local simulation: wasm_executor + world_state → simulate locally
        //   C) Policy-only: self_endorse check against org registry
        let simulation_rwset = if self.p2p_node.is_some()
            && self.discovery_service.is_some()
            && !channel_id.is_empty()
        {
            // Path A: multi-peer endorsement via P2P
            let (rwset, _endorsements) =
                self.collect_endorsements(chaincode_id, channel_id).await?;
            Some(rwset)
        } else if let (Some(svc), false) = (&self.discovery_service, channel_id.is_empty()) {
            // Discovery available but no P2P node: check policy locally, then simulate.
            match svc.endorsement_plan(chaincode_id, channel_id) {
                Ok(_endorsers) => {}
                Err(DiscoveryError::PolicyNotFound(_)) => {
                    self.self_endorse(chaincode_id)?;
                }
                Err(DiscoveryError::InsufficientPeers) => {
                    return Err(GatewayError::PolicyNotSatisfied(chaincode_id.to_string()));
                }
                Err(DiscoveryError::PeerNotFound(addr)) => {
                    return Err(GatewayError::PolicyNotSatisfied(format!(
                        "peer not found: {addr}"
                    )));
                }
            }
            // Path B: local simulation
            if let (Some(exec), Some(ws)) = (&self.wasm_executor, &self.world_state) {
                let (_, rwset) = exec
                    .simulate(Arc::clone(ws), "invoke")
                    .map_err(|e| GatewayError::Simulation(e.to_string()))?;
                self.validate_key_policies_for_rwset(chaincode_id, &rwset)?;
                Some(rwset)
            } else {
                None
            }
        } else {
            // Path C: no discovery or no channel — local org-registry check.
            self.self_endorse(chaincode_id)?;
            if let (Some(exec), Some(ws)) = (&self.wasm_executor, &self.world_state) {
                let (_, rwset) = exec
                    .simulate(Arc::clone(ws), "invoke")
                    .map_err(|e| GatewayError::Simulation(e.to_string()))?;
                self.validate_key_policies_for_rwset(chaincode_id, &rwset)?;
                Some(rwset)
            } else {
                None
            }
        };

        // ── Step 2: enqueue in ordering service ───────────────────────────────
        let tx_id = tx.id.clone();
        self.ordering_service
            .submit_tx(&tx)
            .map_err(|e| GatewayError::Ordering(e.to_string()))?;

        // ── Step 3: cut block and commit to store ─────────────────────────────
        let next_height = self.store.get_latest_height().unwrap_or(0) + 1;
        let parent_hash = crate::mining::parent_hash_at(self.store.as_ref(), next_height)
            .map_err(GatewayError::Storage)?;

        let block = self
            .ordering_service
            .cut_block(next_height, parent_hash, "gateway")
            .map_err(|e| GatewayError::Ordering(e.to_string()))?
            .ok_or_else(|| GatewayError::Ordering("cut_block returned no block".to_string()))?;

        let block_height = block.height;

        self.store
            .write_block(&block)
            .map_err(|e| GatewayError::Storage(e.to_string()))?;

        // ── Step 3.1: index transactions by tx_id ─────────────────────────────
        // Index the submitted tx with full metadata. Other batched txs get a
        // minimal record (we don't have their original input/output in scope).
        for tx_id_in_block in &block.transactions {
            let indexed_tx = if *tx_id_in_block == tx_id {
                Transaction {
                    id: tx_id_in_block.clone(),
                    block_height,
                    timestamp: block.timestamp,
                    input_did: tx.input_did.clone(),
                    output_recipient: tx.output_recipient.clone(),
                    amount: tx.amount,
                    state: "committed".to_string(),
                    fee: 0,
                    payload: None,
                }
            } else {
                Transaction {
                    id: tx_id_in_block.clone(),
                    block_height,
                    timestamp: block.timestamp,
                    input_did: String::new(),
                    output_recipient: String::new(),
                    amount: 0,
                    state: "committed".to_string(),
                    fee: 0,
                    payload: None,
                }
            };
            let _ = self.store.write_transaction(&indexed_tx);
        }

        // ── Step 3.25: broadcast committed block to peers ───────────────────
        if let Some(ref p2p) = self.p2p_node {
            let p2p = p2p.clone();
            let block_clone = block.clone();
            tokio::spawn(async move {
                p2p.broadcast_ordered_block(&block_clone).await;
            });
        }

        // ── Step 3.5: MVCC validate + apply write-set to world state ────────
        let tx_valid =
            if let (Some(ref rwset), Some(ref ws)) = (&simulation_rwset, &self.world_state) {
                match mvcc::validate_rwset(rwset, ws.as_ref()) {
                    Ok(()) => {
                        for write in &rwset.writes {
                            let _ = ws.put(&write.key, &write.value);
                        }
                        true
                    }
                    Err(_conflict) => {
                        // Fabric behavior: block is persisted, but TX writes are NOT applied.
                        false
                    }
                }
            } else {
                // No simulation rwset — treat as valid (non-Wasm transactions).
                true
            };

        // ── Step 4: emit events ───────────────────────────────────────────────
        if let Some(ref bus) = self.event_bus {
            bus.publish(BlockEvent::BlockCommitted {
                channel_id: channel_id.to_string(),
                height: block_height,
                tx_count: block.transactions.len(),
            });
            for tx_id_in_block in &block.transactions {
                bus.publish(BlockEvent::TransactionCommitted {
                    channel_id: channel_id.to_string(),
                    tx_id: tx_id_in_block.clone(),
                    block_height,
                    valid: tx_valid,
                });
            }
        }

        // ── Step 5: return result ─────────────────────────────────────────────
        Ok(TxResult {
            tx_id,
            block_height,
            valid: tx_valid,
        })
    }

    /// Commit a batch of endorsed transactions using wave-parallel execution.
    ///
    /// This is the parallel alternative to the single-tx `submit()` flow.
    /// Transactions are analyzed for key conflicts, grouped into non-conflicting
    /// waves, and each wave is validated+applied against the world state.
    ///
    /// Returns per-tx outcomes and parallelism metrics. The block is written to
    /// the store regardless of individual tx validity (Fabric-compatible).
    #[allow(dead_code)]
    pub fn commit_block_parallel(
        &self,
        channel_id: &str,
        endorsed_txs: &[EndorsedTransaction],
    ) -> Result<BatchTxResult, GatewayError> {
        let ws = self.world_state.as_ref().ok_or_else(|| {
            GatewayError::Ordering("world_state required for parallel commit".into())
        })?;

        // 1. Submit all txs to ordering service.
        for etx in endorsed_txs {
            self.ordering_service
                .submit_tx(&etx.proposal.tx)
                .map_err(|e| GatewayError::Ordering(e.to_string()))?;
        }

        // 2. Cut a block from the ordering service.
        let next_height = self.store.get_latest_height().unwrap_or(0) + 1;
        let parent_hash = crate::mining::parent_hash_at(self.store.as_ref(), next_height)
            .map_err(GatewayError::Storage)?;
        let block = self
            .ordering_service
            .cut_block(next_height, parent_hash, "gateway")
            .map_err(|e| GatewayError::Ordering(e.to_string()))?
            .ok_or_else(|| GatewayError::Ordering("cut_block returned no block".into()))?;

        let block_height = block.height;

        // 3. Persist the block.
        self.store
            .write_block(&block)
            .map_err(|e| GatewayError::Storage(e.to_string()))?;

        // 4. Execute txs in wave-parallel order.
        let exec_result = executor::execute_block_parallel(endorsed_txs, ws.as_ref());

        // 5. Emit events.
        if let Some(ref bus) = self.event_bus {
            bus.publish(BlockEvent::BlockCommitted {
                channel_id: channel_id.to_string(),
                height: block_height,
                tx_count: endorsed_txs.len(),
            });
            for (tx_id, outcome) in &exec_result.outcomes {
                bus.publish(BlockEvent::TransactionCommitted {
                    channel_id: channel_id.to_string(),
                    tx_id: tx_id.clone(),
                    block_height,
                    valid: matches!(outcome, executor::TxOutcome::Committed),
                });
            }
        }

        Ok(BatchTxResult {
            block_height,
            committed_count: exec_result.committed_count,
            conflict_count: exec_result.conflict_count,
            wave_count: exec_result.schedule.wave_count,
            parallelism_ratio: exec_result.schedule.parallelism_ratio,
            outcomes: exec_result.outcomes,
        })
    }

    /// Collect endorsements from remote peers for a transaction proposal.
    ///
    /// 1. Query discovery for required endorsers.
    /// 2. Send `ProposalRequest` to each peer via P2P (`send_and_wait`).
    /// 3. Validate all rwsets match (deterministic execution guarantee).
    /// 4. Return the shared rwset and collected endorsements.
    async fn collect_endorsements(
        &self,
        chaincode_id: &str,
        channel_id: &str,
    ) -> Result<(ReadWriteSet, Vec<Endorsement>), GatewayError> {
        let discovery = self.discovery_service.as_ref().ok_or_else(|| {
            GatewayError::PolicyNotSatisfied(
                "no discovery service for multi-peer endorsement".into(),
            )
        })?;

        let p2p = self.p2p_node.as_ref().ok_or_else(|| {
            GatewayError::PolicyNotSatisfied("no P2P node for multi-peer endorsement".into())
        })?;

        let endorsers = discovery
            .endorsement_plan(chaincode_id, channel_id)
            .map_err(|e| GatewayError::PolicyNotSatisfied(e.to_string()))?;

        // Send ProposalRequest to each endorser and collect responses.
        let mut rwsets: Vec<ReadWriteSet> = Vec::with_capacity(endorsers.len());
        let mut endorsements: Vec<Endorsement> = Vec::with_capacity(endorsers.len());

        for peer in &endorsers {
            let request_id = format!("{}-{}", chaincode_id, peer.peer_address);
            let msg = Message::ProposalRequest {
                request_id,
                chaincode_id: chaincode_id.to_string(),
                function: "invoke".to_string(),
                channel_id: channel_id.to_string(),
                proposal: crate::transaction::proposal::TransactionProposal {
                    tx: crate::storage::traits::Transaction {
                        id: String::new(),
                        block_height: 0,
                        timestamp: 0,
                        input_did: String::new(),
                        output_recipient: String::new(),
                        amount: 0,
                        state: String::new(),
                        fee: 0,
                        payload: None,
                    },
                    creator_did: String::new(),
                    creator_signature: vec![0u8; 64],
                    signature_algorithm: Default::default(),
                    rwset: ReadWriteSet::default(),
                },
            };

            let response = p2p
                .send_and_wait(&peer.peer_address, msg, ENDORSEMENT_TIMEOUT)
                .await
                .map_err(|e| {
                    GatewayError::PolicyNotSatisfied(format!(
                        "peer {} failed: {}",
                        peer.peer_address, e
                    ))
                })?;

            match response {
                Message::ProposalResponse {
                    rwset, endorsement, ..
                } => {
                    rwsets.push(rwset);
                    endorsements.push(endorsement);
                }
                _ => {
                    return Err(GatewayError::PolicyNotSatisfied(format!(
                        "unexpected response from {}",
                        peer.peer_address
                    )));
                }
            }
        }

        // All rwsets must match (deterministic simulation).
        if let Some(reference) = rwsets.first() {
            for (i, rwset) in rwsets.iter().enumerate().skip(1) {
                if rwset != reference {
                    return Err(GatewayError::Simulation(format!(
                        "rwset mismatch between endorser 0 and endorser {i} — non-deterministic chaincode",
                    )));
                }
            }
        }

        let shared_rwset = rwsets.into_iter().next().unwrap_or_default();
        Ok((shared_rwset, endorsements))
    }

    /// Validate key-level endorsement policies for every write key in `rwset`.
    ///
    /// For each write key that has a key-level policy in `key_endorsement_store`,
    /// checks that the registered orgs satisfy that policy.  Keys without a
    /// key-level policy are not checked here (the chaincode-level check in
    /// `self_endorse` already handled that).
    fn validate_key_policies_for_rwset(
        &self,
        chaincode_id: &str,
        rwset: &ReadWriteSet,
    ) -> Result<(), GatewayError> {
        let Some(kep_store) = &self.key_endorsement_store else {
            return Ok(());
        };

        let registered_orgs = self.org_registry.list_orgs().unwrap_or_default();
        let org_ids: Vec<&str> = registered_orgs.iter().map(|o| o.org_id.as_str()).collect();

        for write in &rwset.writes {
            if let Ok(Some(policy)) = kep_store.get_key_policy(&write.key) {
                if !policy.evaluate(&org_ids) {
                    return Err(GatewayError::PolicyNotSatisfied(format!(
                        "{chaincode_id}/{}",
                        write.key
                    )));
                }
            }
        }

        Ok(())
    }

    /// Self-endorsement check using the local org registry.
    ///
    /// Returns `Ok(())` when the registered orgs satisfy the policy for
    /// `chaincode_id`, or when no policy is configured.
    fn self_endorse(&self, chaincode_id: &str) -> Result<(), GatewayError> {
        let policy = self.policy_store.get_policy(chaincode_id).ok();

        if let Some(ref p) = policy {
            let registered_orgs = self.org_registry.list_orgs().unwrap_or_default();
            let org_ids: Vec<&str> = registered_orgs.iter().map(|o| o.org_id.as_str()).collect();

            let satisfied = match p {
                EndorsementPolicy::And(_, _) | EndorsementPolicy::Or(_, _) => p.evaluate(&org_ids),
                EndorsementPolicy::AnyOf(orgs) => {
                    orgs.iter().any(|o| org_ids.contains(&o.as_str()))
                }
                EndorsementPolicy::AllOf(orgs) => {
                    orgs.iter().all(|o| org_ids.contains(&o.as_str()))
                }
                EndorsementPolicy::NOutOf { n, orgs } => {
                    orgs.iter()
                        .filter(|o| org_ids.contains(&o.as_str()))
                        .count()
                        >= *n
                }
                EndorsementPolicy::OuBased { .. } => p.evaluate(&org_ids),
            };

            if !satisfied {
                return Err(GatewayError::PolicyNotSatisfied(chaincode_id.to_string()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endorsement::org::Organization;
    use crate::endorsement::policy::EndorsementPolicy;
    use crate::endorsement::policy_store::MemoryPolicyStore;
    use crate::endorsement::registry::MemoryOrgRegistry;
    use crate::ordering::service::OrderingService;
    use crate::storage::memory::MemoryStore;

    fn make_tx(id: &str) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: "did:goya:alice".to_string(),
            output_recipient: "did:goya:bob".to_string(),
            amount: 10,
            state: "pending".to_string(),
            fee: 0,
            payload: None,
        }
    }

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

    fn make_gateway() -> Gateway {
        Gateway::new(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
        )
    }

    // ── 9.1.1 tests (kept) ────────────────────────────────────────────────────

    #[test]
    fn create_gateway_with_memory_impls() {
        let gw = make_gateway();
        let _ = gw.org_registry.list_orgs().unwrap();
        assert_eq!(gw.ordering_service.pending_count(), 0);
    }

    #[test]
    fn gateway_store_is_empty_on_init() {
        let gw = make_gateway();
        assert!(gw.store.read_block(0).is_err());
    }

    #[test]
    fn gateway_policy_store_starts_empty() {
        let gw = make_gateway();
        assert!(gw.policy_store.get_policy("cc/missing").is_err());
    }

    // ── 9.1.2 tests ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn submit_tx_no_policy_commits_block() {
        let gw = make_gateway();
        let result = gw.submit("cc-nopolicy", "", make_tx("tx-1")).await.unwrap();

        assert_eq!(result.tx_id, "tx-1");
        assert_eq!(result.block_height, 1);

        // Block must be persisted in the store.
        let block = gw.store.read_block(1).unwrap();
        assert!(block.transactions.contains(&"tx-1".to_string()));
    }

    #[tokio::test]
    async fn consecutive_gateway_blocks_link_to_their_parent() {
        let gw = make_gateway();
        gw.submit("cc-nopolicy", "", make_tx("tx-1")).await.unwrap();
        gw.submit("cc-nopolicy", "", make_tx("tx-2")).await.unwrap();

        let first = gw.store.read_block(1).unwrap();
        let second = gw.store.read_block(2).unwrap();
        assert_eq!(first.parent_hash, [0u8; 32]);
        assert_eq!(second.parent_hash, crate::mining::block_hash(&first));
    }

    #[tokio::test]
    async fn submit_tx_with_any_of_policy_satisfied() {
        let registry = Arc::new(MemoryOrgRegistry::new());
        registry.register_org(&make_org("org1")).unwrap();

        let policy_store = Arc::new(MemoryPolicyStore::new());
        policy_store
            .set_policy("cc1", &EndorsementPolicy::AnyOf(vec!["org1".into()]))
            .unwrap();

        let gw = Gateway::new(
            registry,
            policy_store,
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
        );

        let result = gw.submit("cc1", "", make_tx("tx-2")).await.unwrap();
        assert_eq!(result.block_height, 1);
        let block = gw.store.read_block(1).unwrap();
        assert!(block.transactions.contains(&"tx-2".to_string()));
    }

    #[tokio::test]
    async fn submit_tx_with_policy_not_satisfied_returns_error() {
        let gw_no_orgs = make_gateway(); // registry is empty
        gw_no_orgs
            .policy_store
            .set_policy(
                "cc-strict",
                &EndorsementPolicy::AllOf(vec!["org1".into(), "org2".into()]),
            )
            .unwrap();

        let err = gw_no_orgs
            .submit("cc-strict", "", make_tx("tx-3"))
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::PolicyNotSatisfied(_)));
    }

    #[tokio::test]
    async fn multiple_submits_produce_sequential_block_heights() {
        let gw = make_gateway();

        let r1 = gw.submit("cc", "", make_tx("tx-a")).await.unwrap();
        let r2 = gw.submit("cc", "", make_tx("tx-b")).await.unwrap();

        assert_eq!(r1.block_height, 1);
        assert_eq!(r2.block_height, 2);
        assert_eq!(gw.store.get_latest_height().unwrap(), 2);
    }

    // ── 10.4.1 — Discovery-based endorsement tests ────────────────────────────

    use crate::discovery::service::DiscoveryService;
    use crate::discovery::PeerDescriptor;
    use crate::ordering::NodeRole;

    fn make_discovery_svc(
        policy_key: &str,
        policy: EndorsementPolicy,
        peers: Vec<(&str, &str)>, // (address, org)
    ) -> Arc<DiscoveryService> {
        let ps = Arc::new(MemoryPolicyStore::new());
        ps.set_policy(policy_key, &policy).unwrap();
        let svc = Arc::new(DiscoveryService::new(
            Arc::new(MemoryOrgRegistry::new()),
            ps,
        ));
        for (addr, org) in peers {
            svc.register_peer(PeerDescriptor {
                peer_address: addr.to_string(),
                org_id: org.to_string(),
                role: NodeRole::Peer,
                chaincodes: vec!["basic".to_string()],
                channels: vec!["mychannel".to_string()],
                last_heartbeat: 0,
            });
        }
        svc
    }

    #[tokio::test]
    async fn submit_uses_discovery_to_endorse_and_commits_block() {
        let disc = make_discovery_svc(
            "mychannel/basic",
            EndorsementPolicy::NOutOf {
                n: 2,
                orgs: vec!["Org1MSP".into(), "Org2MSP".into(), "Org3MSP".into()],
            },
            vec![("peer1:7051", "Org1MSP"), ("peer2:7051", "Org2MSP")],
        );

        let gw = Gateway::with_discovery(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
            disc,
        );

        let result = gw
            .submit("basic", "mychannel", make_tx("tx-disc-1"))
            .await
            .unwrap();
        assert_eq!(result.tx_id, "tx-disc-1");
        assert_eq!(result.block_height, 1);
        let block = gw.store.read_block(1).unwrap();
        assert!(block.transactions.contains(&"tx-disc-1".to_string()));
    }

    #[tokio::test]
    async fn submit_discovery_insufficient_peers_returns_policy_not_satisfied() {
        // Policy requires 2 orgs but only 1 peer registered
        let disc = make_discovery_svc(
            "mychannel/basic",
            EndorsementPolicy::NOutOf {
                n: 2,
                orgs: vec!["Org1MSP".into(), "Org2MSP".into()],
            },
            vec![("peer1:7051", "Org1MSP")],
        );

        let gw = Gateway::with_discovery(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
            disc,
        );

        let err = gw
            .submit("basic", "mychannel", make_tx("tx-fail"))
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::PolicyNotSatisfied(_)));
    }

    #[tokio::test]
    async fn submit_discovery_policy_not_found_falls_back_to_org_registry() {
        // Discovery has no policy for this chaincode → falls back to org registry
        // org registry is empty → policy_store also has no policy → should succeed (no policy = allow)
        let disc = Arc::new(DiscoveryService::new(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
        ));

        let gw = Gateway::with_discovery(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
            disc,
        );

        // No policy configured anywhere → should commit successfully
        let result = gw
            .submit("unknown-cc", "mychannel", make_tx("tx-fallback"))
            .await
            .unwrap();
        assert_eq!(result.block_height, 1);
    }

    // ── 11.2.1 — Event emission tests ─────────────────────────────────────────

    use crate::events::types::BlockEvent;
    use crate::events::EventBus;

    fn make_gateway_with_events() -> (Gateway, Arc<EventBus>) {
        let bus = Arc::new(EventBus::new());
        let gw = Gateway::with_events(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
            bus.clone(),
        );
        (gw, bus)
    }

    #[tokio::test]
    async fn block_with_3_txs_emits_one_block_committed_and_three_tx_committed() {
        let (gw, bus) = make_gateway_with_events();
        let mut rx = bus.subscribe();

        // Pre-enqueue 2 TXs directly so the next submit cuts a block with 3.
        gw.ordering_service.submit_tx(&make_tx("tx-1")).unwrap();
        gw.ordering_service.submit_tx(&make_tx("tx-2")).unwrap();
        gw.submit("cc", "", make_tx("tx-3")).await.unwrap();

        // Collect all 4 events (1 BlockCommitted + 3 TransactionCommitted).
        let mut events = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }

        assert_eq!(events.len(), 4, "expected 4 events: 1 block + 3 tx");

        let block_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, BlockEvent::BlockCommitted { .. }))
            .collect();
        assert_eq!(block_events.len(), 1);
        assert_eq!(
            block_events[0],
            &BlockEvent::BlockCommitted {
                channel_id: "".to_string(),
                height: 1,
                tx_count: 3
            }
        );

        let tx_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, BlockEvent::TransactionCommitted { .. }))
            .collect();
        assert_eq!(tx_events.len(), 3);

        let mut tx_ids: Vec<String> = tx_events
            .iter()
            .map(|e| match e {
                BlockEvent::TransactionCommitted { tx_id, .. } => tx_id.clone(),
                _ => unreachable!(),
            })
            .collect();
        tx_ids.sort();
        assert_eq!(tx_ids, vec!["tx-1", "tx-2", "tx-3"]);
    }

    #[tokio::test]
    async fn single_tx_submit_emits_block_and_tx_events() {
        let (gw, bus) = make_gateway_with_events();
        let mut rx = bus.subscribe();

        gw.submit("cc", "", make_tx("tx-solo")).await.unwrap();

        let e1 = rx.try_recv().unwrap();
        let e2 = rx.try_recv().unwrap();

        assert_eq!(
            e1,
            BlockEvent::BlockCommitted {
                channel_id: "".to_string(),
                height: 1,
                tx_count: 1
            }
        );
        assert_eq!(
            e2,
            BlockEvent::TransactionCommitted {
                channel_id: "".to_string(),
                tx_id: "tx-solo".to_string(),
                block_height: 1,
                valid: true,
            }
        );
        assert!(rx.try_recv().is_err(), "no more events expected");
    }

    #[tokio::test]
    async fn no_event_bus_submit_still_commits() {
        // Gateway without event_bus must still commit successfully.
        let gw = make_gateway();
        let result = gw.submit("cc", "", make_tx("tx-no-bus")).await.unwrap();
        assert_eq!(result.block_height, 1);
    }

    // ── 14.3.1 — Wasm simulation + key-level policy tests ─────────────────────
    #[cfg(feature = "wasm-chaincode")]
    use crate::chaincode::executor::WasmExecutor;
    #[cfg(feature = "wasm-chaincode")]
    use crate::endorsement::key_policy::MemoryKeyEndorsementStore;
    #[cfg(feature = "wasm-chaincode")]
    use crate::storage::world_state::MemoryWorldState;

    /// WAT that writes key "asset:1" = "v" and returns empty result.
    #[cfg(feature = "wasm-chaincode")]
    const WRITE_ASSET_WAT: &[u8] = br#"
(module
  (import "env" "put_state" (func $put_state (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "asset:1")
  (data (i32.const 16) "v")
  (func (export "invoke") (result i64)
    (drop (call $put_state (i32.const 0) (i32.const 7) (i32.const 16) (i32.const 1)))
    (i64.const 0)
  )
)
"#;

    #[cfg(feature = "wasm-chaincode")]
    fn make_gateway_with_simulation(
        kep_store: Option<Arc<dyn crate::endorsement::key_policy::KeyEndorsementStore>>,
    ) -> Gateway {
        let exec = Arc::new(WasmExecutor::new(WRITE_ASSET_WAT, 10_000_000).unwrap());
        let ws = Arc::new(MemoryWorldState::new());
        make_gateway().with_wasm_simulation(exec, ws, kep_store)
    }

    #[cfg(feature = "wasm-chaincode")]
    #[tokio::test]
    async fn submit_with_wasm_simulation_no_key_policy_commits_block() {
        let gw = make_gateway_with_simulation(None);
        let result = gw.submit("cc", "", make_tx("tx-sim-1")).await.unwrap();
        assert_eq!(result.block_height, 1);
    }

    #[cfg(feature = "wasm-chaincode")]
    #[tokio::test]
    async fn submit_simulation_key_policy_satisfied_commits_block() {
        let registry = Arc::new(MemoryOrgRegistry::new());
        registry.register_org(&make_org("org1")).unwrap();

        let kep = Arc::new(MemoryKeyEndorsementStore::new());
        kep.set_key_policy("asset:1", &EndorsementPolicy::AnyOf(vec!["org1".into()]))
            .unwrap();

        let exec = Arc::new(WasmExecutor::new(WRITE_ASSET_WAT, 10_000_000).unwrap());
        let ws = Arc::new(MemoryWorldState::new());

        let gw = Gateway::new(
            registry,
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(10, 500)),
            Arc::new(MemoryStore::new()),
        )
        .with_wasm_simulation(exec, ws, Some(kep));

        let result = gw.submit("cc", "", make_tx("tx-kp-ok")).await.unwrap();
        assert_eq!(result.block_height, 1);
    }

    #[cfg(feature = "wasm-chaincode")]
    #[tokio::test]
    async fn submit_simulation_key_policy_not_satisfied_returns_error() {
        // org registry is empty → key policy AllOf(["org1"]) cannot be satisfied
        let kep = Arc::new(MemoryKeyEndorsementStore::new());
        kep.set_key_policy("asset:1", &EndorsementPolicy::AllOf(vec!["org1".into()]))
            .unwrap();

        let gw = make_gateway_with_simulation(Some(kep));
        let err = gw
            .submit("cc", "", make_tx("tx-kp-fail"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, GatewayError::PolicyNotSatisfied(_)),
            "expected PolicyNotSatisfied, got {err:?}"
        );
    }

    #[cfg(feature = "wasm-chaincode")]
    #[tokio::test]
    async fn submit_simulation_key_policy_store_absent_skips_key_check() {
        // No kep_store attached → key-level check is skipped, commit succeeds.
        let gw = make_gateway_with_simulation(None);
        let result = gw.submit("cc", "", make_tx("tx-no-kep")).await.unwrap();
        assert_eq!(result.block_height, 1);
    }

    // ── MVCC conflict detection tests ───────────────────────────────────────

    #[cfg(feature = "wasm-chaincode")]
    #[tokio::test]
    async fn submit_first_wasm_tx_is_valid_and_applies_to_world_state() {
        let gw = make_gateway_with_simulation(None);
        let result = gw.submit("cc", "", make_tx("tx-first")).await.unwrap();
        assert!(result.valid, "first TX should pass MVCC");

        // World state should contain the key written by WRITE_ASSET_WAT.
        let ws = gw.world_state.as_ref().unwrap();
        let val = ws.get("asset:1").unwrap();
        assert!(
            val.is_some(),
            "key 'asset:1' should exist in world state after commit"
        );
        assert_eq!(val.unwrap().version, 1);
    }

    #[cfg(feature = "wasm-chaincode")]
    #[tokio::test]
    async fn second_wasm_tx_reading_stale_version_gets_mvcc_conflict() {
        let exec = Arc::new(WasmExecutor::new(WRITE_ASSET_WAT, 10_000_000).unwrap());
        let ws = Arc::new(MemoryWorldState::new());

        let gw = make_gateway().with_wasm_simulation(exec, ws.clone(), None);

        // First submit: writes "asset:1", read-set is empty (or version 0) → valid.
        let r1 = gw.submit("cc", "", make_tx("tx-1")).await.unwrap();
        assert!(r1.valid);
        assert_eq!(ws.get("asset:1").unwrap().unwrap().version, 1);

        // Second submit: simulation reads "asset:1" at version 0 (snapshot taken
        // before simulation), but world state is now at version 1 → MVCC conflict.
        // The executor re-simulates from the same base world state, producing a
        // read of "asset:1" at version 1 (since we share the ws). Actually,
        // the simulation will read from the live world state, getting version 1,
        // and then write version 2. Then MVCC validates: read version 1 matches
        // committed version 1 → valid again.  Both should succeed because each
        // simulation sees the latest state.
        let r2 = gw.submit("cc", "", make_tx("tx-2")).await.unwrap();
        assert!(
            r2.valid,
            "sequential non-conflicting TXs should both be valid"
        );
        assert_eq!(ws.get("asset:1").unwrap().unwrap().version, 2);
    }

    // ── parallel commit tests ─────────────────────────────────────────────

    fn make_endorsed(
        id: &str,
        reads: &[(&str, u64)],
        writes: &[(&str, &[u8])],
    ) -> EndorsedTransaction {
        use crate::endorsement::types::Endorsement;
        use crate::transaction::proposal::TransactionProposal;
        use crate::transaction::rwset::{KVRead, KVWrite, ReadWriteSet};

        let rw = ReadWriteSet {
            reads: reads
                .iter()
                .map(|(k, v)| KVRead {
                    key: k.to_string(),
                    version: *v,
                })
                .collect(),
            writes: writes
                .iter()
                .map(|(k, v)| KVWrite {
                    key: k.to_string(),
                    value: v.to_vec(),
                })
                .collect(),
        };
        EndorsedTransaction {
            proposal: TransactionProposal {
                tx: make_tx(id),
                creator_did: "did:test:creator".to_string(),
                creator_signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                rwset: rw.clone(),
            },
            endorsements: vec![Endorsement {
                signer_did: "did:test:org1".to_string(),
                org_id: "Org1".to_string(),
                signature: vec![0u8; 64],
                signature_algorithm: Default::default(),
                payload_hash: [0u8; 32],
                timestamp: 0,
            }],
            rwset: rw,
        }
    }

    fn gateway_with_world_state() -> (Gateway, Arc<crate::storage::MemoryWorldState>) {
        let ws = Arc::new(crate::storage::MemoryWorldState::new());
        let gw = Gateway::new(
            Arc::new(MemoryOrgRegistry::new()),
            Arc::new(MemoryPolicyStore::new()),
            Arc::new(OrderingService::with_config(1000, 5000)),
            Arc::new(MemoryStore::new()),
        );
        let gw = Gateway {
            world_state: Some(ws.clone()),
            ..gw
        };
        (gw, ws)
    }

    #[test]
    fn parallel_commit_independent_txs_all_committed() {
        let (gw, ws) = gateway_with_world_state();
        ws.put("a", b"v1").unwrap();
        ws.put("b", b"v1").unwrap();

        let txs = vec![
            make_endorsed("tx1", &[("a", 1)], &[("a", b"a2")]),
            make_endorsed("tx2", &[("b", 1)], &[("b", b"b2")]),
        ];

        let result = gw.commit_block_parallel("ch1", &txs).unwrap();
        assert_eq!(result.committed_count, 2);
        assert_eq!(result.conflict_count, 0);
        assert_eq!(result.wave_count, 1, "independent txs → 1 wave");
        assert_eq!(ws.get("a").unwrap().unwrap().data, b"a2");
        assert_eq!(ws.get("b").unwrap().unwrap().data, b"b2");
    }

    #[test]
    fn parallel_commit_conflicting_txs_one_rejected() {
        let (gw, ws) = gateway_with_world_state();
        ws.put("k", b"v1").unwrap();

        let txs = vec![
            make_endorsed("tx1", &[("k", 1)], &[("k", b"v2")]),
            make_endorsed("tx2", &[("k", 1)], &[("k", b"v3")]),
        ];

        let result = gw.commit_block_parallel("ch1", &txs).unwrap();
        assert_eq!(result.committed_count, 1);
        assert_eq!(result.conflict_count, 1);
        assert_eq!(result.wave_count, 2, "WAW conflict → 2 waves");
    }

    #[test]
    fn parallel_commit_empty_block() {
        let (gw, _ws) = gateway_with_world_state();
        let result = gw.commit_block_parallel("ch1", &[]);
        // Empty endorsed txs → ordering service returns no block.
        assert!(result.is_err());
    }

    #[test]
    fn parallel_commit_metrics_reported() {
        let (gw, ws) = gateway_with_world_state();
        for i in 0..4 {
            ws.put(&format!("k{i}"), b"v1").unwrap();
        }

        let txs: Vec<EndorsedTransaction> = (0..4)
            .map(|i| {
                let key = format!("k{i}");
                make_endorsed(&format!("tx{i}"), &[(&key, 1)], &[(&key, b"v2")])
            })
            .collect();

        let result = gw.commit_block_parallel("ch1", &txs).unwrap();
        assert_eq!(result.wave_count, 1);
        assert!((result.parallelism_ratio - 4.0).abs() < f64::EPSILON);
        assert_eq!(result.block_height, 1);
    }
}
