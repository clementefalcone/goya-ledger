//! BFT controller — bridges the RoundManager state machine with the P2P
//! network and block storage. Mines blocks when this node is leader.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::consensus::bft::round::{RoundAction, RoundEvent};
use crate::consensus::bft::round_manager::{ManagerAction, RoundManager, RoundManagerConfig};
use crate::consensus::bft::safety::ChainAncestryChecker;
use crate::consensus::bft::types::{QuorumCertificate, VoteMessage};
use crate::consensus::bft::validator_registry::RegistryVerifier;
use crate::identity::signing::SigningProvider;
use crate::mining::MiningService;
use crate::network::Node;
use crate::storage::traits::{Block, Transaction};
use crate::storage::BlockStore;
use crate::transaction::mempool::TransactionPool;

/// Events fed into the BFT controller from the network layer.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum BftEvent {
    /// A BFT proposal arrived from a peer.
    Proposal {
        round: u64,
        block_hash: [u8; 32],
        leader_id: String,
        block: Block,
        /// QC justifying this proposal (leader's high_qc).
        justify_qc: Option<crate::consensus::bft::types::QuorumCertificate>,
    },
    /// A BFT vote arrived from a peer.
    Vote(VoteMessage),
    Transaction(Transaction),
}

/// Run the BFT consensus loop. Mines when leader, votes when follower.
#[allow(clippy::too_many_arguments)]
pub async fn run_bft_loop(
    node_id: String,
    validators: Vec<String>,
    mut rx: mpsc::UnboundedReceiver<BftEvent>,
    node: Arc<Node>,
    store: Arc<dyn crate::storage::BlockStore>,
    signer: Arc<dyn SigningProvider>,
    mining_service: Arc<MiningService>,
    tx_pool: Arc<std::sync::Mutex<TransactionPool>>,
    verifier: RegistryVerifier,
    wake: Arc<tokio::sync::Notify>,
) {
    let config = RoundManagerConfig::default();
    let mut book = ProposalBook::new(store.clone());
    let mut manager = RoundManager::with_ancestry(
        node_id.clone(),
        validators,
        verifier,
        config,
        Box::new(book.ancestry.clone()),
    );
    let mut pending_block: Option<Block> = None;
    // Buffer votes that arrive before the proposal for the current round.
    let mut early_votes: Vec<VoteMessage> = Vec::new();

    let action = manager.start();
    handle_action(&action, &node, &signer, &node_id, &mut manager).await;

    // If we're leader of round 0, try to mine immediately.
    if manager.is_current_leader() {
        try_mine_and_propose(
            &mut manager,
            &mut pending_block,
            &node_id,
            &node,
            &signer,
            &mining_service,
            &tx_pool,
            &mut book,
        )
        .await;
    }

    let timeout_ms = manager.current_timeout_ms();
    #[allow(unused_mut)]
    let mut timeout = tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    BftEvent::Proposal { round, block_hash, leader_id, block, justify_qc } => {
                        while manager.current_round() < round {
                            let _ = manager.on_timeout();
                        }
                        if round != manager.current_round() {
                            continue;
                        }
                        if leader_id != manager.current_leader() {
                            log::warn!("BFT: rejected proposal from {leader_id} in round {round}: leader is {}", manager.current_leader());
                            continue;
                        }
                        if crate::mining::block_hash(&block) != block_hash {
                            log::warn!("BFT: rejected proposal from {leader_id} in round {round}: block body does not hash to {}", hex::encode(block_hash));
                            continue;
                        }
                        book.record(&block);
                        reset_timeout(&mut timeout, &manager);
                        pending_block = Some(block);
                        let action = manager.process_event(RoundEvent::Proposal { block_hash, leader_id, justify_qc });
                        let mut decided = handle_action(&action, &node, &signer, &node_id, &mut manager).await;
                        // Replay votes that arrived before this proposal.
                        if !decided {
                            for buffered in early_votes.drain(..) {
                                let a = manager.process_event(RoundEvent::Vote(buffered));
                                if handle_action(&a, &node, &signer, &node_id, &mut manager).await {
                                    decided = true;
                                    break;
                                }
                            }
                        }
                        early_votes.clear();
                        if decided {
                            if let Some(blk) = pending_block.take() {
                                commit_block(blk, &manager, &store, &node, &tx_pool).await;
                            }
                            advance_round(&mut manager, &mut pending_block, &mut timeout, &node_id, &node, &signer, &mining_service, &tx_pool, &mut book).await;
                        } else {
                            reset_timeout(&mut timeout, &manager);
                        }
                    }
                    BftEvent::Vote(vote) => {
                        // Buffer votes that arrive before the proposal for this round.
                        if vote.round == manager.current_round() && pending_block.is_none() {
                            log::debug!("BFT: buffering early vote from {} phase={:?} round={}", vote.voter_id, vote.phase, vote.round);
                            early_votes.push(vote);
                            continue;
                        }
                        let action = manager.process_event(RoundEvent::Vote(vote));
                        if handle_action(&action, &node, &signer, &node_id, &mut manager).await {
                            if let Some(blk) = pending_block.take() {
                                commit_block(blk, &manager, &store, &node, &tx_pool).await;
                            }
                            advance_round(&mut manager, &mut pending_block, &mut timeout, &node_id, &node, &signer, &mining_service, &tx_pool, &mut book).await;
                        } else {
                            reset_timeout(&mut timeout, &manager);
                        }
                    }
                    BftEvent::Transaction(tx) => {
                        let id = tx.id.clone();
                        if let Err(reason) = tx_pool.lock().unwrap_or_else(|e| e.into_inner()).add(tx) {
                            log::debug!("BFT: gossiped transaction {id} not queued: {reason}");
                            continue;
                        }
                        if manager.is_current_leader() && pending_block.is_none() {
                            try_mine_and_propose(&mut manager, &mut pending_block, &node_id, &node, &signer, &mining_service, &tx_pool, &mut book).await;
                        }
                    }
                }
            }
            _ = wake.notified() => {
                if manager.is_current_leader() && pending_block.is_none() {
                    try_mine_and_propose(&mut manager, &mut pending_block, &node_id, &node, &signer, &mining_service, &tx_pool, &mut book).await;
                }
            }
            _ = &mut timeout => {
                early_votes.clear();
                let action = manager.on_timeout();
                handle_action(&action, &node, &signer, &node_id, &mut manager).await;
                pending_block = None;
                reset_timeout(&mut timeout, &manager);
                let am_leader = manager.is_current_leader();
                log::info!("BFT timeout: advanced to round {}, am_leader={am_leader}", manager.current_round());
                if am_leader {
                    try_mine_and_propose(&mut manager, &mut pending_block, &node_id, &node, &signer, &mining_service, &tx_pool, &mut book).await;
                }
            }
        }
    }
}

struct ProposalBook {
    ancestry: Arc<ChainAncestryChecker>,
    bodies: HashMap<[u8; 32], Block>,
    store: Arc<dyn BlockStore>,
}

impl ProposalBook {
    fn new(store: Arc<dyn BlockStore>) -> Self {
        Self {
            ancestry: Arc::new(ChainAncestryChecker::new(store.clone())),
            bodies: HashMap::new(),
            store,
        }
    }

    fn record(&mut self, block: &Block) {
        self.ancestry.index_proposal(block);
        self.bodies
            .insert(crate::mining::block_hash(block), block.clone());
    }

    fn reproposal(&self, high_qc: Option<&QuorumCertificate>) -> Option<Block> {
        reproposable_block(high_qc, &self.bodies, self.store.as_ref())
    }

    fn forget_decided(&mut self) {
        let Ok(tip) = self.store.get_latest_height() else {
            return;
        };
        self.bodies.retain(|_, block| block.height > tip);
    }
}

fn reproposable_block(
    high_qc: Option<&QuorumCertificate>,
    bodies: &HashMap<[u8; 32], Block>,
    store: &dyn BlockStore,
) -> Option<Block> {
    let block = bodies.get(&high_qc?.block_hash)?;
    let is_decided = store.block_exists(block.height).unwrap_or(true);
    let parent_is_tip =
        crate::mining::parent_hash_at(store, block.height).ok()? == block.parent_hash;
    (!is_decided && parent_is_tip).then(|| block.clone())
}

fn build_proposal(
    book: &ProposalBook,
    high_qc: Option<&QuorumCertificate>,
    mining_service: &MiningService,
    tx_pool: &std::sync::Mutex<TransactionPool>,
) -> Option<Block> {
    if let Some(block) = book.reproposal(high_qc) {
        log::info!("BFT leader re-proposes undecided block {}", block.height);
        return Some(block);
    }
    let txs = tx_pool
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drain_for_block(50);
    if txs.is_empty() {
        return None;
    }
    let tx_count = txs.len();
    match mining_service.build_block("auto-miner", txs) {
        Ok(block) => {
            log::info!(
                "BFT leader built block {} with {tx_count} tx(s)",
                block.height
            );
            Some(block)
        }
        Err(e) => {
            log::error!("BFT leader could not build a block with {tx_count} tx(s): {e}");
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_mine_and_propose(
    manager: &mut RoundManager<RegistryVerifier>,
    pending_block: &mut Option<Block>,
    node_id: &str,
    node: &Arc<Node>,
    signer: &Arc<dyn SigningProvider>,
    mining_service: &Arc<MiningService>,
    tx_pool: &Arc<std::sync::Mutex<TransactionPool>>,
    book: &mut ProposalBook,
) {
    let Some(block) = build_proposal(book, manager.safety().high_qc(), mining_service, tx_pool)
    else {
        return;
    };
    let height = block.height;
    let block_hash = crate::mining::block_hash(&block);
    book.record(&block);
    *pending_block = Some(block.clone());

    let block_data = serde_json::to_vec(&block).unwrap_or_default();
    let justify_qc_data = manager
        .safety()
        .high_qc()
        .and_then(|qc| serde_json::to_vec(qc).ok())
        .unwrap_or_default();
    let msg = crate::network::Message::BftProposal {
        round: manager.current_round(),
        block_hash,
        leader_id: node_id.to_string(),
        block_data,
        justify_qc: justify_qc_data,
    };
    node.broadcast_message(&msg).await;

    let action = manager.process_event(RoundEvent::StartAsLeader { block_hash });
    handle_action(&action, node, signer, node_id, manager).await;
    log::info!(
        "BFT: proposed block {} at round {}",
        height,
        manager.current_round()
    );
}

#[allow(clippy::too_many_arguments)]
async fn advance_round(
    manager: &mut RoundManager<RegistryVerifier>,
    pending_block: &mut Option<Block>,
    timeout: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    node_id: &str,
    node: &Arc<Node>,
    signer: &Arc<dyn SigningProvider>,
    mining_service: &Arc<MiningService>,
    tx_pool: &Arc<std::sync::Mutex<TransactionPool>>,
    book: &mut ProposalBook,
) {
    book.forget_decided();
    let adv = manager.advance_after_decide();
    handle_action(&adv, node, signer, node_id, manager).await;
    reset_timeout(timeout, manager);
    if manager.is_current_leader() {
        try_mine_and_propose(
            manager,
            pending_block,
            node_id,
            node,
            signer,
            mining_service,
            tx_pool,
            book,
        )
        .await;
    }
}

fn reset_timeout(
    timeout: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    manager: &RoundManager<RegistryVerifier>,
) {
    let ms = manager.current_timeout_ms();
    timeout
        .as_mut()
        .reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(ms));
}

async fn handle_action(
    action: &ManagerAction,
    node: &Arc<Node>,
    signer: &Arc<dyn SigningProvider>,
    node_id: &str,
    manager: &mut RoundManager<RegistryVerifier>,
) -> bool {
    match action {
        ManagerAction::Round(RoundAction::SendVote(vote)) => {
            let mut signed_vote = vote.clone();
            let payload = VoteMessage::signing_payload_v2(
                vote.phase,
                &vote.block_hash,
                vote.round,
                &vote.voter_id,
            );
            signed_vote.signature = signer.sign(&payload).unwrap_or_default();
            // Count our own vote locally so we contribute to quorum.
            let self_action = manager.process_event(RoundEvent::Vote(signed_vote.clone()));
            let msg = crate::network::Message::BftVote(signed_vote);
            node.broadcast_message(&msg).await;
            matches!(
                self_action,
                ManagerAction::Round(RoundAction::Decide { .. })
            )
        }
        ManagerAction::Round(RoundAction::BroadcastProposal { block_hash }) => {
            log::info!(
                "BFT: broadcasting proposal hash={}",
                hex::encode(block_hash)
            );
            // Leader also votes Prepare (counts toward quorum).
            let mut vote = VoteMessage {
                block_hash: *block_hash,
                round: manager.current_round(),
                phase: crate::consensus::bft::types::BftPhase::Prepare,
                voter_id: node_id.to_string(),
                signature: Vec::new(),
            };
            let payload =
                VoteMessage::signing_payload_v2(vote.phase, block_hash, vote.round, node_id);
            vote.signature = signer.sign(&payload).unwrap_or_default();
            let self_action = manager.process_event(RoundEvent::Vote(vote.clone()));
            let msg = crate::network::Message::BftVote(vote);
            node.broadcast_message(&msg).await;
            matches!(
                self_action,
                ManagerAction::Round(RoundAction::Decide { .. })
            )
        }
        ManagerAction::Round(RoundAction::PhaseComplete { phase, qc }) => {
            log::info!(
                "BFT: phase {:?} complete with {} votes",
                phase,
                qc.voter_count()
            );
            // After phase completes, send our vote for the next phase.
            let next_phase = match phase {
                crate::consensus::bft::types::BftPhase::Prepare => {
                    Some(crate::consensus::bft::types::BftPhase::PreCommit)
                }
                crate::consensus::bft::types::BftPhase::PreCommit => {
                    Some(crate::consensus::bft::types::BftPhase::Commit)
                }
                _ => None,
            };
            if let (Some(next), Some(bh)) = (next_phase, qc.votes.first().map(|v| v.block_hash)) {
                let mut vote = VoteMessage {
                    block_hash: bh,
                    round: qc.round,
                    phase: next,
                    voter_id: node_id.to_string(),
                    signature: Vec::new(),
                };
                let payload = VoteMessage::signing_payload_v2(next, &bh, qc.round, node_id);
                vote.signature = signer.sign(&payload).unwrap_or_default();
                let self_action = manager.process_event(RoundEvent::Vote(vote.clone()));
                let msg = crate::network::Message::BftVote(vote);
                node.broadcast_message(&msg).await;
                if matches!(
                    self_action,
                    ManagerAction::Round(RoundAction::Decide { .. })
                ) {
                    return true;
                }
            }
            false
        }
        ManagerAction::Round(RoundAction::Decide {
            block_hash, round, ..
        }) => {
            log::info!(
                "BFT: DECIDED block {} at round {round}",
                hex::encode(block_hash)
            );
            true
        }
        ManagerAction::NewRound {
            round, leader_id, ..
        } => {
            let is_me = leader_id == node_id;
            log::info!(
                "BFT: round {round}, leader={leader_id}{}",
                if is_me { " (me)" } else { "" }
            );
            false
        }
        ManagerAction::Round(RoundAction::None) | ManagerAction::None => false,
    }
}

fn forget_committed(tx_pool: &std::sync::Mutex<TransactionPool>, block: &Block) {
    let mut pool = tx_pool.lock().unwrap_or_else(|e| e.into_inner());
    for tx in &block.transaction_data {
        pool.remove(&tx.id);
    }
}

async fn commit_block(
    mut block: Block,
    manager: &RoundManager<RegistryVerifier>,
    store: &Arc<dyn crate::storage::BlockStore>,
    node: &Arc<Node>,
    tx_pool: &std::sync::Mutex<TransactionPool>,
) {
    block.commit_qc = manager.highest_commit_qc().cloned();
    match crate::mining::persist_block(store.as_ref(), &block) {
        Ok(()) => {
            forget_committed(tx_pool, &block);
            log::info!("BFT: committed block {} with QC", block.height);
            let node = node.clone();
            let blk = block.clone();
            tokio::spawn(async move {
                node.broadcast_ordered_block(&blk).await;
            });
        }
        Err(e) => log::error!("BFT: failed to write block {}: {e}", block.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::types::{BftPhase, QuorumCertificate};
    use crate::mining::{block_hash, MiningConfig};
    use crate::storage::{BlockStore, MemoryStore};
    use std::collections::HashMap;

    struct Fixture {
        store: Arc<MemoryStore>,
        mining: MiningService,
        proposals: HashMap<[u8; 32], Block>,
    }

    impl Fixture {
        fn with_genesis() -> Self {
            let store = Arc::new(MemoryStore::new());
            let mining = MiningService::new(store.clone(), MiningConfig::default());
            mining.mine_block("genesis", vec![]).unwrap();
            Self {
                store,
                mining,
                proposals: HashMap::new(),
            }
        }

        fn propose(&mut self) -> Block {
            let block = self.mining.build_block("leader", vec![]).unwrap();
            self.proposals.insert(block_hash(&block), block.clone());
            block
        }

        fn reproposal_for(&self, block: &Block) -> Option<Block> {
            let qc = QuorumCertificate {
                block_hash: block_hash(block),
                round: 3,
                phase: BftPhase::Prepare,
                votes: vec![],
            };
            reproposable_block(Some(&qc), &self.proposals, self.store.as_ref())
        }
    }

    #[test]
    fn committed_transactions_leave_the_mempool() {
        let fixture = Fixture::with_genesis();
        let pending = |id: &str| Transaction {
            id: id.to_string(),
            block_height: 0,
            timestamp: 0,
            input_did: "did:goya:a".into(),
            output_recipient: "did:goya:a".into(),
            amount: 0,
            state: "pending".into(),
            fee: 0,
            payload: None,
        };
        let pool = std::sync::Mutex::new(TransactionPool::new());
        pool.lock().unwrap().add(pending("kept")).unwrap();
        pool.lock().unwrap().add(pending("included")).unwrap();
        let block = fixture
            .mining
            .build_block("leader", vec![pending("included")])
            .unwrap();

        forget_committed(&pool, &block);

        let ids: Vec<_> = pool
            .lock()
            .unwrap()
            .all()
            .iter()
            .map(|tx| tx.id.clone())
            .collect();
        assert_eq!(ids, vec!["kept".to_string()]);
    }

    #[test]
    fn reproposes_undecided_high_qc_block_on_tip() {
        let mut fixture = Fixture::with_genesis();
        let pending = fixture.propose();

        let block = fixture.reproposal_for(&pending).unwrap();

        assert_eq!(block_hash(&block), block_hash(&pending));
    }

    #[test]
    fn builds_fresh_once_high_qc_block_is_decided() {
        let mut fixture = Fixture::with_genesis();
        let decided = fixture.propose();
        fixture.store.write_block(&decided).unwrap();

        assert!(fixture.reproposal_for(&decided).is_none());
    }

    #[test]
    fn builds_fresh_when_high_qc_block_is_off_the_tip() {
        let mut fixture = Fixture::with_genesis();
        let stale = fixture.propose();
        fixture.mining.mine_block("other", vec![]).unwrap();

        assert!(fixture.reproposal_for(&stale).is_none());
    }

    #[test]
    fn builds_fresh_without_high_qc_or_body() {
        let fixture = Fixture::with_genesis();
        let unknown = fixture.mining.build_block("leader", vec![]).unwrap();

        assert!(reproposable_block(None, &fixture.proposals, fixture.store.as_ref()).is_none());
        assert!(fixture.reproposal_for(&unknown).is_none());
    }
}
