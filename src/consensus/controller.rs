//! BFT controller — bridges the RoundManager state machine with the P2P
//! network and block storage. Mines blocks when this node is leader.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::consensus::bft::round::{RoundAction, RoundEvent};
use crate::consensus::bft::round_manager::{ManagerAction, RoundManager, RoundManagerConfig};
use crate::consensus::bft::types::VoteMessage;
use crate::consensus::bft::validator_registry::RegistryVerifier;
use crate::identity::signing::SigningProvider;
use crate::mining::MiningService;
use crate::network::Node;
use crate::storage::traits::Block;
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
) {
    let config = RoundManagerConfig::default();
    let ancestry = Box::new(crate::consensus::bft::safety::ChainAncestryChecker::new(
        store.clone(),
    ));
    let mut manager =
        RoundManager::with_ancestry(node_id.clone(), validators, verifier, config, ancestry);
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
            &store,
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
                                commit_block(blk, &manager, &store, &node).await;
                            }
                            advance_round(&mut manager, &mut pending_block, &mut timeout, &node_id, &node, &signer, &mining_service, &tx_pool, &store).await;
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
                                commit_block(blk, &manager, &store, &node).await;
                            }
                            advance_round(&mut manager, &mut pending_block, &mut timeout, &node_id, &node, &signer, &mining_service, &tx_pool, &store).await;
                        } else {
                            reset_timeout(&mut timeout, &manager);
                        }
                    }
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
                    try_mine_and_propose(&mut manager, &mut pending_block, &node_id, &node, &signer, &mining_service, &tx_pool, &store).await;
                }
            }
        }
    }
}

/// If mempool has transactions, mine a block and broadcast the BFT proposal.
#[allow(clippy::too_many_arguments)]
async fn try_mine_and_propose(
    manager: &mut RoundManager<RegistryVerifier>,
    pending_block: &mut Option<Block>,
    node_id: &str,
    node: &Arc<Node>,
    signer: &Arc<dyn SigningProvider>,
    mining_service: &Arc<MiningService>,
    tx_pool: &Arc<std::sync::Mutex<TransactionPool>>,
    store: &Arc<dyn crate::storage::BlockStore>,
) {
    let txs = {
        let mut pool = tx_pool.lock().unwrap_or_else(|e| e.into_inner());
        let drained = pool.drain_for_block(50);
        log::info!("BFT try_mine: drained {} tx(s) from mempool", drained.len());
        drained
    };
    if txs.is_empty() {
        return;
    }

    let tx_count = txs.len();

    match mining_service.mine_block("auto-miner", txs) {
        Ok(height) => {
            log::info!("⛏ BFT leader mined block {height} with {tx_count} tx(s)");
            if let Ok(block) = store.read_block(height) {
                let block_hash = crate::mining::block_hash(&block);
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
        }
        Err(e) => log::error!("BFT leader mine failed: {e}"),
    }
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
    store: &Arc<dyn crate::storage::BlockStore>,
) {
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
            store,
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

async fn commit_block(
    mut block: Block,
    manager: &RoundManager<RegistryVerifier>,
    store: &Arc<dyn crate::storage::BlockStore>,
    node: &Arc<Node>,
) {
    block.commit_qc = manager.highest_commit_qc().cloned();
    match store.write_block(&block) {
        Ok(()) => {
            for tx in &block.transaction_data {
                let mut committed_tx = tx.clone();
                if let Err(e) = crate::transaction::apply_tx_payload(store.as_ref(), tx) {
                    log::warn!("BFT: tx {} payload rejected: {e}", tx.id);
                    committed_tx.state = "invalid_payload".to_string();
                }
                let _ = store.write_transaction(&committed_tx);
            }
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
