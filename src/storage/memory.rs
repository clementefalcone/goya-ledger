//! In-memory BlockStore implementation for testing and development.

use std::collections::HashMap;
use std::sync::Mutex;

use super::errors::{StorageError, StorageResult};
use super::traits::{
    Acta, AliasEntry, Assembly, Block, BlockStore, ClaimStatus, Credential, IdentityRecord,
    InferenceChallenge, InferenceClaim, Invitation, NotarizationEntry, OwnershipTransfer, Scope,
    Session, Transaction,
};
use crate::registry::compliance::{ComplianceResult, ComplianceRule};
use crate::registry::tokenization::AssetToken;
use crate::registry::types::{Asset, AssetEvent};

/// In-memory store backed by HashMaps; safe for concurrent use via Mutex.
pub struct MemoryStore {
    blocks: Mutex<HashMap<u64, Block>>,
    transactions: Mutex<HashMap<String, Transaction>>,
    identities: Mutex<HashMap<String, IdentityRecord>>,
    civil_anchors: Mutex<HashMap<String, String>>,
    credentials: Mutex<HashMap<String, Credential>>,
    latest_height: Mutex<u64>,
    /// Governance proposals: id → Proposal
    proposals: Mutex<HashMap<u64, crate::governance::proposals::Proposal>>,
    /// Governance votes: (proposal_id, voter) → Vote
    votes: Mutex<HashMap<(u64, String), crate::governance::voting::Vote>>,
    /// Vault: DID → encrypted wallet JSON (opaque blob)
    vault: Mutex<HashMap<String, serde_json::Value>>,
    /// Vault recovery: blind_index → DID
    vault_recovery: Mutex<HashMap<String, String>>,
    /// Scopes: id → Scope
    scopes: Mutex<HashMap<String, Scope>>,
    /// Assemblies: id → Assembly
    assemblies: Mutex<HashMap<String, Assembly>>,
    /// Sessions: id → Session
    sessions: Mutex<HashMap<String, Session>>,
    /// Actas: id → Acta
    actas: Mutex<HashMap<String, Acta>>,
    /// Assets: id → Asset
    assets: Mutex<HashMap<String, Asset>>,
    /// Asset events: id → AssetEvent
    asset_events: Mutex<HashMap<String, AssetEvent>>,
    /// Asset tokens: id → AssetToken
    asset_tokens: Mutex<HashMap<String, AssetToken>>,
    /// Compliance rules: id → ComplianceRule
    compliance_rules: Mutex<HashMap<String, ComplianceRule>>,
    /// Compliance results: id → ComplianceResult
    compliance_results: Mutex<HashMap<String, ComplianceResult>>,
    /// Alias registry: commitment → AliasEntry
    aliases: Mutex<HashMap<String, AliasEntry>>,
    /// Inference claims: claim_id → InferenceClaim
    inference_claims: Mutex<HashMap<String, InferenceClaim>>,
    /// Inference challenges: challenge_id → InferenceChallenge
    inference_challenges: Mutex<HashMap<String, InferenceChallenge>>,
    /// Invitations: id → Invitation
    invitations: Mutex<HashMap<String, Invitation>>,
    /// Notarizations: id → NotarizationEntry
    notarizations: Mutex<HashMap<String, NotarizationEntry>>,
    /// Ownership transfers: content_hash → Vec<OwnershipTransfer>
    ownership_transfers: Mutex<HashMap<String, Vec<OwnershipTransfer>>>,
    /// LexChain contracts: id → LexContract
    lexcontracts: Mutex<HashMap<String, crate::lexchain::types::LexContract>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            blocks: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            identities: Mutex::new(HashMap::new()),
            civil_anchors: Mutex::new(HashMap::new()),
            credentials: Mutex::new(HashMap::new()),
            latest_height: Mutex::new(0),
            proposals: Mutex::new(HashMap::new()),
            votes: Mutex::new(HashMap::new()),
            vault: Mutex::new(HashMap::new()),
            vault_recovery: Mutex::new(HashMap::new()),
            scopes: Mutex::new(HashMap::new()),
            assemblies: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            actas: Mutex::new(HashMap::new()),
            assets: Mutex::new(HashMap::new()),
            asset_events: Mutex::new(HashMap::new()),
            asset_tokens: Mutex::new(HashMap::new()),
            compliance_rules: Mutex::new(HashMap::new()),
            compliance_results: Mutex::new(HashMap::new()),
            aliases: Mutex::new(HashMap::new()),
            inference_claims: Mutex::new(HashMap::new()),
            inference_challenges: Mutex::new(HashMap::new()),
            invitations: Mutex::new(HashMap::new()),
            notarizations: Mutex::new(HashMap::new()),
            ownership_transfers: Mutex::new(HashMap::new()),
            lexcontracts: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for MemoryStore {
    fn write_block(&self, block: &Block) -> StorageResult<()> {
        let mut blocks = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        // Reject overwrites of committed blocks — immutability guarantee
        if blocks.contains_key(&block.height) {
            return Err(crate::storage::errors::StorageError::Other(format!(
                "block at height {} already committed",
                block.height
            )));
        }
        let mut latest = self.latest_height.lock().unwrap_or_else(|e| e.into_inner());
        if block.height > *latest {
            *latest = block.height;
        }
        blocks.insert(block.height, block.clone());
        Ok(())
    }

    fn read_block(&self, height: u64) -> StorageResult<Block> {
        self.blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&height)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("BLK:{height:012}")))
    }

    fn write_transaction(&self, tx: &Transaction) -> StorageResult<()> {
        self.transactions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(tx.id.clone(), tx.clone());
        Ok(())
    }

    fn read_transaction(&self, tx_id: &str) -> StorageResult<Transaction> {
        self.transactions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tx_id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("TX:{tx_id}")))
    }

    fn write_identity(&self, identity: &IdentityRecord) -> StorageResult<()> {
        self.identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(identity.did.clone(), identity.clone());
        Ok(())
    }

    fn read_identity(&self, did: &str) -> StorageResult<IdentityRecord> {
        self.identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(did)
            .cloned()
            .ok_or_else(|| StorageError::IdentityNotFound(did.to_string()))
    }

    fn list_identities(&self) -> StorageResult<Vec<IdentityRecord>> {
        Ok(self
            .identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }

    fn write_civil_anchor(&self, anchor_hash: &str, did: &str) -> StorageResult<()> {
        self.civil_anchors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(anchor_hash.to_string(), did.to_string());
        Ok(())
    }

    fn resolve_by_civil_anchor(&self, anchor_hash: &str) -> StorageResult<String> {
        self.civil_anchors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(anchor_hash)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("civil_anchor:{anchor_hash}")))
    }

    fn write_credential(&self, credential: &Credential) -> StorageResult<()> {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(credential.id.clone(), credential.clone());
        Ok(())
    }

    fn read_credential(&self, cred_id: &str) -> StorageResult<Credential> {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cred_id)
            .cloned()
            .ok_or_else(|| StorageError::CredentialNotFound(cred_id.to_string()))
    }

    fn list_credentials(&self) -> StorageResult<Vec<Credential>> {
        Ok(self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }

    fn write_batch(&self, blocks: &[Block], txs: &[Transaction]) -> StorageResult<()> {
        if blocks.is_empty() && txs.is_empty() {
            return Err(StorageError::BatchOperationFailed(
                "Empty batch".to_string(),
            ));
        }
        for block in blocks {
            self.write_block(block)?;
        }
        for tx in txs {
            self.write_transaction(tx)?;
        }
        Ok(())
    }

    fn get_latest_height(&self) -> StorageResult<u64> {
        Ok(*self.latest_height.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn block_exists(&self, height: u64) -> StorageResult<bool> {
        Ok(self
            .blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&height))
    }

    fn transactions_by_block_height(&self, height: u64) -> StorageResult<Vec<Transaction>> {
        let txs = self
            .transactions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|tx| tx.block_height == height)
            .cloned()
            .collect();
        Ok(txs)
    }

    fn credentials_by_subject_did(&self, subject_did: &str) -> StorageResult<Vec<Credential>> {
        let creds = self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| c.subject_did == subject_did)
            .cloned()
            .collect();
        Ok(creds)
    }

    fn credentials_by_issuer_did(&self, issuer_did: &str) -> StorageResult<Vec<Credential>> {
        let creds = self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| c.issuer_did == issuer_did)
            .cloned()
            .collect();
        Ok(creds)
    }

    // ── Governance persistence ─────────────────────────────────────────────

    fn write_proposal(
        &self,
        proposal: &crate::governance::proposals::Proposal,
    ) -> StorageResult<()> {
        self.proposals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(proposal.id, proposal.clone());
        Ok(())
    }

    fn read_proposal(&self, id: u64) -> StorageResult<crate::governance::proposals::Proposal> {
        self.proposals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("PROPOSAL:{id:012}")))
    }

    fn list_proposals(&self) -> StorageResult<Vec<crate::governance::proposals::Proposal>> {
        let mut all: Vec<_> = self
            .proposals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        all.sort_by_key(|p| p.id);
        Ok(all)
    }

    fn write_vote(&self, vote: &crate::governance::voting::Vote) -> StorageResult<()> {
        self.votes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((vote.proposal_id, vote.voter.clone()), vote.clone());
        Ok(())
    }

    fn list_votes(&self, proposal_id: u64) -> StorageResult<Vec<crate::governance::voting::Vote>> {
        let all: Vec<_> = self
            .votes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|v| v.proposal_id == proposal_id)
            .cloned()
            .collect();
        Ok(all)
    }

    fn write_vault(&self, did: &str, encrypted_wallet: &serde_json::Value) -> StorageResult<()> {
        self.vault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(did.to_string(), encrypted_wallet.clone());
        Ok(())
    }

    fn read_vault(&self, did: &str) -> StorageResult<serde_json::Value> {
        self.vault
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(did)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("vault:{did}")))
    }

    fn write_vault_recovery(&self, blind_index: &str, did: &str) -> StorageResult<()> {
        self.vault_recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(blind_index.to_string(), did.to_string());
        Ok(())
    }

    fn read_vault_by_recovery(&self, blind_index: &str) -> StorageResult<String> {
        self.vault_recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(blind_index)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound("vault recovery entry not found".into()))
    }

    // ── Governance entities ─────────────────────────────────────────────

    fn write_scope(&self, scope: &Scope) -> StorageResult<()> {
        self.scopes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(scope.id.clone(), scope.clone());
        Ok(())
    }
    fn read_scope(&self, id: &str) -> StorageResult<Scope> {
        self.scopes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("scope:{id}")))
    }
    fn list_scopes(&self) -> StorageResult<Vec<Scope>> {
        Ok(self
            .scopes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn delete_scope(&self, id: &str) -> StorageResult<()> {
        self.scopes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    fn write_assembly(&self, assembly: &Assembly) -> StorageResult<()> {
        self.assemblies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(assembly.id.clone(), assembly.clone());
        Ok(())
    }
    fn read_assembly(&self, id: &str) -> StorageResult<Assembly> {
        self.assemblies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("assembly:{id}")))
    }
    fn list_assemblies(&self) -> StorageResult<Vec<Assembly>> {
        Ok(self
            .assemblies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn list_assemblies_by_scope(&self, scope_id: &str) -> StorageResult<Vec<Assembly>> {
        Ok(self
            .assemblies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|a| a.scope_id == scope_id)
            .cloned()
            .collect())
    }

    fn delete_assembly(&self, id: &str) -> StorageResult<()> {
        self.assemblies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    fn write_session(&self, session: &Session) -> StorageResult<()> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session.id.clone(), session.clone());
        Ok(())
    }
    fn read_session(&self, id: &str) -> StorageResult<Session> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("session:{id}")))
    }
    fn list_sessions_by_assembly(&self, assembly_id: &str) -> StorageResult<Vec<Session>> {
        Ok(self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|s| s.assembly_id == assembly_id)
            .cloned()
            .collect())
    }

    fn delete_session(&self, id: &str) -> StorageResult<()> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    fn write_acta(&self, acta: &Acta) -> StorageResult<()> {
        self.actas
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(acta.id.clone(), acta.clone());
        Ok(())
    }
    fn read_acta(&self, id: &str) -> StorageResult<Acta> {
        self.actas
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("acta:{id}")))
    }
    fn list_actas(&self) -> StorageResult<Vec<Acta>> {
        Ok(self
            .actas
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn delete_acta(&self, id: &str) -> StorageResult<()> {
        self.actas
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    // ── Asset Registry ──────────────────────────────────────────────────

    fn write_asset(&self, asset: &Asset) -> StorageResult<()> {
        self.assets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(asset.id.clone(), asset.clone());
        Ok(())
    }
    fn read_asset(&self, id: &str) -> StorageResult<Asset> {
        self.assets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("asset:{id}")))
    }
    fn list_assets(&self) -> StorageResult<Vec<Asset>> {
        Ok(self
            .assets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn delete_asset(&self, id: &str) -> StorageResult<()> {
        self.assets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    fn write_asset_event(&self, event: &AssetEvent) -> StorageResult<()> {
        self.asset_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(event.id.clone(), event.clone());
        Ok(())
    }
    fn read_asset_event(&self, id: &str) -> StorageResult<AssetEvent> {
        self.asset_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("asset_event:{id}")))
    }
    fn list_asset_events(&self, asset_id: &str) -> StorageResult<Vec<AssetEvent>> {
        Ok(self
            .asset_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|e| e.asset_id == asset_id)
            .cloned()
            .collect())
    }

    // ── RWA Tokenization ────────────────────────────────────────────────

    fn write_asset_token(&self, token: &AssetToken) -> StorageResult<()> {
        self.asset_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.id.clone(), token.clone());
        Ok(())
    }
    fn read_asset_token(&self, id: &str) -> StorageResult<AssetToken> {
        self.asset_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("token:{id}")))
    }
    fn list_asset_tokens(&self) -> StorageResult<Vec<AssetToken>> {
        Ok(self
            .asset_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn delete_asset_token(&self, id: &str) -> StorageResult<()> {
        self.asset_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    // ── Compliance Automation ───────────────────────────────────────────

    fn write_compliance_rule(&self, rule: &ComplianceRule) -> StorageResult<()> {
        self.compliance_rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(rule.id.clone(), rule.clone());
        Ok(())
    }
    fn read_compliance_rule(&self, id: &str) -> StorageResult<ComplianceRule> {
        self.compliance_rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("rule:{id}")))
    }
    fn list_compliance_rules(&self) -> StorageResult<Vec<ComplianceRule>> {
        Ok(self
            .compliance_rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
    fn delete_compliance_rule(&self, id: &str) -> StorageResult<()> {
        self.compliance_rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        Ok(())
    }

    fn write_compliance_result(&self, result: &ComplianceResult) -> StorageResult<()> {
        self.compliance_results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(result.id.clone(), result.clone());
        Ok(())
    }
    fn list_compliance_results(&self, asset_id: &str) -> StorageResult<Vec<ComplianceResult>> {
        Ok(self
            .compliance_results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|r| r.asset_id == asset_id)
            .cloned()
            .collect())
    }

    // ── Alias Registry ──────────────────────────────────────────────────

    fn write_alias(&self, entry: &AliasEntry) -> StorageResult<()> {
        self.aliases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.commitment.clone(), entry.clone());
        Ok(())
    }

    fn read_alias(&self, commitment: &str) -> StorageResult<AliasEntry> {
        self.aliases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(commitment)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("alias:{commitment}")))
    }

    fn read_alias_by_did(&self, did: &str) -> StorageResult<AliasEntry> {
        self.aliases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|e| e.did == did && e.status == "active")
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("alias for DID:{did}")))
    }

    fn delete_alias(&self, commitment: &str) -> StorageResult<()> {
        self.aliases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(commitment);
        Ok(())
    }

    // ── Inference Claims ────────────────────────────────────────────────

    fn write_inference_claim(&self, claim: &InferenceClaim) -> StorageResult<()> {
        self.inference_claims
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(claim.id.clone(), claim.clone());
        Ok(())
    }

    fn read_inference_claim(&self, id: &str) -> StorageResult<InferenceClaim> {
        self.inference_claims
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("inference_claim:{id}")))
    }

    fn list_inference_claims(
        &self,
        status: Option<&ClaimStatus>,
        oracle_id: Option<&str>,
        model_hash: Option<&str>,
    ) -> StorageResult<Vec<InferenceClaim>> {
        let claims = self
            .inference_claims
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let results = claims
            .values()
            .filter(|c| status.is_none_or(|s| &c.status == s))
            .filter(|c| oracle_id.is_none_or(|o| c.oracle_id == o))
            .filter(|c| model_hash.is_none_or(|m| c.model_hash == m))
            .cloned()
            .collect();
        Ok(results)
    }

    fn write_inference_challenge(&self, challenge: &InferenceChallenge) -> StorageResult<()> {
        self.inference_challenges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(challenge.id.clone(), challenge.clone());
        Ok(())
    }

    fn list_challenges_by_claim(&self, claim_id: &str) -> StorageResult<Vec<InferenceChallenge>> {
        let challenges = self
            .inference_challenges
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let results = challenges
            .values()
            .filter(|c| c.claim_id == claim_id)
            .cloned()
            .collect();
        Ok(results)
    }

    // ── Invitations ─────────────────────────────────────────────────────

    fn write_invitation(&self, invitation: &Invitation) -> StorageResult<()> {
        self.invitations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(invitation.id.clone(), invitation.clone());
        Ok(())
    }

    fn read_invitation(&self, id: &str) -> StorageResult<Invitation> {
        self.invitations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("invitation:{id}")))
    }

    fn list_invitations_by_commitment(
        &self,
        to_commitment: &str,
    ) -> StorageResult<Vec<Invitation>> {
        Ok(self
            .invitations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|i| i.to_commitment == to_commitment)
            .cloned()
            .collect())
    }

    fn list_invitations_by_sender(&self, from_did: &str) -> StorageResult<Vec<Invitation>> {
        Ok(self
            .invitations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|i| i.from_did == from_did)
            .cloned()
            .collect())
    }

    // ── Notarization ─────────────────────────────────────────────────────

    fn write_notarization(&self, entry: &NotarizationEntry) -> StorageResult<()> {
        self.notarizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.id.clone(), entry.clone());
        Ok(())
    }

    fn read_notarization(&self, id: &str) -> StorageResult<NotarizationEntry> {
        self.notarizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("notarization:{id}")))
    }

    fn read_notarization_by_hash(&self, content_hash: &str) -> StorageResult<NotarizationEntry> {
        self.notarizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|e| e.content_hash == content_hash)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("notarization:hash:{content_hash}")))
    }

    fn list_notarizations(&self, signer: Option<&str>) -> StorageResult<Vec<NotarizationEntry>> {
        let all = self.notarizations.lock().unwrap_or_else(|e| e.into_inner());
        let mut result: Vec<_> = all
            .values()
            .filter(|e| signer.is_none_or(|s| e.signer == s))
            .cloned()
            .collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.notarized_at));
        Ok(result)
    }

    // ── Ownership Transfers ─────────────────────────────────────────────

    fn write_ownership_transfer(&self, transfer: &OwnershipTransfer) -> StorageResult<()> {
        self.ownership_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(transfer.content_hash.clone())
            .or_default()
            .push(transfer.clone());
        Ok(())
    }

    fn read_ownership_transfers(
        &self,
        content_hash: &str,
    ) -> StorageResult<Vec<OwnershipTransfer>> {
        Ok(self
            .ownership_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(content_hash)
            .cloned()
            .unwrap_or_default())
    }

    fn write_lexcontract(
        &self,
        contract: &crate::lexchain::types::LexContract,
    ) -> StorageResult<()> {
        self.lexcontracts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(contract.id.clone(), contract.clone());
        Ok(())
    }

    fn read_lexcontract(&self, id: &str) -> StorageResult<crate::lexchain::types::LexContract> {
        self.lexcontracts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(format!("lexcontract:{id}")))
    }

    fn list_lexcontracts(&self) -> StorageResult<Vec<crate::lexchain::types::LexContract>> {
        Ok(self
            .lexcontracts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::SignatureLevel;

    fn sample_block(height: u64) -> Block {
        Block {
            height,
            timestamp: 1_000 + height,
            parent_hash: [0u8; 32],
            merkle_root: [1u8; 32],
            transactions: vec![format!("tx-{}", height)],
            proposer: "node-1".to_string(),
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

    fn sample_tx(id: &str, height: u64) -> Transaction {
        Transaction {
            id: id.to_string(),
            block_height: height,
            timestamp: 1_000,
            input_did: "did:goya:sender".to_string(),
            output_recipient: "did:goya:receiver".to_string(),
            amount: 42,
            state: "confirmed".to_string(),
            fee: 0,
            payload: None,
        }
    }

    #[test]
    fn write_and_read_block() {
        let store = MemoryStore::new();
        let block = sample_block(1);
        store.write_block(&block).unwrap();
        let fetched = store.read_block(1).unwrap();
        assert_eq!(fetched.height, 1);
        assert_eq!(fetched.proposer, "node-1");
    }

    #[test]
    fn read_missing_block_returns_error() {
        let store = MemoryStore::new();
        assert!(store.read_block(99).is_err());
    }

    #[test]
    fn latest_height_tracks_max() {
        let store = MemoryStore::new();
        assert_eq!(store.get_latest_height().unwrap(), 0);
        store.write_block(&sample_block(3)).unwrap();
        store.write_block(&sample_block(1)).unwrap();
        store.write_block(&sample_block(5)).unwrap();
        assert_eq!(store.get_latest_height().unwrap(), 5);
    }

    #[test]
    fn block_exists_returns_correct_result() {
        let store = MemoryStore::new();
        assert!(!store.block_exists(1).unwrap());
        store.write_block(&sample_block(1)).unwrap();
        assert!(store.block_exists(1).unwrap());
    }

    #[test]
    fn write_and_read_transaction() {
        let store = MemoryStore::new();
        let tx = sample_tx("tx-abc", 1);
        store.write_transaction(&tx).unwrap();
        let fetched = store.read_transaction("tx-abc").unwrap();
        assert_eq!(fetched.amount, 42);
    }

    #[test]
    fn read_missing_transaction_returns_error() {
        let store = MemoryStore::new();
        assert!(store.read_transaction("ghost").is_err());
    }

    #[test]
    fn write_and_read_identity() {
        let store = MemoryStore::new();
        let id = IdentityRecord {
            did: "did:goya:alice".to_string(),
            public_key: String::new(),
            created_at: 100,
            updated_at: 200,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
        };
        store.write_identity(&id).unwrap();
        let fetched = store.read_identity("did:goya:alice").unwrap();
        assert_eq!(fetched.status, "active");
    }

    #[test]
    fn read_missing_identity_returns_error() {
        let store = MemoryStore::new();
        assert!(store.read_identity("did:goya:ghost").is_err());
    }

    #[test]
    fn write_and_read_credential() {
        let store = MemoryStore::new();
        let cred = Credential {
            id: "cred-1".to_string(),
            issuer_did: "did:goya:issuer".to_string(),
            subject_did: "did:goya:subject".to_string(),
            cred_type: "eid".to_string(),
            issued_at: 100,
            expires_at: 999,
            revoked_at: None,
            ..Default::default()
        };
        store.write_credential(&cred).unwrap();
        let fetched = store.read_credential("cred-1").unwrap();
        assert_eq!(fetched.cred_type, "eid");
        assert!(fetched.revoked_at.is_none());
    }

    #[test]
    fn read_missing_credential_returns_error() {
        let store = MemoryStore::new();
        assert!(store.read_credential("ghost").is_err());
    }

    #[test]
    fn write_batch_succeeds() {
        let store = MemoryStore::new();
        let blocks = vec![sample_block(1), sample_block(2)];
        let txs = vec![sample_tx("tx-1", 1), sample_tx("tx-2", 2)];
        store.write_batch(&blocks, &txs).unwrap();
        assert_eq!(store.get_latest_height().unwrap(), 2);
        assert!(store.read_transaction("tx-2").is_ok());
    }

    #[test]
    fn write_batch_empty_returns_error() {
        let store = MemoryStore::new();
        assert!(store.write_batch(&[], &[]).is_err());
    }

    // ── Secondary index: transactions_by_block_height ─────────────────────────

    #[test]
    fn transactions_by_block_height_returns_empty_for_unknown_height() {
        let store = MemoryStore::new();
        assert!(store.transactions_by_block_height(99).unwrap().is_empty());
    }

    #[test]
    fn transactions_by_block_height_filters_correctly() {
        let store = MemoryStore::new();
        store.write_transaction(&sample_tx("tx-1", 3)).unwrap();
        store.write_transaction(&sample_tx("tx-2", 3)).unwrap();
        store.write_transaction(&sample_tx("tx-3", 4)).unwrap();

        let result = store.transactions_by_block_height(3).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|t| t.block_height == 3));
    }

    #[test]
    fn transactions_by_block_height_returns_all_for_height() {
        let store = MemoryStore::new();
        for i in 0..5u64 {
            store
                .write_transaction(&sample_tx(&format!("tx-{i}"), 10))
                .unwrap();
        }
        assert_eq!(store.transactions_by_block_height(10).unwrap().len(), 5);
    }

    // ── Secondary index: credentials_by_subject_did ───────────────────────────

    fn sample_cred(id: &str, subject_did: &str) -> Credential {
        Credential {
            id: id.to_string(),
            issuer_did: "did:goya:issuer".to_string(),
            subject_did: subject_did.to_string(),
            cred_type: "eid".to_string(),
            issued_at: 1_000,
            expires_at: 9_999,
            ..Default::default()
        }
    }

    #[test]
    fn credentials_by_subject_did_returns_empty_for_unknown_subject() {
        let store = MemoryStore::new();
        assert!(store
            .credentials_by_subject_did("did:goya:ghost")
            .unwrap()
            .is_empty());
    }

    // ── Governance persistence ────────────────────────────────────────────────

    fn sample_proposal(id: u64) -> crate::governance::proposals::Proposal {
        crate::governance::proposals::Proposal {
            id,
            proposer: "alice".to_string(),
            action: crate::governance::proposals::ProposalAction::TextProposal {
                title: "Test".to_string(),
                description: "A test proposal".to_string(),
            },
            status: crate::governance::proposals::ProposalStatus::Voting,
            deposit: 100,
            submitted_at: 10,
            voting_ends_at: 110,
            timelock_ends_at: None,
            finalized_at: None,
            description: "test".to_string(),
        }
    }

    fn sample_vote(proposal_id: u64, voter: &str) -> crate::governance::voting::Vote {
        crate::governance::voting::Vote {
            voter: voter.to_string(),
            proposal_id,
            option: crate::governance::voting::VoteOption::Yes,
            power: 1000,
            voted_at: 50,
            signature_level: Default::default(),
            signature_algorithm: Default::default(),
            biometric_evidence: vec![],
        }
    }

    #[test]
    fn write_and_read_proposal() {
        let store = MemoryStore::new();
        let p = sample_proposal(1);
        store.write_proposal(&p).unwrap();
        let fetched = store.read_proposal(1).unwrap();
        assert_eq!(fetched.proposer, "alice");
    }

    #[test]
    fn read_missing_proposal_returns_error() {
        let store = MemoryStore::new();
        assert!(store.read_proposal(999).is_err());
    }

    #[test]
    fn list_proposals_sorted_by_id() {
        let store = MemoryStore::new();
        store.write_proposal(&sample_proposal(3)).unwrap();
        store.write_proposal(&sample_proposal(1)).unwrap();
        store.write_proposal(&sample_proposal(2)).unwrap();
        let all = store.list_proposals().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, 1);
        assert_eq!(all[2].id, 3);
    }

    #[test]
    fn write_and_list_votes() {
        let store = MemoryStore::new();
        store.write_vote(&sample_vote(1, "alice")).unwrap();
        store.write_vote(&sample_vote(1, "bob")).unwrap();
        store.write_vote(&sample_vote(2, "alice")).unwrap();
        let votes = store.list_votes(1).unwrap();
        assert_eq!(votes.len(), 2);
        assert!(votes.iter().all(|v| v.proposal_id == 1));
    }

    #[test]
    fn list_votes_empty_for_unknown_proposal() {
        let store = MemoryStore::new();
        assert!(store.list_votes(999).unwrap().is_empty());
    }

    #[test]
    fn proposal_update_overwrites() {
        let store = MemoryStore::new();
        let mut p = sample_proposal(1);
        store.write_proposal(&p).unwrap();
        p.status = crate::governance::proposals::ProposalStatus::Passed;
        store.write_proposal(&p).unwrap();
        let fetched = store.read_proposal(1).unwrap();
        assert_eq!(
            fetched.status,
            crate::governance::proposals::ProposalStatus::Passed
        );
    }

    #[test]
    fn credentials_by_subject_did_filters_correctly() {
        let store = MemoryStore::new();
        store
            .write_credential(&sample_cred("cred-1", "did:goya:alice"))
            .unwrap();
        store
            .write_credential(&sample_cred("cred-2", "did:goya:alice"))
            .unwrap();
        store
            .write_credential(&sample_cred("cred-3", "did:goya:bob"))
            .unwrap();

        let alice = store.credentials_by_subject_did("did:goya:alice").unwrap();
        assert_eq!(alice.len(), 2);
        assert!(alice.iter().all(|c| c.subject_did == "did:goya:alice"));

        let bob = store.credentials_by_subject_did("did:goya:bob").unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].id, "cred-3");
    }

    // ── Notarization with signature level + biometric evidence ───────

    #[test]
    fn notarization_roundtrip_with_signature_level_and_biometrics() {
        use crate::signature::{BiometricEvidence, BiometricType, SignatureLevel};

        let store = MemoryStore::new();
        let entry = NotarizationEntry {
            signer_proof: None,
            id: "nota-fea-1".into(),
            content_hash: "a".repeat(64),
            signer: "did:goya:fea1".into(),
            metadata: None,
            notarized_at: 1700000000,
            block_height: 42,
            signature: "ff".repeat(32),
            public_key: "aa".repeat(1952),
            cades_der: None,
            signature_algorithm: crate::identity::signing::SigningAlgorithm::MlDsa65,
            signature_level: SignatureLevel::Advanced,
            biometric_evidence: vec![
                BiometricEvidence {
                    evidence_type: BiometricType::Fingerprint,
                    commitment: "b".repeat(64),
                    captured_at: 1700000000,
                    capture_device: Some("Scanner-v1".into()),
                },
                BiometricEvidence {
                    evidence_type: BiometricType::Rut,
                    commitment: "c".repeat(64),
                    captured_at: 1700000000,
                    capture_device: None,
                },
            ],
        };
        store.write_notarization(&entry).unwrap();

        let read = store.read_notarization("nota-fea-1").unwrap();
        assert_eq!(read.signature_level, SignatureLevel::Advanced);
        assert_eq!(read.biometric_evidence.len(), 2);
        assert_eq!(
            read.biometric_evidence[0].evidence_type,
            BiometricType::Fingerprint
        );
        assert_eq!(read.biometric_evidence[1].commitment, "c".repeat(64));

        let by_hash = store.read_notarization_by_hash(&"a".repeat(64)).unwrap();
        assert_eq!(by_hash.signature_level, SignatureLevel::Advanced);
        assert_eq!(by_hash.biometric_evidence.len(), 2);
    }

    #[test]
    fn notarization_simple_has_empty_biometrics() {
        let store = MemoryStore::new();
        let entry = NotarizationEntry {
            signer_proof: None,
            id: "nota-fes-1".into(),
            content_hash: "d".repeat(64),
            signer: "did:goya:fes1".into(),
            metadata: None,
            notarized_at: 1700000000,
            block_height: 1,
            signature: "ee".repeat(32),
            public_key: "aa".repeat(32),
            cades_der: None,
            signature_algorithm: Default::default(),
            signature_level: SignatureLevel::default(),
            biometric_evidence: vec![],
        };
        store.write_notarization(&entry).unwrap();

        let read = store.read_notarization("nota-fes-1").unwrap();
        assert_eq!(read.signature_level, SignatureLevel::Simple);
        assert!(read.biometric_evidence.is_empty());
    }

    #[test]
    fn notarization_backwards_compat_legacy_json() {
        // Simulate a legacy JSON without signature_level or biometric_evidence
        let legacy_json = r#"{
            "id": "legacy-1",
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "signer": "did:goya:old",
            "notarized_at": 1600000000,
            "block_height": 5,
            "signature": "abcd",
            "signature_algorithm": "Ed25519"
        }"#;
        let entry: NotarizationEntry = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(entry.signature_level, SignatureLevel::Simple);
        assert!(entry.biometric_evidence.is_empty());
        assert_eq!(
            entry.signature_algorithm,
            crate::identity::signing::SigningAlgorithm::Ed25519
        );
    }

    #[test]
    fn notarization_list_preserves_biometrics() {
        use crate::signature::{BiometricEvidence, BiometricType, SignatureLevel};

        let store = MemoryStore::new();
        for i in 0..3 {
            let entry = NotarizationEntry {
                signer_proof: None,
                id: format!("nota-list-{i}"),
                content_hash: format!("{:0>64}", i),
                signer: "did:goya:lister".into(),
                metadata: None,
                notarized_at: 1700000000 + i,
                block_height: i,
                signature: "ff".repeat(32),
                public_key: "aa".repeat(1952),
                cades_der: None,
                signature_algorithm: crate::identity::signing::SigningAlgorithm::MlDsa65,
                signature_level: SignatureLevel::Advanced,
                biometric_evidence: vec![BiometricEvidence {
                    evidence_type: BiometricType::FacialRecognition,
                    commitment: format!("{:a>64}", i),
                    captured_at: 1700000000,
                    capture_device: None,
                }],
            };
            store.write_notarization(&entry).unwrap();
        }

        let all = store.list_notarizations(Some("did:goya:lister")).unwrap();
        assert_eq!(all.len(), 3);
        for entry in &all {
            assert_eq!(entry.signature_level, SignatureLevel::Advanced);
            assert_eq!(entry.biometric_evidence.len(), 1);
        }
    }

    #[test]
    fn ownership_transfer_with_signature_level() {
        use crate::signature::{BiometricEvidence, BiometricType, SignatureLevel};

        let store = MemoryStore::new();
        // First create a notarization
        let nota = NotarizationEntry {
            signer_proof: None,
            id: "nota-xfer".into(),
            content_hash: "e".repeat(64),
            signer: "did:goya:alice".into(),
            metadata: None,
            notarized_at: 1700000000,
            block_height: 1,
            signature: "ff".repeat(32),
            public_key: "aa".repeat(32),
            cades_der: None,
            signature_algorithm: Default::default(),
            signature_level: Default::default(),
            biometric_evidence: vec![],
        };
        store.write_notarization(&nota).unwrap();

        let transfer = OwnershipTransfer {
            content_hash: "e".repeat(64),
            from_did: "did:goya:alice".into(),
            to_did: "did:goya:bob".into(),
            signature: "aa".repeat(32),
            public_key: "bb".repeat(16),
            transferred_at: 1700001000,
            signature_algorithm: crate::identity::signing::SigningAlgorithm::MlDsa65,
            signature_level: SignatureLevel::Advanced,
            biometric_evidence: vec![BiometricEvidence {
                evidence_type: BiometricType::Fingerprint,
                commitment: "c".repeat(64),
                captured_at: 1700001000,
                capture_device: None,
            }],
        };
        store.write_ownership_transfer(&transfer).unwrap();

        let transfers = store.read_ownership_transfers(&"e".repeat(64)).unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].signature_level, SignatureLevel::Advanced);
        assert_eq!(transfers[0].biometric_evidence.len(), 1);
    }

    #[test]
    fn no_bare_unwrap_in_production_code() {
        let source = include_str!("memory.rs");
        let prod_code = source.split("#[cfg(test)]").next().unwrap_or(source);
        let violations: Vec<(usize, &str)> = prod_code
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains(".unwrap()") && !l.trim().starts_with("//"))
            .collect();
        assert!(
            violations.is_empty(),
            "memory.rs production code has {} bare .unwrap() calls — use .unwrap_or_else(|e| e.into_inner()) for mutex locks:\n  {}",
            violations.len(),
            violations.iter().take(5).map(|(i, l)| format!("line {}: {}", i + 1, l.trim())).collect::<Vec<_>>().join("\n  ")
        );
    }

    #[test]
    fn ownership_transfer_backwards_compat_legacy_json() {
        let legacy_json = r#"{
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "from_did": "did:goya:a",
            "to_did": "did:goya:b",
            "signature": "abcd",
            "public_key": "1234",
            "transferred_at": 1600000000
        }"#;
        let transfer: OwnershipTransfer = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(transfer.signature_level, SignatureLevel::Simple);
        assert!(transfer.biometric_evidence.is_empty());
    }
}
