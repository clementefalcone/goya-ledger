use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::app_state::AppState;
use crate::governance::params::ParamValue;
use crate::governance::proposals::{ProposalAction, ProposalStatus, SubmitParams};
use crate::governance::voting::VoteOption;
use crate::storage::traits::BlockStore;

/// Get the default store for governance persistence (fire-and-forget).
fn default_store(state: &AppState) -> Option<std::sync::Arc<dyn BlockStore>> {
    state
        .store
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get("default")
        .cloned()
}

/// Persist a proposal to the default store. Logs on failure.
fn persist_proposal(state: &AppState, proposal: &crate::governance::proposals::Proposal) {
    if let Some(store) = default_store(state) {
        if let Err(e) = store.write_proposal(proposal) {
            log::warn!("Failed to persist proposal {}: {e}", proposal.id);
        }
    }
}

/// Persist a vote to the default store. Logs on failure.
fn persist_vote(state: &AppState, vote: &crate::governance::voting::Vote) {
    if let Some(store) = default_store(state) {
        if let Err(e) = store.write_vote(vote) {
            log::warn!(
                "Failed to persist vote for proposal {}: {e}",
                vote.proposal_id
            );
        }
    }
}

// ── Request / Response types ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubmitProposalRequest {
    pub proposer: String,
    pub description: String,
    pub deposit: u64,
    pub action: ProposalActionRequest,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum ProposalActionRequest {
    #[serde(rename = "param_change")]
    ParamChange { changes: Vec<ParamChangeEntry> },
    #[serde(rename = "text")]
    TextProposal { title: String, description: String },
}

#[derive(Deserialize)]
pub struct ParamChangeEntry {
    pub key: String,
    pub value: u64,
}

#[derive(Deserialize)]
pub struct CastVoteRequest {
    pub voter: String,
    pub option: VoteOption,
    /// Signature over the vote payload (hex).
    #[serde(default)]
    pub signature: Option<String>,
    /// Public key of the voter (hex).
    #[serde(default)]
    pub public_key: Option<String>,
    /// Client-generated blinding nonce (hex). Mixed into the blind voter ID
    /// to prevent brute-force deanonymization from the member list.
    /// The nonce is never stored — only its contribution to the blind ID.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: crate::signature::SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: crate::identity::signing::SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<crate::signature::BiometricEvidence>,
}

#[derive(Deserialize)]
pub struct DelegateRequest {
    pub delegator: String,
    pub delegate: String,
}

#[derive(Deserialize)]
pub struct VetoRequest {
    pub caller: String,
}

#[derive(Serialize)]
pub struct ParamEntry {
    pub key: String,
    pub value: String,
    pub raw: ParamValue,
}

#[derive(Serialize)]
struct TallyResponse {
    proposal_id: u64,
    yes_power: u64,
    no_power: u64,
    abstain_power: u64,
    total_voted_power: u64,
    total_staked_power: u64,
    quorum_reached: bool,
    passed: bool,
}

// ── Size limits ─────────────────────────────────────────────────────────────

const MAX_PROPOSER_LEN: usize = 256;
const MAX_DESCRIPTION_LEN: usize = 4096;
const MAX_TITLE_LEN: usize = 256;
const MAX_VOTER_LEN: usize = 256;
const MAX_PARAM_CHANGES: usize = 50;
const MAX_PARAM_KEY_LEN: usize = 128;

fn err_dto(msg: &str) -> ErrorDto {
    ErrorDto {
        code: "GOVERNANCE_ERROR".to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn err_field(field: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: "VALIDATION_ERROR".to_string(),
        message: msg.to_string(),
        field: Some(field.to_string()),
    }
}

/// Semantic validation for known governance parameters.
fn validate_param_value(key: &str, value: u64) -> Option<ErrorDto> {
    match (key, value) {
        ("quorum_percent" | "pass_threshold_percent", v) if v == 0 || v > 100 => {
            Some(err_field(key, "must be between 1 and 100"))
        }
        ("voting_period_blocks", 0) => Some(err_field(key, "must be greater than 0")),
        _ => None,
    }
}

fn validate_bounded(field: &str, value: &str, max: usize) -> Result<(), ErrorDto> {
    if value.is_empty() {
        return Err(err_field(field, "must not be empty"));
    }
    if value.len() > max {
        return Err(err_field(
            field,
            &format!("exceeds maximum length of {max} bytes"),
        ));
    }
    if value.contains('\0') {
        return Err(err_field(field, "contains null bytes"));
    }
    Ok(())
}

/// Get current chain height from BlockStore.
fn chain_height(state: &AppState) -> u64 {
    if let Ok(store_map) = state.store.read() {
        if let Some(store) = store_map.get("default") {
            return store.get_latest_height().unwrap_or(0);
        }
    }
    0
}

/// Get total staked power from StakingManager.
fn total_staked_power(state: &AppState) -> u64 {
    state
        .staking_manager
        .get_active_validators()
        .iter()
        .map(|v| v.staked_amount)
        .sum()
}

/// Get a voter's stake from StakingManager (own + delegated).
fn voter_power(state: &AppState, voter: &str) -> u64 {
    let own_stake = state
        .staking_manager
        .get_validator(voter)
        .map(|v| v.staked_amount)
        .unwrap_or(0);

    // Add delegated power
    let delegated: u64 = if let Some(vs) = &state.vote_store {
        vs.get_delegators(voter)
            .iter()
            .filter_map(|d| state.staking_manager.get_validator(d))
            .map(|v| v.staked_amount)
            .sum()
    } else {
        0
    };

    own_stake + delegated
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/v1/governance/params
#[get("/governance/params")]
pub async fn list_params(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let registry = match &state.param_registry {
        Some(r) => r,
        None => return Ok(HttpResponse::Ok().json(ApiResponse::<Vec<()>>::success(vec![], trace))),
    };
    let mut params: Vec<ParamEntry> = registry
        .list()
        .into_iter()
        .map(|(k, v)| ParamEntry {
            value: v.to_string(),
            raw: v,
            key: k,
        })
        .collect();
    params.sort_by_key(|p| p.key.clone());
    Ok(HttpResponse::Ok().json(ApiResponse::success(params, trace)))
}

/// POST /api/v1/governance/proposals — submit with real chain height and deposit verification
#[post("/governance/proposals")]
pub async fn submit_governance_proposal(
    state: web::Data<AppState>,
    body: web::Json<SubmitProposalRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    // ── Input validation ──
    if let Err(e) = validate_bounded("proposer", &body.proposer, MAX_PROPOSER_LEN) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
    }
    if let Err(e) = validate_bounded("description", &body.description, MAX_DESCRIPTION_LEN) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
    }
    match &body.action {
        ProposalActionRequest::ParamChange { changes } => {
            if changes.len() > MAX_PARAM_CHANGES {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_field(
                        "changes",
                        &format!("exceeds maximum of {MAX_PARAM_CHANGES} entries"),
                    ),
                    400,
                )));
            }
            for c in changes {
                if let Err(e) = validate_bounded("key", &c.key, MAX_PARAM_KEY_LEN) {
                    return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
                }
                // Semantic bounds for known governance parameters
                if let Some(err) = validate_param_value(&c.key, c.value) {
                    return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(err, 400)));
                }
            }
        }
        ProposalActionRequest::TextProposal { title, description } => {
            if let Err(e) = validate_bounded("title", title, MAX_TITLE_LEN) {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
            }
            if let Err(e) = validate_bounded("description", description, MAX_DESCRIPTION_LEN) {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
            }
        }
    }

    let store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };
    let registry = match &state.param_registry {
        Some(r) => r,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };
    let required_deposit = registry.get_u64("proposal_deposit", 10_000);
    let voting_period = registry.get_u64("voting_period_blocks", 17_280);
    let current_height = chain_height(&state);

    // Verify proposer has enough stake to cover deposit (skip in permissive mode)
    if !crate::api::errors::acl_permissive() {
        let proposer_stake = state
            .staking_manager
            .get_validator(&body.proposer)
            .map(|v| v.staked_amount)
            .unwrap_or(0);
        let already_locked = store.locked_deposit_for(&body.proposer);
        let available = proposer_stake.saturating_sub(already_locked);
        if available < body.deposit {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto(&format!(
                    "insufficient available stake: have {available} (stake {proposer_stake} - locked {already_locked}), need {} for deposit",
                    body.deposit
                )),
                400,
            )));
        }
    }

    let action = match &body.action {
        ProposalActionRequest::ParamChange { changes } => ProposalAction::ParamChange {
            changes: changes
                .iter()
                .map(|c| (c.key.clone(), ParamValue::U64(c.value)))
                .collect(),
        },
        ProposalActionRequest::TextProposal { title, description } => {
            ProposalAction::TextProposal {
                title: title.clone(),
                description: description.clone(),
            }
        }
    };

    match store.submit(SubmitParams {
        proposer: &body.proposer,
        action,
        description: &body.description,
        deposit: body.deposit,
        required_deposit,
        current_height,
        voting_period,
    }) {
        Ok(id) => {
            let proposal = store.get(id);
            if let Some(ref p) = proposal {
                persist_proposal(&state, p);
            }
            Ok(HttpResponse::Created().json(ApiResponse::success(proposal, trace)))
        }
        Err(e) => {
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400)))
        }
    }
}

/// Query parameters for listing governance proposals.
#[derive(serde::Deserialize)]
pub struct ProposalListQuery {
    pub status: Option<String>,
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

/// GET /api/v1/governance/proposals (paginated)
#[get("/governance/proposals")]
pub async fn list_governance_proposals(
    state: web::Data<AppState>,
    query: web::Query<ProposalListQuery>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let store = match &state.proposal_store {
        Some(s) => s,
        None => return Ok(HttpResponse::Ok().json(ApiResponse::<Vec<()>>::success(vec![], trace))),
    };

    let proposals = if let Some(status_str) = &query.status {
        let status = match status_str.as_str() {
            "Voting" => ProposalStatus::Voting,
            "Passed" => ProposalStatus::Passed,
            "Rejected" => ProposalStatus::Rejected,
            "Executed" => ProposalStatus::Executed,
            "Cancelled" => ProposalStatus::Cancelled,
            "Expired" => ProposalStatus::Expired,
            _ => {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_dto(&format!("invalid status: {status_str}")),
                    400,
                )))
            }
        };
        store.list_by_status(status)
    } else {
        store.list_all()
    };

    let pagination = crate::api::pagination::PaginationParams {
        page: query.page,
        limit: query.limit,
        cursor: None,
    };
    let total = proposals.len();
    let page: Vec<_> = proposals
        .into_iter()
        .skip(pagination.offset())
        .take(pagination.limit())
        .collect();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        crate::api::pagination::PaginatedResponse::new(page, total, &pagination),
        trace,
    )))
}

/// GET /api/v1/governance/proposals/{id}
#[get("/governance/proposals/{id}")]
pub async fn get_governance_proposal(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();
    let store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("governance not configured"),
                404,
            )))
        }
    };
    match store.get(id) {
        Some(p) => Ok(HttpResponse::Ok().json(ApiResponse::success(p, trace))),
        None => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto(&format!("proposal {id} not found")),
            404,
        ))),
    }
}

/// POST /api/v1/governance/proposals/{id}/vote — uses real stake from StakingManager
#[post("/governance/proposals/{id}/vote")]
pub async fn cast_governance_vote(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<CastVoteRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();

    // ── Input validation ──
    if let Err(e) = validate_bounded("voter", &body.voter, MAX_VOTER_LEN) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
    }

    let vote_store = match &state.vote_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };

    let proposal_store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };
    let proposal = match proposal_store.get(id) {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto(&format!("proposal {id} not found")),
                404,
            )))
        }
    };

    // ── Signature verification (if provided) ──
    // When both signature and public_key are present, verify the signature
    // over the canonical vote payload. Supports Simple (Ed25519) and
    // Advanced (ML-DSA-65 + biometric evidence).
    if let (Some(sig_hex), Some(pk_hex)) = (&body.signature, &body.public_key) {
        // Validate FES/FEA constraints
        if let Err(e) = crate::signature::validate_fes_fea(
            body.signature_level,
            body.signature_algorithm,
            &body.biometric_evidence,
            pk_hex,
        ) {
            return Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400)));
        }

        let option_str = match body.option {
            VoteOption::Yes => "Yes",
            VoteOption::No => "No",
            VoteOption::Abstain => "Abstain",
        };

        // Build level-appropriate payload
        let payload = match body.signature_level {
            crate::signature::SignatureLevel::Simple => {
                format!("vote:{id}:{option_str}:{pk_hex}")
            }
            _ => {
                let bio_hash = crate::signature::compute_biometrics_hash(&body.biometric_evidence);
                format!("vote_fea:{id}:{option_str}:{pk_hex}:{bio_hash}")
            }
        };

        if !crate::signature::verify_signature(
            body.signature_algorithm,
            pk_hex,
            payload.as_bytes(),
            sig_hex,
        ) {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("signature verification failed — vote rejected"),
                400,
            )));
        }

        // Verify voter DID matches the public key
        let identities = crate::api::handlers::channels::get_channel_store(&state, "default")?;
        if !crate::identity::operations::key_controls_did(identities.as_ref(), &body.voter, pk_hex)
        {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("voter DID does not match public key"),
                400,
            )));
        }
    }

    // ── Vote secrecy: blind voter identity ──
    // When a signed vote arrives, store it under a blinded voter ID:
    //   blind_id = sha256(proposal_id || voter_did)
    // This preserves:
    //   - Deduplication (same voter → same blind_id per proposal)
    //   - Secrecy (blind_id cannot be reversed to voter DID)
    //   - Cross-proposal unlinkability (different blind_id per proposal)
    // Unsigned votes (legacy/permissive mode) use the raw voter DID.
    let effective_voter = if body.signature.is_some() {
        use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(id.to_le_bytes());
        hasher.update(body.voter.as_bytes());
        // Mix in client nonce to prevent brute-force deanonymization
        if let Some(ref nonce) = body.nonce {
            hasher.update(nonce.as_bytes());
        }
        let blind = hasher.finalize();
        format!("blind:{}", hex::encode(&blind[..20]))
    } else {
        body.voter.clone()
    };

    // Resolve real voting power from StakingManager (own + delegated).
    // In permissive mode, grant power=1 so sandbox demos work without staking.
    let power = {
        let real = voter_power(&state, &body.voter);
        if real > 0 {
            real
        } else if crate::api::errors::acl_permissive() {
            1
        } else {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("voter has no staked tokens (zero voting power)"),
                400,
            )));
        }
    };

    let current_height = chain_height(&state);

    match vote_store.cast_vote(
        id,
        &effective_voter,
        body.option,
        power,
        current_height,
        proposal.voting_ends_at,
    ) {
        Ok(()) => {
            // Attach FES/FEA metadata to the vote
            vote_store.set_vote_signature_data(
                id,
                &effective_voter,
                body.signature_level,
                body.signature_algorithm,
                body.biometric_evidence.clone(),
            );
            // Persist vote to storage layer
            if let Some(vote) = vote_store.get_vote(id, &effective_voter) {
                persist_vote(&state, &vote);
            }

            // Return tally (aggregates only) — never expose individual votes.
            let registry =
                match &state.param_registry {
                    Some(r) => r,
                    None => {
                        return Ok(HttpResponse::ServiceUnavailable().json(
                            ApiResponse::<()>::error(err_dto("governance not configured"), 503),
                        ))
                    }
                };
            let quorum = registry.get_u64("quorum_percent", 33);
            let threshold = registry.get_u64("pass_threshold_percent", 67);
            let total_staked = total_staked_power(&state).max(1);
            let tally = vote_store.tally(id, total_staked, quorum, threshold);
            Ok(HttpResponse::Ok().json(ApiResponse::success(
                TallyResponse {
                    proposal_id: tally.proposal_id,
                    yes_power: tally.yes_power,
                    no_power: tally.no_power,
                    abstain_power: tally.abstain_power,
                    total_voted_power: tally.total_voted_power,
                    total_staked_power: tally.total_staked_power,
                    quorum_reached: tally.quorum_reached,
                    passed: tally.passed,
                },
                trace,
            )))
        }
        Err(e) => {
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400)))
        }
    }
}

/// GET /api/v1/governance/proposals/{id}/votes
///
/// Returns individual votes. Requires admin role (`X-Msp-Role: admin`) unless
/// in permissive mode. Public auditors should use `/tally` instead.
#[get("/governance/proposals/{id}/votes")]
pub async fn get_governance_votes(
    req: actix_web::HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    // Require admin role for individual vote access (privacy)
    if !crate::api::errors::acl_permissive() {
        let role = req
            .headers()
            .get("X-Msp-Role")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if role != "admin" {
            return Ok(HttpResponse::Forbidden().json(ApiResponse::<()>::error(
                err_dto("individual votes require admin role — use /tally for public audit"),
                403,
            )));
        }
    }

    let id = path.into_inner();
    let vote_store = match &state.vote_store {
        Some(s) => s,
        None => return Ok(HttpResponse::Ok().json(ApiResponse::<Vec<()>>::success(vec![], trace))),
    };
    let votes = vote_store.get_votes(id);
    Ok(HttpResponse::Ok().json(ApiResponse::success(votes, trace)))
}

/// GET /api/v1/governance/votes?voter={did}
///
/// Returns all proposals where the voter participated, with option and timestamp.
/// Searches by raw voter DID and by blind voter ID (for signed votes).
#[get("/governance/votes")]
pub async fn get_voter_history(
    state: web::Data<AppState>,
    query: web::Query<VoterHistoryQuery>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let voter_did = &query.voter;

    if voter_did.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_field("voter", "voter query parameter is required"),
            400,
        )));
    }

    let vote_store = match &state.vote_store {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::Ok()
                .json(ApiResponse::success(Vec::<VoterHistoryEntry>::new(), trace)))
        }
    };
    let proposal_store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::Ok()
                .json(ApiResponse::success(Vec::<VoterHistoryEntry>::new(), trace)))
        }
    };

    let proposals = proposal_store.list_all();
    let mut history: Vec<VoterHistoryEntry> = Vec::new();

    for proposal in &proposals {
        // Try raw voter DID (unsigned votes)
        let vote = vote_store.get_vote(proposal.id, voter_did);
        // Try blind voter ID (signed votes)
        let vote = vote.or_else(|| {
            use pqc_crypto_module::legacy::sha256::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(proposal.id.to_le_bytes());
            hasher.update(voter_did.as_bytes());
            let blind = hasher.finalize();
            let blind_id = format!("blind:{}", hex::encode(&blind[..20]));
            vote_store.get_vote(proposal.id, &blind_id)
        });

        if let Some(v) = vote {
            history.push(VoterHistoryEntry {
                proposal_id: proposal.id,
                description: proposal.description.clone(),
                status: format!("{:?}", proposal.status),
                option: v.option,
                voted_at: v.voted_at,
                power: v.power,
            });
        }
    }

    Ok(HttpResponse::Ok().json(ApiResponse::success(history, trace)))
}

#[derive(Deserialize)]
pub struct VoterHistoryQuery {
    #[serde(default)]
    pub voter: String,
}

#[derive(Serialize)]
struct VoterHistoryEntry {
    proposal_id: u64,
    description: String,
    status: String,
    option: VoteOption,
    voted_at: u64,
    power: u64,
}

/// GET /api/v1/governance/proposals/{id}/tally — uses real total staked from StakingManager
#[get("/governance/proposals/{id}/tally")]
pub async fn tally_governance_votes(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();

    let vote_store = match &state.vote_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };

    let registry = match &state.param_registry {
        Some(r) => r,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };
    let quorum = registry.get_u64("quorum_percent", 33);
    let threshold = registry.get_u64("pass_threshold_percent", 67);

    // Real total staked from StakingManager
    let total_staked = total_staked_power(&state).max(1); // avoid div by zero

    let tally = vote_store.tally(id, total_staked, quorum, threshold);

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        TallyResponse {
            proposal_id: tally.proposal_id,
            yes_power: tally.yes_power,
            no_power: tally.no_power,
            abstain_power: tally.abstain_power,
            total_voted_power: tally.total_voted_power,
            total_staked_power: tally.total_staked_power,
            quorum_reached: tally.quorum_reached,
            passed: tally.passed,
        },
        trace,
    )))
}

/// POST /api/v1/governance/proposals/{id}/execute — applies param changes to ParamRegistry
#[post("/governance/proposals/{id}/execute")]
pub async fn execute_governance_proposal(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();

    let proposal_store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };

    let current_height = chain_height(&state);

    match proposal_store.mark_executed(id, current_height) {
        Ok(proposal) => {
            // Apply parameter changes to the live registry
            if let ProposalAction::ParamChange { ref changes } = proposal.action {
                if let Some(registry) = &state.param_registry {
                    for (key, value) in changes {
                        registry.set(key, value.clone());
                    }
                }
            }
            persist_proposal(&state, &proposal);
            Ok(HttpResponse::Ok().json(ApiResponse::success(proposal, trace)))
        }
        Err(e) => {
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400)))
        }
    }
}

/// POST /api/v1/governance/delegate — delegate voting power
#[post("/governance/delegate")]
pub async fn delegate_vote(
    state: web::Data<AppState>,
    body: web::Json<DelegateRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    // ── Input validation ──
    if let Err(e) = validate_bounded("delegator", &body.delegator, MAX_VOTER_LEN) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
    }
    if let Err(e) = validate_bounded("delegate", &body.delegate, MAX_VOTER_LEN) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
    }

    let vote_store = match &state.vote_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };

    match vote_store.delegate(&body.delegator, &body.delegate) {
        Ok(()) => {
            #[derive(Serialize)]
            struct DelegationResult {
                delegator: String,
                delegate: String,
            }
            Ok(HttpResponse::Ok().json(ApiResponse::success(
                DelegationResult {
                    delegator: body.delegator.clone(),
                    delegate: body.delegate.clone(),
                },
                trace,
            )))
        }
        Err(e) => {
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400)))
        }
    }
}

/// POST /api/v1/governance/proposals/{id}/veto — emergency veto by authorized address
#[post("/governance/proposals/{id}/veto")]
pub async fn veto_governance_proposal(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<VetoRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();

    // ── Input validation ──
    if let Err(e) = validate_bounded("caller", &body.caller, MAX_VOTER_LEN) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e, 400)));
    }

    let proposal_store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };

    // Item 11: Only admin-role orgs can veto (msp_id containing "admin")
    let authorized: Vec<String> = if let Some(org_reg) = &state.org_registry {
        org_reg
            .list_orgs()
            .unwrap_or_default()
            .iter()
            .filter(|o| o.msp_id.to_lowercase().contains("admin"))
            .map(|o| o.msp_id.clone())
            .collect()
    } else {
        vec![]
    };

    let current_height = chain_height(&state);

    match proposal_store.emergency_veto(id, &body.caller, &authorized, current_height) {
        Ok(proposal) => {
            persist_proposal(&state, &proposal);
            Ok(HttpResponse::Ok().json(ApiResponse::success(proposal, trace)))
        }
        Err(e) => {
            Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400)))
        }
    }
}

/// POST /api/v1/governance/proposals/{id}/close — tally votes, mark passed or rejected
///
/// Item 7: This endpoint closes voting after the voting period ends.
/// It tallies the votes, checks quorum + threshold, and transitions the
/// proposal to Passed (with timelock) or Rejected (with deposit refund).
///
/// Item 9: Vote change is intentionally not supported. Once cast, a vote
/// is final. This prevents last-minute vote manipulation and simplifies
/// audit trails. Voters should undelegate and re-evaluate before voting.
#[post("/governance/proposals/{id}/close")]
pub async fn close_governance_voting(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();

    let proposal_store = match &state.proposal_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };

    let vote_store = match &state.vote_store {
        Some(s) => s,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };
    let registry = match &state.param_registry {
        Some(r) => r,
        None => {
            return Ok(
                HttpResponse::ServiceUnavailable().json(ApiResponse::<()>::error(
                    err_dto("governance not configured"),
                    503,
                )),
            )
        }
    };
    let current_height = chain_height(&state);

    let quorum = registry.get_u64("quorum_percent", 33);
    let threshold = registry.get_u64("pass_threshold_percent", 67);
    let timelock = registry.get_u64("timelock_blocks", 5_760);
    let total_staked = total_staked_power(&state).max(1);

    let tally = vote_store.tally(id, total_staked, quorum, threshold);

    if tally.passed {
        match proposal_store.mark_passed(id, current_height, timelock) {
            Ok(()) => {
                let proposal = proposal_store.get(id);
                if let Some(ref p) = proposal {
                    persist_proposal(&state, p);
                }
                Ok(HttpResponse::Ok().json(ApiResponse::success(proposal, trace)))
            }
            Err(e) => Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400))),
        }
    } else {
        match proposal_store.mark_rejected(id, current_height) {
            Ok(()) => {
                let proposal = proposal_store.get(id);
                if let Some(ref p) = proposal {
                    persist_proposal(&state, p);
                }
                Ok(HttpResponse::Ok().json(ApiResponse::success(proposal, trace)))
            }
            Err(e) => Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto(&e.to_string()), 400))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    fn make_app_data() -> web::Data<AppState> {
        web::Data::new(AppState::test_default())
    }

    // ── submit_governance_proposal: input validation ──────────────────

    #[actix_web::test]
    async fn submit_rejects_empty_proposer() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals")
            .set_json(serde_json::json!({
                "proposer": "",
                "description": "test",
                "deposit": 10000,
                "action": { "type": "text", "title": "T", "description": "D" },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "VALIDATION_ERROR");
    }

    #[actix_web::test]
    async fn submit_rejects_null_bytes_in_proposer() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals")
            .set_json(serde_json::json!({
                "proposer": "alice\u{0000}bob",
                "description": "test",
                "deposit": 10000,
                "action": { "type": "text", "title": "T", "description": "D" },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("null bytes"));
    }

    #[actix_web::test]
    async fn submit_rejects_quorum_percent_zero() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals")
            .set_json(serde_json::json!({
                "proposer": "alice",
                "description": "test",
                "deposit": 10000,
                "action": {
                    "type": "param_change",
                    "changes": [{ "key": "quorum_percent", "value": 0 }],
                },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("between 1 and 100"));
    }

    #[actix_web::test]
    async fn submit_rejects_quorum_percent_over_100() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals")
            .set_json(serde_json::json!({
                "proposer": "alice",
                "description": "test",
                "deposit": 10000,
                "action": {
                    "type": "param_change",
                    "changes": [{ "key": "quorum_percent", "value": 101 }],
                },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn submit_rejects_voting_period_zero() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals")
            .set_json(serde_json::json!({
                "proposer": "alice",
                "description": "test",
                "deposit": 10000,
                "action": {
                    "type": "param_change",
                    "changes": [{ "key": "voting_period_blocks", "value": 0 }],
                },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // ── cast_governance_vote: input validation ───────────────────────

    #[actix_web::test]
    async fn vote_rejects_empty_voter() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(cast_governance_vote)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals/1/vote")
            .set_json(serde_json::json!({
                "voter": "",
                "option": "Yes",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "VALIDATION_ERROR");
    }

    #[actix_web::test]
    async fn vote_returns_503_when_governance_not_configured() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(cast_governance_vote)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals/9999/vote")
            .set_json(serde_json::json!({
                "voter": "alice",
                "option": "Yes",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 503);
    }

    // ── get_governance_proposal: not found ───────────────────────────

    #[actix_web::test]
    async fn get_proposal_not_found() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(get_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/governance/proposals/9999")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ── list_governance_proposals: invalid status ────────────────────

    #[actix_web::test]
    async fn list_proposals_returns_empty_when_not_configured() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(list_governance_proposals)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/governance/proposals")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    // ── veto: input validation ──────────────────────────────────────

    #[actix_web::test]
    async fn veto_rejects_empty_caller() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(veto_governance_proposal)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/governance/proposals/1/veto")
            .set_json(serde_json::json!({ "caller": "" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    // ── voter_history: missing voter param ──────────────────────────

    #[actix_web::test]
    async fn voter_history_rejects_empty_voter() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(get_voter_history)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/governance/votes?voter=")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
}
