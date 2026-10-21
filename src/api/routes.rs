use actix_web::{web, Scope};

#[cfg(feature = "evm")]
use crate::api::handlers::evm;
use crate::api::handlers::{
    acl, airdrop, alias, audit, billing, blocks, bridge, certificates, chain, chaincode, channels,
    compliance, compliance_auto, contact, contracts, credentials, crl, discovery, events, forensic,
    gateway, governance, governance_entities, identity, inference, intelligence, interop,
    invitations, legal_oracle, lexchain, msp, network, notarize, ocsp, oid4vci, oid4vp, oracle,
    organizations, pentest, pin, policy, private_data, proposals, ra, registry, regulatory,
    savings, snapshots, staking, stats, stress, stripe, tokenization, tokenomics, transactions,
    tsa, tsl, utilities, vault, wallets, zkp,
};

/// API routes configuration
pub struct ApiRoutes;

impl ApiRoutes {
    /// Full configuration: metrics + standalone `/api/v1` scope with scaffold routes.
    /// Used by integration tests that don't load the legacy router.
    pub fn configure(cfg: &mut web::ServiceConfig) {
        Self::configure_metrics(cfg);
        cfg.service(Self::register(web::scope("/api/v1")));
    }

    /// Only register the `/metrics` endpoint (used in production where legacy
    /// router owns the `/api/v1` scope and calls `ApiRoutes::register`).
    pub fn configure_metrics(cfg: &mut web::ServiceConfig) {
        cfg.service(utilities::get_metrics)
            .route("/swagger", web::get().to(utilities::swagger_ui));
    }

    /// Register all scaffold routes into an existing `/api/v1` scope.
    ///
    /// Uses `configure()` closures to break the type chain and avoid
    /// stack overflow from deeply nested Actix generic wrappers.
    pub fn register(scope: Scope) -> Scope {
        scope
            // Sub-scoped (have their own path prefix)
            .service(Self::blocks_routes())
            .service(Self::store_blocks_routes())
            .service(Self::chain_routes())
            .service(Self::credentials_routes())
            // Break the chain with configure() to limit generic nesting depth
            .configure(Self::register_store_handlers)
            .configure(Self::register_tx_handlers)
            .configure(Self::register_infra_handlers)
    }

    fn register_store_handlers(cfg: &mut web::ServiceConfig) {
        cfg.service(transactions::store_write_transaction)
            .service(transactions::store_get_transaction)
            .service(identity::create_identity)
            .service(identity::resolve_by_document)
            .service(identity::revoke_identity)
            .service(identity::get_identity_methods)
            .service(identity::store_write_identity)
            .service(identity::store_list_identities)
            .service(identity::store_get_identity)
            .service(identity::auth_challenge)
            .service(identity::auth_verify)
            .service(credentials::store_write_credential)
            .service(credentials::store_list_credentials)
            .service(credentials::store_get_credential)
            .service(credentials::store_get_credentials_by_subject)
            .service(credentials::store_get_credentials_by_issuer)
            .service(organizations::store_create_organization)
            .service(organizations::store_list_organizations)
            .service(organizations::store_get_organization)
            .service(organizations::store_set_policy)
            .service(organizations::store_get_policy)
            // Governance entities (Cerulean Voto)
            .service(governance_entities::create_scope)
            .service(governance_entities::list_scopes)
            .service(governance_entities::get_scope)
            .service(governance_entities::update_scope)
            .service(governance_entities::remove_scope)
            .service(governance_entities::create_assembly)
            .service(governance_entities::list_assemblies)
            .service(governance_entities::get_assembly)
            .service(governance_entities::update_assembly)
            .service(governance_entities::remove_assembly)
            .service(governance_entities::create_session)
            .service(governance_entities::list_sessions)
            .service(governance_entities::get_session)
            .service(governance_entities::update_session)
            .service(governance_entities::remove_session)
            .service(governance_entities::create_acta)
            .service(governance_entities::list_actas)
            .service(governance_entities::get_acta)
            .service(governance_entities::update_acta)
            .service(governance_entities::remove_acta)
            // Asset Registry
            .service(registry::create_asset)
            .service(registry::list_assets)
            .service(registry::get_asset)
            .service(registry::update_asset)
            .service(registry::remove_asset)
            .service(registry::create_asset_event)
            .service(registry::create_asset_events_batch)
            .service(registry::list_asset_events)
            .service(registry::get_asset_event)
            .service(registry::export_asset)
            // RWA Tokenization
            .service(tokenization::create_token)
            .service(tokenization::list_tokens)
            .service(tokenization::get_token)
            .service(tokenization::update_token)
            .service(tokenization::remove_token)
            // Compliance Automation
            .service(compliance_auto::create_rule)
            .service(compliance_auto::list_rules)
            .service(compliance_auto::get_rule)
            .service(compliance_auto::remove_rule)
            .service(compliance_auto::evaluate_asset)
            .service(compliance_auto::get_results);
    }

    fn register_tx_handlers(cfg: &mut web::ServiceConfig) {
        cfg.service(transactions::create_transaction)
            .service(savings::lock_savings)
            .service(savings::release_savings)
            .service(savings::list_savings)
            .service(transactions::get_mempool)
            .service(transactions::get_tx_by_id)
            .service(blocks::explorer_list_blocks)
            .service(blocks::explorer_get_block)
            .service(proposals::submit_proposal)
            .service(proposals::submit_endorsed_transaction)
            .service(channels::create_channel)
            .service(channels::list_channels)
            .service(channels::update_channel_config)
            .service(channels::get_channel_config)
            .service(channels::get_channel_config_history)
            .service(msp::revoke_serial)
            .service(msp::get_msp_info)
            .service(gateway::gateway_submit);
    }

    fn register_infra_handlers(cfg: &mut web::ServiceConfig) {
        cfg.service(private_data::register_collection)
            .service(private_data::put_private_data)
            .service(private_data::get_private_data)
            .service(chaincode::install_chaincode)
            .service(chaincode::approve_chaincode)
            .service(chaincode::commit_chaincode)
            .service(chaincode::simulate_chaincode)
            .service(chaincode::invoke_chaincode)
            .service(chaincode::get_sandbox_report)
            .service(discovery::get_endorsers)
            .service(discovery::get_channel_peers)
            .service(discovery::post_register_peer)
            .service(events::events_blocks)
            .service(events::events_blocks_filtered)
            .service(events::events_blocks_private)
            .service(acl::set_acl)
            .service(acl::list_acls)
            .service(acl::get_acl)
            .service(snapshots::create_snapshot)
            .service(snapshots::list_snapshots)
            .service(snapshots::download_snapshot)
            .service(audit::list_audit_entries)
            .service(audit::export_audit_csv);
        #[cfg(feature = "evm")]
        cfg.service(evm::evm_deploy)
            .service(evm::evm_call)
            .service(evm::evm_static_call)
            .service(evm::evm_list_contracts);
        cfg.service(governance::list_params)
            .service(governance::submit_governance_proposal)
            .service(governance::list_governance_proposals)
            .service(governance::get_governance_proposal)
            .service(governance::cast_governance_vote)
            .service(governance::get_governance_votes)
            .service(governance::get_voter_history)
            .service(governance::tally_governance_votes)
            .service(governance::execute_governance_proposal)
            .service(governance::delegate_vote)
            .service(governance::veto_governance_proposal)
            .service(governance::close_governance_voting)
            .service(pin::generate_pin)
            .service(pin::verify_pin);
        // Commitment-based attribute verification
        cfg.service(zkp::prove_commitment)
            .service(zkp::verify_commitment);
        // Oracle, forensic, compliance
        cfg.service(oracle::get_oracle_feed)
            .service(oracle::list_oracle_feeds)
            .service(oracle::list_oracle_nodes)
            .service(oracle::oracle_status)
            .service(oracle::register_oracle);
        // Legal oracle
        cfg.service(legal_oracle::query_legal_oracle)
            .service(legal_oracle::list_legal_oracle_records)
            .service(legal_oracle::get_legal_oracle_record)
            .service(forensic::forensic_timeline)
            .service(forensic::forensic_security)
            .service(forensic::forensic_export)
            .service(forensic::forensic_replay)
            .service(forensic::forensic_integrity)
            .service(intelligence::detect_anomalies)
            .service(intelligence::evaluate_risk)
            .service(intelligence::detect_patterns)
            .service(compliance::validate_pacs008)
            .service(compliance::validate_pacs002)
            .service(compliance::validate_pacs004)
            .service(compliance::validate_pain001)
            .service(compliance::validate_pain002)
            .service(compliance::validate_camt053)
            .service(compliance::validate_camt052)
            .service(compliance::list_countries)
            .service(compliance::list_currencies)
            .service(contact::submit_contact)
            .service(contact::list_contacts)
            .service(regulatory::run_checks)
            .service(regulatory::compliance_report)
            .service(stress::stress_report)
            .service(pentest::pentest_report);
        // W3C interoperability (DID Resolution, JSON-LD export)
        // Note: get_credential_as_vc is registered in credentials_routes() scope
        cfg.service(interop::resolve_did)
            .service(interop::export_governance_jsonld);
        // Vault (encrypted wallet backup + recovery)
        cfg.service(vault::vault_store)
            .service(vault::vault_get)
            .service(vault::vault_recover);
        // Bridge (cross-chain transfers)
        cfg.service(bridge::initiate_transfer)
            .service(bridge::process_inbound)
            .service(bridge::get_transfer_status)
            .service(bridge::list_chains)
            .service(bridge::get_balances);
        // Inference (Optimistic ML Oracle)
        cfg.service(inference::submit_inference)
            .service(inference::submit_proven)
            .service(inference::challenge_inference)
            .service(inference::finalize_inference)
            .service(inference::list_claims)
            .service(inference::get_claim)
            .service(inference::list_models);
        // Staking (validator registration, unstaking, queries)
        cfg.service(staking::get_validators)
            .service(staking::get_validator)
            .service(staking::get_my_stake);
        // Tokenomics (supply, fees, inflation)
        cfg.service(tokenomics::supply)
            .service(tokenomics::fee)
            .service(tokenomics::inflation);
        // Alias registry (zero-knowledge alias system)
        cfg.service(alias::alias_register)
            .service(alias::alias_resolve)
            .service(alias::alias_by_did)
            .service(alias::alias_revoke);
        // Notarization (Proof of Existence)
        cfg.service(notarize::notarize_pdf)
            .service(notarize::submit_notarization)
            .service(notarize::verify_notarization)
            .service(notarize::verify_document)
            .service(notarize::verify_raw_document)
            .service(notarize::get_notarization)
            .service(notarize::list_notarizations)
            .service(notarize::transfer_document)
            .service(notarize::get_document_owner)
            .service(notarize::get_document_provenance)
            .service(notarize::sign_fea)
            .service(notarize::sign_fes_bulk)
            .service(notarize::verify_fes_bulk);
        // TSA (Time Stamping Authority — RFC 3161)
        cfg.service(tsa::request_timestamp)
            .service(tsa::request_timestamp_der)
            .service(tsa::tsa_policy)
            .service(tsa::verify_timestamp);
        // LexChain (legal contract engine)
        cfg.service(lexchain::deploy_contract)
            .service(lexchain::sign_contract)
            .service(lexchain::list_templates)
            .service(lexchain::list_contracts)
            .service(lexchain::get_contract);
        // Registration Authority (Ley 19.799 Art. 15)
        cfg.service(ra::submit_proof)
            .service(ra::approve_proof)
            .service(ra::reject_proof)
            .service(ra::get_proof_status)
            .service(ra::verify_identity);
        // CP/CPS Policy (RFC 3647 / ETSI TS 102 042)
        cfg.service(policy::get_cp)
            .service(policy::get_cps)
            .service(policy::get_cp_document)
            .service(policy::get_cps_document)
            .service(policy::get_oids);
        // OCSP Responder (RFC 6960)
        cfg.service(ocsp::ocsp_query)
            .service(ocsp::ocsp_query_der)
            .service(ocsp::ocsp_status);
        // CRL Distribution Point (RFC 5280 §5)
        cfg.service(crl::get_crl_der).service(crl::get_crl_pem);
        // FEA Certificate Issuance & Revocation (Ley 19.799 / EA-103)
        cfg.service(certificates::issue_fea_cert)
            .service(certificates::revoke_fea_cert);
        // Trust Service List (ETSI TS 119 612)
        cfg.service(tsl::get_tsl);
        // OpenID4VCI (EUDI Wallet credential issuance)
        cfg.service(oid4vci::issuer_metadata)
            .service(oid4vci::oauth_as_metadata)
            .service(oid4vci::jwt_vc_issuer_metadata)
            .service(oid4vci::par_endpoint)
            .service(oid4vci::authorize_endpoint)
            .service(oid4vci::token_endpoint)
            .service(oid4vci::credential_endpoint)
            .service(oid4vci::nonce_endpoint)
            .service(oid4vci::credential_offer_endpoint)
            .service(oid4vci::credential_offer_get)
            .service(oid4vci::status_list_endpoint);
        // OpenID4VP (EUDI Wallet credential presentation)
        cfg.service(oid4vp::register_rp)
            .service(oid4vp::list_rps)
            .service(oid4vp::create_request)
            .service(oid4vp::get_request)
            .service(oid4vp::submit_response);
        // Invitations (governance proposal invitations via alias)
        cfg.service(invitations::create_invitation)
            .service(invitations::list_invitations)
            .service(invitations::respond_invitation);
        // Contracts (ERC-20 + NFT/ERC-721)
        cfg.service(contracts::deploy_contract_debug)
            .service(contracts::deploy_contract)
            .service(contracts::get_all_contracts)
            .service(contracts::get_contract)
            .service(contracts::execute_contract_function)
            .service(contracts::get_contract_balance)
            .service(contracts::get_contract_allowance)
            .service(contracts::get_contract_total_supply)
            .service(contracts::get_nft_owner)
            .service(contracts::get_nft_token_uri)
            .service(contracts::get_nft_approved)
            .service(contracts::get_nft_metadata)
            .service(contracts::set_nft_metadata)
            .service(contracts::get_nft_balance)
            .service(contracts::get_nft_total_supply)
            .service(contracts::get_nft_tokens_of_owner)
            .service(contracts::get_nft_token_by_index);
        // Airdrop
        cfg.service(airdrop::get_node_tracking)
            .service(airdrop::get_airdrop_statistics)
            .service(airdrop::get_eligible_nodes)
            .service(airdrop::get_eligibility_info)
            .service(airdrop::get_claim_history)
            .service(airdrop::get_airdrop_tiers);
        // Stats
        cfg.service(stats::get_stats);
        // Network (peers, sync, mine)
        cfg.service(network::get_peers)
            .service(network::connect_peer)
            .service(network::sync_blockchain)
            .service(network::mine_block);
        // Accounts (wallet-compatible balance + nonce)
        cfg.service(wallets::get_account);
        // Wallets (balance, creation, tx history)
        cfg.service(wallets::get_wallet_balance)
            .service(wallets::create_wallet)
            .service(wallets::get_wallet_transactions);
        // Billing (API key management)
        cfg.service(billing::create_api_key)
            .service(billing::deactivate_api_key)
            .service(billing::get_billing_usage);
        // Stripe (checkout, webhook)
        cfg.service(stripe::create_checkout)
            .service(stripe::stripe_webhook);
        // Utilities (health, version, openapi)
        cfg.route("/health", web::get().to(utilities::health_check))
            .route("/version", web::get().to(utilities::get_version))
            .route("/openapi.json", web::get().to(utilities::get_openapi));
    }

    fn blocks_routes() -> Scope {
        web::scope("/blocks")
            .service(blocks::create_block)
            .service(blocks::list_blocks)
            .service(blocks::get_block_by_index)
            .service(blocks::get_block_by_hash)
    }

    fn store_blocks_routes() -> Scope {
        web::scope("/store/blocks")
            .service(blocks::store_list_blocks)
            .service(blocks::store_latest_height)
            .service(blocks::store_get_block)
            .service(transactions::store_get_transactions_by_block)
    }

    fn chain_routes() -> Scope {
        web::scope("/chain")
            .service(chain::verify_chain)
            .service(chain::get_blockchain_info)
    }

    fn credentials_routes() -> Scope {
        web::scope("/credentials").service(interop::get_credential_as_vc)
    }
}

/// Light client routes — Starter tier only.
///
/// Exposes: notarization, identity, credentials, audit, chain info,
/// commitment verification, health, version, and openapi. Everything else is excluded.
pub struct LightRoutes;

impl LightRoutes {
    /// Full configuration for light mode: metrics + restricted `/api/v1` scope.
    pub fn configure(cfg: &mut web::ServiceConfig) {
        ApiRoutes::configure_metrics(cfg);
        cfg.service(Self::register(web::scope("/api/v1")));
    }

    /// Register only Starter-tier routes into an `/api/v1` scope.
    pub fn register(scope: Scope) -> Scope {
        scope
            .service(Self::chain_routes())
            .service(Self::credentials_routes())
            .configure(Self::register_starter_handlers)
    }

    fn register_starter_handlers(cfg: &mut web::ServiceConfig) {
        // Identity (DID management)
        cfg.service(identity::store_write_identity)
            .service(identity::store_list_identities)
            .service(identity::store_get_identity)
            .service(identity::migrate_did)
            .service(identity::auth_challenge)
            .service(identity::auth_verify);
        // Tokenomics
        cfg.service(tokenomics::supply)
            .service(tokenomics::fee)
            .service(tokenomics::inflation);
        // Credentials (VCs)
        cfg.service(credentials::store_write_credential)
            .service(credentials::store_list_credentials)
            .service(credentials::store_get_credential)
            .service(credentials::store_get_credentials_by_subject)
            .service(credentials::store_get_credentials_by_issuer)
            .service(credentials::erase_claims);
        // Notarization (Proof of Existence)
        cfg.service(notarize::notarize_pdf)
            .service(notarize::submit_notarization)
            .service(notarize::verify_notarization)
            .service(notarize::verify_document)
            .service(notarize::verify_raw_document)
            .service(notarize::get_notarization)
            .service(notarize::list_notarizations)
            .service(notarize::transfer_document)
            .service(notarize::get_document_owner)
            .service(notarize::get_document_provenance)
            .service(notarize::sign_fea)
            .service(notarize::sign_fes_bulk)
            .service(notarize::verify_fes_bulk);
        // Audit trail
        cfg.service(audit::list_audit_entries)
            .service(audit::export_audit_csv);
        // Commitment-based attribute verification
        cfg.service(zkp::prove_commitment)
            .service(zkp::verify_commitment);
        // W3C interop
        cfg.service(interop::resolve_did);
        // Alias
        cfg.service(alias::alias_register)
            .service(alias::alias_resolve)
            .service(alias::alias_by_did)
            .service(alias::alias_revoke);
        // Utilities (health, version, openapi)
        cfg.route("/health", web::get().to(utilities::health_check))
            .route("/version", web::get().to(utilities::get_version))
            .route("/openapi.json", web::get().to(utilities::get_openapi));
    }

    fn chain_routes() -> Scope {
        web::scope("/chain")
            .service(chain::verify_chain)
            .service(chain::get_blockchain_info)
    }

    fn credentials_routes() -> Scope {
        web::scope("/credentials").service(interop::get_credential_as_vc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_structs_are_zst() {
        assert_eq!(std::mem::size_of::<ApiRoutes>(), 0);
        assert_eq!(std::mem::size_of::<LightRoutes>(), 0);
    }
}
