//! Legacy API router — all handlers migrated to `api::handlers::*`.
//!
//! This module only provides `config_routes` which creates the `/api/v1` scope
//! and delegates to `ApiRoutes::register` for all endpoint registration.

use actix_web::web;

/// Configures the `/api/v1` scope with all scaffold routes.
/// Also registers OID4VCI/VP endpoints at the root level (EUDI Wallet expects
/// /.well-known/openid-credential-issuer, /token, /nonce, /credential at root).
pub fn config_routes(cfg: &mut web::ServiceConfig) {
    use crate::api::handlers::{issuers, oid4vci, oid4vp, security_txt};

    let scope = crate::api::routes::ApiRoutes::register(web::scope("/api/v1"));
    cfg.service(scope);

    cfg.service(security_txt::security_txt);

    // OID4VCI endpoints at root (EUDI wallet standard paths)
    cfg.service(oid4vci::issuer_metadata)
        .service(oid4vci::oauth_as_metadata)
        .service(oid4vci::token_endpoint)
        .service(oid4vci::credential_endpoint)
        .service(oid4vci::deferred_credential_endpoint)
        .service(oid4vci::nonce_endpoint)
        .service(oid4vci::credential_offer_endpoint)
        .service(oid4vci::credential_offer_get)
        .route(
            "/.well-known/jwt-vc-issuer/api/v1/issuers/{did}",
            web::get().to(issuers::jwt_vc_issuer_metadata),
        );

    // OID4VP at /api/v1 (already in scope above, but we also expose
    // the submit_response at root for direct_post compatibility)
    cfg.service(oid4vp::submit_response);
}
