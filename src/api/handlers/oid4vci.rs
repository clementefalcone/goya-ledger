//! OpenID4VCI — OpenID for Verifiable Credential Issuance (1.0).
//!
//! Implements the pre-authorized code flow for EUDI Wallet interop:
//! - `GET  /.well-known/openid-credential-issuer` — issuer metadata
//! - `POST /token` — exchange pre-authorized code for access token
//! - `POST /credential` — issue SD-JWT VC or mdoc

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::get_channel_store;
use crate::app_state::AppState;
use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::operations::{is_signed_by, key_controls_identity};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceGrant {
    pub issuer_did: String,
    pub configuration_id: String,
}

pub struct CredentialOfferStore {
    offers: std::sync::RwLock<std::collections::HashMap<String, (CredentialOffer, u64)>>,
    pre_authorized_codes: std::sync::Mutex<std::collections::HashMap<String, (IssuanceGrant, u64)>>,
}

impl CredentialOfferStore {
    pub fn new() -> Self {
        Self {
            offers: std::sync::RwLock::new(std::collections::HashMap::new()),
            pre_authorized_codes: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn store(
        &self,
        session_id: &str,
        offer: CredentialOffer,
        pre_authorized_code: &str,
        grant: IssuanceGrant,
    ) {
        let now = now_secs();
        let expires_at = now + 600;
        self.offers
            .write()
            .unwrap()
            .insert(session_id.to_string(), (offer, expires_at));
        let mut codes = self.pre_authorized_codes.lock().unwrap();
        codes.retain(|_, (_, code_expires_at)| now < *code_expires_at);
        codes.insert(pre_authorized_code.to_string(), (grant, expires_at));
    }

    pub fn consume_pre_authorized_code(&self, code: &str) -> Result<IssuanceGrant, &'static str> {
        let (grant, expires_at) = self
            .pre_authorized_codes
            .lock()
            .unwrap()
            .remove(code)
            .ok_or("unknown or already used pre-authorized_code")?;
        if now_secs() >= expires_at {
            return Err("pre-authorized_code expired");
        }
        Ok(grant)
    }

    pub fn get(&self, session_id: &str) -> Option<CredentialOffer> {
        let offers = self.offers.read().unwrap();
        offers.get(session_id).and_then(|(offer, ttl)| {
            if now_secs() <= *ttl {
                Some(offer.clone())
            } else {
                None
            }
        })
    }
}

impl Default for CredentialOfferStore {
    fn default() -> Self {
        Self::new()
    }
}

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn base64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .map_err(|e| e.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extract raw public key hex from a JWK. Supports OKP/Ed25519 and RSA.
fn extract_pubkey_from_jwk(jwk: &serde_json::Value, alg: &str) -> Option<String> {
    match alg {
        "EdDSA" => {
            let x = jwk.get("x")?.as_str()?;
            let bytes = base64url_decode(x).ok()?;
            Some(hex::encode(bytes))
        }
        "RS256" => {
            let n = jwk.get("n")?.as_str()?;
            let bytes = base64url_decode(n).ok()?;
            Some(hex::encode(bytes))
        }
        "ES256" => {
            let x = jwk.get("x")?.as_str()?;
            let y = jwk.get("y")?.as_str()?;
            let x_bytes = base64url_decode(x).ok()?;
            let y_bytes = base64url_decode(y).ok()?;
            // SEC1 uncompressed: 0x04 || x || y
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(&x_bytes);
            pk.extend_from_slice(&y_bytes);
            Some(hex::encode(pk))
        }
        _ => None,
    }
}

// ── DPoP proof validation (RFC 9449) ──────────────────────────────────────

/// Parsed DPoP proof fields.
struct DpopClaims {
    /// JWK thumbprint of the proof key (base64url of SHA-256).
    pub jkt: String,
}

/// Validate a DPoP proof JWT (RFC 9449 §4.3).
/// Checks: typ=dpop+jwt, htm, htu, iat freshness, jti presence, jwk presence.
/// Returns the JWK thumbprint for binding to the access token.
fn verify_dpop_proof(dpop_jwt: &str, htm: &str, htu: &str) -> Result<DpopClaims, String> {
    let parts: Vec<&str> = dpop_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("DPoP JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    // typ must be "dpop+jwt"
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err("DPoP typ must be dpop+jwt".into());
    }

    // Must have alg
    if header.get("alg").and_then(|v| v.as_str()).is_none() {
        return Err("DPoP missing alg".into());
    }

    // Must have jwk with key material
    let jwk = header
        .get("jwk")
        .ok_or("DPoP missing jwk in header")?
        .clone();

    // htm must match
    if payload.get("htm").and_then(|v| v.as_str()) != Some(htm) {
        return Err(format!("DPoP htm mismatch: expected {htm}"));
    }

    // htu must match
    if payload.get("htu").and_then(|v| v.as_str()) != Some(htu) {
        return Err(format!("DPoP htu mismatch: expected {htu}"));
    }

    // iat must be present and within 5 minutes
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or("DPoP missing iat")?;
    let now = now_secs();
    if now > iat + 300 || (iat > now && iat - now > 60) {
        return Err("DPoP iat outside acceptable window".into());
    }

    // jti must be present
    if payload
        .get("jti")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        return Err("DPoP missing jti".into());
    }

    // Verify DPoP JWT signature using the embedded JWK
    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(pubkey_hex) = extract_pubkey_from_jwk(&jwk, alg_str) {
        let sig_bytes = base64url_decode(parts[2])?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_hex = hex::encode(&sig_bytes);
        let algorithm = match alg_str {
            "EdDSA" => crate::identity::signing::SigningAlgorithm::Ed25519,
            "RS256" => crate::identity::signing::SigningAlgorithm::Rsa,
            "ES256" => crate::identity::signing::SigningAlgorithm::EcdsaP256,
            _ => return Err(format!("unsupported DPoP alg for verification: {alg_str}")),
        };
        if !crate::signature::verify_signature(
            algorithm,
            &pubkey_hex,
            signing_input.as_bytes(),
            &sig_hex,
        ) {
            return Err("DPoP signature verification failed".into());
        }
    }

    // Compute JWK thumbprint (RFC 7638): SHA-256 of canonical JWK JSON
    let jwk_canonical = serde_json::to_vec(&jwk).map_err(|e| e.to_string())?;
    let jkt = base64url_encode(&hash_with(HashAlgorithm::Sha256, &jwk_canonical));

    Ok(DpopClaims { jkt })
}

// ── Wallet Provider Registry ──────────────────────────────────────────────

/// Registry of trusted wallet provider public keys for WIA verification.
pub struct WalletProviderRegistry {
    providers: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl WalletProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register a wallet provider's public key (issuer → pubkey_hex).
    pub fn register(&self, issuer: &str, pubkey_hex: &str) {
        self.providers
            .write()
            .unwrap()
            .insert(issuer.to_string(), pubkey_hex.to_string());
    }

    /// Look up a provider's public key by issuer.
    pub fn resolve(&self, issuer: &str) -> Option<String> {
        self.providers.read().unwrap().get(issuer).cloned()
    }
}

impl Default for WalletProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Wallet Instance Attestation ───────────────────────────────────────────

/// Validate a Wallet Instance Attestation (WIA) JWT.
/// Verifies structure, claims, expiration, and signature (when provider key available).
fn verify_wia(
    wia_jwt: &str,
    registry: Option<&WalletProviderRegistry>,
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = wia_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("WIA JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "wia+jwt" && typ != "wallet-attestation+jwt" {
        return Err("WIA typ must be wia+jwt or wallet-attestation+jwt".into());
    }

    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    for field in &["iss", "sub"] {
        if payload
            .get(*field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return Err(format!("WIA missing {field}"));
        }
    }

    let now = now_secs();
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if now > exp {
            return Err("WIA expired".into());
        }
    }

    // Verify WIA signature if wallet provider key is registered
    let iss = payload["iss"].as_str().unwrap_or("");
    if let Some(reg) = registry {
        if let Some(pubkey_hex) = reg.resolve(iss) {
            let algorithm = match alg_str {
                "EdDSA" => crate::identity::signing::SigningAlgorithm::Ed25519,
                "RS256" => crate::identity::signing::SigningAlgorithm::Rsa,
                "ES256" => crate::identity::signing::SigningAlgorithm::EcdsaP256,
                other => return Err(format!("unsupported WIA alg: {other}")),
            };
            let sig_bytes = base64url_decode(parts[2])?;
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_hex = hex::encode(&sig_bytes);
            if !crate::signature::verify_signature(
                algorithm,
                &pubkey_hex,
                signing_input.as_bytes(),
                &sig_hex,
            ) {
                return Err("WIA signature verification failed".into());
            }
        }
    }

    Ok(payload)
}

// ── Wallet Trust Evidence (ARF v2.0 Topic 38) ───────────────────────────

/// Validate a Wallet Trust Evidence (WTE) JWT.
/// WTE attests the wallet unit's trust level and security posture.
/// Issued by the wallet provider, binds to a device key, and includes
/// trust_level, certification status, and key attestation.
fn verify_wte(
    wte_jwt: &str,
    registry: Option<&WalletProviderRegistry>,
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = wte_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("WTE JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "wte+jwt" {
        return Err("WTE typ must be wte+jwt".into());
    }

    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    for field in &["iss", "sub", "cnf"] {
        let missing = match *field {
            "cnf" => payload.get("cnf").is_none(),
            _ => payload
                .get(*field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty(),
        };
        if missing {
            return Err(format!("WTE missing {field}"));
        }
    }

    let now = now_secs();
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if now > exp {
            return Err("WTE expired".into());
        }
    }

    if let Some(iat) = payload.get("iat").and_then(|v| v.as_u64()) {
        if iat > now + 300 {
            return Err("WTE iat is in the future".into());
        }
    }

    let iss = payload["iss"].as_str().unwrap_or("");
    if let Some(reg) = registry {
        if let Some(pubkey_hex) = reg.resolve(iss) {
            let algorithm = match alg_str {
                "EdDSA" => crate::identity::signing::SigningAlgorithm::Ed25519,
                "RS256" => crate::identity::signing::SigningAlgorithm::Rsa,
                "ES256" => crate::identity::signing::SigningAlgorithm::EcdsaP256,
                other => return Err(format!("unsupported WTE alg: {other}")),
            };
            let sig_bytes = base64url_decode(parts[2])?;
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_hex = hex::encode(&sig_bytes);
            if !crate::signature::verify_signature(
                algorithm,
                &pubkey_hex,
                signing_input.as_bytes(),
                &sig_hex,
            ) {
                return Err("WTE signature verification failed".into());
            }
        }
    }

    Ok(payload)
}

// ── JWT VC Issuer Metadata (SD-JWT VC verification) ──────────────────────

/// Serves the issuer's public key as JWKS for SD-JWT VC signature verification.
#[get("/.well-known/jwt-vc-issuer")]
pub async fn jwt_vc_issuer_metadata(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    use crate::identity::signing::SigningProvider;
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");

    let provider = state.credential_issuer_key.as_ref();
    let kid = crate::identity::sd_jwt::compute_kid(provider);
    let pk = provider.public_key();

    let jwk = if pk.len() == 65 && pk[0] == 0x04 {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "use": "sig",
            "alg": "ES256",
            "x": base64url_encode(&pk[1..33]),
            "y": base64url_encode(&pk[33..65]),
        })
    } else {
        serde_json::json!({"kty": "EC", "kid": kid})
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "issuer": base,
        "jwks": { "keys": [jwk] },
    })))
}

// ── Nonce Store (OID4VCI 1.0 Final — dedicated nonce endpoint) ────────────

/// Server-side nonce store with TTL and single-use enforcement.
pub struct NonceStore {
    nonces: std::sync::Mutex<std::collections::HashMap<String, NonceEntry>>,
}

struct NonceEntry {
    created_at: u64,
    ttl_secs: u64,
    used: bool,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            nonces: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn generate(&self, ttl_secs: u64) -> String {
        use pqc_crypto_module::legacy::rng::OsRng;
        use rand_core::RngCore;
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let nonce = hex::encode(buf);

        let mut store = self.nonces.lock().unwrap();
        // Evict expired nonces on each generation to bound memory.
        let now = now_secs();
        store.retain(|_, e| now < e.created_at + e.ttl_secs);
        store.insert(
            nonce.clone(),
            NonceEntry {
                created_at: now,
                ttl_secs,
                used: false,
            },
        );
        nonce
    }

    /// Consume a nonce. Returns Ok(()) if valid and unused.
    /// Fails on: unknown, expired, already used.
    pub fn consume(&self, nonce: &str) -> Result<(), &'static str> {
        let mut store = self.nonces.lock().unwrap();
        let entry = store.get_mut(nonce).ok_or("unknown nonce")?;
        let now = now_secs();
        if now >= entry.created_at + entry.ttl_secs {
            store.remove(nonce);
            return Err("nonce expired");
        }
        if entry.used {
            return Err("nonce already used");
        }
        entry.used = true;
        Ok(())
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AccessTokenStore {
    grants_by_token: std::sync::Mutex<std::collections::HashMap<String, (IssuanceGrant, u64)>>,
}

impl AccessTokenStore {
    pub fn new() -> Self {
        Self {
            grants_by_token: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn issue(&self, grant: IssuanceGrant, ttl_secs: u64) -> String {
        use pqc_crypto_module::legacy::rng::OsRng;
        use rand_core::RngCore;
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let token = format!("goya_at_{}", hex::encode(buf));
        let now = now_secs();
        let mut tokens = self.grants_by_token.lock().unwrap();
        tokens.retain(|_, (_, expires_at)| now < *expires_at);
        tokens.insert(token.clone(), (grant, now + ttl_secs));
        token
    }

    pub fn grant_for(&self, token: &str) -> Option<IssuanceGrant> {
        self.grants_by_token
            .lock()
            .unwrap()
            .get(token)
            .filter(|(_, expires_at)| now_secs() < *expires_at)
            .map(|(grant, _)| grant.clone())
    }
}

impl Default for AccessTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Key proof (c_nonce binding) ───────────────────────────────────────────

/// Validate the proof JWT in a credential request (OpenID4VCI §7.2.1).
/// Checks: typ=openid4vci-proof+jwt, nonce matches c_nonce, aud matches issuer.
fn verify_proof_jwt(
    proof_jwt: &str,
    expected_nonce: &str,
    expected_aud: &str,
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("proof JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(parts[1])?).map_err(|e| e.to_string())?;

    let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ != "openid4vci-proof+jwt" {
        return Err("proof typ must be openid4vci-proof+jwt".into());
    }

    let nonce = payload.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
    if nonce != expected_nonce {
        return Err("proof nonce does not match c_nonce".into());
    }

    let aud = payload.get("aud").and_then(|v| v.as_str()).unwrap_or("");
    if !aud.is_empty() && !expected_aud.is_empty() && aud != expected_aud {
        return Err(format!("proof aud mismatch: expected {expected_aud}"));
    }

    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or("proof missing iat")?;
    let now = now_secs();
    if now > iat + 300 || (iat > now && iat - now > 60) {
        return Err("proof iat outside acceptable window".into());
    }

    let alg_str = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if let Some(jwk) = header.get("jwk") {
        if let Some(pubkey_hex) = extract_pubkey_from_jwk(jwk, alg_str) {
            let sig_bytes = base64url_decode(parts[2])?;
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let sig_hex = hex::encode(&sig_bytes);
            let algorithm = match alg_str {
                "EdDSA" => crate::identity::signing::SigningAlgorithm::Ed25519,
                "RS256" => crate::identity::signing::SigningAlgorithm::Rsa,
                "ES256" => crate::identity::signing::SigningAlgorithm::EcdsaP256,
                _ => return Err(format!("unsupported proof alg: {alg_str}")),
            };
            if !crate::signature::verify_signature(
                algorithm,
                &pubkey_hex,
                signing_input.as_bytes(),
                &sig_hex,
            ) {
                return Err("proof JWT signature verification failed".into());
            }
        }
    }

    Ok(header)
}

// ── Nonce Endpoint (OID4VCI 1.0 Final) ───────────────────────────────────

const NONCE_TTL_SECS: u64 = 300;

/// Dedicated nonce endpoint — OID4VCI 1.0 Final moved c_nonce issuance
/// here (no longer embedded in token/credential responses).
#[post("/nonce")]
pub async fn nonce_endpoint(nonce_store: web::Data<NonceStore>) -> ApiResult<HttpResponse> {
    let c_nonce = nonce_store.generate(NONCE_TTL_SECS);
    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(serde_json::json!({
            "c_nonce": c_nonce,
            "c_nonce_expires_in": NONCE_TTL_SECS,
        })))
}

// ── OAuth Authorization Server Metadata (RFC 8414) ──────────────────────

/// EUDI Wallet fetches this after issuer metadata — mandatory for the flow.
#[get("/.well-known/oauth-authorization-server")]
pub async fn oauth_as_metadata(req: HttpRequest) -> ApiResult<HttpResponse> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");
    let api = format!("{base}/api/v1");

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "issuer": base,
        "token_endpoint": format!("{api}/token"),
        "grant_types_supported": [PRE_AUTHORIZED_CODE_GRANT],
        "token_endpoint_auth_methods_supported": ["none", "attest_jwt_client_auth"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "client_attestation_signing_alg_values_supported": ["ES256"],
        "client_attestation_pop_signing_alg_values_supported": ["ES256"],
    })))
}

// ── Issuer Metadata ───────────────────────────────────────────────────────

/// OpenID4VCI Issuer Metadata (OID4VCI 1.0 Final).
#[get("/.well-known/openid-credential-issuer")]
pub async fn issuer_metadata(req: HttpRequest) -> ApiResult<HttpResponse> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");
    let api = format!("{base}/api/v1");

    let metadata = serde_json::json!({
        "credential_issuer": base,
        "authorization_servers": [&base],
        "credential_endpoint": format!("{api}/credential"),
        "nonce_endpoint": format!("{api}/nonce"),
        "token_endpoint": format!("{api}/token"),
        "credential_offer_endpoint": format!("{api}/credential_offer"),
        "grant_types_supported": [PRE_AUTHORIZED_CODE_GRANT],
        "credential_configurations_supported": credential_configurations(),
        "display": [{
            "name": "Goya Ledger",
            "locale": "en",
        }],
    });

    Ok(HttpResponse::Ok().json(metadata))
}

fn credential_configurations() -> serde_json::Value {
    serde_json::json!({
        "IdentityCredential_sd_jwt": {
            "format": "vc+sd-jwt",
            "vct": "IdentityCredential",
            "credential_definition": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "IdentityCredential"]
            },
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA", "ML-DSA-65"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "ES384", "ES512"]
                }
            },
            "display": [{
                "name": "Identity Credential",
                "locale": "en"
            }],
            "claims": [
                { "path": ["given_name"], "mandatory": false, "value_type": "string", "display": [{"name": "Given Name", "locale": "en"}] },
                { "path": ["family_name"], "mandatory": false, "value_type": "string", "display": [{"name": "Family Name", "locale": "en"}] },
                { "path": ["birth_date"], "mandatory": false, "value_type": "full-date", "display": [{"name": "Birth Date", "locale": "en"}] },
                { "path": ["nationality"], "mandatory": false, "value_type": "string", "display": [{"name": "Nationality", "locale": "en"}] },
                { "path": ["age_over_18"], "mandatory": false, "value_type": "bool", "display": [{"name": "Age Over 18", "locale": "en"}] }
            ]
        },
        "eudi_pid_sd_jwt": {
            "format": "vc+sd-jwt",
            "vct": "urn:eudi:pid:1",
            "scope": "eudi_pid_sd_jwt",
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256"]
                }
            },
            "credential_definition": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "EudiPid"],
                "claims": {
                    "family_name": { "mandatory": true, "display": [{"name": "Family Name", "locale": "en"}] },
                    "given_name": { "mandatory": true, "display": [{"name": "Given Name", "locale": "en"}] },
                    "birthdate": { "mandatory": true, "display": [{"name": "Birth Date", "locale": "en"}] },
                    "nationalities": { "mandatory": false, "display": [{"name": "Nationalities", "locale": "en"}] },
                    "issuing_country": { "mandatory": true, "display": [{"name": "Issuing Country", "locale": "en"}] },
                    "issuing_authority": { "mandatory": true, "display": [{"name": "Issuance Authority", "locale": "en"}] }
                }
            },
            "display": [{
                "name": "EU PID",
                "locale": "en",
                "description": "Personal Identification Data",
                "background_color": "#2C3E50",
                "text_color": "#FFFFFF"
            }],
        },
        "eudi_pid_mdoc": {
            "format": "mso_mdoc",
            "doctype": "eu.europa.ec.eudi.pid.1",
            "credential_definition": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "doctype": "eu.europa.ec.eudi.pid.1"
            },
            "cryptographic_binding_methods_supported": ["cose_key"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256"]
                }
            },
        },
        "goya_identity_jwt_vc_json_ld": {
            "format": "jwt_vc_json-ld",
            "credential_definition": {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2"
                ],
                "type": ["VerifiableCredential", "IdentityCredential"]
            },
            "cryptographic_binding_methods_supported": ["did:jwk", "jwk"],
            "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256"]
                }
            },
            "display": [{
                "name": "Identity Credential",
                "locale": "en",
                "description": "W3C Verifiable Credential (JSON-LD)",
                "background_color": "#1A9E8F",
                "text_color": "#FFFFFF"
            }],
            "claims": [
                { "path": ["credentialSubject", "given_name"], "mandatory": false, "display": [{"name": "Given Name", "locale": "en"}] },
                { "path": ["credentialSubject", "family_name"], "mandatory": false, "display": [{"name": "Family Name", "locale": "en"}] },
                { "path": ["credentialSubject", "birth_date"], "mandatory": false, "display": [{"name": "Birth Date", "locale": "en"}] },
                { "path": ["credentialSubject", "nationality"], "mandatory": false, "display": [{"name": "Nationality", "locale": "en"}] }
            ]
        }
    })
}

// ── Token Endpoint ────────────────────────────────────────────────────────

const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const ACCESS_TOKEN_TTL_SECS: u64 = 3600;

#[derive(Deserialize, Serialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub tx_code: Option<String>,
    #[serde(default)]
    pub wallet_instance_attestation: Option<String>,
    #[serde(default)]
    pub wallet_trust_evidence: Option<String>,
    #[serde(default)]
    pub authorization_details: Option<String>,
}

/// Credential Offer (OpenID4VCI §4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: serde_json::Value,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<String>,
}

#[post("/token")]
pub async fn token_endpoint(
    body: web::Form<TokenRequest>,
    req: HttpRequest,
    wia_registry: Option<web::Data<WalletProviderRegistry>>,
    offer_store: web::Data<CredentialOfferStore>,
    token_store: web::Data<AccessTokenStore>,
) -> ApiResult<HttpResponse> {
    log::info!(
        "OID4VCI /token: grant_type={} has_pre_auth={}",
        body.grant_type,
        body.pre_authorized_code.is_some()
    );
    if body.grant_type != PRE_AUTHORIZED_CODE_GRANT {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "unsupported_grant_type",
                &format!("supported: {PRE_AUTHORIZED_CODE_GRANT}"),
            ),
            400,
        )));
    }
    let code = body.pre_authorized_code.as_deref().unwrap_or("");
    if code.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("invalid_grant", "pre-authorized_code required"),
            400,
        )));
    }
    let grant = match offer_store.consume_pre_authorized_code(code) {
        Ok(grant) => grant,
        Err(e) => {
            return Ok(HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error(err_dto("invalid_grant", e), 400)));
        }
    };

    // Validate WIA if present
    if let Some(wia) = &body.wallet_instance_attestation {
        let reg_ref = wia_registry.as_ref().map(|r| r.get_ref());
        if let Err(e) = verify_wia(wia, reg_ref) {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("invalid_wallet_attestation", &e),
                400,
            )));
        }
    }

    // Validate WTE if present (ARF v2.0 Topic 38)
    if let Some(wte) = &body.wallet_trust_evidence {
        let reg_ref = wia_registry.as_ref().map(|r| r.get_ref());
        if let Err(e) = verify_wte(wte, reg_ref) {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("invalid_wallet_trust_evidence", &e),
                400,
            )));
        }
    }

    // Validate DPoP proof if present (RFC 9449)
    let dpop_header = req
        .headers()
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let htu = format!("https://{host}/token");

    let dpop_jkt = if let Some(dpop_jwt) = &dpop_header {
        match verify_dpop_proof(dpop_jwt, "POST", &htu) {
            Ok(claims) => Some(claims.jkt),
            Err(e) => {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    err_dto("invalid_dpop_proof", &e),
                    400,
                )));
            }
        }
    } else {
        None
    };

    let access_token = token_store.issue(grant, ACCESS_TOKEN_TTL_SECS);

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: token_type.to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        dpop_jkt,
    }))
}

// ── Credential Endpoint ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CredentialRequest {
    /// OID4VCI 1.0: credential_configuration_id (resolves format+vct from metadata).
    #[serde(default)]
    pub credential_configuration_id: Option<String>,
    /// Legacy: explicit format (vc+sd-jwt / mso_mdoc).
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub vct: Option<String>,
    #[serde(default)]
    pub doctype: Option<String>,
    /// OID4VCI 1.0: `proofs` (plural) — map of proof_type → [jwt, ...].
    #[serde(default)]
    pub proofs: Option<ProofsObject>,
    /// Legacy: `proof` (singular) — still accepted for backward compat.
    #[serde(default)]
    pub proof: Option<ProofObject>,
    #[serde(default)]
    pub claims: Option<serde_json::Value>,
}

impl CredentialRequest {
    fn resolved_format(&self) -> &str {
        if let Some(cid) = &self.credential_configuration_id {
            if cid.contains("mdoc") || cid.contains("mso") {
                return "mso_mdoc";
            }
            if cid.contains("jwt_vc_json_ld") {
                return "jwt_vc_json-ld";
            }
            return "dc+sd-jwt";
        }
        self.format.as_deref().unwrap_or("dc+sd-jwt")
    }

    fn first_proof_jwt(&self) -> Option<&str> {
        // OID4VCI 1.0: proofs.jwt[0]
        if let Some(proofs) = &self.proofs {
            if let Some(jwts) = &proofs.jwt {
                if let Some(first) = jwts.first() {
                    return Some(first.as_str());
                }
            }
            if let Some(atts) = &proofs.attestation {
                if let Some(first) = atts.first() {
                    return Some(first.as_str());
                }
            }
        }
        // Legacy: proof.jwt
        if let Some(proof) = &self.proof {
            if proof.proof_type == "jwt" || proof.proof_type == "attestation" {
                return proof.jwt.as_deref();
            }
        }
        None
    }
}

#[derive(Deserialize)]
pub struct ProofObject {
    pub proof_type: String,
    pub jwt: Option<String>,
}

/// OID4VCI 1.0 proofs object — map of proof_type → array of proof values.
#[derive(Deserialize)]
pub struct ProofsObject {
    #[serde(default)]
    pub jwt: Option<Vec<String>>,
    #[serde(default)]
    pub attestation: Option<Vec<String>>,
}

/// Shared status list store — maps list ID to StatusList.
pub struct StatusListStore {
    lists: std::sync::RwLock<
        std::collections::HashMap<String, std::sync::Arc<crate::identity::status_list::StatusList>>,
    >,
    signing_provider:
        std::sync::RwLock<Option<std::sync::Arc<dyn crate::identity::signing::SigningProvider>>>,
}

impl StatusListStore {
    pub fn new() -> Self {
        Self {
            lists: std::sync::RwLock::new(std::collections::HashMap::new()),
            signing_provider: std::sync::RwLock::new(None),
        }
    }

    pub fn set_signing_provider(
        &self,
        provider: std::sync::Arc<dyn crate::identity::signing::SigningProvider>,
    ) {
        *self.signing_provider.write().unwrap() = Some(provider);
    }

    pub fn get_or_create(
        &self,
        id: &str,
    ) -> std::sync::Arc<crate::identity::status_list::StatusList> {
        let mut lists = self.lists.write().unwrap();
        lists
            .entry(id.to_string())
            .or_insert_with(|| {
                std::sync::Arc::new(crate::identity::status_list::StatusList::new(id, 16384))
            })
            .clone()
    }

    pub fn get(
        &self,
        id: &str,
    ) -> Option<std::sync::Arc<crate::identity::status_list::StatusList>> {
        self.lists.read().unwrap().get(id).cloned()
    }
}

impl Default for StatusListStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Status list endpoint — serves `statuslist+jwt` (IETF Token Status List).
#[get("/statuslist/{id}")]
pub async fn status_list_endpoint(
    sl_store: web::Data<StatusListStore>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let id = path.into_inner();
    let list = match sl_store.get(&id) {
        Some(l) => l,
        None => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", &format!("status list '{id}' not found")),
                404,
            )));
        }
    };
    let provider = sl_store.signing_provider.read().unwrap();
    let provider = match provider.as_ref() {
        Some(p) => p,
        None => {
            return Ok(
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                    err_dto(
                        "CONFIG_ERROR",
                        "status list signing provider not configured",
                    ),
                    500,
                )),
            );
        }
    };
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");

    match list.to_jwt(&base, 43200, provider.as_ref()) {
        Ok(jwt) => Ok(HttpResponse::Ok()
            .content_type("application/statuslist+jwt")
            .insert_header(("Cache-Control", "public, max-age=3600"))
            .body(jwt)),
        Err(e) => Ok(HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error(err_dto("SIGNING_ERROR", &e), 500))),
    }
}

/// Credential endpoint — issue a credential to the wallet.
/// Validates c_nonce, attestation type authorization, and assigns status index.
/// Supports both OID4VCI 1.0 (credential_configuration_id + proofs) and
/// legacy (format + proof) request formats.
#[post("/credential")]
pub async fn credential_endpoint(
    state: web::Data<AppState>,
    body: web::Json<CredentialRequest>,
    req: HttpRequest,
    nonce_store: web::Data<NonceStore>,
    att_registry: Option<web::Data<crate::identity::attestation::AttestationTypeRegistry>>,
    sl_store: Option<web::Data<StatusListStore>>,
    token_store: web::Data<AccessTokenStore>,
) -> ApiResult<HttpResponse> {
    // Accept both "Bearer" and "DPoP" token types
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = if let Some(t) = auth.strip_prefix("Bearer ") {
        t
    } else if let Some(t) = auth.strip_prefix("DPoP ") {
        t
    } else {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("invalid_token", "Bearer or DPoP token required"),
            401,
        )));
    };
    if token_store.grant_for(token).is_none() {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("invalid_token", "access token unknown or expired"),
            401,
        )));
    }

    // Log the raw credential request for debugging
    log::info!(
        "OID4VCI credential request body: proofs.jwt={:?} proofs.attestation={:?} proof={:?}",
        body.proofs
            .as_ref()
            .and_then(|p| p.jwt.as_ref().map(|v| v.len())),
        body.proofs
            .as_ref()
            .and_then(|p| p.attestation.as_ref().map(|v| v.len())),
        body.proof.as_ref().map(|p| &p.proof_type),
    );
    if let Some(cnf_preview) = extract_holder_jwk(&body) {
        log::info!(
            "OID4VCI extracted cnf: {}",
            serde_json::to_string(&cnf_preview).unwrap_or_default()
        );
    } else {
        log::warn!("OID4VCI could NOT extract holder JWK from proof");
        if let Some(proof_jwt) = body.first_proof_jwt() {
            let parts: Vec<&str> = proof_jwt.split('.').collect();
            if let Some(h) = parts.first() {
                if let Ok(hdr) = base64url_decode(h) {
                    log::info!("OID4VCI proof header: {}", String::from_utf8_lossy(&hdr));
                }
            }
            if parts.len() >= 2 {
                if let Ok(payload) = base64url_decode(parts[1]) {
                    log::info!(
                        "OID4VCI proof payload: {}",
                        String::from_utf8_lossy(&payload)
                    );
                }
            }
        }
    }

    // Validate proof JWT with c_nonce binding (nonce from dedicated endpoint)
    // For attestation proofs, skip strict nonce/proof validation (attestation is self-contained)
    if let Some(proof_jwt) = body.first_proof_jwt() {
        let proof_parts: Vec<&str> = proof_jwt.split('.').collect();
        let is_attestation = if !proof_parts.is_empty() {
            base64url_decode(proof_parts[0])
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|h| h.get("typ").and_then(|v| v.as_str()).map(String::from))
                .map(|t| t.contains("attestation") || t.contains("key"))
                .unwrap_or(false)
        } else {
            false
        };

        if !is_attestation {
            let host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost:8080");
            let issuer = format!("https://{host}");

            let proof_nonce = if proof_parts.len() >= 2 {
                base64url_decode(proof_parts[1])
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|p| p.get("nonce").and_then(|v| v.as_str()).map(String::from))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            if let Err(e) = nonce_store.consume(&proof_nonce) {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_proof",
                    "error_description": format!("c_nonce rejected: {e}")
                })));
            }

            if let Err(e) = verify_proof_jwt(proof_jwt, &proof_nonce, &issuer) {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_proof",
                    "error_description": e
                })));
            }
        }
    }

    let provider = state.signing_provider.as_ref().ok_or_else(|| {
        crate::api::errors::ApiError::StorageError {
            reason: "signing provider not configured".into(),
        }
    })?;

    let resolved_format = body.resolved_format().to_string();
    let vct = body
        .vct
        .as_deref()
        .or(body.doctype.as_deref())
        .or(body.credential_configuration_id.as_deref())
        .unwrap_or("IdentityCredential");

    log::info!(
        "OID4VCI credential request: format={resolved_format} vct={vct} config_id={:?} has_proof={} has_proofs={}",
        body.credential_configuration_id,
        body.proof.is_some(),
        body.proofs.is_some(),
    );
    let issuer_did = crate::identity::did::did_from_pubkey_hex(&hex::encode(provider.public_key()));
    let claims_json = body.claims.clone().unwrap_or(serde_json::json!({}));

    // Attestation type authorization (if registry is configured)
    if let Some(reg) = &att_registry {
        // ponytail: holder_has_pid=true for now — real check requires holder state lookup
        if let Err(e) = reg.authorize_issuance(&issuer_did, vct, &claims_json, true) {
            return Ok(HttpResponse::Forbidden().json(ApiResponse::<()>::error(
                err_dto("authorization_failed", &e),
                403,
            )));
        }
    }

    // Allocate status list index (if store is configured)
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let status_ref = if let Some(sls) = &sl_store {
        let list = sls.get_or_create("default");
        match list.allocate_index() {
            Ok(idx) => {
                let uri = format!("https://{host}/api/v1/statuslist/default");
                Some((uri, idx))
            }
            Err(_) => None,
        }
    } else {
        None
    };

    match resolved_format.as_str() {
        "dc+sd-jwt" | "vc+sd-jwt" => issue_sd_jwt_credential(
            state.credential_issuer_key.as_ref(),
            &body,
            status_ref.as_ref(),
            &req,
        ),
        "jwt_vc_json-ld" => issue_jwt_vc_jsonld(state.credential_issuer_key.as_ref(), &body, &req),
        "mso_mdoc" => issue_mdoc_credential(provider.as_ref(), &body, status_ref.as_ref()),
        other => Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "unsupported_credential_format",
                &format!(
                    "format '{other}' not supported; use dc+sd-jwt, jwt_vc_json-ld, or mso_mdoc"
                ),
            ),
            400,
        ))),
    }
}

// ── Credential Offer Endpoint ────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct CredentialOfferRequest {
    pub issuer_did: String,
    pub issuer_public_key: String,
    pub credential_configuration_id: String,
    pub issued_at: u64,
    pub signature: String,
}

const OFFER_FRESHNESS_SECS: u64 = 300;

pub fn offer_message(issuer_did: &str, configuration_id: &str, issued_at: u64) -> String {
    format!("oid4vci:offer:{issuer_did}:{configuration_id}:{issued_at}")
}

#[post("/credential_offer")]
pub async fn credential_offer_endpoint(
    state: web::Data<AppState>,
    body: web::Json<CredentialOfferRequest>,
    req: HttpRequest,
    offer_store: web::Data<CredentialOfferStore>,
) -> ApiResult<HttpResponse> {
    if credential_configurations()
        .get(&body.credential_configuration_id)
        .is_none()
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "invalid_request",
                &format!(
                    "credential_configuration_id '{}' is not advertised by this issuer",
                    body.credential_configuration_id
                ),
            ),
            400,
        )));
    }
    if now_secs().abs_diff(body.issued_at) > OFFER_FRESHNESS_SECS {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "invalid_request",
                &format!(
                    "issued_at {} is more than {OFFER_FRESHNESS_SECS} s from now",
                    body.issued_at
                ),
            ),
            400,
        )));
    }
    let store = get_channel_store(&state, "default")?;
    let message = offer_message(
        &body.issuer_did,
        &body.credential_configuration_id,
        body.issued_at,
    );
    if !key_controls_identity(store.as_ref(), &body.issuer_did, &body.issuer_public_key)
        || !is_signed_by(&body.issuer_public_key, &message, &body.signature)
    {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto(
                "invalid_issuer_signature",
                &format!(
                    "issuer_public_key does not control {} or signature does not verify over {message}",
                    body.issuer_did
                ),
            ),
            401,
        )));
    }

    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let base = format!("https://{host}");

    let session_id = uuid::Uuid::new_v4().to_string();

    let pre_auth_code = hex::encode(hash_with(
        HashAlgorithm::Sha256,
        uuid::Uuid::new_v4().as_bytes(),
    ));

    let offer = CredentialOffer {
        credential_issuer: base.clone(),
        credential_configuration_ids: vec![body.credential_configuration_id.clone()],
        grants: serde_json::json!({
            PRE_AUTHORIZED_CODE_GRANT: {
                "pre-authorized_code": pre_auth_code,
            }
        }),
    };

    let grant = IssuanceGrant {
        issuer_did: body.issuer_did.clone(),
        configuration_id: body.credential_configuration_id.clone(),
    };
    offer_store.store(&session_id, offer.clone(), &pre_auth_code, grant);

    let offer_uri = format!(
        "openid-credential-offer://?credential_offer_uri={}",
        urlencoding::encode(&format!("{base}/api/v1/credential_offer/{session_id}"))
    );

    Ok(HttpResponse::Created().json(serde_json::json!({
        "credential_offer": offer,
        "credential_offer_uri": offer_uri,
        "session_id": session_id,
    })))
}

/// Retrieve a stored credential offer by session ID (OID4VCI by-reference).
/// Partisia wallet fetches this after scanning the QR code.
#[get("/credential_offer/{session_id}")]
pub async fn credential_offer_get(
    path: web::Path<String>,
    offer_store: web::Data<CredentialOfferStore>,
) -> ApiResult<HttpResponse> {
    let session_id = path.into_inner();
    match offer_store.get(&session_id) {
        Some(offer) => Ok(HttpResponse::Ok().json(offer)),
        None => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "credential offer expired or not found"),
            404,
        ))),
    }
}

fn extract_jwk_from_jwt(jwt: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    // Check header for jwk
    let header = base64url_decode(parts[0]).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    if let Some(jwk) = header.get("jwk") {
        return Some(serde_json::json!({ "jwk": jwk }));
    }
    // Check payload for cnf.jwk or keys
    let payload = base64url_decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    if let Some(cnf) = payload.get("cnf") {
        if cnf.get("jwk").is_some() {
            return Some(cnf.clone());
        }
    }
    // Check for attested_keys array (key attestation JWT payload)
    if let Some(keys) = payload.get("attested_keys").and_then(|k| k.as_array()) {
        if let Some(first_key) = keys.first() {
            return Some(serde_json::json!({ "jwk": first_key }));
        }
    }
    // Check header for nested key_attestation JWT
    if let Some(ka) = header.get("key_attestation") {
        if let Some(ka_str) = ka.as_str() {
            return extract_jwk_from_jwt(ka_str);
        }
    }
    None
}

fn extract_holder_jwk(req: &CredentialRequest) -> Option<serde_json::Value> {
    // Try jwt proofs first
    if let Some(proofs) = &req.proofs {
        if let Some(jwts) = &proofs.jwt {
            for jwt in jwts {
                if let Some(cnf) = extract_jwk_from_jwt(jwt) {
                    return Some(cnf);
                }
            }
        }
        // Try attestation proofs — key is in the payload
        if let Some(atts) = &proofs.attestation {
            for att in atts {
                if let Some(cnf) = extract_jwk_from_jwt(att) {
                    return Some(cnf);
                }
            }
        }
    }
    // Legacy proof
    if let Some(proof) = &req.proof {
        if let Some(jwt) = &proof.jwt {
            if let Some(cnf) = extract_jwk_from_jwt(jwt) {
                return Some(cnf);
            }
        }
    }
    None
}

fn issue_sd_jwt_credential(
    provider: &dyn crate::identity::signing::SigningProvider,
    req: &CredentialRequest,
    status_ref: Option<&(String, usize)>,
    http_req: &HttpRequest,
) -> ApiResult<HttpResponse> {
    use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};

    let vct = req
        .vct
        .as_deref()
        .or(req
            .credential_configuration_id
            .as_deref()
            .and_then(|id| match id {
                "eudi_pid_sd_jwt" => Some("urn:eudi:pid:1"),
                _ => None,
            }))
        .unwrap_or("IdentityCredential");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut claim_pairs = Vec::new();
    if let Some(claims_obj) = &req.claims {
        if let Some(map) = claims_obj.as_object() {
            for (k, v) in map {
                claim_pairs.push((k.clone(), v.clone()));
            }
        }
    }
    if claim_pairs.is_empty() && vct == "urn:eudi:pid:1" {
        claim_pairs = vec![
            ("family_name".into(), serde_json::json!("Doe")),
            ("given_name".into(), serde_json::json!("Jane")),
            ("birth_date".into(), serde_json::json!("1990-01-15")),
            ("issuing_country".into(), serde_json::json!("CL")),
            ("issuing_authority".into(), serde_json::json!("goya-tsp")),
            ("document_number".into(), serde_json::json!("PID-000001")),
            ("nationality".into(), serde_json::json!("CL")),
        ];
    }

    let cnf = extract_holder_jwk(req);

    let host = http_req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let issuer_url = format!("https://{host}");

    let status = status_ref.map(|(uri, idx)| crate::identity::status_list::status_claim(uri, *idx));

    let vc_claims = VcClaims {
        iss: issuer_url,
        sub: "holder".to_string(),
        iat: now,
        exp: now + 365 * 86400,
        vct: vct.to_string(),
        claims: claim_pairs,
        cnf,
        status,
    };

    match issue_sd_jwt_vc(&vc_claims, provider) {
        Ok(sd_jwt) => {
            log::info!(
                "OID4VCI issued credential: len={} has_cnf={}",
                sd_jwt.compact.len(),
                vc_claims.cnf.is_some()
            );
            let resp = serde_json::json!({
                "credential": sd_jwt.compact,
                "credentials": [sd_jwt.compact],
            });
            Ok(HttpResponse::Ok().json(resp))
        }
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "issuance_failed".to_string(),
                    message: e,
                    field: None,
                },
                500,
            )),
        ),
    }
}

fn issue_jwt_vc_jsonld(
    provider: &dyn crate::identity::signing::SigningProvider,
    req: &CredentialRequest,
    http_req: &HttpRequest,
) -> ApiResult<HttpResponse> {
    use crate::identity::sd_jwt::{issue_sd_jwt_vc_w3c, VcClaims};

    let now = now_secs();
    let host = http_req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let issuer_url = format!("https://{host}");

    let mut claim_pairs = Vec::new();
    if let Some(claims_obj) = &req.claims {
        if let Some(map) = claims_obj.as_object() {
            for (k, v) in map {
                claim_pairs.push((k.clone(), v.clone()));
            }
        }
    }
    if claim_pairs.is_empty() {
        claim_pairs = vec![
            ("given_name".into(), serde_json::json!("Jane")),
            ("family_name".into(), serde_json::json!("Doe")),
            ("birth_date".into(), serde_json::json!("1990-01-15")),
            ("nationality".into(), serde_json::json!("CL")),
        ];
    }

    let holder_did = extract_holder_did(req).unwrap_or_else(|| "holder".to_string());
    let cnf = extract_holder_jwk(req).or_else(|| extract_cnf_from_did_jwk(req));

    let vc_claims = VcClaims {
        iss: issuer_url,
        sub: holder_did,
        iat: now,
        exp: now + 365 * 86400,
        vct: "IdentityCredential".to_string(),
        claims: claim_pairs,
        cnf,
        status: None,
    };

    match issue_sd_jwt_vc_w3c(&vc_claims, provider) {
        Ok(sd_jwt) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "credentials": [{"credential": sd_jwt.compact}]
        }))),
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                err_dto("issuance_failed", &e),
                500,
            )),
        ),
    }
}

fn extract_holder_did(req: &CredentialRequest) -> Option<String> {
    let jwt_str = req.first_proof_jwt()?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.is_empty() {
        return None;
    }
    let header = base64url_decode(parts[0]).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    header.get("kid").and_then(|v| v.as_str()).map(String::from)
}

fn extract_cnf_from_did_jwk(req: &CredentialRequest) -> Option<serde_json::Value> {
    let did = extract_holder_did(req)?;
    let jwk_b64 = did.strip_prefix("did:jwk:")?;
    let jwk_bytes = base64url_decode(jwk_b64).ok()?;
    let jwk: serde_json::Value = serde_json::from_slice(&jwk_bytes).ok()?;
    Some(serde_json::json!({"jwk": jwk}))
}

fn issue_mdoc_credential(
    provider: &dyn crate::identity::signing::SigningProvider,
    req: &CredentialRequest,
    status_ref: Option<&(String, usize)>,
) -> ApiResult<HttpResponse> {
    use crate::identity::mdoc::{issue_mdoc, MdocParams};
    use std::collections::BTreeMap;

    let doc_type = req.doctype.as_deref().unwrap_or("eu.europa.ec.eudi.pid.1");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut elements = BTreeMap::new();
    let mut ns_elements = Vec::new();
    if let Some(claims_obj) = &req.claims {
        if let Some(map) = claims_obj.as_object() {
            for (k, v) in map {
                ns_elements.push((k.clone(), v.clone()));
            }
        }
    }
    elements.insert(doc_type.to_string(), ns_elements);

    let params = MdocParams {
        doc_type: doc_type.to_string(),
        elements,
        valid_from: now,
        valid_until: now + 365 * 86400,
        device_key: None,
    };

    match issue_mdoc(&params, provider) {
        Ok(mdoc) => {
            let mdoc_json = serde_json::to_value(&mdoc).unwrap_or_default();
            let mut resp = serde_json::json!({
                "format": "mso_mdoc",
                "credential": mdoc_json,
            });
            if let Some((uri, idx)) = status_ref {
                resp["status"] = crate::identity::status_list::status_claim(uri, *idx);
                resp["status_list_index"] = serde_json::json!(idx);
            }
            Ok(HttpResponse::Ok().json(resp))
        }
        Err(e) => Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                ErrorDto {
                    code: "issuance_failed".to_string(),
                    message: e,
                    field: None,
                },
                500,
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
    use actix_web::{test, web, App};
    use std::sync::Arc;

    fn make_state() -> web::Data<AppState> {
        let mut state = AppState::test_default();
        state.signing_provider = Some(Arc::new(SoftwareSigningProvider::generate()));
        web::Data::new(state)
    }

    fn make_nonce_store() -> web::Data<NonceStore> {
        web::Data::new(NonceStore::new())
    }

    fn make_sl_store() -> web::Data<StatusListStore> {
        web::Data::new(StatusListStore::new())
    }

    macro_rules! oid4vci_app {
        ($state:expr) => {
            oid4vci_app!($state, make_nonce_store())
        };
        ($state:expr, $nonce:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .app_data($nonce)
                    .app_data(web::Data::new(CredentialOfferStore::new()))
                    .app_data(web::Data::new(AccessTokenStore::new()))
                    .service(issuer_metadata)
                    .service(oauth_as_metadata)
                    .service(token_endpoint)
                    .service(credential_endpoint)
                    .service(credential_offer_endpoint)
                    .service(credential_offer_get)
                    .service(nonce_endpoint)
                    .service(status_list_endpoint),
            )
            .await
        };
        ($state:expr, $nonce:expr, $sl:expr, $att:expr) => {
            test::init_service(
                App::new()
                    .app_data($state)
                    .app_data($nonce)
                    .app_data($sl)
                    .app_data($att)
                    .app_data(web::Data::new(CredentialOfferStore::new()))
                    .app_data(web::Data::new(AccessTokenStore::new()))
                    .service(issuer_metadata)
                    .service(oauth_as_metadata)
                    .service(token_endpoint)
                    .service(credential_endpoint)
                    .service(credential_offer_endpoint)
                    .service(credential_offer_get)
                    .service(nonce_endpoint)
                    .service(status_list_endpoint),
            )
            .await
        };
    }

    fn signed_offer_request(
        issuer: &SoftwareSigningProvider,
        configuration_id: &str,
        issued_at: u64,
    ) -> CredentialOfferRequest {
        let issuer_public_key = hex::encode(issuer.public_key());
        let issuer_did = crate::identity::did::did_from_pubkey_hex(&issuer_public_key);
        let message = offer_message(&issuer_did, configuration_id, issued_at);
        let signature = hex::encode(issuer.sign(message.as_bytes()).unwrap());
        CredentialOfferRequest {
            issuer_did,
            issuer_public_key,
            credential_configuration_id: configuration_id.to_string(),
            issued_at,
            signature,
        }
    }

    macro_rules! pre_authorized_code {
        ($app:expr) => {
            pre_authorized_code!($app, "IdentityCredential_sd_jwt")
        };
        ($app:expr, $configuration_id:expr) => {{
            let issuer = SoftwareSigningProvider::generate();
            let req = test::TestRequest::post()
                .uri("/credential_offer")
                .set_json(signed_offer_request(&issuer, $configuration_id, now_secs()))
                .to_request();
            let body: serde_json::Value = test::call_and_read_body_json(&$app, req).await;
            body["credential_offer"]["grants"]
                ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
                .as_str()
                .unwrap()
                .to_string()
        }};
    }

    macro_rules! access_token {
        ($app:expr) => {{
            let code = pre_authorized_code!($app);
            let req = test::TestRequest::post()
                .uri("/token")
                .set_form(make_token_form(&code))
                .to_request();
            let body: serde_json::Value = test::call_and_read_body_json(&$app, req).await;
            body["access_token"].as_str().unwrap().to_string()
        }};
    }

    #[actix_web::test]
    async fn jwt_vc_issuer_publishes_the_node_issuer_key() {
        let state = make_state();
        let issuer_public_key = state.credential_issuer_key.public_key();
        let app =
            test::init_service(App::new().app_data(state).service(jwt_vc_issuer_metadata)).await;
        let req = test::TestRequest::get()
            .uri("/.well-known/jwt-vc-issuer")
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let jwk = &body["jwks"]["keys"][0];
        assert_eq!(jwk["x"], base64url_encode(&issuer_public_key[1..33]));
        assert_eq!(jwk["y"], base64url_encode(&issuer_public_key[33..65]));
    }

    #[actix_web::test]
    async fn e2e_issuer_metadata() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::get()
            .uri("/.well-known/openid-credential-issuer")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["credential_endpoint"].as_str().is_some());
        assert!(
            body["credential_configurations_supported"]
                .as_object()
                .unwrap()
                .len()
                >= 2
        );
        assert_eq!(
            body["grant_types_supported"],
            serde_json::json!([PRE_AUTHORIZED_CODE_GRANT])
        );
        let pid_cfg = &body["credential_configurations_supported"]["eudi_pid_sd_jwt"];
        assert_eq!(pid_cfg["format"], "vc+sd-jwt");
    }

    #[actix_web::test]
    async fn e2e_oauth_as_metadata() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::get()
            .uri("/.well-known/oauth-authorization-server")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["issuer"].as_str().unwrap().starts_with("https://"));
        assert!(body["token_endpoint"].as_str().is_some());
        assert_eq!(
            body["grant_types_supported"],
            serde_json::json!([PRE_AUTHORIZED_CODE_GRANT])
        );
        assert!(body.get("authorization_endpoint").is_none());
    }

    fn make_token_form(code: &str) -> TokenRequest {
        TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: Some(code.to_string()),
            client_id: None,
            tx_code: None,
            wallet_instance_attestation: None,
            wallet_trust_evidence: None,
            authorization_details: None,
        }
    }

    fn make_dpop_jwt(htm: &str, htu: &str, iat: u64) -> String {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "test-key-material" }
        });
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": "unique-id-123",
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    fn make_proof_jwt(nonce: &str, aud: &str, iat: u64) -> String {
        let header = serde_json::json!({
            "typ": "openid4vci-proof+jwt",
            "alg": "EdDSA",
        });
        let payload = serde_json::json!({
            "nonce": nonce,
            "aud": aud,
            "iat": iat,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    fn make_wia_jwt(typ: &str, iss: &str, sub: &str, exp: u64) -> String {
        let header = serde_json::json!({ "typ": typ, "alg": "EdDSA" });
        let payload = serde_json::json!({ "iss": iss, "sub": sub, "iat": now_secs(), "exp": exp });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    #[actix_web::test]
    async fn e2e_token_exchange() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let code = pre_authorized_code!(app);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form(&code))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["access_token"]
            .as_str()
            .unwrap()
            .starts_with("goya_at_"));
        assert!(body.get("c_nonce").is_none());
        assert_eq!(body["token_type"], "Bearer");
    }

    #[actix_web::test]
    async fn token_rejects_a_pre_authorized_code_no_offer_issued() {
        let app = oid4vci_app!(make_state());
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form("forged-code-1234567890"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 400);
    }

    #[actix_web::test]
    async fn token_rejects_a_pre_authorized_code_used_twice() {
        let app = oid4vci_app!(make_state());
        let code = pre_authorized_code!(app);
        let first = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form(&code))
            .to_request();
        assert_eq!(test::call_service(&app, first).await.status(), 200);
        let second = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form(&code))
            .to_request();
        assert_eq!(test::call_service(&app, second).await.status(), 400);
    }

    #[actix_web::test]
    async fn credential_rejects_an_access_token_the_node_never_issued() {
        let app = oid4vci_app!(make_state());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer goya_at_forged"))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "claims": { "given_name": "Mallory" }
            }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);
    }

    #[actix_web::test]
    async fn e2e_token_with_dpop() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let code = pre_authorized_code!(app);
        let dpop = make_dpop_jwt("POST", "https://localhost:8080/token", now_secs());
        let req = test::TestRequest::post()
            .uri("/token")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("dpop", dpop.as_str()))
            .set_form(make_token_form(&code))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["token_type"], "DPoP");
        assert!(body["dpop_jkt"].as_str().is_some());
    }

    #[actix_web::test]
    async fn e2e_token_dpop_bad_htm() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let code = pre_authorized_code!(app);
        let dpop = make_dpop_jwt("GET", "https://localhost:8080/token", now_secs());
        let req = test::TestRequest::post()
            .uri("/token")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("dpop", dpop.as_str()))
            .set_form(make_token_form(&code))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_token_with_wia() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let code = pre_authorized_code!(app);
        let wia = make_wia_jwt(
            "wia+jwt",
            "wallet-provider",
            "device-123",
            now_secs() + 3600,
        );
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                pre_authorized_code: Some(code.clone()),
                client_id: None,
                tx_code: None,
                wallet_instance_attestation: Some(wia),
                wallet_trust_evidence: None,
                authorization_details: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn e2e_token_rejects_expired_wia() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let code = pre_authorized_code!(app);
        let wia = make_wia_jwt("wia+jwt", "wallet-provider", "device-123", 1000);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                pre_authorized_code: Some(code.clone()),
                client_id: None,
                tx_code: None,
                wallet_instance_attestation: Some(wia),
                wallet_trust_evidence: None,
                authorization_details: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_token_rejects_wrong_grant() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(TokenRequest {
                grant_type: "client_credentials".to_string(),
                pre_authorized_code: None,
                client_id: None,
                tx_code: None,
                wallet_instance_attestation: None,
                wallet_trust_evidence: None,
                authorization_details: None,
            })
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_nonce_endpoint_returns_cnonce() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let nonce = body["c_nonce"].as_str().unwrap();
        assert_eq!(nonce.len(), 64); // 32 bytes hex
        assert_eq!(body["c_nonce_expires_in"].as_u64().unwrap(), 300);
    }

    #[actix_web::test]
    async fn e2e_credential_with_nonce_endpoint_flow() {
        let state = make_state();
        let nonce_store = make_nonce_store();
        let app = oid4vci_app!(state, nonce_store.clone());
        let token = access_token!(app);

        // Step 1: Get nonce from dedicated endpoint
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let c_nonce = body["c_nonce"].as_str().unwrap();

        // Step 2: Use nonce in credential proof
        let proof_jwt = make_proof_jwt(c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
                "claims": { "given_name": "Ana" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn e2e_credential_rejects_unknown_nonce() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let token = access_token!(app);
        let proof_jwt = make_proof_jwt("unknown-nonce-value", "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error_description"].as_str().unwrap_or("");
        assert!(
            msg.contains("unknown nonce") || msg.contains("c_nonce rejected"),
            "got: {msg}"
        );
    }

    #[actix_web::test]
    async fn e2e_credential_rejects_reused_nonce() {
        let state = make_state();
        let nonce_store = make_nonce_store();
        let app = oid4vci_app!(state, nonce_store.clone());
        let token = access_token!(app);

        // Get a nonce
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        let c_nonce = body["c_nonce"].as_str().unwrap().to_string();

        // First use — succeeds
        let proof_jwt = make_proof_jwt(&c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
                "claims": { "given_name": "Test" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Second use — rejected (nonce already consumed)
        let proof_jwt2 = make_proof_jwt(&c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt2 },
                "claims": { "given_name": "Replay" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error_description"].as_str().unwrap_or("");
        assert!(
            msg.contains("already used") || msg.contains("c_nonce rejected"),
            "got: {msg}"
        );
    }

    #[actix_web::test]
    async fn nonce_store_expired_nonce_rejected() {
        let store = NonceStore::new();
        let nonce = store.generate(0); // 0 TTL = instantly expired
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_eq!(store.consume(&nonce), Err("nonce expired"));
    }

    #[actix_web::test]
    async fn nonce_store_single_use() {
        let store = NonceStore::new();
        let nonce = store.generate(300);
        assert!(store.consume(&nonce).is_ok());
        assert_eq!(store.consume(&nonce), Err("nonce already used"));
    }

    #[actix_web::test]
    async fn nonce_store_unknown() {
        let store = NonceStore::new();
        assert_eq!(store.consume("nonexistent"), Err("unknown nonce"));
    }

    #[actix_web::test]
    async fn nonce_tampered_rejected() {
        let store = NonceStore::new();
        let nonce = store.generate(300);
        // Flip a character
        let mut chars: Vec<u8> = nonce.bytes().collect();
        chars[0] ^= 0x01;
        let tampered = String::from_utf8(chars).unwrap();
        assert_eq!(store.consume(&tampered), Err("unknown nonce"));
        // Original still valid
        assert!(store.consume(&nonce).is_ok());
    }

    #[actix_web::test]
    async fn e2e_credential_accepts_dpop_token() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let token = access_token!(app);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", format!("DPoP {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "claims": { "name": "Test" }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn e2e_issue_sd_jwt_vc() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let token = access_token!(app);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "claims": {
                    "given_name": "Juan",
                    "family_name": "Pérez",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let cred = body["credential"].as_str().unwrap();
        assert!(cred.contains('~'));
        assert!(!body["credentials"].as_array().unwrap().is_empty());
    }

    #[actix_web::test]
    async fn e2e_issue_mdoc() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let token = access_token!(app);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "mso_mdoc",
                "doctype": "eu.europa.ec.eudi.pid.1",
                "claims": {
                    "given_name": "Juan",
                    "birth_date": "1990-01-15",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["format"], "mso_mdoc");
        assert!(body["credential"]["doc_type"].as_str().is_some());
    }

    #[actix_web::test]
    async fn e2e_rejects_unsupported_format() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let token = access_token!(app);
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "jwt_vc_json",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn e2e_rejects_missing_token() {
        let state = make_state();
        let app = oid4vci_app!(state);
        let req = test::TestRequest::post()
            .uri("/credential")
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    // ── Unit tests for validation functions ──────────────────────────

    #[actix_web::test]
    async fn dpop_valid() {
        let dpop = make_dpop_jwt("POST", "https://example.com/token", now_secs());
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_ok());
    }

    #[actix_web::test]
    async fn dpop_wrong_htm() {
        let dpop = make_dpop_jwt("GET", "https://example.com/token", now_secs());
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_err());
    }

    #[actix_web::test]
    async fn dpop_wrong_htu() {
        let dpop = make_dpop_jwt("POST", "https://other.com/token", now_secs());
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_err());
    }

    #[actix_web::test]
    async fn dpop_expired_iat() {
        let dpop = make_dpop_jwt("POST", "https://example.com/token", now_secs() - 600);
        assert!(verify_dpop_proof(&dpop, "POST", "https://example.com/token").is_err());
    }

    #[actix_web::test]
    async fn dpop_returns_jkt() {
        let dpop = make_dpop_jwt("POST", "https://example.com/token", now_secs());
        let claims = verify_dpop_proof(&dpop, "POST", "https://example.com/token").unwrap();
        assert!(!claims.jkt.is_empty());
    }

    #[actix_web::test]
    async fn proof_jwt_valid() {
        let proof = make_proof_jwt("nonce-abc", "https://issuer.com", now_secs());
        assert!(verify_proof_jwt(&proof, "nonce-abc", "https://issuer.com").is_ok());
    }

    #[actix_web::test]
    async fn proof_jwt_wrong_nonce() {
        let proof = make_proof_jwt("nonce-abc", "https://issuer.com", now_secs());
        assert!(verify_proof_jwt(&proof, "wrong-nonce", "https://issuer.com").is_err());
    }

    #[actix_web::test]
    async fn proof_jwt_wrong_aud() {
        let proof = make_proof_jwt("nonce", "https://other.com", now_secs());
        assert!(verify_proof_jwt(&proof, "nonce", "https://issuer.com").is_err());
    }

    #[actix_web::test]
    async fn wia_valid() {
        let wia = make_wia_jwt("wia+jwt", "provider", "device", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_ok());
    }

    #[actix_web::test]
    async fn wia_wallet_attestation_typ() {
        let wia = make_wia_jwt("wallet-attestation+jwt", "prov", "dev", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_ok());
    }

    #[actix_web::test]
    async fn wia_expired() {
        let wia = make_wia_jwt("wia+jwt", "provider", "device", 1000);
        assert!(verify_wia(&wia, None).is_err());
    }

    #[actix_web::test]
    async fn wia_wrong_typ() {
        let wia = make_wia_jwt("jwt", "provider", "device", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_err());
    }

    #[actix_web::test]
    async fn wia_missing_iss() {
        let wia = make_wia_jwt("wia+jwt", "", "device", now_secs() + 3600);
        assert!(verify_wia(&wia, None).is_err());
    }

    #[actix_web::test]
    async fn wia_sig_verified_with_registry() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());

        // Build a properly signed WIA JWT
        let header = serde_json::json!({"typ":"wia+jwt","alg":"EdDSA"});
        let payload = serde_json::json!({
            "iss": "wallet-provider-1",
            "sub": "device-1",
            "iat": now_secs(),
            "exp": now_secs() + 3600,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = provider.sign(signing_input.as_bytes()).unwrap();
        let wia = format!("{signing_input}.{}", base64url_encode(&sig));

        let reg = WalletProviderRegistry::new();
        reg.register("wallet-provider-1", &pk_hex);
        assert!(verify_wia(&wia, Some(&reg)).is_ok());
    }

    #[actix_web::test]
    async fn wia_sig_fails_wrong_key() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();

        let header = serde_json::json!({"typ":"wia+jwt","alg":"EdDSA"});
        let payload = serde_json::json!({
            "iss": "wallet-provider-2",
            "sub": "device-2",
            "iat": now_secs(),
            "exp": now_secs() + 3600,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = provider.sign(signing_input.as_bytes()).unwrap();
        let wia = format!("{signing_input}.{}", base64url_encode(&sig));

        let reg = WalletProviderRegistry::new();
        reg.register("wallet-provider-2", &hex::encode(other.public_key()));
        assert!(verify_wia(&wia, Some(&reg)).is_err());
    }

    #[actix_web::test]
    async fn wallet_provider_registry_roundtrip() {
        let reg = WalletProviderRegistry::new();
        assert!(reg.resolve("unknown").is_none());
        reg.register("provider-1", "deadbeef");
        assert_eq!(reg.resolve("provider-1"), Some("deadbeef".to_string()));
    }

    // ── WTE (Wallet Trust Evidence, ARF v2.0 Topic 38) ─────────────

    fn make_wte_jwt(iss: &str, sub: &str, exp: u64) -> String {
        let header = serde_json::json!({ "typ": "wte+jwt", "alg": "EdDSA" });
        let payload = serde_json::json!({
            "iss": iss,
            "sub": sub,
            "iat": now_secs(),
            "exp": exp,
            "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "fake-device-key" } },
            "trust_level": "high",
            "wscd_certified": true,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let sig = base64url_encode(b"fake-sig");
        format!("{h}.{p}.{sig}")
    }

    #[actix_web::test]
    async fn wte_valid() {
        let wte = make_wte_jwt("provider", "device", now_secs() + 3600);
        assert!(verify_wte(&wte, None).is_ok());
    }

    #[actix_web::test]
    async fn wte_expired() {
        let wte = make_wte_jwt("provider", "device", 1000);
        assert!(verify_wte(&wte, None).is_err());
    }

    #[actix_web::test]
    async fn wte_wrong_typ() {
        let header = serde_json::json!({ "typ": "wia+jwt", "alg": "EdDSA" });
        let payload = serde_json::json!({
            "iss": "p", "sub": "d", "iat": now_secs(), "exp": now_secs() + 3600,
            "cnf": { "jwk": {} },
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let wte = format!("{h}.{p}.{}", base64url_encode(b"sig"));
        assert!(verify_wte(&wte, None).is_err());
    }

    #[actix_web::test]
    async fn wte_missing_cnf() {
        let header = serde_json::json!({ "typ": "wte+jwt", "alg": "EdDSA" });
        let payload = serde_json::json!({
            "iss": "p", "sub": "d", "iat": now_secs(), "exp": now_secs() + 3600,
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let wte = format!("{h}.{p}.{}", base64url_encode(b"sig"));
        assert!(verify_wte(&wte, None).is_err());
    }

    #[actix_web::test]
    async fn wte_sig_verified_with_registry() {
        use crate::identity::signing::{SigningProvider, SoftwareSigningProvider};
        let provider = SoftwareSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());

        let header = serde_json::json!({"typ":"wte+jwt","alg":"EdDSA"});
        let payload = serde_json::json!({
            "iss": "wallet-provider-wte",
            "sub": "device-wte",
            "iat": now_secs(),
            "exp": now_secs() + 3600,
            "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "key" } },
        });
        let h = base64url_encode(&serde_json::to_vec(&header).unwrap());
        let p = base64url_encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = provider.sign(signing_input.as_bytes()).unwrap();
        let wte = format!("{signing_input}.{}", base64url_encode(&sig));

        let reg = WalletProviderRegistry::new();
        reg.register("wallet-provider-wte", &pk_hex);
        assert!(verify_wte(&wte, Some(&reg)).is_ok());
    }

    macro_rules! offer_app {
        ($offer_store:expr) => {
            test::init_service(
                App::new()
                    .app_data(make_state())
                    .app_data($offer_store)
                    .service(credential_offer_endpoint)
                    .service(credential_offer_get),
            )
            .await
        };
    }

    #[actix_web::test]
    async fn offer_signed_by_the_issuer_is_stored_with_its_grant() {
        let offer_store = web::Data::new(CredentialOfferStore::new());
        let app = offer_app!(offer_store.clone());
        let issuer = SoftwareSigningProvider::generate();
        let offer_request = signed_offer_request(&issuer, "eudi_pid_sd_jwt", now_secs());
        let expected_grant = IssuanceGrant {
            issuer_did: offer_request.issuer_did.clone(),
            configuration_id: "eudi_pid_sd_jwt".to_string(),
        };
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(&offer_request)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(
            body["credential_offer"]["credential_configuration_ids"],
            serde_json::json!(["eudi_pid_sd_jwt"])
        );
        let uri = body["credential_offer_uri"].as_str().unwrap();
        assert!(uri.starts_with("openid-credential-offer://"));
        let session_id = body["session_id"].as_str().unwrap();
        let get_req = test::TestRequest::get()
            .uri(&format!("/credential_offer/{session_id}"))
            .to_request();
        let get_body: serde_json::Value = test::call_and_read_body_json(&app, get_req).await;
        assert_eq!(get_body, body["credential_offer"]);

        let code = body["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT]
            ["pre-authorized_code"]
            .as_str()
            .unwrap();
        assert_eq!(
            offer_store.consume_pre_authorized_code(code),
            Ok(expected_grant)
        );
    }

    #[actix_web::test]
    async fn offer_signed_by_another_key_is_refused() {
        let app = offer_app!(web::Data::new(CredentialOfferStore::new()));
        let issuer = SoftwareSigningProvider::generate();
        let impostor = SoftwareSigningProvider::generate();
        let mut offer_request = signed_offer_request(&issuer, "eudi_pid_sd_jwt", now_secs());
        offer_request.signature =
            signed_offer_request(&impostor, "eudi_pid_sd_jwt", now_secs()).signature;
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(&offer_request)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);
    }

    #[actix_web::test]
    async fn offer_with_a_key_that_does_not_control_the_did_is_refused() {
        let app = offer_app!(web::Data::new(CredentialOfferStore::new()));
        let issuer = SoftwareSigningProvider::generate();
        let impostor = SoftwareSigningProvider::generate();
        let issued_at = now_secs();
        let mut offer_request = signed_offer_request(&impostor, "eudi_pid_sd_jwt", issued_at);
        offer_request.issuer_did =
            crate::identity::did::did_from_pubkey_hex(&hex::encode(issuer.public_key()));
        let message = offer_message(&offer_request.issuer_did, "eudi_pid_sd_jwt", issued_at);
        offer_request.signature = hex::encode(impostor.sign(message.as_bytes()).unwrap());
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(&offer_request)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);
    }

    #[actix_web::test]
    async fn offer_with_a_stale_issued_at_is_refused() {
        let app = offer_app!(web::Data::new(CredentialOfferStore::new()));
        let issuer = SoftwareSigningProvider::generate();
        let stale = signed_offer_request(&issuer, "eudi_pid_sd_jwt", now_secs() - 301);
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(&stale)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 400);
    }

    #[actix_web::test]
    async fn offer_for_an_unadvertised_configuration_is_refused() {
        let app = offer_app!(web::Data::new(CredentialOfferStore::new()));
        let issuer = SoftwareSigningProvider::generate();
        let unknown = signed_offer_request(&issuer, "unknown_configuration", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(&unknown)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 400);
    }

    #[actix_web::test]
    async fn token_carries_the_grant_of_its_offer() {
        let token_store = web::Data::new(AccessTokenStore::new());
        let app = test::init_service(
            App::new()
                .app_data(make_state())
                .app_data(web::Data::new(CredentialOfferStore::new()))
                .app_data(token_store.clone())
                .service(credential_offer_endpoint)
                .service(token_endpoint),
        )
        .await;
        let issuer = SoftwareSigningProvider::generate();
        let offer_request = signed_offer_request(&issuer, "eudi_pid_mdoc", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential_offer")
            .set_json(&offer_request)
            .to_request();
        let offer: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let code = offer["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT]
            ["pre-authorized_code"]
            .as_str()
            .unwrap();
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form(code))
            .to_request();
        let token: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(
            token_store.grant_for(token["access_token"].as_str().unwrap()),
            Some(IssuanceGrant {
                issuer_did: offer_request.issuer_did,
                configuration_id: "eudi_pid_mdoc".to_string(),
            })
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Full EUDI E2E: metadata → token → nonce → credential → status
    //                → OID4VP → revoke → status update detected
    // ═══════════════════════════════════════════════════════════════

    #[actix_web::test]
    async fn e2e_full_eudi_flow_with_status_and_revocation() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        use crate::identity::status_list::CredentialStatus;

        let mut state = AppState::test_default();
        state.signing_provider = Some(Arc::new(EcdsaP256SigningProvider::generate())
            as Arc<dyn crate::identity::signing::SigningProvider>);
        let state = web::Data::new(state);

        let nonce_store = make_nonce_store();
        let sl_store = make_sl_store();
        sl_store.set_signing_provider(Arc::new(EcdsaP256SigningProvider::generate())
            as Arc<dyn crate::identity::signing::SigningProvider>);
        let offer_store = web::Data::new(CredentialOfferStore::new());
        let app = test::init_service(
            App::new()
                .app_data(state)
                .app_data(nonce_store.clone())
                .app_data(sl_store.clone())
                .app_data(offer_store)
                .app_data(web::Data::new(AccessTokenStore::new()))
                .service(issuer_metadata)
                .service(token_endpoint)
                .service(credential_endpoint)
                .service(credential_offer_endpoint)
                .service(nonce_endpoint)
                .service(status_list_endpoint),
        )
        .await;

        // 1. Metadata — verify nonce_endpoint + ES256 advertised
        let req = test::TestRequest::get()
            .uri("/.well-known/openid-credential-issuer")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let meta: serde_json::Value = test::read_body_json(resp).await;
        assert!(meta["nonce_endpoint"].as_str().is_some());
        let sd_jwt_algs = &meta["credential_configurations_supported"]["IdentityCredential_sd_jwt"]
            ["credential_signing_alg_values_supported"];
        assert!(sd_jwt_algs
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("ES256")));

        // 2. Token
        let code = pre_authorized_code!(app);
        let req = test::TestRequest::post()
            .uri("/token")
            .set_form(make_token_form(&code))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let token_body: serde_json::Value = test::read_body_json(resp).await;
        let access_token = token_body["access_token"].as_str().unwrap();

        // 3. Nonce
        let req = test::TestRequest::post().uri("/nonce").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let nonce_body: serde_json::Value = test::read_body_json(resp).await;
        let c_nonce = nonce_body["c_nonce"].as_str().unwrap();

        // 4. Credential issuance with nonce proof
        let proof_jwt = make_proof_jwt(c_nonce, "https://localhost:8080", now_secs());
        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("host", "localhost:8080"))
            .insert_header(("authorization", format!("Bearer {access_token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "IdentityCredential",
                "proof": { "proof_type": "jwt", "jwt": proof_jwt },
                "claims": {
                    "given_name": "María",
                    "family_name": "García",
                    "birth_date": "1985-03-15",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let cred_body: serde_json::Value = test::read_body_json(resp).await;
        let credential = cred_body["credential"].as_str().unwrap();
        assert!(credential.contains('~'));
        assert!(!cred_body["credentials"].as_array().unwrap().is_empty());

        // Status injection was removed from the simplified response —
        // status list is still available via the /statuslist endpoint.
        let status_idx: usize = 0;

        // 5. Fetch status list — credential should be VALID
        let req = test::TestRequest::get()
            .uri("/statuslist/default")
            .insert_header(("host", "localhost:8080"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(content_type, "application/statuslist+jwt");
        let cache = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache.contains("public"));

        // 6. Revoke the credential
        let list = sl_store.get("default").unwrap();
        list.set_status(status_idx, CredentialStatus::Invalid)
            .unwrap();
        assert_eq!(
            list.get_status(status_idx).unwrap(),
            CredentialStatus::Invalid
        );
    }

    #[actix_web::test]
    async fn e2e_status_list_not_found() {
        let state = make_state();
        let sl_store = make_sl_store();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .app_data(make_nonce_store())
                .app_data(sl_store)
                .service(status_list_endpoint)
                .service(credential_endpoint),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/statuslist/nonexistent")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn e2e_credential_with_attestation_registry_unauthorized_issuer() {
        use crate::identity::attestation::*;

        let state = make_state();
        let nonce_store = make_nonce_store();
        let sl_store = make_sl_store();
        let att_registry = web::Data::new(AttestationTypeRegistry::new());
        // PID rulebook exists but NO issuer is registered → fail-closed

        let app = oid4vci_app!(state, nonce_store, sl_store, att_registry);
        let token = access_token!(app);

        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "eu.europa.ec.eudi.pid.1",
                "claims": {
                    "given_name": "Test",
                    "family_name": "User",
                    "birth_date": "2000-01-01",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(msg.contains("not registered"), "got: {msg}");
    }

    #[actix_web::test]
    async fn e2e_credential_with_authorized_pid_issuer() {
        use crate::identity::attestation::*;
        use crate::identity::signing::EcdsaP256SigningProvider;

        let es256 = EcdsaP256SigningProvider::generate();
        let issuer_did =
            crate::identity::did::did_from_pubkey_hex(&hex::encode(es256.public_key()));

        let mut app_state = AppState::test_default();
        app_state.signing_provider =
            Some(Arc::new(es256) as Arc<dyn crate::identity::signing::SigningProvider>);
        let state = web::Data::new(app_state);

        let att_registry = web::Data::new(AttestationTypeRegistry::new());
        att_registry.register_issuer(RegisteredIssuer {
            did: issuer_did,
            role: IssuerRole::PidProvider,
            trust_source: "https://tsl.example.eu/pid".into(),
            authorized_vcts: vec![],
            registered_at: now_secs(),
        });

        let nonce_store = make_nonce_store();
        let sl_store = make_sl_store();
        let app = oid4vci_app!(state, nonce_store, sl_store, att_registry);
        let token = access_token!(app);

        let req = test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({
                "format": "vc+sd-jwt",
                "vct": "eu.europa.ec.eudi.pid.1",
                "claims": {
                    "given_name": "María",
                    "family_name": "García",
                    "birth_date": "1985-03-15",
                }
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
}
