//! Notarization endpoints — Proof of Existence service.
//!
//! Supports two signature levels:
//! - **Simple (FES)**: Ed25519 signature, DID-based identity
//! - **Advanced (FEA)**: ML-DSA-65 (PQC) signature + biometric evidence
//!
//! Legal alignment: Chile Ley 19.799, EU eIDAS 910/2014, US ESIGN Act.
//!
//! Endpoints:
//! - POST   /api/v1/notarize              — register a document hash
//! - GET    /api/v1/notarize/verify/{hash} — verify a document hash
//! - GET    /api/v1/notarize/{id}         — get notarization by ID
//! - GET    /api/v1/notarize              — list notarizations
//! - POST   /api/v1/notarize/{hash}/transfer — transfer ownership
//! - GET    /api/v1/notarize/{hash}/owner — current owner
//! - GET    /api/v1/notarize/{hash}/provenance — full chain

use crate::api::errors::{ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::app_state::AppState;
use crate::document::DocumentFingerprint;
use crate::identity::signing::SigningAlgorithm;
use crate::signature::{
    compute_biometrics_hash, is_signer_proven, verify_signature, BiometricEvidence, SignatureLevel,
    SignerProof,
};
use crate::storage::traits::{NotarizationEntry, OwnershipTransfer};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

fn obtain_tsa_token(state: &AppState, signature: &[u8]) -> Option<Vec<u8>> {
    let tsa = state.tsa_provider.as_ref()?;
    let imprint = hex::encode(crate::crypto::hasher::hash_with(
        crate::crypto::hasher::HashAlgorithm::Sha256,
        signature,
    ));
    let req = crate::tsa::TimeStampRequest {
        hash_algorithm: crate::crypto::hasher::HashAlgorithm::Sha256,
        message_imprint: imprint,
        nonce: None,
        require_ordering: false,
    };
    tsa.issue_der(&req).ok()
}

fn err_dto(code: &str, msg: &str) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: msg.to_string(),
        field: None,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Request types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct NotarizeRequest {
    /// SHA-256 hash of the document (64 hex chars = 32 bytes).
    pub content_hash: String,
    /// DID or address of the signer.
    pub signer: String,
    /// Public key (hex). Size depends on algorithm:
    /// - Ed25519: 64 hex chars (32 bytes)
    /// - ML-DSA-65: 3904 hex chars (1952 bytes)
    pub public_key: String,
    /// Signature over the signing payload, hex-encoded.
    pub signature: String,
    /// Optional metadata (document name, description, etc.).
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
    #[serde(default)]
    pub signer_proof: Option<SignerProof>,
}

fn signer_not_proven(signer: &str) -> HttpResponse {
    HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
        err_dto(
            "SIGNER_MISMATCH",
            &format!("signer {signer} is not proven by the signing key or a valid signer_proof"),
        ),
        401,
    ))
}

#[derive(Deserialize)]
pub struct NotarizeListQuery {
    /// Filter by signer DID/address.
    pub signer: Option<String>,
}

// ── Signing payload construction ─────────────────────────────────────────────

/// Build the signing payload based on signature level.
///
/// - Simple:   `"notarize:{signer}:{content_hash}"`
/// - Advanced: `"notarize_fea:{signer}:{content_hash}:{biometrics_hash}"`
fn build_notarize_payload(
    level: SignatureLevel,
    signer: &str,
    content_hash: &str,
    biometric_evidence: &[BiometricEvidence],
) -> String {
    match level {
        SignatureLevel::Simple => format!("notarize:{signer}:{content_hash}"),
        SignatureLevel::Advanced | SignatureLevel::Qualified | SignatureLevel::Seal => {
            let bio_hash = compute_biometrics_hash(biometric_evidence);
            format!("notarize_fea:{signer}:{content_hash}:{bio_hash}")
        }
    }
}

/// Build the transfer signing payload based on signature level.
fn build_transfer_payload(
    level: SignatureLevel,
    content_hash: &str,
    from_did: &str,
    to_did: &str,
    biometric_evidence: &[BiometricEvidence],
) -> String {
    match level {
        SignatureLevel::Simple => format!("transfer_doc:{content_hash}:{from_did}:{to_did}"),
        SignatureLevel::Advanced | SignatureLevel::Qualified | SignatureLevel::Seal => {
            let bio_hash = compute_biometrics_hash(biometric_evidence);
            format!("transfer_fea:{content_hash}:{from_did}:{to_did}:{bio_hash}")
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Register a document hash for on-chain timestamping.
///
/// Supports Simple (FES) and Advanced (FEA) electronic signatures.
/// Advanced requires ML-DSA-65 algorithm and at least one biometric evidence.
#[post("/notarize")]
pub async fn submit_notarization(
    state: web::Data<AppState>,
    body: web::Json<NotarizeRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate content_hash: must be 64 hex chars (SHA-256)
    if body.content_hash.len() != 64 || hex::decode(&body.content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_HASH",
                "content_hash must be 64 hex characters (SHA-256)",
            ),
            400,
        )));
    }

    // Validate FES/FEA constraints
    if let Err(e) = crate::signature::validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("VALIDATION", &e.to_string()),
            400,
        )));
    }

    // Build and verify signature over the level-appropriate payload
    let sign_msg = build_notarize_payload(
        body.signature_level,
        &body.signer,
        &body.content_hash,
        &body.biometric_evidence,
    );
    if !is_signer_proven(
        &body.signer,
        &body.public_key,
        body.signer_proof.as_ref(),
        sign_msg.as_bytes(),
    ) {
        return Ok(signer_not_proven(&body.signer));
    }
    if !verify_signature(
        body.signature_algorithm,
        &body.public_key,
        sign_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto(
                "INVALID_SIGNATURE",
                &format!("{} signature verification failed", body.signature_algorithm),
            ),
            401,
        )));
    }

    // Check for duplicate: same content_hash already notarized
    if store.read_notarization_by_hash(&body.content_hash).is_ok() {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto("ALREADY_NOTARIZED", "document already notarized"),
            409,
        )));
    }

    // Get current block height for anchoring
    let block_height = store.get_latest_height().unwrap_or(0);

    let entry = NotarizationEntry {
        signer_proof: body.signer_proof.clone(),
        id: uuid::Uuid::new_v4().to_string(),
        content_hash: body.content_hash.clone(),
        signer: body.signer.clone(),
        metadata: body.metadata.clone(),
        notarized_at: now_secs(),
        block_height,
        signature: body.signature.clone(),
        public_key: body.public_key.clone(),
        cades_der: None,
        signature_algorithm: body.signature_algorithm,
        signature_level: body.signature_level,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_notarization(&entry)
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    // Enqueue as transaction so it gets included in the next block and propagated.
    {
        let tx = crate::storage::traits::Transaction {
            id: format!("notarize:{}", entry.id),
            block_height: 0,
            timestamp: entry.notarized_at,
            input_did: entry.signer.clone(),
            output_recipient: entry.content_hash.clone(),
            amount: 0,
            state: serde_json::to_string(&entry).unwrap_or_else(|_| "notarize".to_string()),
            fee: 0,
            payload: None,
        };
        let mut pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
        let _ = pool.add(tx);
    }

    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({
            "id": entry.id,
            "content_hash": entry.content_hash,
            "signer": entry.signer,
            "notarized_at": entry.notarized_at,
            "block_height": entry.block_height,
            "signature_level": entry.signature_level,
            "signature_algorithm": entry.signature_algorithm,
        }),
        trace,
    )))
}

// ── PDF Fingerprint endpoint ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PdfNotarizeRequest {
    /// PDF file content, base64-encoded.
    pub pdf_base64: String,
    /// Signer DID.
    pub signer: String,
    /// Biometric evidence (required — FEA server-side signing).
    pub biometric_evidence: Vec<BiometricEvidence>,
    pub signer_proof: SignerProof,
}

/// Notarize a PDF with server-side ML-DSA-65 signature.
///
/// 1. Decodes PDF, computes dimensional fingerprint (content/structure/metadata).
/// 2. Signs the canonical_hash with the node's ML-DSA-65 key.
/// 3. Produces CAdES DER envelope with biometric commitment.
/// 4. Stores on-chain and returns signature + fingerprint.
///
/// The client never handles PQC keys — they stay on the node.
#[post("/notarize/pdf")]
pub async fn notarize_pdf(
    state: web::Data<AppState>,
    body: web::Json<PdfNotarizeRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if body.biometric_evidence.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "BIOMETRIC_REQUIRED",
                "PDF notarization requires at least one biometric evidence",
            ),
            400,
        )));
    }
    for evidence in &body.biometric_evidence {
        if let Err(e) = evidence.validate() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_BIOMETRIC", &e.to_string()),
                400,
            )));
        }
    }

    let provider = state.signing_provider.as_ref().ok_or_else(|| {
        crate::api::errors::ApiError::StorageError {
            reason: "signing provider not configured".into(),
        }
    })?;

    if provider.algorithm() != crate::identity::signing::SigningAlgorithm::MlDsa65 {
        return Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                err_dto(
                    "ALGORITHM_MISMATCH",
                    "PDF notarization requires ML-DSA-65 but node signing provider is not post-quantum",
                ),
                500,
            )),
        );
    }

    let pdf_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.pdf_base64)
            .map_err(|_| crate::api::errors::ApiError::StorageError {
                reason: "invalid base64 in pdf_base64".into(),
            })?;

    let fingerprint = crate::document::pdf_parser::fingerprint_pdf(&pdf_bytes)
        .map_err(|e| crate::api::errors::ApiError::StorageError { reason: e })?;

    if store
        .read_notarization_by_hash(&fingerprint.canonical_hash)
        .is_ok()
    {
        return Ok(HttpResponse::Conflict().json(ApiResponse::<()>::error(
            err_dto("ALREADY_NOTARIZED", "document already notarized"),
            409,
        )));
    }

    let bio_hash = compute_biometrics_hash(&body.biometric_evidence);
    let payload = format!(
        "notarize_fea:{}:{}:{}",
        body.signer, fingerprint.canonical_hash, bio_hash
    );
    if !is_signer_proven(
        &body.signer,
        "",
        Some(&body.signer_proof),
        payload.as_bytes(),
    ) {
        return Ok(signer_not_proven(&body.signer));
    }

    let signature = provider.sign(payload.as_bytes()).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("signing failed: {e}"),
        }
    })?;

    let content_bytes = hex::decode(&fingerprint.canonical_hash).unwrap_or_default();
    let signing_content = [content_bytes.as_slice(), bio_hash.as_bytes()].concat();
    let tsa_token = obtain_tsa_token(&state, &signature);
    let cades_params = crate::signature::cades_der::CadesParams {
        content: &signing_content,
        provider: provider.as_ref(),
        signing_time: now_secs(),
        signer_cert_der: None,
        commitment: crate::signature::cades_der::CadesCommitment::Fea,
        policy_oid: Some(crate::pki_policy::SIGNATURE_POLICY_OID),
        tsa_token_der: tsa_token.as_deref(),
    };

    let cades_der = crate::signature::cades_der::build_cades_der(&cades_params).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("CAdES signing failed: {e}"),
        }
    })?;

    let block_height = store.get_latest_height().unwrap_or(0);
    let fp_json = serde_json::to_value(&fingerprint).unwrap_or_default();
    let sig_hex = hex::encode(&signature);

    let entry = NotarizationEntry {
        signer_proof: Some(body.signer_proof.clone()),
        id: uuid::Uuid::new_v4().to_string(),
        content_hash: fingerprint.canonical_hash.clone(),
        signer: body.signer.clone(),
        metadata: Some(serde_json::json!({ "fingerprint": fp_json })),
        notarized_at: now_secs(),
        block_height,
        signature: sig_hex.clone(),
        public_key: hex::encode(provider.public_key()),
        cades_der: Some(hex::encode(&cades_der)),
        signature_algorithm: provider.algorithm(),
        signature_level: SignatureLevel::Advanced,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store
        .write_notarization(&entry)
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    {
        let tx = crate::storage::traits::Transaction {
            id: format!("notarize:{}", entry.id),
            block_height: 0,
            timestamp: entry.notarized_at,
            input_did: entry.signer.clone(),
            output_recipient: entry.content_hash.clone(),
            amount: 0,
            state: serde_json::to_string(&entry).unwrap_or_else(|_| "notarize".to_string()),
            fee: 0,
            payload: None,
        };
        let mut pool = state.tx_pool.lock().unwrap_or_else(|e| e.into_inner());
        let _ = pool.add(tx);
    }

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::CertificateIssued,
        "",
        Some(format!("pdf_notarize:signer={}", body.signer)),
    );

    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({
            "id": entry.id,
            "canonical_hash": fingerprint.canonical_hash,
            "fingerprint": {
                "content_hash": fingerprint.content_hash,
                "structure_hash": fingerprint.structure_hash,
                "metadata_hash": fingerprint.metadata_hash,
                "tables_hash": fingerprint.tables_hash,
                "images_hash": fingerprint.images_hash,
            },
            "signature": sig_hex,
            "public_key": hex::encode(provider.public_key()),
            "signature_algorithm": provider.algorithm(),
            "cades_der": hex::encode(&cades_der),
            "biometric_hash": bio_hash,
            "signer": entry.signer,
            "notarized_at": entry.notarized_at,
            "block_height": entry.block_height,
        }),
        trace,
    )))
}

struct EntryVerification {
    signature: Option<bool>,
    cades: Option<bool>,
    signer: bool,
}

impl EntryVerification {
    fn is_authentic(&self) -> bool {
        self.signature == Some(true) && self.cades != Some(false) && self.signer
    }
}

fn verify_entry(state: &AppState, entry: &NotarizationEntry) -> EntryVerification {
    if entry.public_key.is_empty() {
        return EntryVerification {
            signature: None,
            cades: None,
            signer: false,
        };
    }
    let payload = build_notarize_payload(
        entry.signature_level,
        &entry.signer,
        &entry.content_hash,
        &entry.biometric_evidence,
    );
    let signature = verify_signature(
        entry.signature_algorithm,
        &entry.public_key,
        payload.as_bytes(),
        &entry.signature,
    );
    let cades = entry
        .cades_der
        .as_ref()
        .map(|cades_hex| verify_entry_cades(state, entry, cades_hex));
    let signer = is_signer_proven(
        &entry.signer,
        &entry.public_key,
        entry.signer_proof.as_ref(),
        payload.as_bytes(),
    );
    EntryVerification {
        signature: Some(signature),
        cades,
        signer,
    }
}

fn verify_entry_cades(state: &AppState, entry: &NotarizationEntry, cades_hex: &str) -> bool {
    let Ok(der) = hex::decode(cades_hex) else {
        return false;
    };
    let bio_hash = compute_biometrics_hash(&entry.biometric_evidence);
    let content_bytes = hex::decode(&entry.content_hash).unwrap_or_default();
    let signing_content = [content_bytes.as_slice(), bio_hash.as_bytes()].concat();
    let ctx = crate::signature::cades_der::VerifyContext {
        trusted_roots: &[],
        crl_store: state.crl_store.as_deref(),
        verify_timestamp: true,
    };
    crate::signature::cades_der::verify_cades_with_context(
        &der,
        &signing_content,
        &entry.public_key,
        &ctx,
    )
    .is_ok()
}

/// Verify a document hash — returns the notarization record if it exists.
#[get("/notarize/verify/{hash}")]
pub async fn verify_notarization(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if content_hash.len() != 64 || hex::decode(&content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "hash must be 64 hex characters (SHA-256)"),
            400,
        )));
    }

    match store.read_notarization_by_hash(&content_hash) {
        Ok(entry) => {
            let verification = verify_entry(&state, &entry);
            if !verification.is_authentic() {
                return Ok(HttpResponse::UnprocessableEntity().json(ApiResponse::<()>::error(
                    err_dto(
                        "INVALID_SIGNATURE",
                        &format!("notarization {} for hash {content_hash} failed signature verification", entry.id),
                    ),
                    422,
                )));
            }

            Ok(HttpResponse::Ok().json(ApiResponse::success(
                serde_json::json!({
                    "verified": true,
                    "signature_verified": verification.signature,
                    "cades_verified": verification.cades,
                    "id": entry.id,
                    "content_hash": entry.content_hash,
                    "signer": entry.signer,
                    "notarized_at": entry.notarized_at,
                    "block_height": entry.block_height,
                    "metadata": entry.metadata,
                    "signature": entry.signature,
                    "signature_algorithm": entry.signature_algorithm,
                    "signature_level": entry.signature_level,
                    "biometric_evidence": entry.biometric_evidence,
                }),
                trace,
            )))
        }
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "no notarization found for this document hash"),
            404,
        ))),
    }
}

/// Get a notarization by ID.
#[get("/notarize/{id}")]
pub async fn get_notarization(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let id = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    match store.read_notarization(&id) {
        Ok(entry) => Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({
                "id": entry.id,
                "content_hash": entry.content_hash,
                "signer": entry.signer,
                "notarized_at": entry.notarized_at,
                "block_height": entry.block_height,
                "metadata": entry.metadata,
                "signature": entry.signature,
                "signature_algorithm": entry.signature_algorithm,
                "signature_level": entry.signature_level,
                "biometric_evidence": entry.biometric_evidence,
            }),
            trace,
        ))),
        Err(_) => Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
            err_dto("NOT_FOUND", "notarization not found"),
            404,
        ))),
    }
}

/// List notarizations, optionally filtered by signer.
#[get("/notarize")]
pub async fn list_notarizations(
    state: web::Data<AppState>,
    query: web::Query<NotarizeListQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let entries = store
        .list_notarizations(query.signer.as_deref())
        .map_err(|e| crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "count": entries.len(),
            "notarizations": entries,
        }),
        trace,
    )))
}

// ── Ownership Transfer ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TransferDocumentRequest {
    /// DID of the current owner (sender).
    pub from_did: String,
    /// DID of the new owner (recipient).
    pub to_did: String,
    /// Public key of the sender (hex).
    pub public_key: String,
    /// Signature over the transfer payload, hex-encoded.
    pub signature: String,
    /// Signature level: "simple" (default) or "advanced".
    #[serde(default)]
    pub signature_level: SignatureLevel,
    /// Signing algorithm: "Ed25519" (default) or "MlDsa65".
    #[serde(default)]
    pub signature_algorithm: SigningAlgorithm,
    /// Biometric evidence (required for Advanced).
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}

/// POST /api/v1/notarize/{hash}/transfer — transfer document ownership.
#[post("/notarize/{hash}/transfer")]
pub async fn transfer_document(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<TransferDocumentRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    // Validate content_hash format
    if content_hash.len() != 64 || hex::decode(&content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "hash must be 64 hex characters"),
            400,
        )));
    }

    // Verify document exists
    store
        .read_notarization_by_hash(&content_hash)
        .map_err(|_| crate::api::errors::ApiError::NotFound {
            resource: format!("notarization {content_hash}"),
        })?;

    // Validate FES/FEA constraints
    if let Err(e) = crate::signature::validate_fes_fea(
        body.signature_level,
        body.signature_algorithm,
        &body.biometric_evidence,
        &body.public_key,
    ) {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("VALIDATION", &e.to_string()),
            400,
        )));
    }

    // Verify from_did matches public_key
    if !crate::identity::did::did_matches_pubkey(&body.from_did, &body.public_key) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("SIGNER_MISMATCH", "from_did does not match public key"),
            401,
        )));
    }

    // Verify signature
    let sign_msg = build_transfer_payload(
        body.signature_level,
        &content_hash,
        &body.from_did,
        &body.to_did,
        &body.biometric_evidence,
    );
    if !verify_signature(
        body.signature_algorithm,
        &body.public_key,
        sign_msg.as_bytes(),
        &body.signature,
    ) {
        return Ok(HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
            err_dto("INVALID_SIGNATURE", "signature verification failed"),
            401,
        )));
    }

    // Resolve current owner: last transfer recipient, or original signer
    let transfers = store
        .read_ownership_transfers(&content_hash)
        .unwrap_or_default();
    let notarization = match store.read_notarization_by_hash(&content_hash) {
        Ok(n) => n,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", "notarization not found for this content hash"),
                404,
            )));
        }
    };
    let current_owner = transfers
        .last()
        .map(|t| t.to_did.as_str())
        .unwrap_or(&notarization.signer);

    // Only current owner can transfer
    if body.from_did != current_owner {
        return Ok(HttpResponse::Forbidden().json(ApiResponse::<()>::error(
            err_dto(
                "NOT_OWNER",
                &format!("only the current owner ({current_owner}) can transfer"),
            ),
            403,
        )));
    }

    let transfer = OwnershipTransfer {
        content_hash: content_hash.clone(),
        from_did: body.from_did.clone(),
        to_did: body.to_did.clone(),
        signature: body.signature.clone(),
        public_key: body.public_key.clone(),
        transferred_at: now_secs(),
        signature_algorithm: body.signature_algorithm,
        signature_level: body.signature_level,
        biometric_evidence: body.biometric_evidence.clone(),
    };

    store.write_ownership_transfer(&transfer).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: e.to_string(),
        }
    })?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "content_hash": content_hash,
            "from": body.from_did,
            "to": body.to_did,
            "transferred_at": transfer.transferred_at,
            "signature_level": transfer.signature_level,
            "signature_algorithm": transfer.signature_algorithm,
        }),
        trace,
    )))
}

/// GET /api/v1/notarize/{hash}/owner — current document owner.
#[get("/notarize/{hash}/owner")]
pub async fn get_document_owner(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let notarization = store
        .read_notarization_by_hash(&content_hash)
        .map_err(|_| crate::api::errors::ApiError::NotFound {
            resource: format!("notarization {content_hash}"),
        })?;

    let transfers = store
        .read_ownership_transfers(&content_hash)
        .unwrap_or_default();
    let current_owner = transfers
        .last()
        .map(|t| t.to_did.clone())
        .unwrap_or_else(|| notarization.signer.clone());

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "content_hash": content_hash,
            "owner": current_owner,
            "original_signer": notarization.signer,
            "transfer_count": transfers.len(),
        }),
        trace,
    )))
}

/// GET /api/v1/notarize/{hash}/provenance — full transfer chain.
#[get("/notarize/{hash}/provenance")]
pub async fn get_document_provenance(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let content_hash = path.into_inner();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let notarization = store
        .read_notarization_by_hash(&content_hash)
        .map_err(|_| crate::api::errors::ApiError::NotFound {
            resource: format!("notarization {content_hash}"),
        })?;

    let transfers = store
        .read_ownership_transfers(&content_hash)
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "content_hash": content_hash,
            "original_signer": notarization.signer,
            "notarized_at": notarization.notarized_at,
            "signature_level": notarization.signature_level,
            "transfers": transfers,
        }),
        trace,
    )))
}

// ── Server-side FEA signing ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignFeaRequest {
    /// SHA-256 hash of the document (64 hex chars).
    pub content_hash: String,
    /// DID of the signer.
    pub signer: String,
    /// Biometric evidence (required, at least one).
    pub biometric_evidence: Vec<BiometricEvidence>,
    /// Output format: "json" (default), "cades-der", "cades-t".
    #[serde(default)]
    pub format: Option<String>,
    pub signer_proof: SignerProof,
}

/// POST /api/v1/sign/fea — server-side FEA signature with CAdES DER.
///
/// Uses the node's persistent signing provider (not ephemeral keys).
/// Produces both a JSON response and a CAdES DER binary signature
/// with biometric hash in signed attributes.
#[post("/sign/fea")]
pub async fn sign_fea(
    state: web::Data<AppState>,
    body: web::Json<SignFeaRequest>,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();

    if body.content_hash.len() != 64 || hex::decode(&body.content_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "content_hash must be 64 hex characters"),
            400,
        )));
    }

    if body.biometric_evidence.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "BIOMETRIC_REQUIRED",
                "FEA requires at least one biometric evidence",
            ),
            400,
        )));
    }
    for evidence in &body.biometric_evidence {
        if let Err(e) = evidence.validate() {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_BIOMETRIC", &e.to_string()),
                400,
            )));
        }
    }

    let provider = state.signing_provider.as_ref().ok_or_else(|| {
        crate::api::errors::ApiError::StorageError {
            reason: "signing provider not configured".into(),
        }
    })?;

    if provider.algorithm() != crate::identity::signing::SigningAlgorithm::MlDsa65 {
        return Ok(
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                err_dto(
                    "ALGORITHM_MISMATCH",
                    "FEA requires ML-DSA-65 but node signing provider is not post-quantum",
                ),
                500,
            )),
        );
    }

    let bio_hash = compute_biometrics_hash(&body.biometric_evidence);
    let content_bytes = hex::decode(&body.content_hash).unwrap_or_default();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = format!(
        "notarize_fea:{}:{}:{}",
        body.signer, body.content_hash, bio_hash
    );
    if !is_signer_proven(
        &body.signer,
        "",
        Some(&body.signer_proof),
        payload.as_bytes(),
    ) {
        return Ok(signer_not_proven(&body.signer));
    }
    let signature = provider.sign(payload.as_bytes()).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("signing failed: {e}"),
        }
    })?;

    let signing_content = [content_bytes.as_slice(), bio_hash.as_bytes()].concat();
    let tsa_token = obtain_tsa_token(&state, &signature);
    let cades_params = crate::signature::cades_der::CadesParams {
        content: &signing_content,
        provider: provider.as_ref(),
        signing_time: now,
        signer_cert_der: None,
        commitment: crate::signature::cades_der::CadesCommitment::Fea,
        policy_oid: Some(crate::pki_policy::SIGNATURE_POLICY_OID),
        tsa_token_der: tsa_token.as_deref(),
    };

    let cades_der = crate::signature::cades_der::build_cades_der(&cades_params).map_err(|e| {
        crate::api::errors::ApiError::StorageError {
            reason: format!("CAdES signing failed: {e}"),
        }
    })?;

    crate::audit::emit_if_present(
        &state.audit_store,
        crate::audit::AuditAction::CertificateIssued,
        "",
        Some(format!("fea:signer={}", body.signer)),
    );

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "signature": hex::encode(&signature),
            "public_key": hex::encode(provider.public_key()),
            "signature_algorithm": provider.algorithm(),
            "signing_payload": payload,
            "cades_der": hex::encode(&cades_der),
            "biometric_hash": bio_hash,
        }),
        trace,
    )))
}

// ── Document integrity verification ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyDocumentRequest {
    pub fingerprint: DocumentFingerprint,
    /// The canonical_hash used when notarizing (lookup key).
    pub registered_hash: String,
}

/// Compare a candidate document fingerprint against a registered notarization.
///
/// The client decomposes the candidate document into its canonical dimensions
/// and submits the fingerprint. The server looks up the original fingerprint
/// (stored in `metadata.fingerprint`) and produces a dimensional comparison.
#[post("/notarize/verify-document")]
pub async fn verify_document(
    state: web::Data<AppState>,
    body: web::Json<VerifyDocumentRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if body.registered_hash.len() != 64 || hex::decode(&body.registered_hash).is_err() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("INVALID_HASH", "registered_hash must be 64 hex characters"),
            400,
        )));
    }

    let entry = match store.read_notarization_by_hash(&body.registered_hash) {
        Ok(e) => e,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(ApiResponse::<()>::error(
                err_dto("NOT_FOUND", "no notarization found for this hash"),
                404,
            )));
        }
    };

    let reference: DocumentFingerprint =
        match &entry.metadata {
            Some(meta) => match meta.get("fingerprint") {
                Some(fp_val) => match serde_json::from_value(fp_val.clone()) {
                    Ok(fp) => fp,
                    Err(_) => {
                        return Ok(HttpResponse::UnprocessableEntity().json(ApiResponse::<()>::error(
                        err_dto(
                            "NO_FINGERPRINT",
                            "notarization exists but was registered without a document fingerprint",
                        ),
                        422,
                    )));
                    }
                },
                None => {
                    return Ok(HttpResponse::UnprocessableEntity().json(ApiResponse::<()>::error(
                    err_dto(
                        "NO_FINGERPRINT",
                        "notarization exists but was registered without a document fingerprint",
                    ),
                    422,
                )));
                }
            },
            None => {
                return Ok(
                    HttpResponse::UnprocessableEntity().json(ApiResponse::<()>::error(
                        err_dto(
                            "NO_FINGERPRINT",
                            "notarization exists but was registered without a document fingerprint",
                        ),
                        422,
                    )),
                );
            }
        };

    if !body
        .fingerprint
        .verify_integrity(crate::crypto::hasher::HashAlgorithm::Sha256)
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto(
                "INTEGRITY_FAILED",
                "candidate fingerprint canonical_hash does not match its dimension hashes",
            ),
            400,
        )));
    }

    let report = body.fingerprint.verify_against(&reference);

    let conclusion = match report.verdict {
        crate::document::VerificationVerdict::Identical => {
            "Este documento es idéntico al documento original registrado en Goya."
        }
        crate::document::VerificationVerdict::ContentMatch => {
            "Este documento corresponde fielmente al documento original registrado en Goya. \
             Las diferencias detectadas corresponden únicamente a cambios de formato/metadata \
             y no alteran el contenido documental."
        }
        crate::document::VerificationVerdict::PartialMatch => {
            "Este documento comparte elementos con el documento original registrado, \
             pero se detectaron modificaciones en algunas dimensiones."
        }
        crate::document::VerificationVerdict::NoMatch => {
            "Este documento no corresponde al documento original registrado en Goya."
        }
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "notarization_id": entry.id,
            "registered_hash": entry.content_hash,
            "verdict": report.verdict,
            "file_identical": report.file_identical,
            "match_ratio": report.match_ratio,
            "dimensions": report.dimensions,
            "conclusion": conclusion,
            "signer": entry.signer,
            "notarized_at": entry.notarized_at,
            "signature_level": entry.signature_level,
        }),
        trace,
    )))
}

// ── Raw document verification ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyRawRequest {
    pub document_base64: String,
}

#[post("/notarize/verify-raw")]
pub async fn verify_raw_document(
    state: web::Data<AppState>,
    body: web::Json<VerifyRawRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let raw = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &body.document_base64,
    ) {
        Ok(d) => d,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                err_dto("INVALID_BASE64", "document_base64 is not valid base64"),
                400,
            )));
        }
    };

    let computed_hash = hex::encode(crate::crypto::hasher::hash_with(
        crate::crypto::hasher::HashAlgorithm::Sha256,
        &raw,
    ));

    let candidate_fingerprint = crate::document::pdf_parser::fingerprint_pdf(&raw).ok();

    match store.read_notarization_by_hash(&computed_hash) {
        Ok(entry) => {
            let signature_verified = if entry.public_key.is_empty() {
                None
            } else {
                let payload = build_notarize_payload(
                    entry.signature_level,
                    &entry.signer,
                    &entry.content_hash,
                    &entry.biometric_evidence,
                );
                Some(verify_signature(
                    entry.signature_algorithm,
                    &entry.public_key,
                    payload.as_bytes(),
                    &entry.signature,
                ))
            };

            let tampered = signature_verified == Some(false);

            let conclusion = if tampered {
                "La firma criptográfica no coincide. El documento o la firma han sido adulterados."
            } else if signature_verified == Some(true) {
                "Este documento es auténtico. Hash y firma criptográfica verificados \
                 matemáticamente contra el registro original en Goya."
            } else {
                "Documento registrado pero sin clave pública almacenada para verificación \
                 criptográfica (registro legacy)."
            };

            Ok(HttpResponse::Ok().json(ApiResponse::success(
                serde_json::json!({
                    "tampered": tampered,
                    "computed_hash": computed_hash,
                    "registered": true,
                    "hash_match": true,
                    "signature_verified": signature_verified,
                    "signer": entry.signer,
                    "signature_algorithm": entry.signature_algorithm,
                    "signature_level": entry.signature_level,
                    "notarized_at": entry.notarized_at,
                    "block_height": entry.block_height,
                    "conclusion": conclusion,
                }),
                trace,
            )))
        }
        Err(_) => {
            let dimensional = candidate_fingerprint.as_ref().and_then(|candidate_fp| {
                let all_entries = store.list_notarizations(None).ok()?;
                for registered in &all_entries {
                    let ref_fp: DocumentFingerprint = registered
                        .metadata
                        .as_ref()?
                        .get("fingerprint")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())?;
                    let report = candidate_fp.verify_against(&ref_fp);
                    if report.match_ratio > 0.0 {
                        return Some(serde_json::json!({
                            "nearest_match": registered.id,
                            "nearest_hash": registered.content_hash,
                            "signer": registered.signer,
                            "notarized_at": registered.notarized_at,
                            "verdict": report.verdict,
                            "match_ratio": report.match_ratio,
                            "file_identical": report.file_identical,
                            "dimensions": report.dimensions,
                        }));
                    }
                }
                None
            });

            let conclusion = if dimensional.is_some() {
                "El hash SHA-256 no coincide con ningún registro, pero el análisis dimensional \
                 encontró un documento similar. Se detectaron modificaciones respecto al original."
            } else {
                "Este documento no tiene registro en Goya. \
                 No se puede verificar su autenticidad."
            };

            Ok(HttpResponse::Ok().json(ApiResponse::success(
                serde_json::json!({
                    "tampered": dimensional.is_some(),
                    "computed_hash": computed_hash,
                    "registered": false,
                    "hash_match": false,
                    "dimensional_analysis": dimensional,
                    "conclusion": conclusion,
                }),
                trace,
            )))
        }
    }
}

// ── Bulk FES endpoint ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BulkFesFile {
    /// File content, base64-encoded.
    pub data_base64: String,
    /// Optional filename for metadata.
    #[serde(default)]
    pub filename: Option<String>,
}

#[derive(Deserialize)]
pub struct BulkFesRequest {
    /// DID of the signer.
    pub signer: String,
    /// Files to sign.
    pub files: Vec<BulkFesFile>,
}

/// Sign multiple files with FES (server-side) in a single request.
///
/// For each file: decode base64 → SHA-256 hash → sign with node's key →
/// store notarization → return proof. TSA timestamp if configured.
///
/// Maximum 100 files per request.
#[post("/sign/fes/bulk")]
pub async fn sign_fes_bulk(
    state: web::Data<AppState>,
    body: web::Json<BulkFesRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    use pqc_crypto_module::legacy::sha256::{Digest, Sha256};

    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if body.files.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("EMPTY", "no files provided"),
            400,
        )));
    }
    if body.files.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("TOO_MANY", "maximum 100 files per bulk request"),
            400,
        )));
    }

    let provider = state.signing_provider.as_ref().ok_or_else(|| {
        crate::api::errors::ApiError::StorageError {
            reason: "signing provider not configured".into(),
        }
    })?;

    let block_height = store.get_latest_height().unwrap_or(0);
    let mut results = Vec::with_capacity(body.files.len());

    for (i, file) in body.files.iter().enumerate() {
        let raw = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &file.data_base64,
        ) {
            Ok(b) => b,
            Err(_) => {
                results.push(serde_json::json!({
                    "index": i,
                    "status": "error",
                    "error": "invalid base64",
                    "filename": file.filename,
                }));
                continue;
            }
        };

        let content_hash = hex::encode(Sha256::digest(&raw));

        if store.read_notarization_by_hash(&content_hash).is_ok() {
            results.push(serde_json::json!({
                "index": i,
                "status": "duplicate",
                "content_hash": content_hash,
                "filename": file.filename,
            }));
            continue;
        }

        let payload = format!("notarize:{}:{}", body.signer, content_hash);
        let signature = match provider.sign(payload.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                results.push(serde_json::json!({
                    "index": i,
                    "status": "error",
                    "error": format!("signing failed: {e}"),
                    "filename": file.filename,
                }));
                continue;
            }
        };

        let sig_hex = hex::encode(&signature);
        let ts = now_secs();
        let id = uuid::Uuid::new_v4().to_string();

        let mut meta = serde_json::json!({});
        if let Some(ref f) = file.filename {
            meta["filename"] = serde_json::json!(f);
        }
        if let Ok(fp) = crate::document::pdf_parser::fingerprint_pdf(&raw) {
            meta["fingerprint"] = serde_json::to_value(&fp).unwrap_or_default();
        }

        let entry = NotarizationEntry {
            signer_proof: None,
            id: id.clone(),
            content_hash: content_hash.clone(),
            signer: body.signer.clone(),
            metadata: Some(meta),
            notarized_at: ts,
            block_height,
            signature: sig_hex.clone(),
            public_key: hex::encode(provider.public_key()),
            cades_der: None,
            signature_algorithm: provider.algorithm(),
            signature_level: SignatureLevel::Simple,
            biometric_evidence: vec![],
        };

        if let Err(e) = store.write_notarization(&entry) {
            results.push(serde_json::json!({
                "index": i,
                "status": "error",
                "error": format!("storage: {e}"),
                "filename": file.filename,
            }));
            continue;
        }

        let tsa_serial = state.tsa_provider.as_ref().and_then(|tsa| {
            let tsa_req = crate::tsa::TimeStampRequest {
                hash_algorithm: crate::crypto::hasher::HashAlgorithm::Sha256,
                message_imprint: content_hash.clone(),
                nonce: Some(ts),
                require_ordering: false,
            };
            tsa.issue(&tsa_req).token.map(|t| t.tst_info.serial_number)
        });

        results.push(serde_json::json!({
            "index": i,
            "status": "signed",
            "id": id,
            "content_hash": content_hash,
            "signature": sig_hex,
            "signature_algorithm": provider.algorithm(),
            "signer": body.signer,
            "notarized_at": ts,
            "block_height": block_height,
            "tsa_serial": tsa_serial,
            "filename": file.filename,
        }));
    }

    let signed_count = results.iter().filter(|r| r["status"] == "signed").count();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "total": body.files.len(),
            "signed": signed_count,
            "results": results,
        }),
        trace,
    )))
}

// ── Bulk verify endpoint ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BulkVerifyItem {
    /// Either a content hash (64 hex chars) or base64-encoded file data.
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub data_base64: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    /// Original hash to compare against (for dimensional analysis of altered files).
    #[serde(default)]
    pub original_hash: Option<String>,
}

#[derive(Deserialize)]
pub struct BulkVerifyRequest {
    pub items: Vec<BulkVerifyItem>,
}

/// Verify multiple documents/hashes against the notarization store.
///
/// Each item can provide either `content_hash` (64 hex) or `data_base64`
/// (file content — will be SHA-256 hashed). Returns verification status
/// for each item including signature details when found.
///
/// Maximum 100 items per request.
#[post("/verify/fes/bulk")]
pub async fn verify_fes_bulk(
    state: web::Data<AppState>,
    body: web::Json<BulkVerifyRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    use pqc_crypto_module::legacy::sha256::{Digest, Sha256};

    let trace = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    if body.items.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("EMPTY", "no items provided"),
            400,
        )));
    }
    if body.items.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            err_dto("TOO_MANY", "maximum 100 items per bulk request"),
            400,
        )));
    }

    let mut results = Vec::with_capacity(body.items.len());

    for (i, item) in body.items.iter().enumerate() {
        let (hash, raw_bytes) = if let Some(ref h) = item.content_hash {
            if h.len() != 64 || hex::decode(h).is_err() {
                results.push(serde_json::json!({
                    "index": i, "status": "error", "error": "invalid hash format",
                    "filename": item.filename,
                }));
                continue;
            }
            (h.clone(), None)
        } else if let Some(ref b64) = item.data_base64 {
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
                Ok(raw) => {
                    let h = hex::encode(Sha256::digest(&raw));
                    (h, Some(raw))
                }
                Err(_) => {
                    results.push(serde_json::json!({
                        "index": i, "status": "error", "error": "invalid base64",
                        "filename": item.filename,
                    }));
                    continue;
                }
            }
        } else {
            results.push(serde_json::json!({
                "index": i, "status": "error",
                "error": "provide either content_hash or data_base64",
                "filename": item.filename,
            }));
            continue;
        };

        match store.read_notarization_by_hash(&hash) {
            Ok(entry) => {
                let status = if verify_entry(&state, &entry).is_authentic() {
                    "verified"
                } else {
                    "invalid_signature"
                };
                results.push(serde_json::json!({
                    "index": i,
                    "status": status,
                    "content_hash": hash,
                    "id": entry.id,
                    "signer": entry.signer,
                    "notarized_at": entry.notarized_at,
                    "block_height": entry.block_height,
                    "signature_algorithm": entry.signature_algorithm,
                    "signature_level": entry.signature_level,
                    "filename": item.filename,
                }));
            }
            Err(_) => {
                if let Some(ref orig_hash) = item.original_hash {
                    if let Ok(original_entry) = store.read_notarization_by_hash(orig_hash) {
                        let mut analysis = serde_json::json!({
                            "original_hash": orig_hash,
                            "current_hash": hash,
                            "original_signer": original_entry.signer,
                            "original_notarized_at": original_entry.notarized_at,
                            "original_signature_algorithm": original_entry.signature_algorithm,
                        });

                        // Try dimensional PDF analysis if both fingerprints are available
                        let original_fp: Option<DocumentFingerprint> = original_entry
                            .metadata
                            .as_ref()
                            .and_then(|m| m.get("fingerprint"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok());

                        if let (Some(ref raw), Some(ref_fp)) = (&raw_bytes, original_fp) {
                            if let Ok(candidate_fp) =
                                crate::document::pdf_parser::fingerprint_pdf(raw)
                            {
                                let report = candidate_fp.verify_against(&ref_fp);
                                analysis["verdict"] = serde_json::json!(report.verdict.to_string());
                                analysis["match_ratio"] = serde_json::json!(report.match_ratio);
                                analysis["file_identical"] =
                                    serde_json::json!(report.file_identical);
                                analysis["dimensions"] =
                                    serde_json::to_value(&report.dimensions).unwrap_or_default();
                            }
                        }

                        results.push(serde_json::json!({
                            "index": i,
                            "status": "altered",
                            "content_hash": hash,
                            "filename": item.filename,
                            "analysis": analysis,
                        }));
                    } else {
                        results.push(serde_json::json!({
                            "index": i,
                            "status": "not_found",
                            "content_hash": hash,
                            "filename": item.filename,
                        }));
                    }
                } else {
                    results.push(serde_json::json!({
                        "index": i,
                        "status": "not_found",
                        "content_hash": hash,
                        "filename": item.filename,
                    }));
                }
            }
        }
    }

    let verified_count = results.iter().filter(|r| r["status"] == "verified").count();

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "total": body.items.len(),
            "verified": verified_count,
            "results": results,
        }),
        trace,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_state::AppState;
    use crate::identity::signing::{
        MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider,
    };
    use actix_web::{test, web, App};

    fn make_app_data() -> web::Data<AppState> {
        web::Data::new(AppState::test_default())
    }

    fn ed25519_identity() -> (String, String, SoftwareSigningProvider) {
        let provider = SoftwareSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&pk_hex);
        (did, pk_hex, provider)
    }

    fn mldsa65_identity() -> (String, String, MlDsaSigningProvider) {
        let provider = MlDsaSigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&pk_hex);
        (did, pk_hex, provider)
    }

    fn signer_proof_for(provider: &SoftwareSigningProvider, payload: &str) -> serde_json::Value {
        serde_json::json!({
            "public_key": hex::encode(provider.public_key()),
            "signature": hex::encode(provider.sign(payload.as_bytes()).unwrap()),
        })
    }

    fn sign_fea_body(
        content_hash: &str,
        biometric_evidence: serde_json::Value,
    ) -> serde_json::Value {
        let (did, _, provider) = ed25519_identity();
        let evidence: Vec<BiometricEvidence> =
            serde_json::from_value(biometric_evidence.clone()).unwrap_or_default();
        let payload = format!(
            "notarize_fea:{did}:{content_hash}:{}",
            compute_biometrics_hash(&evidence)
        );
        serde_json::json!({
            "content_hash": content_hash,
            "signer": did,
            "biometric_evidence": biometric_evidence,
            "signer_proof": signer_proof_for(&provider, &payload),
        })
    }

    fn fingerprint_evidence() -> serde_json::Value {
        serde_json::json!([{
            "evidence_type": "fingerprint",
            "commitment": "a".repeat(64),
            "captured_at": 1700000000u64,
        }])
    }

    struct NodeSignedFea {
        body: serde_json::Value,
        payload: String,
    }

    fn node_signed_fea_request(signer: &str, hash: &str) -> NodeSignedFea {
        let (_, node_pk, node) = mldsa65_identity();
        let evidence: Vec<BiometricEvidence> =
            serde_json::from_value(fingerprint_evidence()).unwrap();
        let payload = format!(
            "notarize_fea:{signer}:{hash}:{}",
            compute_biometrics_hash(&evidence)
        );
        let body = serde_json::json!({
            "content_hash": hash,
            "signer": signer,
            "public_key": node_pk,
            "signature": hex::encode(node.sign(payload.as_bytes()).unwrap()),
            "signature_level": "advanced",
            "signature_algorithm": "MlDsa65",
            "biometric_evidence": fingerprint_evidence(),
        });
        NodeSignedFea { body, payload }
    }

    #[actix_web::test]
    async fn sign_fea_rejects_signer_proof_from_another_key() {
        let mut state = AppState::test_default();
        state.signing_provider = Some(std::sync::Arc::new(MlDsaSigningProvider::generate()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;
        let (victim_did, _, _) = ed25519_identity();
        let (_, _, attacker) = ed25519_identity();
        let mut body = sign_fea_body(&"a".repeat(64), fingerprint_evidence());
        body["signer"] = serde_json::json!(victim_did);
        body["signer_proof"] = signer_proof_for(&attacker, "anything");

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "SIGNER_MISMATCH");
    }

    #[actix_web::test]
    async fn notarize_advanced_rejects_unproven_signer() {
        let app = test::init_service(
            App::new()
                .app_data(make_app_data())
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;
        let (victim_did, _, _) = ed25519_identity();
        let request = node_signed_fea_request(&victim_did, &content_hash());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(request.body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "SIGNER_MISMATCH");
    }

    #[actix_web::test]
    async fn notarize_advanced_with_signer_proof_verifies() {
        let app = test::init_service(
            App::new().app_data(make_app_data()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_notarization),
            ),
        )
        .await;
        let (signer_did, _, signer) = ed25519_identity();
        let hash = content_hash();
        let mut request = node_signed_fea_request(&signer_did, &hash);
        request.body["signer_proof"] = signer_proof_for(&signer, &request.payload);

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(request.body)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 200);
    }

    #[actix_web::test]
    async fn verify_rejects_advanced_entry_without_signer_proof() {
        let state = make_app_data();
        let (victim_did, _, _) = ed25519_identity();
        let (_, node_pk, node) = mldsa65_identity();
        let hash = content_hash();
        let payload = format!(
            "notarize_fea:{victim_did}:{hash}:{}",
            compute_biometrics_hash(&[])
        );
        get_channel_store(&state, "default")
            .unwrap()
            .write_notarization(&NotarizationEntry {
                signer_proof: None,
                id: uuid::Uuid::new_v4().to_string(),
                content_hash: hash.clone(),
                signer: victim_did,
                metadata: None,
                notarized_at: 1_700_000_000,
                block_height: 0,
                signature: hex::encode(node.sign(payload.as_bytes()).unwrap()),
                public_key: node_pk,
                cades_der: None,
                signature_algorithm: SigningAlgorithm::MlDsa65,
                signature_level: SignatureLevel::Advanced,
                biometric_evidence: Vec::new(),
            })
            .unwrap();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_notarization)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 422);
    }

    fn content_hash() -> String {
        use pqc_crypto_module::legacy::sha256::Digest;
        let hash = pqc_crypto_module::legacy::sha256::Sha256::digest(b"test document");
        hex::encode(hash)
    }

    fn store_forged_notarization(state: &web::Data<AppState>, hash: &str) {
        let (did, pk_hex, provider) = ed25519_identity();
        let signature_over_other_document = hex::encode(
            provider
                .sign(format!("notarize:{did}:{}", "0".repeat(64)).as_bytes())
                .unwrap(),
        );
        let store = get_channel_store(state, "default").unwrap();
        store
            .write_notarization(&NotarizationEntry {
                signer_proof: None,
                id: uuid::Uuid::new_v4().to_string(),
                content_hash: hash.to_string(),
                signer: did,
                metadata: None,
                notarized_at: 1_700_000_000,
                block_height: 0,
                signature: signature_over_other_document,
                public_key: pk_hex,
                cades_der: None,
                signature_algorithm: SigningAlgorithm::Ed25519,
                signature_level: SignatureLevel::Simple,
                biometric_evidence: Vec::new(),
            })
            .unwrap();
    }

    #[actix_web::test]
    async fn verify_rejects_entry_with_invalid_signature() {
        let state = make_app_data();
        let hash = content_hash();
        store_forged_notarization(&state, &hash);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_notarization)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 422);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_SIGNATURE");
    }

    #[actix_web::test]
    async fn bulk_verify_rejects_entry_with_invalid_signature() {
        let state = make_app_data();
        let hash = content_hash();
        store_forged_notarization(&state, &hash);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_fes_bulk)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/verify/fes/bulk")
            .set_json(serde_json::json!({ "items": [{ "content_hash": hash }] }))
            .to_request();
        let body: serde_json::Value =
            test::read_body_json(test::call_service(&app, req).await).await;
        assert_eq!(body["data"]["verified"], 0);
        assert_eq!(body["data"]["results"][0]["status"], "invalid_signature");
    }

    // ── E2E: Simple (FES) with Ed25519 ──────────────────────────────

    #[actix_web::test]
    async fn e2e_simple_notarize_and_verify() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_notarization),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["signature_level"], "simple");
        assert_eq!(body["data"]["signature_algorithm"], "Ed25519");

        // Verify
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verified"], true);
        assert_eq!(body["data"]["signature_level"], "simple");
    }

    // ── E2E: Advanced (FEA) with ML-DSA-65 + biometric ──────────────

    #[actix_web::test]
    async fn e2e_advanced_notarize_with_mldsa65_and_biometric() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_notarization)
                    .service(get_notarization),
            ),
        )
        .await;

        let (did, pk_hex, provider) = mldsa65_identity();
        let hash = content_hash();
        let fingerprint_commitment = "a".repeat(64);
        let rut_commitment = "b".repeat(64);
        let bio_evidence = vec![
            serde_json::json!({
                "evidence_type": "fingerprint",
                "commitment": fingerprint_commitment,
                "captured_at": 1700000000u64,
            }),
            serde_json::json!({
                "evidence_type": "rut",
                "commitment": rut_commitment,
                "captured_at": 1700000000u64,
            }),
        ];

        // Build the FEA signing payload
        let bio_for_hash = vec![
            crate::signature::BiometricEvidence {
                evidence_type: crate::signature::BiometricType::Fingerprint,
                commitment: fingerprint_commitment.clone(),
                captured_at: 1700000000,
                capture_device: None,
            },
            crate::signature::BiometricEvidence {
                evidence_type: crate::signature::BiometricType::Rut,
                commitment: rut_commitment.clone(),
                captured_at: 1700000000,
                capture_device: None,
            },
        ];
        let bio_hash = crate::signature::compute_biometrics_hash(&bio_for_hash);
        let payload = format!("notarize_fea:{did}:{hash}:{bio_hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "MlDsa65",
                "biometric_evidence": bio_evidence,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201, "FEA notarize should succeed");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["signature_level"], "advanced");
        assert_eq!(body["data"]["signature_algorithm"], "MlDsa65");

        // Verify — should include biometric evidence
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{hash}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verified"], true);
        assert_eq!(body["data"]["signature_level"], "advanced");
        assert_eq!(body["data"]["signature_algorithm"], "MlDsa65");
        let bio = body["data"]["biometric_evidence"].as_array().unwrap();
        assert_eq!(bio.len(), 2);
        assert_eq!(bio[0]["evidence_type"], "fingerprint");
        assert_eq!(bio[1]["evidence_type"], "rut");
    }

    // ── Verify: rejection paths ────────────────────────────────────────

    #[actix_web::test]
    async fn verify_rejects_invalid_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_notarization)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/notarize/verify/tooshort")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn verify_returns_404_for_unknown_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_notarization)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/notarize/verify/{}", "ab".repeat(32)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ── Rejection: Advanced with Ed25519 ─────────────────────────────

    #[actix_web::test]
    async fn e2e_advanced_with_ed25519_rejected() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "Ed25519",
                "biometric_evidence": [{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"]["code"]
            .as_str()
            .unwrap()
            .contains("VALIDATION"));
    }

    // ── Rejection: Advanced without biometric ────────────────────────

    #[actix_web::test]
    async fn e2e_advanced_without_biometric_rejected() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = mldsa65_identity();
        let hash = content_hash();
        let payload = format!("notarize_fea:{did}:{hash}:{}", "0".repeat(64));
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "MlDsa65",
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["error"]["code"]
            .as_str()
            .unwrap()
            .contains("VALIDATION"));
    }

    // ── Backwards compat: old request without signature_level ────────

    #[actix_web::test]
    async fn e2e_legacy_request_defaults_to_simple() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        // No signature_level, signature_algorithm, or biometric_evidence
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["signature_level"], "simple");
    }

    // ── Rejection: invalid content_hash ────────────────────────────────

    #[actix_web::test]
    async fn submit_rejects_short_content_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let sig = hex::encode(provider.sign(b"whatever").unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": "tooshort",
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_HASH");
    }

    #[actix_web::test]
    async fn submit_rejects_non_hex_content_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let sig = hex::encode(provider.sign(b"whatever").unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": "z".repeat(64),
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_HASH");
    }

    // ── Rejection: signer DID ↔ pubkey mismatch ─────────────────────

    #[actix_web::test]
    async fn submit_rejects_did_pubkey_mismatch() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (_did, _pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let wrong_did = "did:goya:0000000000000000";
        let pk_hex = hex::encode(provider.public_key());
        let payload = format!("notarize:{wrong_did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": wrong_did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "SIGNER_MISMATCH");
    }

    // ── Rejection: invalid signature ────────────────────────────────

    #[actix_web::test]
    async fn submit_rejects_invalid_signature() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, _provider) = ed25519_identity();
        let hash = content_hash();
        let bad_sig = "aa".repeat(32);

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": bad_sig,
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_SIGNATURE");
    }

    // ── Rejection: duplicate notarization ────────────────────────────

    #[actix_web::test]
    async fn submit_rejects_duplicate_content_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let body_json = serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk_hex,
            "signature": sig,
        });

        // First submit — success
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(&body_json)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        // Second submit — conflict
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(&body_json)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 409);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "ALREADY_NOTARIZED");
    }

    // ── Transfer: rejection paths ──────────────────────────────────────

    fn notarize_json(
        did: &str,
        pk_hex: &str,
        provider: &SoftwareSigningProvider,
        hash: &str,
    ) -> serde_json::Value {
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());
        serde_json::json!({
            "content_hash": hash,
            "signer": did,
            "public_key": pk_hex,
            "signature": sig,
        })
    }

    #[actix_web::test]
    async fn transfer_rejects_invalid_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(transfer_document)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/tooshort/transfer")
            .set_json(serde_json::json!({
                "from_did": "did:goya:aaa",
                "to_did": "did:goya:bbb",
                "public_key": "aa".repeat(32),
                "signature": "bb".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn transfer_rejects_nonexistent_document() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(transfer_document)),
        )
        .await;

        let hash = "ab".repeat(32);
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": "did:goya:aaa",
                "to_did": "did:goya:bbb",
                "public_key": "aa".repeat(32),
                "signature": "bb".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn transfer_rejects_did_mismatch() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&did, &pk_hex, &provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let wrong_did = "did:goya:0000000000000000";
        let transfer_payload = format!("transfer_doc:{hash}:{wrong_did}:did:goya:recipient");
        let sig = hex::encode(provider.sign(transfer_payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": wrong_did,
                "to_did": "did:goya:recipient",
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "SIGNER_MISMATCH");
    }

    #[actix_web::test]
    async fn transfer_rejects_bad_signature() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&did, &pk_hex, &provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": did,
                "to_did": "did:goya:recipient",
                "public_key": pk_hex,
                "signature": "aa".repeat(32),
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_SIGNATURE");
    }

    #[actix_web::test]
    async fn transfer_rejects_non_owner() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        // Alice notarizes
        let (alice_did, alice_pk, alice_provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&alice_did, &alice_pk, &alice_provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        // Bob tries to transfer Alice's document
        let (bob_did, bob_pk, bob_provider) = ed25519_identity();
        let transfer_payload = format!("transfer_doc:{hash}:{bob_did}:did:goya:thief");
        let sig = hex::encode(bob_provider.sign(transfer_payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": bob_did,
                "to_did": "did:goya:thief",
                "public_key": bob_pk,
                "signature": sig,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "NOT_OWNER");
    }

    #[actix_web::test]
    async fn transfer_rejects_advanced_with_ed25519() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state.clone()).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(transfer_document),
            ),
        )
        .await;

        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(notarize_json(&did, &pk_hex, &provider, &hash))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        let sig = hex::encode(provider.sign(b"whatever").unwrap());
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/notarize/{hash}/transfer"))
            .set_json(serde_json::json!({
                "from_did": did,
                "to_did": "did:goya:recipient",
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "advanced",
                "signature_algorithm": "Ed25519",
                "biometric_evidence": [{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "VALIDATION");
    }

    // ── sign_fea: rejection paths ───────────────────────────────────────

    #[actix_web::test]
    async fn sign_fea_rejects_invalid_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(sign_fea_body(
                "short",
                serde_json::json!([{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }]),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_HASH");
    }

    #[actix_web::test]
    async fn sign_fea_rejects_empty_biometrics() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(sign_fea_body(&"a".repeat(64), serde_json::json!([])))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "BIOMETRIC_REQUIRED");
    }

    #[actix_web::test]
    async fn sign_fea_rejects_invalid_biometric() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(sign_fea_body(
                &"a".repeat(64),
                serde_json::json!([{
                    "evidence_type": "fingerprint",
                    "commitment": "tooshort",
                    "captured_at": 1700000000u64,
                }]),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INVALID_BIOMETRIC");
    }

    #[actix_web::test]
    async fn sign_fea_rejects_ed25519_provider() {
        let mut state = AppState::test_default();
        state.signing_provider = Some(std::sync::Arc::new(SoftwareSigningProvider::generate()));
        let state = web::Data::new(state);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(sign_fea_body(
                &"a".repeat(64),
                serde_json::json!([{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }]),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 500);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "ALGORITHM_MISMATCH");
    }

    #[actix_web::test]
    async fn sign_fea_succeeds_with_mldsa65_provider() {
        let mut state = AppState::test_default();
        state.signing_provider = Some(std::sync::Arc::new(MlDsaSigningProvider::generate()));
        let state = web::Data::new(state);
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(sign_fea)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/v1/sign/fea")
            .set_json(sign_fea_body(
                &"a".repeat(64),
                serde_json::json!([{
                    "evidence_type": "fingerprint",
                    "commitment": "a".repeat(64),
                    "captured_at": 1700000000u64,
                }]),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "Success");
        assert!(body["data"]["signature_algorithm"]
            .as_str()
            .unwrap()
            .contains("MlDsa65"));
    }

    // ── E2E: Qualified rejected (QTSP not supported) ──────────────────

    #[actix_web::test]
    async fn e2e_qualified_notarize_rejected() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(submit_notarization)),
        )
        .await;

        let (did, pk_hex, provider) = mldsa65_identity();
        let hash = content_hash();
        let bio_commitment = "d".repeat(64);
        let bio_for_hash = vec![crate::signature::BiometricEvidence {
            evidence_type: crate::signature::BiometricType::GovernmentId,
            commitment: bio_commitment.clone(),
            captured_at: 1700000000,
            capture_device: None,
        }];
        let bio_hash = crate::signature::compute_biometrics_hash(&bio_for_hash);
        let payload = format!("notarize_fea:{did}:{hash}:{bio_hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
                "signature_level": "qualified",
                "signature_algorithm": "MlDsa65",
                "biometric_evidence": [{
                    "evidence_type": "government_id",
                    "commitment": bio_commitment,
                    "captured_at": 1700000000u64,
                }],
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let msg = body["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("Qualified") && msg.contains("not yet supported"),
            "Expected QTSP rejection message, got: {msg}"
        );
    }

    // ── Document integrity verification (verify-document) ──────────────

    fn make_fingerprint(content_seed: &[u8], structure_seed: &[u8]) -> DocumentFingerprint {
        use crate::crypto::hasher::{hash_with, HashAlgorithm};
        let ch = hex::encode(hash_with(HashAlgorithm::Sha256, content_seed));
        let sh = hex::encode(hash_with(HashAlgorithm::Sha256, structure_seed));
        let canonical = DocumentFingerprint::compute_canonical_hash(
            &ch,
            &sh,
            None,
            None,
            None,
            HashAlgorithm::Sha256,
        );
        DocumentFingerprint {
            content_hash: ch,
            structure_hash: sh,
            tables_hash: None,
            images_hash: None,
            metadata_hash: None,
            canonical_hash: canonical,
        }
    }

    macro_rules! notarize_fp {
        ($app:expr, $fp:expr) => {{
            let (did, pk_hex, provider) = ed25519_identity();
            let hash = &$fp.canonical_hash;
            let payload = format!("notarize:{did}:{hash}");
            let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());
            let req = test::TestRequest::post()
                .uri("/api/v1/notarize")
                .set_json(serde_json::json!({
                    "content_hash": hash,
                    "signer": did,
                    "public_key": pk_hex,
                    "signature": sig,
                    "metadata": { "fingerprint": $fp },
                }))
                .to_request();
            let resp = test::call_service(&$app, req).await;
            assert_eq!(resp.status(), 201);
            hash.clone()
        }};
    }

    macro_rules! verify_doc_app {
        () => {{
            let state = make_app_data();
            test::init_service(
                App::new().app_data(state).service(
                    web::scope("/api/v1")
                        .service(submit_notarization)
                        .service(verify_document),
                ),
            )
            .await
        }};
    }

    #[actix_web::test]
    async fn verify_document_identical_fingerprint() {
        let app = verify_doc_app!();
        let fp = make_fingerprint(b"contract text", b"heading;paragraph;signature");
        let hash = notarize_fp!(app, fp);

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-document")
            .set_json(serde_json::json!({
                "registered_hash": hash,
                "fingerprint": fp,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verdict"], "identical");
        assert_eq!(body["data"]["file_identical"], true);
        assert_eq!(body["data"]["match_ratio"], 1.0);
    }

    #[actix_web::test]
    async fn verify_document_rejects_tampered_canonical_hash() {
        let app = verify_doc_app!();
        let fp = make_fingerprint(b"contract text", b"heading;paragraph;signature");
        let hash = notarize_fp!(app, fp);

        let mut candidate = fp.clone();
        candidate.canonical_hash = "ff".repeat(32);

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-document")
            .set_json(serde_json::json!({
                "registered_hash": hash,
                "fingerprint": candidate,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "INTEGRITY_FAILED");
    }

    #[actix_web::test]
    async fn verify_document_partial_match() {
        let app = verify_doc_app!();
        let fp = make_fingerprint(b"contract text", b"heading;paragraph;signature");
        let hash = notarize_fp!(app, fp);

        let modified = make_fingerprint(b"contract text", b"different structure");

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-document")
            .set_json(serde_json::json!({
                "registered_hash": hash,
                "fingerprint": modified,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verdict"], "partial_match");
        assert_eq!(body["data"]["match_ratio"], 0.5);
    }

    #[actix_web::test]
    async fn verify_document_no_match() {
        let app = verify_doc_app!();
        let fp = make_fingerprint(b"contract text", b"heading;paragraph;signature");
        let hash = notarize_fp!(app, fp);

        let different = make_fingerprint(b"totally different", b"other structure");

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-document")
            .set_json(serde_json::json!({
                "registered_hash": hash,
                "fingerprint": different,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["verdict"], "no_match");
        assert_eq!(body["data"]["match_ratio"], 0.0);
    }

    #[actix_web::test]
    async fn verify_document_404_for_unknown_hash() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_document)),
        )
        .await;

        let fp = make_fingerprint(b"anything", b"anything");
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-document")
            .set_json(serde_json::json!({
                "registered_hash": "ab".repeat(32),
                "fingerprint": fp,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn verify_document_422_when_no_fingerprint_in_metadata() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_document),
            ),
        )
        .await;

        // Notarize without fingerprint in metadata
        let (did, pk_hex, provider) = ed25519_identity();
        let hash = content_hash();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 201);

        // Try verify-document against it
        let fp = make_fingerprint(b"anything", b"anything");
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-document")
            .set_json(serde_json::json!({
                "registered_hash": hash,
                "fingerprint": fp,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 422);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "NO_FINGERPRINT");
    }

    // ── verify-raw ──────────────────────────────────────────────────

    #[actix_web::test]
    async fn verify_raw_unregistered_document() {
        let state = make_app_data();
        let app = test::init_service(
            App::new()
                .app_data(state)
                .service(web::scope("/api/v1").service(verify_raw_document)),
        )
        .await;

        let doc = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"unknown document",
        );
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-raw")
            .set_json(serde_json::json!({ "document_base64": doc }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["registered"], false);
        assert_eq!(body["data"]["hash_match"], false);
    }

    #[actix_web::test]
    async fn verify_raw_registered_document_matches() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_raw_document),
            ),
        )
        .await;

        let document = b"contract for verify-raw test";
        let hash = hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            document,
        ));
        let (did, pk_hex, provider) = ed25519_identity();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let doc_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, document);
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-raw")
            .set_json(serde_json::json!({ "document_base64": doc_b64 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["registered"], true);
        assert_eq!(body["data"]["hash_match"], true);
        assert_eq!(body["data"]["signature_verified"], true);
        assert_eq!(body["data"]["tampered"], false);
    }

    #[actix_web::test]
    async fn verify_raw_tampered_document_not_found() {
        let state = make_app_data();
        let app = test::init_service(
            App::new().app_data(state).service(
                web::scope("/api/v1")
                    .service(submit_notarization)
                    .service(verify_raw_document),
            ),
        )
        .await;

        let original = b"original document content";
        let hash = hex::encode(crate::crypto::hasher::hash_with(
            crate::crypto::hasher::HashAlgorithm::Sha256,
            original,
        ));
        let (did, pk_hex, provider) = ed25519_identity();
        let payload = format!("notarize:{did}:{hash}");
        let sig = hex::encode(provider.sign(payload.as_bytes()).unwrap());

        let req = test::TestRequest::post()
            .uri("/api/v1/notarize")
            .set_json(serde_json::json!({
                "content_hash": hash,
                "signer": did,
                "public_key": pk_hex,
                "signature": sig,
            }))
            .to_request();
        test::call_service(&app, req).await;

        let tampered = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"TAMPERED document content",
        );
        let req = test::TestRequest::post()
            .uri("/api/v1/notarize/verify-raw")
            .set_json(serde_json::json!({ "document_base64": tampered }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["data"]["registered"], false);
        assert_eq!(body["data"]["hash_match"], false);
    }
}
