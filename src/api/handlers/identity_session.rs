use crate::api::errors::{ApiError, ApiResponse, ApiResult, ErrorDto};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::api::handlers::identity::{jose_algorithm, now_secs, session_signer};
use crate::app_state::AppState;
use actix_web::{post, web, HttpRequest, HttpResponse};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

static REDEEMED_SESSIONS: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, serde::Deserialize)]
pub struct RedeemSessionRequest {
    pub session_token: String,
    #[serde(default)]
    pub allow_read: bool,
}

fn session_access(session_type: &serde_json::Value, allow_read: bool) -> Option<&'static str> {
    match (session_type.as_str(), allow_read) {
        (Some("session"), _) => Some("full"),
        (Some("read_session"), true) => Some("read"),
        _ => None,
    }
}

fn rejection(code: &str, message: String) -> HttpResponse {
    HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
        ErrorDto {
            code: code.to_string(),
            message,
            field: None,
        },
        401,
    ))
}

fn decode_part(part: &str) -> Option<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, part).ok()
}

fn decode_json(part: &str) -> Option<serde_json::Value> {
    serde_json::from_slice(&decode_part(part)?).ok()
}

fn mark_redeemed(signature: &str, exp: u64) -> bool {
    let now = now_secs();
    let mut redeemed = REDEEMED_SESSIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    redeemed.retain(|_, expires_at| *expires_at > now);
    redeemed.insert(signature.to_string(), exp).is_none()
}

#[post("/identity/auth/session/redeem")]
pub async fn redeem_session(
    state: web::Data<AppState>,
    body: web::Json<RedeemSessionRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let signer = session_signer(&state)?;
    let parts: Vec<&str> = body.session_token.split('.').collect();
    let [header_part, payload_part, signature_part] = parts[..] else {
        return Err(ApiError::ValidationError {
            field: "session_token".to_string(),
            reason: "session_token must be a JWT with three parts".to_string(),
        });
    };
    let expected_alg =
        jose_algorithm(signer.algorithm()).map_err(|reason| ApiError::InternalError { reason })?;
    let header = decode_json(header_part).unwrap_or_default();
    if header["alg"] != expected_alg {
        return Ok(rejection(
            "WRONG_ALGORITHM",
            format!("session token alg {} is not {expected_alg}", header["alg"]),
        ));
    }
    let signature = decode_part(signature_part).unwrap_or_default();
    let is_signed_by_node = crate::signature::verify_signature(
        signer.algorithm(),
        &hex::encode(signer.public_key()),
        format!("{header_part}.{payload_part}").as_bytes(),
        &hex::encode(&signature),
    );
    if !is_signed_by_node {
        return Ok(rejection(
            "INVALID_SIGNATURE",
            "session token is not signed by this node".to_string(),
        ));
    }
    let claims = decode_json(payload_part).unwrap_or_default();
    let exp = claims["exp"].as_u64().unwrap_or(0);
    let is_read_session = claims["type"] == "read_session";
    let is_known_session = claims["type"] == "session" || is_read_session;
    if claims["iss"] != "goya-ledger" || !is_known_session || exp <= now_secs() {
        return Ok(rejection(
            "SESSION_EXPIRED",
            "session token is expired or is not a goya-ledger session".to_string(),
        ));
    }
    let Some(access) = session_access(&claims["type"], body.allow_read) else {
        return Ok(rejection(
            "READ_ONLY_SESSION",
            "a read-only session needs allow_read from an app that separates reading from acting"
                .to_string(),
        ));
    };
    let did = claims["sub"].as_str().unwrap_or_default().to_string();
    let store = get_channel_store(&state, channel_id_from_req(&req))?;
    let record = store
        .read_identity(&did)
        .ok()
        .filter(|record| record.status == "active");
    let Some(record) = record else {
        return Ok(rejection(
            "IDENTITY_INACTIVE",
            format!("identity {did} is not active on this node"),
        ));
    };
    let reader_entry_id = claims["reader_entry_id"].as_str().unwrap_or_default();
    let is_reader_active =
        crate::identity::reader_login::active_reader_key(&record, reader_entry_id).is_some();
    if is_read_session && !is_reader_active {
        return Ok(rejection(
            "READER_REVOKED",
            format!("reader {reader_entry_id} of {did} is revoked or unknown"),
        ));
    }
    if !mark_redeemed(signature_part, exp) {
        return Ok(rejection(
            "SESSION_ALREADY_REDEEMED",
            format!("session token for {did} was already redeemed"),
        ));
    }
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({
            "did": did,
            "exp": exp,
            "access": access,
            "verified_factors": claims["verified_factors"],
            "device_factors": claims["device_factors"],
        }),
        uuid::Uuid::new_v4().to_string(),
    )))
}
