use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::get_channel_store;
use crate::api::handlers::identity::{commit_ledger_op, identity_op_error, now_secs};
use crate::api::handlers::oid4vci::{
    configuration_vct, credential_issuer, PendingIssuance, PendingIssuanceStore,
    SIGNED_REQUEST_FRESHNESS_SECS,
};
use crate::app_state::AppState;
use crate::identity::credential_ops::require_issuer_signature;
use crate::identity::issuer_keys::{self, https_url_path, issuer_path, sec1_public_key_hex};
use crate::identity::operations::Change;
use crate::identity::sd_jwt::verify_sd_jwt_vc;
use crate::identity::signing::SigningAlgorithm;
use crate::identity::status_lists;
use crate::storage::traits::{IssuerCredentialKey, IssuerStatusList, P256PublicJwk, TxPayload};
use actix_web::{get, post, put, web, HttpRequest, HttpResponse};

const ISSUER_CHANNEL: &str = "default";

#[derive(Debug, serde::Deserialize)]
pub struct RegisterCredentialKeyRequest {
    pub jwk: P256PublicJwk,
    pub registered_at: u64,
    pub public_key: String,
    pub signature: String,
}

#[post("/issuers/{did}/credential-key")]
pub async fn register_credential_key(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<RegisterCredentialKeyRequest>,
) -> ApiResult<HttpResponse> {
    let RegisterCredentialKeyRequest {
        jwk,
        registered_at,
        public_key,
        signature,
    } = body.into_inner();
    let registration = IssuerCredentialKey {
        did: path.into_inner(),
        jwk,
        registered_at,
        public_key,
        signature,
    };
    let store = get_channel_store(&state, ISSUER_CHANNEL)?;
    let change = issuer_keys::check_register_credential_key(store.as_ref(), &registration)
        .map_err(identity_op_error)?;
    if change == Change::AlreadyApplied {
        return Err(ApiError::Conflict {
            reason: format!(
                "this credential key is already registered for {}",
                registration.did
            ),
        });
    }
    commit_ledger_op(
        &state,
        store.as_ref(),
        ISSUER_CHANNEL,
        &registration.did,
        TxPayload::RegisterIssuerCredentialKey {
            registration: Box::new(registration.clone()),
        },
    )?;
    Ok(HttpResponse::Created().json(ApiResponse::success(
        registration,
        uuid::Uuid::new_v4().to_string(),
    )))
}

fn read_credential_key(state: &AppState, did: &str) -> Result<IssuerCredentialKey, ApiError> {
    get_channel_store(state, ISSUER_CHANNEL)?
        .read_issuer_credential_key(did)
        .map_err(|_| ApiError::NotFound {
            resource: format!("credential key of issuer {did}"),
        })
}

#[get("/issuers/{did}/credential-key")]
pub async fn get_credential_key(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let registration = read_credential_key(&state, &path.into_inner())?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        registration,
        uuid::Uuid::new_v4().to_string(),
    )))
}

pub async fn jwt_vc_issuer_metadata(
    state: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let registration = read_credential_key(&state, &did)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "issuer": format!("{}/api/v1/issuers/{did}", credential_issuer(&req)),
        "jwks": { "keys": [registration.jwk] },
    })))
}

#[derive(Debug, serde::Deserialize)]
pub struct PublishStatusListRequest {
    pub status_list_jwt: String,
}

#[put("/issuers/{did}/status-lists/{list_id}")]
pub async fn publish_status_list(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Json<PublishStatusListRequest>,
) -> ApiResult<HttpResponse> {
    let (did, list_id) = path.into_inner();
    let status_list = IssuerStatusList {
        did,
        list_id,
        jwt: body.into_inner().status_list_jwt,
    };
    let store = get_channel_store(&state, ISSUER_CHANNEL)?;
    let change = status_lists::check_publish_status_list(store.as_ref(), &status_list)
        .map_err(identity_op_error)?;
    if change == Change::AlreadyApplied {
        return Err(ApiError::Conflict {
            reason: format!(
                "status list {} of {} is already this JWT",
                status_list.list_id, status_list.did
            ),
        });
    }
    commit_ledger_op(
        &state,
        store.as_ref(),
        ISSUER_CHANNEL,
        &status_list.did,
        TxPayload::PublishIssuerStatusList {
            status_list: Box::new(status_list.clone()),
        },
    )?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "did": status_list.did, "list_id": status_list.list_id }),
        uuid::Uuid::new_v4().to_string(),
    )))
}

#[get("/issuers/{did}/status-lists/{list_id}")]
pub async fn get_status_list(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> ApiResult<HttpResponse> {
    let (did, list_id) = path.into_inner();
    let status_list = get_channel_store(&state, ISSUER_CHANNEL)?
        .read_issuer_status_list(&did, &list_id)
        .map_err(|_| ApiError::NotFound {
            resource: format!("status list {list_id} of issuer {did}"),
        })?;
    Ok(HttpResponse::Ok()
        .content_type("application/statuslist+jwt")
        .body(status_list.jwt))
}

pub fn pending_issuances_message(did: &str, issued_at: u64) -> String {
    format!("oid4vci:pending:{did}:{issued_at}")
}

#[derive(Debug, serde::Deserialize)]
pub struct PendingIssuancesQuery {
    pub public_key: String,
    pub issued_at: u64,
    pub signature: String,
}

#[derive(serde::Serialize)]
struct PendingIssuanceView {
    transaction_id: String,
    configuration_id: String,
    vct: Option<String>,
    holder_jwk: serde_json::Value,
    created_at: u64,
}

#[get("/issuers/{did}/issuances")]
pub async fn list_pending_issuances(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<PendingIssuancesQuery>,
    pending_store: web::Data<PendingIssuanceStore>,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    if now_secs().abs_diff(query.issued_at) > SIGNED_REQUEST_FRESHNESS_SECS {
        return Err(ApiError::UnauthorizedWithMessage {
            message: format!(
                "issued_at {} is more than {SIGNED_REQUEST_FRESHNESS_SECS} s from now",
                query.issued_at
            ),
        });
    }
    require_issuer_signature(
        get_channel_store(&state, ISSUER_CHANNEL)?.as_ref(),
        &did,
        &query.public_key,
        &pending_issuances_message(&did, query.issued_at),
        &query.signature,
    )
    .map_err(identity_op_error)?;
    let pending: Vec<PendingIssuanceView> = pending_store
        .undelivered_by_issuer(&did)
        .into_iter()
        .map(|(transaction_id, issuance)| PendingIssuanceView {
            transaction_id,
            vct: configuration_vct(&issuance.grant.configuration_id),
            configuration_id: issuance.grant.configuration_id,
            holder_jwk: issuance.holder_jwk,
            created_at: issuance.created_at,
        })
        .collect();
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        pending,
        uuid::Uuid::new_v4().to_string(),
    )))
}

#[derive(Debug, serde::Deserialize)]
pub struct DeliverCredentialRequest {
    pub credential: String,
}

fn names_issuer(iss: &str, did: &str) -> bool {
    https_url_path(iss) == Some(issuer_path(did).as_str())
}

fn is_same_public_jwk(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    ["kty", "crv", "x", "y"]
        .iter()
        .all(|member| left.get(member) == right.get(member))
}

fn invalid_credential(field: &str, reason: String) -> ApiError {
    ApiError::ValidationError {
        field: field.to_string(),
        reason,
    }
}

fn verify_delivered_credential(
    credential: &str,
    registration: &IssuerCredentialKey,
    issuance: &PendingIssuance,
) -> Result<(), ApiError> {
    let did = &registration.did;
    let credential_key_hex =
        sec1_public_key_hex(&registration.jwk).ok_or_else(|| ApiError::InternalError {
            reason: format!("registered credential key of {did} is not a P-256 JWK"),
        })?;
    let verified = verify_sd_jwt_vc(credential, &credential_key_hex)
        .ok()
        .filter(|verified| verified.algorithm == SigningAlgorithm::EcdsaP256)
        .ok_or_else(|| ApiError::UnauthorizedWithMessage {
            message: format!(
                "credential is not an SD-JWT VC signed with ES256 by the registered credential key of {did}"
            ),
        })?;
    if !names_issuer(&verified.iss, did) {
        return Err(invalid_credential(
            "iss",
            format!(
                "iss {} is not https://{{host}}/api/v1/issuers/{did}",
                verified.iss
            ),
        ));
    }
    let expected_vct = configuration_vct(&issuance.grant.configuration_id);
    if expected_vct.as_deref() != Some(verified.vct.as_str()) {
        return Err(invalid_credential(
            "vct",
            format!(
                "vct {} is not {expected_vct:?} of configuration {}",
                verified.vct, issuance.grant.configuration_id
            ),
        ));
    }
    let bound_jwk = verified.cnf.as_ref().and_then(|cnf| cnf.get("jwk"));
    if !bound_jwk.is_some_and(|jwk| is_same_public_jwk(jwk, &issuance.holder_jwk)) {
        return Err(invalid_credential(
            "cnf",
            "cnf.jwk is not the holder key proven in the credential request".to_string(),
        ));
    }
    let Some(status) = &verified.status else {
        return Ok(());
    };
    let status_list_uri = status["status_list"]["uri"].as_str().unwrap_or_default();
    if !status_lists::is_own_status_list_uri(status_list_uri, did) {
        return Err(invalid_credential(
            "status",
            format!(
                "status.status_list.uri {status_list_uri:?} is not https://{{host}}/api/v1/issuers/{did}/status-lists/{{list_id}}"
            ),
        ));
    }
    Ok(())
}

#[post("/issuers/{did}/issuances/{transaction_id}")]
pub async fn deliver_issuance(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Json<DeliverCredentialRequest>,
    pending_store: web::Data<PendingIssuanceStore>,
) -> ApiResult<HttpResponse> {
    let (did, transaction_id) = path.into_inner();
    let issuance = pending_store
        .find(&transaction_id)
        .filter(|issuance| issuance.grant.issuer_did == did)
        .ok_or_else(|| ApiError::NotFound {
            resource: format!("pending issuance {transaction_id} of issuer {did}"),
        })?;
    if issuance.credential.is_some() {
        return Err(ApiError::Conflict {
            reason: format!("issuance {transaction_id} was already delivered"),
        });
    }
    let registration = read_credential_key(&state, &did)?;
    verify_delivered_credential(&body.credential, &registration, &issuance)?;
    pending_store
        .deliver(&transaction_id, body.into_inner().credential)
        .map_err(|reason| ApiError::Conflict {
            reason: format!("issuance {transaction_id} not delivered: {reason}"),
        })?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "transaction_id": transaction_id }),
        uuid::Uuid::new_v4().to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::oid4vci::{
        deferred_credential_endpoint, AccessTokenStore, IssuanceGrant,
    };
    use crate::identity::issuer_keys::credential_key_message;
    use crate::identity::sd_jwt::{issue_sd_jwt_vc, VcClaims};
    use crate::identity::signing::{
        EcdsaP256SigningProvider, SigningProvider, SoftwareSigningProvider,
    };
    use crate::storage::traits::BlockStore;
    use crate::storage::MemoryStore;
    use actix_web::{test, App};

    fn base64url(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    fn public_jwk(credential_key: &EcdsaP256SigningProvider) -> serde_json::Value {
        let sec1 = credential_key.public_key();
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64url(&sec1[1..33]),
            "y": base64url(&sec1[33..65]),
        })
    }

    struct Issuer {
        key: SoftwareSigningProvider,
        public_key: String,
        did: String,
    }

    fn issuer() -> Issuer {
        let key = SoftwareSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        Issuer {
            key,
            public_key,
            did,
        }
    }

    fn key_registration_body(
        signer: &Issuer,
        did: &str,
        jwk: &serde_json::Value,
        registered_at: u64,
    ) -> serde_json::Value {
        let typed_jwk: P256PublicJwk = serde_json::from_value(jwk.clone()).unwrap();
        let message = credential_key_message(did, &typed_jwk, registered_at);
        serde_json::json!({
            "jwk": jwk,
            "registered_at": registered_at,
            "public_key": signer.public_key,
            "signature": hex::encode(signer.key.sign(message.as_bytes()).unwrap()),
        })
    }

    macro_rules! issuers_app {
        ($state:expr) => {
            issuers_app!(
                $state,
                web::Data::new(PendingIssuanceStore::new()),
                web::Data::new(AccessTokenStore::new())
            )
        };
        ($state:expr, $pending:expr, $tokens:expr) => {
            test::init_service(
                App::new()
                    .app_data($state.clone())
                    .app_data($pending.clone())
                    .app_data($tokens.clone())
                    .service(deferred_credential_endpoint)
                    .route(
                        "/.well-known/jwt-vc-issuer/api/v1/issuers/{did}",
                        web::get().to(jwt_vc_issuer_metadata),
                    )
                    .service(
                        web::scope("/api/v1")
                            .service(register_credential_key)
                            .service(get_credential_key)
                            .service(list_pending_issuances)
                            .service(deliver_issuance)
                            .service(publish_status_list)
                            .service(get_status_list)
                            .route(
                                "/issuers/{did}/.well-known/jwt-vc-issuer",
                                web::get().to(jwt_vc_issuer_metadata),
                            ),
                    ),
            )
            .await
        };
    }

    macro_rules! post_status {
        ($app:expr, $uri:expr, $body:expr) => {{
            let req = test::TestRequest::post()
                .uri($uri)
                .set_json($body)
                .to_request();
            test::call_service($app, req).await.status().as_u16()
        }};
    }

    #[actix_web::test]
    async fn signed_credential_key_is_registered_replicated_and_served() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let issuer = issuer();
        let uri = format!("/api/v1/issuers/{}/credential-key", issuer.did);
        let jwk = public_jwk(&EcdsaP256SigningProvider::generate());
        let body = key_registration_body(&issuer, &issuer.did, &jwk, 100);

        let get = || test::TestRequest::get().uri(&uri).to_request();
        assert_eq!(test::call_service(&app, get()).await.status(), 404);
        assert_eq!(post_status!(&app, &uri, &body), 201);
        assert_eq!(post_status!(&app, &uri, &body), 409);
        let served: serde_json::Value = test::call_and_read_body_json(&app, get()).await;
        assert_eq!(served["data"]["jwk"], jwk);

        let queued = state
            .tx_pool
            .lock()
            .unwrap()
            .all()
            .iter()
            .find(|tx| {
                matches!(
                    tx.payload,
                    Some(TxPayload::RegisterIssuerCredentialKey { .. })
                )
            })
            .cloned()
            .unwrap();
        let replica = MemoryStore::new();
        crate::transaction::apply_tx_payload(&replica, &queued).unwrap();
        assert_eq!(
            serde_json::to_value(replica.read_issuer_credential_key(&issuer.did).unwrap()).unwrap()
                ["jwk"],
            jwk
        );
    }

    #[actix_web::test]
    async fn credential_key_not_signed_by_the_did_key_is_refused() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let (issuer, impostor) = (issuer(), issuer());
        let uri = format!("/api/v1/issuers/{}/credential-key", issuer.did);
        let jwk = public_jwk(&EcdsaP256SigningProvider::generate());

        let signed_by_other_did = key_registration_body(&impostor, &issuer.did, &jwk, 100);
        assert_eq!(post_status!(&app, &uri, &signed_by_other_did), 401);

        let mut unsigned = key_registration_body(&issuer, &issuer.did, &jwk, 100);
        unsigned["signature"] = "00".repeat(64).into();
        assert_eq!(post_status!(&app, &uri, &unsigned), 401);

        let get = test::TestRequest::get().uri(&uri).to_request();
        assert_eq!(test::call_service(&app, get).await.status(), 404);
    }

    #[actix_web::test]
    async fn credential_key_carrying_a_private_component_is_refused() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let issuer = issuer();
        let uri = format!("/api/v1/issuers/{}/credential-key", issuer.did);
        let jwk = public_jwk(&EcdsaP256SigningProvider::generate());
        let mut body = key_registration_body(&issuer, &issuer.did, &jwk, 100);
        body["jwk"]["d"] = base64url(&[7u8; 32]).into();
        assert_eq!(post_status!(&app, &uri, &body), 400);
    }

    const PID_CONFIGURATION: &str = "eudi_pid_sd_jwt";
    const PID_VCT: &str = "urn:eudi:pid:1";

    fn issuer_url(did: &str) -> String {
        format!("https://localhost:8080/api/v1/issuers/{did}")
    }

    fn holder_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64url(&SoftwareSigningProvider::generate().public_key()),
        })
    }

    fn vc_claims(iss: &str, vct: &str, bound_jwk: &serde_json::Value) -> VcClaims {
        VcClaims {
            iss: iss.to_string(),
            sub: "holder".to_string(),
            iat: now_secs(),
            exp: now_secs() + 3600,
            vct: vct.to_string(),
            claims: vec![("given_name".to_string(), serde_json::json!("Ada"))],
            cnf: Some(serde_json::json!({ "jwk": bound_jwk })),
            status: None,
        }
    }

    fn sd_jwt_vc(
        credential_key: &EcdsaP256SigningProvider,
        iss: &str,
        vct: &str,
        bound_jwk: &serde_json::Value,
    ) -> String {
        issue_sd_jwt_vc(&vc_claims(iss, vct, bound_jwk), credential_key)
            .unwrap()
            .compact
    }

    struct OpenIssuance {
        access_token: String,
        transaction_id: String,
        holder_jwk: serde_json::Value,
    }

    fn open_issuance(
        tokens: &AccessTokenStore,
        pending: &PendingIssuanceStore,
        did: &str,
    ) -> OpenIssuance {
        let grant = IssuanceGrant {
            issuer_did: did.to_string(),
            configuration_id: PID_CONFIGURATION.to_string(),
        };
        let access_token = tokens.issue(grant.clone(), 3600);
        let holder_jwk = holder_jwk();
        let transaction_id = pending.record(&access_token, grant, holder_jwk.clone());
        OpenIssuance {
            access_token,
            transaction_id,
            holder_jwk,
        }
    }

    macro_rules! register_key {
        ($app:expr, $issuer:expr, $credential_key:expr) => {{
            let jwk = public_jwk($credential_key);
            let uri = format!("/api/v1/issuers/{}/credential-key", $issuer.did);
            let body = key_registration_body($issuer, &$issuer.did, &jwk, now_secs());
            assert_eq!(post_status!($app, &uri, &body), 201);
            jwk
        }};
    }

    macro_rules! deliver_status {
        ($app:expr, $did:expr, $transaction_id:expr, $credential:expr) => {
            post_status!(
                $app,
                &format!("/api/v1/issuers/{}/issuances/{}", $did, $transaction_id),
                &serde_json::json!({ "credential": $credential })
            )
        };
    }

    #[actix_web::test]
    async fn jwt_vc_issuer_metadata_serves_the_registered_key_only() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let issuer = issuer();
        let uris = [
            format!("/.well-known/jwt-vc-issuer/api/v1/issuers/{}", issuer.did),
            format!("/api/v1/issuers/{}/.well-known/jwt-vc-issuer", issuer.did),
        ];
        let get = |uri: &str| {
            test::TestRequest::get()
                .uri(uri)
                .insert_header(("host", "localhost:8080"))
                .to_request()
        };
        for uri in &uris {
            assert_eq!(test::call_service(&app, get(uri)).await.status(), 404);
        }
        let jwk = register_key!(&app, &issuer, &EcdsaP256SigningProvider::generate());
        for uri in &uris {
            let metadata: serde_json::Value = test::call_and_read_body_json(&app, get(uri)).await;
            assert_eq!(
                metadata,
                serde_json::json!({ "issuer": issuer_url(&issuer.did), "jwks": { "keys": [jwk] } })
            );
        }
    }

    #[actix_web::test]
    async fn pending_issuances_are_listed_only_to_their_issuer_with_a_fresh_signature() {
        let state = web::Data::new(AppState::test_default());
        let pending = web::Data::new(PendingIssuanceStore::new());
        let tokens = web::Data::new(AccessTokenStore::new());
        let app = issuers_app!(state, pending, tokens);
        let (issuer, other) = (issuer(), issuer());
        let own = open_issuance(&tokens, &pending, &issuer.did);
        open_issuance(&tokens, &pending, &other.did);

        let list_status = |signer: &Issuer, issued_at: u64| {
            let message = pending_issuances_message(&issuer.did, issued_at);
            let signature = hex::encode(signer.key.sign(message.as_bytes()).unwrap());
            test::TestRequest::get()
                .uri(&format!(
                    "/api/v1/issuers/{}/issuances?public_key={}&issued_at={issued_at}&signature={signature}",
                    issuer.did, signer.public_key
                ))
                .to_request()
        };
        let stale = list_status(&issuer, now_secs() - 301);
        assert_eq!(test::call_service(&app, stale).await.status(), 401);
        let by_other = list_status(&other, now_secs());
        assert_eq!(test::call_service(&app, by_other).await.status(), 401);

        let listed: serde_json::Value =
            test::call_and_read_body_json(&app, list_status(&issuer, now_secs())).await;
        let items = listed["data"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["transaction_id"], own.transaction_id);
        assert_eq!(items[0]["configuration_id"], PID_CONFIGURATION);
        assert_eq!(items[0]["vct"], PID_VCT);
        assert_eq!(items[0]["holder_jwk"], own.holder_jwk);
    }

    #[actix_web::test]
    async fn delivered_credential_reaches_the_wallet_through_deferred_credential() {
        let state = web::Data::new(AppState::test_default());
        let pending = web::Data::new(PendingIssuanceStore::new());
        let tokens = web::Data::new(AccessTokenStore::new());
        let app = issuers_app!(state, pending, tokens);
        let issuer = issuer();
        let credential_key = EcdsaP256SigningProvider::generate();
        register_key!(&app, &issuer, &credential_key);
        let issuance = open_issuance(&tokens, &pending, &issuer.did);
        let credential = sd_jwt_vc(
            &credential_key,
            &issuer_url(&issuer.did),
            PID_VCT,
            &issuance.holder_jwk,
        );

        assert_eq!(
            deliver_status!(&app, issuer.did, issuance.transaction_id, &credential),
            200
        );
        assert_eq!(
            deliver_status!(&app, issuer.did, issuance.transaction_id, &credential),
            409
        );
        let req = test::TestRequest::post()
            .uri("/deferred_credential")
            .insert_header(("authorization", format!("Bearer {}", issuance.access_token)))
            .set_json(serde_json::json!({ "transaction_id": issuance.transaction_id }))
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(
            body,
            serde_json::json!({ "credentials": [{ "credential": credential }] })
        );
    }

    #[actix_web::test]
    async fn delivery_refuses_a_credential_that_does_not_match_the_issuance() {
        let state = web::Data::new(AppState::test_default());
        let pending = web::Data::new(PendingIssuanceStore::new());
        let tokens = web::Data::new(AccessTokenStore::new());
        let app = issuers_app!(state, pending, tokens);
        let (issuer, other) = (issuer(), issuer());
        let credential_key = EcdsaP256SigningProvider::generate();
        register_key!(&app, &issuer, &credential_key);
        register_key!(&app, &other, &EcdsaP256SigningProvider::generate());
        let issuance = open_issuance(&tokens, &pending, &issuer.did);
        let iss = issuer_url(&issuer.did);
        let holder = &issuance.holder_jwk;
        let refusals = [
            (
                sd_jwt_vc(&EcdsaP256SigningProvider::generate(), &iss, PID_VCT, holder),
                401,
            ),
            (
                sd_jwt_vc(&credential_key, &issuer_url(&other.did), PID_VCT, holder),
                400,
            ),
            (
                sd_jwt_vc(&credential_key, &iss, "IdentityCredential", holder),
                400,
            ),
            (
                sd_jwt_vc(&credential_key, &iss, PID_VCT, &holder_jwk()),
                400,
            ),
        ];
        for (credential, status) in &refusals {
            assert_eq!(
                deliver_status!(&app, issuer.did, issuance.transaction_id, credential),
                *status
            );
        }
        let genuine = sd_jwt_vc(&credential_key, &iss, PID_VCT, holder);
        assert_eq!(
            deliver_status!(&app, other.did, issuance.transaction_id, &genuine),
            404
        );
        assert_eq!(
            deliver_status!(&app, issuer.did, "goya_tx_unknown", &genuine),
            404
        );
        assert!(pending
            .find(&issuance.transaction_id)
            .unwrap()
            .credential
            .is_none());
    }

    const STATUS_LIST_ID: &str = "revocations";

    fn status_list_jwt(
        signer: &EcdsaP256SigningProvider,
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> String {
        let encode = |segment: &serde_json::Value| base64url(&serde_json::to_vec(segment).unwrap());
        let signing_input = format!("{}.{}", encode(&header), encode(&payload));
        let signature = signer.sign(signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", base64url(&signature))
    }

    fn status_list_header() -> serde_json::Value {
        serde_json::json!({ "typ": "statuslist+jwt", "alg": "ES256" })
    }

    fn status_list_payload(did: &str, list_id: &str, iat: u64) -> serde_json::Value {
        serde_json::json!({
            "iss": issuer_url(did),
            "sub": format!("{}/status-lists/{list_id}", issuer_url(did)),
            "iat": iat,
            "status_list": { "bits": 1, "lst": "eNrbuRgAAhcBXQ" },
        })
    }

    fn status_list_uri(did: &str, list_id: &str) -> String {
        format!("/api/v1/issuers/{did}/status-lists/{list_id}")
    }

    macro_rules! publish_status {
        ($app:expr, $uri:expr, $jwt:expr) => {{
            let req = test::TestRequest::put()
                .uri($uri)
                .set_json(serde_json::json!({ "status_list_jwt": $jwt }))
                .to_request();
            test::call_service($app, req).await.status().as_u16()
        }};
    }

    macro_rules! served_status_list {
        ($app:expr, $uri:expr) => {{
            let req = test::TestRequest::get().uri($uri).to_request();
            let response = test::call_service($app, req).await;
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get("content-type")
                .map(|value| value.to_str().unwrap().to_string());
            let body = test::read_body(response).await;
            (
                status,
                content_type,
                String::from_utf8(body.to_vec()).unwrap(),
            )
        }};
    }

    fn queued_transactions(state: &AppState) -> Vec<crate::storage::traits::Transaction> {
        state.tx_pool.lock().unwrap().all().to_vec()
    }

    #[actix_web::test]
    async fn status_list_signed_by_the_registered_key_is_published_replicated_and_served() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let issuer = issuer();
        let credential_key = EcdsaP256SigningProvider::generate();
        register_key!(&app, &issuer, &credential_key);
        let uri = status_list_uri(&issuer.did, STATUS_LIST_ID);
        let jwt = status_list_jwt(
            &credential_key,
            status_list_header(),
            status_list_payload(&issuer.did, STATUS_LIST_ID, 100),
        );

        assert_eq!(served_status_list!(&app, &uri).0, 404);
        assert_eq!(publish_status!(&app, &uri, &jwt), 200);
        assert_eq!(publish_status!(&app, &uri, &jwt), 409);
        assert_eq!(
            served_status_list!(&app, &uri),
            (
                200,
                Some("application/statuslist+jwt".to_string()),
                jwt.clone()
            )
        );

        let replica = MemoryStore::new();
        for tx in queued_transactions(&state) {
            crate::transaction::apply_tx_payload(&replica, &tx).unwrap();
        }
        assert_eq!(
            replica
                .read_issuer_status_list(&issuer.did, STATUS_LIST_ID)
                .unwrap()
                .jwt,
            jwt
        );

        let replica_without_key = MemoryStore::new();
        let published = queued_transactions(&state)
            .into_iter()
            .find(|tx| matches!(tx.payload, Some(TxPayload::PublishIssuerStatusList { .. })))
            .unwrap();
        assert!(crate::transaction::apply_tx_payload(&replica_without_key, &published).is_err());
    }

    #[actix_web::test]
    async fn status_list_is_refused_unless_signed_and_named_for_its_list() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let (issuer, other) = (issuer(), issuer());
        let credential_key = EcdsaP256SigningProvider::generate();
        let uri = status_list_uri(&issuer.did, STATUS_LIST_ID);
        let payload = status_list_payload(&issuer.did, STATUS_LIST_ID, 100);
        let genuine = status_list_jwt(&credential_key, status_list_header(), payload.clone());

        assert_eq!(publish_status!(&app, &uri, &genuine), 404);
        register_key!(&app, &issuer, &credential_key);

        let (signing_input, _) = genuine.rsplit_once('.').unwrap();
        let unsigned = format!("{signing_input}.{}", base64url(&[0u8; 64]));
        let mut plain_jwt_header = status_list_header();
        plain_jwt_header["typ"] = "JWT".into();
        let mut bits_three = payload.clone();
        bits_three["status_list"]["bits"] = 3.into();
        let mut empty_list = payload.clone();
        empty_list["status_list"]["lst"] = "".into();
        let mut no_iat = payload.clone();
        no_iat.as_object_mut().unwrap().remove("iat");
        let refusals = [
            (
                status_list_jwt(
                    &EcdsaP256SigningProvider::generate(),
                    status_list_header(),
                    payload.clone(),
                ),
                401,
            ),
            (unsigned, 401),
            (
                status_list_jwt(&credential_key, plain_jwt_header, payload.clone()),
                400,
            ),
            (
                status_list_jwt(
                    &credential_key,
                    status_list_header(),
                    serde_json::json!({ "iss": issuer_url(&other.did), "sub": payload["sub"], "iat": 100, "status_list": payload["status_list"] }),
                ),
                400,
            ),
            (
                status_list_jwt(
                    &credential_key,
                    status_list_header(),
                    status_list_payload(&issuer.did, "suspensions", 100),
                ),
                400,
            ),
            (
                status_list_jwt(&credential_key, status_list_header(), bits_three),
                400,
            ),
            (
                status_list_jwt(&credential_key, status_list_header(), empty_list),
                400,
            ),
            (
                status_list_jwt(&credential_key, status_list_header(), no_iat),
                400,
            ),
            ("not-a-jwt".to_string(), 400),
            ("a".repeat(64 * 1024 + 1), 400),
        ];
        for (jwt, status) in &refusals {
            assert_eq!(publish_status!(&app, &uri, jwt), *status, "{jwt:.80}");
        }
        assert_eq!(
            publish_status!(&app, &status_list_uri(&issuer.did, "bad.id"), &genuine),
            400
        );
        assert_eq!(served_status_list!(&app, &uri).0, 404);
    }

    #[actix_web::test]
    async fn newer_status_list_replaces_and_an_older_one_is_refused() {
        let state = web::Data::new(AppState::test_default());
        let app = issuers_app!(state);
        let issuer = issuer();
        let credential_key = EcdsaP256SigningProvider::generate();
        register_key!(&app, &issuer, &credential_key);
        let uri = status_list_uri(&issuer.did, STATUS_LIST_ID);
        let signed_at = |iat: u64, lst: &str| {
            let mut payload = status_list_payload(&issuer.did, STATUS_LIST_ID, iat);
            payload["status_list"]["lst"] = lst.into();
            status_list_jwt(&credential_key, status_list_header(), payload)
        };

        assert_eq!(publish_status!(&app, &uri, &signed_at(100, "AQ")), 200);
        assert_eq!(publish_status!(&app, &uri, &signed_at(50, "Ag")), 409);
        assert_eq!(publish_status!(&app, &uri, &signed_at(100, "Ag")), 409);
        let newer = signed_at(200, "Ag");
        assert_eq!(publish_status!(&app, &uri, &newer), 200);
        assert_eq!(served_status_list!(&app, &uri).2, newer);
    }

    #[actix_web::test]
    async fn delivery_accepts_only_a_status_list_of_the_same_issuer() {
        let state = web::Data::new(AppState::test_default());
        let pending = web::Data::new(PendingIssuanceStore::new());
        let tokens = web::Data::new(AccessTokenStore::new());
        let app = issuers_app!(state, pending, tokens);
        let (issuer, other) = (issuer(), issuer());
        let credential_key = EcdsaP256SigningProvider::generate();
        register_key!(&app, &issuer, &credential_key);
        let issuance = open_issuance(&tokens, &pending, &issuer.did);
        let with_status = |status: serde_json::Value| {
            let claims = VcClaims {
                status: Some(status),
                ..vc_claims(&issuer_url(&issuer.did), PID_VCT, &issuance.holder_jwk)
            };
            issue_sd_jwt_vc(&claims, &credential_key).unwrap().compact
        };
        let pointing_at = |did: &str| {
            with_status(serde_json::json!({
                "status_list": { "idx": 7, "uri": format!("{}/status-lists/{STATUS_LIST_ID}", issuer_url(did)) }
            }))
        };

        let refusals = [
            pointing_at(&other.did),
            with_status(serde_json::json!({ "status_list": { "idx": 7 } })),
        ];
        for credential in &refusals {
            assert_eq!(
                deliver_status!(&app, issuer.did, issuance.transaction_id, credential),
                400
            );
        }
        assert_eq!(
            deliver_status!(
                &app,
                issuer.did,
                issuance.transaction_id,
                &pointing_at(&issuer.did)
            ),
            200
        );
    }
}
