use crate::api::errors::{ApiError, ApiResponse, ApiResult};
use crate::api::handlers::channels::get_channel_store;
use crate::api::handlers::identity::{commit_ledger_op, identity_op_error};
use crate::app_state::AppState;
use crate::identity::issuer_keys;
use crate::identity::operations::Change;
use crate::storage::traits::{IssuerCredentialKey, P256PublicJwk, TxPayload};
use actix_web::{get, post, web, HttpResponse};

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

pub(crate) fn read_credential_key(
    state: &AppState,
    did: &str,
) -> Result<IssuerCredentialKey, ApiError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::issuer_keys::credential_key_message;
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
            test::init_service(
                App::new().app_data($state.clone()).service(
                    web::scope("/api/v1")
                        .service(register_credential_key)
                        .service(get_credential_key),
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
}
