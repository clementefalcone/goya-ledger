use actix_web::{test, web, App};
use rust_bc::api::handlers::credentials::{
    store_get_credential, store_revoke_credential, store_write_credential,
};
use rust_bc::api::handlers::identity::{store_get_identity, store_write_identity};
use rust_bc::api::handlers::issuers::{
    deliver_issuance, get_status_list, jwt_vc_issuer_metadata, list_pending_issuances,
    pending_issuances_message, publish_status_list, register_credential_key,
};
use rust_bc::api::handlers::oid4vci::{
    credential_endpoint, credential_offer_endpoint, deferred_credential_endpoint, nonce_endpoint,
    offer_message, token_endpoint, AccessTokenStore, CredentialOfferStore, NonceStore,
    PendingIssuanceStore,
};
use rust_bc::app_state::AppState;
use rust_bc::identity::credential_ops::{issue_message, revoke_message};
use rust_bc::identity::did::did_from_pubkey_hex;
use rust_bc::identity::issuer_credentials::{
    anchor_id, issue_holder_credential, sign_anchor, CredentialDraft, StatusListEntry,
};
use rust_bc::identity::issuer_keys::{
    credential_key_message, p256_public_jwk, sec1_public_key_hex,
};
use rust_bc::identity::operations::is_signed_by;
use rust_bc::identity::sd_jwt::verify_sd_jwt_vc;
use rust_bc::identity::signing::{
    EcdsaP256SigningProvider, MlDsaSigningProvider, SigningProvider, SoftwareSigningProvider,
};
use rust_bc::identity::status_lists::{read_status, sign_status_list_jwt, StatusListDraft};
use rust_bc::storage::traits::{Credential, P256PublicJwk};

const HOST: &str = "localhost:8080";
const CREDENTIAL_ISSUER: &str = "https://localhost:8080";
const CONFIGURATION_ID: &str = "eudi_pid_sd_jwt";
const STATUS_LIST_ID: &str = "main";
const STATUS_INDEX: usize = 42;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn base64url(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

fn holder_proof(holder: &SoftwareSigningProvider, nonce: &str) -> String {
    let header = serde_json::json!({
        "typ": "openid4vci-proof+jwt",
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": base64url(&holder.public_key()) },
    });
    let payload = serde_json::json!({ "nonce": nonce, "aud": CREDENTIAL_ISSUER, "iat": now() });
    let signing_input = format!(
        "{}.{}",
        base64url(&serde_json::to_vec(&header).unwrap()),
        base64url(&serde_json::to_vec(&payload).unwrap())
    );
    let signature = holder.sign(signing_input.as_bytes()).unwrap();
    format!("{signing_input}.{}", base64url(&signature))
}

struct Issuer {
    did_key: Box<dyn SigningProvider>,
    public_key: String,
    did: String,
    credential_key: EcdsaP256SigningProvider,
}

impl Issuer {
    fn new(did_key: Box<dyn SigningProvider>) -> Self {
        let public_key = hex::encode(did_key.public_key());
        Self {
            did: did_from_pubkey_hex(&public_key),
            public_key,
            did_key,
            credential_key: EcdsaP256SigningProvider::generate(),
        }
    }

    fn sign(&self, message: &str) -> String {
        hex::encode(self.did_key.sign(message.as_bytes()).unwrap())
    }

    fn url(&self) -> String {
        format!("{CREDENTIAL_ISSUER}/api/v1/issuers/{}", self.did)
    }

    fn status_list(&self, revoked: &[usize], issued_at: u64) -> serde_json::Value {
        let jwt = sign_status_list_jwt(
            &self.credential_key,
            &StatusListDraft {
                issuer_url: &self.url(),
                list_id: STATUS_LIST_ID,
                revoked_indices: revoked,
                issued_at,
            },
        )
        .unwrap();
        serde_json::json!({ "status_list_jwt": jwt })
    }
}

macro_rules! node {
    () => {
        test::init_service(
            App::new()
                .app_data(web::Data::new(AppState::test_default()))
                .app_data(web::Data::new(NonceStore::new()))
                .app_data(web::Data::new(PendingIssuanceStore::new()))
                .app_data(web::Data::new(CredentialOfferStore::new()))
                .app_data(web::Data::new(AccessTokenStore::new()))
                .service(token_endpoint)
                .service(credential_endpoint)
                .service(deferred_credential_endpoint)
                .service(credential_offer_endpoint)
                .service(nonce_endpoint)
                .route(
                    "/.well-known/jwt-vc-issuer/api/v1/issuers/{did}",
                    web::get().to(jwt_vc_issuer_metadata),
                )
                .service(
                    web::scope("/api/v1")
                        .service(store_write_identity)
                        .service(store_get_identity)
                        .service(store_write_credential)
                        .service(store_revoke_credential)
                        .service(store_get_credential)
                        .service(register_credential_key)
                        .service(list_pending_issuances)
                        .service(deliver_issuance)
                        .service(publish_status_list)
                        .service(get_status_list),
                ),
        )
        .await
    };
}

macro_rules! call {
    ($app:expr, $req:expr) => {{
        let resp = test::call_service(&$app, $req.insert_header(("host", HOST)).to_request()).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        (
            status,
            json,
            String::from_utf8(body.to_vec()).unwrap_or_default(),
        )
    }};
}

macro_rules! verify_as_relying_party {
    ($app:expr, $issuer_did:expr, $credential:expr) => {{
        let uri = format!("/.well-known/jwt-vc-issuer/api/v1/issuers/{}", $issuer_did);
        let (status, metadata, _) = call!($app, test::TestRequest::get().uri(&uri));
        assert_eq!(status, 200, "issuer metadata");
        let jwk: P256PublicJwk =
            serde_json::from_value(metadata["jwks"]["keys"][0].clone()).unwrap();
        let credential_key_hex = sec1_public_key_hex(&jwk).unwrap();
        let verified = verify_sd_jwt_vc($credential, &credential_key_hex).unwrap();

        let status_list = &verified.status.as_ref().unwrap()["status_list"];
        let status_path = status_list["uri"]
            .as_str()
            .unwrap()
            .trim_start_matches(CREDENTIAL_ISSUER)
            .to_string();
        let (status, _, status_list_jwt) = call!($app, test::TestRequest::get().uri(&status_path));
        assert_eq!(status, 200, "status list");
        let is_revoked = read_status(
            &status_list_jwt,
            &credential_key_hex,
            status_list["idx"].as_u64().unwrap() as usize,
        )
        .unwrap();

        let anchor_uri = format!("/api/v1/store/credentials/{}", anchor_id($credential));
        let (status, anchor, _) = call!($app, test::TestRequest::get().uri(&anchor_uri));
        assert_eq!(status, 200, "post-quantum anchor");
        let anchor: Credential = serde_json::from_value(anchor["data"].clone()).unwrap();
        let identity_uri = format!("/api/v1/store/identities/{}", anchor.issuer_did);
        let (status, identity, _) = call!($app, test::TestRequest::get().uri(&identity_uri));
        assert_eq!(status, 200, "issuer identity");
        let did_public_key = identity["data"]["public_key"].as_str().unwrap();
        assert!(is_signed_by(
            did_public_key,
            &issue_message(&anchor),
            &anchor.signature
        ));
        assert_eq!(anchor.issuer_did, $issuer_did);
        (verified, is_revoked, anchor.status)
    }};
}

macro_rules! issue_and_revoke {
    ($did_key:expr) => {{
        let app = node!();
        let issuer = Issuer::new($did_key);
        let registered_at = now();

        let (status, _, _) = call!(
            app,
            test::TestRequest::post()
                .uri("/api/v1/store/identities")
                .set_json(serde_json::json!({
                    "did": issuer.did, "public_key": issuer.public_key,
                    "created_at": registered_at, "updated_at": registered_at, "status": "active",
                    "signature": issuer.sign(&format!("identity:register:{}", issuer.did)),
                }))
        );
        assert_eq!(status, 201, "issuer identity registered");

        let jwk = p256_public_jwk(&issuer.credential_key);
        let (status, _, _) = call!(
            app,
            test::TestRequest::post()
                .uri(&format!("/api/v1/issuers/{}/credential-key", issuer.did))
                .set_json(serde_json::json!({
                    "jwk": jwk, "registered_at": registered_at, "public_key": issuer.public_key,
                    "signature": issuer.sign(&credential_key_message(&issuer.did, &jwk, registered_at)),
                }))
        );
        assert_eq!(status, 201, "ES256 credential key bound to the DID");

        let (status, offer, _) = call!(
            app,
            test::TestRequest::post()
                .uri("/credential_offer")
                .set_json(serde_json::json!({
                    "issuer_did": issuer.did, "issuer_public_key": issuer.public_key,
                    "credential_configuration_id": CONFIGURATION_ID, "issued_at": registered_at,
                    "signature": issuer.sign(&offer_message(&issuer.did, CONFIGURATION_ID, registered_at)),
                }))
        );
        assert_eq!(status, 201, "offer signed by the issuer");
        let code = offer["credential_offer"]["grants"]
            ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, token, _) = call!(
            app,
            test::TestRequest::post().uri("/token").set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                ("pre-authorized_code", code.as_str()),
            ])
        );
        assert_eq!(status, 200, "token");
        let bearer = format!("Bearer {}", token["access_token"].as_str().unwrap());
        let (_, nonce, _) = call!(app, test::TestRequest::post().uri("/nonce"));
        let holder = SoftwareSigningProvider::generate();
        let (status, transaction, _) = call!(
            app,
            test::TestRequest::post()
                .uri("/credential")
                .insert_header(("authorization", bearer.clone()))
                .set_json(serde_json::json!({
                    "credential_configuration_id": CONFIGURATION_ID,
                    "proofs": { "jwt": [holder_proof(&holder, nonce["c_nonce"].as_str().unwrap())] },
                }))
        );
        assert_eq!(status, 202, "wallet gets a deferred transaction");
        let transaction_id = transaction["transaction_id"].as_str().unwrap().to_string();
        let deferred = || {
            test::TestRequest::post()
                .uri("/deferred_credential")
                .insert_header(("authorization", bearer.clone()))
                .set_json(serde_json::json!({ "transaction_id": transaction_id }))
        };
        let (status, pending, _) = call!(app, deferred());
        assert_eq!((status, pending["error"].as_str()), (400, Some("issuance_pending")));

        let listed_at = now();
        let (status, pending, _) = call!(
            app,
            test::TestRequest::get().uri(&format!(
                "/api/v1/issuers/{}/issuances?public_key={}&issued_at={listed_at}&signature={}",
                issuer.did,
                issuer.public_key,
                issuer.sign(&pending_issuances_message(&issuer.did, listed_at)),
            ))
        );
        assert_eq!(status, 200, "issuer lists its pending issuances");
        let request = &pending["data"][0];
        assert_eq!(request["transaction_id"], transaction_id.as_str());
        let holder_jwk = request["holder_jwk"].clone();

        let issued = issue_holder_credential(
            &issuer.credential_key,
            &CredentialDraft {
                issuer_url: issuer.url(),
                vct: request["vct"].as_str().unwrap().to_string(),
                holder_jwk: holder_jwk.clone(),
                claims: vec![
                    ("given_name".to_string(), serde_json::json!("Ada")),
                    ("family_name".to_string(), serde_json::json!("Lovelace")),
                ],
                status: Some(StatusListEntry {
                    list_id: STATUS_LIST_ID.to_string(),
                    index: STATUS_INDEX,
                }),
            },
            now(),
        )
        .unwrap();
        let status_list_uri = format!("/api/v1/issuers/{}/status-lists/{STATUS_LIST_ID}", issuer.did);
        let (status, _, _) = call!(
            app,
            test::TestRequest::put()
                .uri(&status_list_uri)
                .set_json(issuer.status_list(&[], now() - 10))
        );
        assert_eq!(status, 200, "issuer publishes its status list");
        let (status, _, _) = call!(
            app,
            test::TestRequest::post()
                .uri(&format!("/api/v1/issuers/{}/issuances/{transaction_id}", issuer.did))
                .set_json(serde_json::json!({ "credential": issued.compact }))
        );
        assert_eq!(status, 200, "node accepts the issuer-signed credential");
        let mut anchor = serde_json::to_value(
            sign_anchor(issuer.did_key.as_ref(), &issuer.did, &issued).unwrap(),
        )
        .unwrap();
        anchor["issuer_public_key"] = issuer.public_key.clone().into();
        let (status, _, _) = call!(
            app,
            test::TestRequest::post().uri("/api/v1/store/credentials").set_json(anchor)
        );
        assert_eq!(status, 201, "post-quantum anchor recorded");

        let (status, delivered, _) = call!(app, deferred());
        assert_eq!(status, 200, "wallet receives the credential");
        let credential = delivered["credentials"][0]["credential"].as_str().unwrap().to_string();
        assert_eq!(credential, issued.compact);
        let (status, _, _) = call!(app, deferred());
        assert_eq!(status, 400, "credential is handed out once");

        let (verified, is_revoked, anchor_status) =
            verify_as_relying_party!(app, issuer.did, &credential);
        assert_eq!(verified.iss, issuer.url());
        assert_eq!(verified.cnf.as_ref().unwrap()["jwk"], holder_jwk);
        assert_eq!(verified.disclosed_claims.len(), 2);
        assert!(!is_revoked);
        assert_eq!(anchor_status, "active");

        let (status, _, _) = call!(
            app,
            test::TestRequest::put()
                .uri(&status_list_uri)
                .set_json(issuer.status_list(&[STATUS_INDEX], now()))
        );
        assert_eq!(status, 200, "issuer publishes the revocation");
        let anchor_id = anchor_id(&credential);
        let revoked_at = now();
        let (status, _, _) = call!(
            app,
            test::TestRequest::post()
                .uri(&format!("/api/v1/store/credentials/{anchor_id}/revoke"))
                .set_json(serde_json::json!({
                    "revoked_at": revoked_at, "issuer_public_key": issuer.public_key,
                    "signature": issuer.sign(&revoke_message(&anchor_id, revoked_at)),
                }))
        );
        assert_eq!(status, 200, "issuer revokes the post-quantum anchor");
        let (_, is_revoked, anchor_status) = verify_as_relying_party!(app, issuer.did, &credential);
        assert!(is_revoked);
        assert_eq!(anchor_status, "revoked");
    }};
}

#[actix_web::test]
async fn ed25519_issuer_issues_to_a_wallet_and_revokes() {
    issue_and_revoke!(Box::new(SoftwareSigningProvider::generate()));
}

#[actix_web::test]
async fn ml_dsa_issuer_issues_to_a_wallet_and_revokes() {
    issue_and_revoke!(Box::new(MlDsaSigningProvider::generate()));
}
