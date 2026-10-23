use crate::api::errors::{ApiResponse, ApiResult};
use crate::api::handlers::channels::{channel_id_from_req, get_channel_store};
use crate::api::handlers::identity::{
    commit_identity_op, identity_op_error, now_secs, OwnerActionRequest,
};
use crate::app_state::AppState;
use crate::identity::operations::Change;
use crate::identity::vault_entries::{
    check_add_vault_entry, check_revoke_vault_entry, AddVaultEntryRequest, RevokeVaultEntryRequest,
};
use crate::storage::traits::{TxPayload, VaultEntry, VaultEntryKind};
use actix_web::{post, web, HttpRequest, HttpResponse};

#[derive(Debug, serde::Deserialize)]
pub struct AddVaultEntryBody {
    pub entry_id: String,
    pub kind: VaultEntryKind,
    pub label: String,
    pub sealed_key: String,
    pub signature: String,
}

#[post("/identity/{did}/vault")]
pub async fn add_vault_entry(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AddVaultEntryBody>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let did = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let entry = VaultEntry {
        entry_id: body.entry_id.clone(),
        kind: body.kind,
        label: body.label.clone(),
        sealed_key: body.sealed_key.clone(),
        added_at: now_secs(),
        revoked_at: None,
    };
    let request = AddVaultEntryRequest {
        did: &did,
        entry: &entry,
        owner_signature: &body.signature,
    };
    if check_add_vault_entry(store.as_ref(), &request).map_err(identity_op_error)?
        == Change::AlreadyApplied
    {
        return Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({ "did": did, "entry_id": entry.entry_id, "status": "already_added" }),
            trace_id,
        )));
    }

    commit_identity_op(
        &state,
        store.as_ref(),
        channel,
        &did,
        TxPayload::AddVaultEntry {
            did: did.clone(),
            entry: entry.clone(),
            owner_signature: body.signature.clone(),
        },
    )?;
    Ok(HttpResponse::Created().json(ApiResponse::success(
        serde_json::json!({ "did": did, "entry_id": entry.entry_id, "added_at": entry.added_at }),
        trace_id,
    )))
}

#[post("/identity/{did}/vault/{entry_id}/revoke")]
pub async fn revoke_vault_entry(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    body: web::Json<OwnerActionRequest>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let (did, entry_id) = path.into_inner();
    let trace_id = uuid::Uuid::new_v4().to_string();
    let channel = channel_id_from_req(&req);
    let store = get_channel_store(&state, channel)?;

    let revoked_at = now_secs();
    let request = RevokeVaultEntryRequest {
        did: &did,
        entry_id: &entry_id,
        revoked_at,
        owner_signature: &body.signature,
    };
    if check_revoke_vault_entry(store.as_ref(), &request).map_err(identity_op_error)?
        == Change::AlreadyApplied
    {
        return Ok(HttpResponse::Ok().json(ApiResponse::success(
            serde_json::json!({ "did": did, "entry_id": entry_id, "status": "already_revoked" }),
            trace_id,
        )));
    }

    commit_identity_op(
        &state,
        store.as_ref(),
        channel,
        &did,
        TxPayload::RevokeVaultEntry {
            did: did.clone(),
            entry_id: entry_id.clone(),
            revoked_at,
            owner_signature: body.signature.clone(),
        },
    )?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(
        serde_json::json!({ "did": did, "entry_id": entry_id, "revoked_at": revoked_at }),
        trace_id,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::{MlDsaSigningProvider, SigningProvider};
    use crate::identity::vault_entries::{add_vault_entry_message, revoke_vault_entry_message};
    use crate::storage::traits::IdentityRecord;

    struct Owner {
        state: web::Data<AppState>,
        key: MlDsaSigningProvider,
        did: String,
    }

    fn sign(key: &MlDsaSigningProvider, message: &str) -> String {
        hex::encode(key.sign(message.as_bytes()).unwrap())
    }

    fn registered_owner() -> Owner {
        let state = web::Data::new(AppState::test_default());
        let key = MlDsaSigningProvider::generate();
        let public_key = hex::encode(key.public_key());
        let did = crate::identity::did::did_from_pubkey_hex(&public_key);
        get_channel_store(&state, "default")
            .unwrap()
            .write_identity(&IdentityRecord {
                did: did.clone(),
                public_key,
                created_at: 1,
                updated_at: 1,
                status: "active".to_string(),
                migrated_from: None,
                signature_algorithm: Some("MlDsa65".to_string()),
                civil_anchor: None,
                recovery_commitment: None,
                vault_entries: Vec::new(),
            })
            .unwrap();
        Owner { state, key, did }
    }

    fn phone_copy() -> VaultEntry {
        VaultEntry {
            entry_id: "0378ffe5".to_string(),
            kind: VaultEntryKind::Device,
            label: "iPhone".to_string(),
            sealed_key: r#"{"kdf":"hkdf","ciphertext":"aa"}"#.to_string(),
            added_at: 0,
            revoked_at: None,
        }
    }

    async fn post(owner: &Owner, uri: &str, body: serde_json::Value) -> u16 {
        let app = actix_web::test::init_service(
            actix_web::App::new().app_data(owner.state.clone()).service(
                web::scope("/api/v1")
                    .service(add_vault_entry)
                    .service(revoke_vault_entry),
            ),
        )
        .await;
        let request = actix_web::test::TestRequest::post()
            .uri(uri)
            .set_json(body)
            .to_request();
        actix_web::test::call_service(&app, request)
            .await
            .status()
            .as_u16()
    }

    fn add_body(entry: &VaultEntry, signature: String) -> serde_json::Value {
        serde_json::json!({
            "entry_id": entry.entry_id,
            "kind": "device",
            "label": entry.label,
            "sealed_key": entry.sealed_key,
            "signature": signature,
        })
    }

    fn stored_entries(owner: &Owner) -> Vec<VaultEntry> {
        get_channel_store(&owner.state, "default")
            .unwrap()
            .read_identity(&owner.did)
            .unwrap()
            .vault_entries
    }

    #[actix_web::test]
    async fn owner_stores_a_device_copy_over_http() {
        let owner = registered_owner();
        let entry = phone_copy();
        let signature = sign(&owner.key, &add_vault_entry_message(&owner.did, &entry));
        let uri = format!("/api/v1/identity/{}/vault", owner.did);
        assert_eq!(
            post(&owner, &uri, add_body(&entry, signature.clone())).await,
            201
        );
        assert_eq!(post(&owner, &uri, add_body(&entry, signature)).await, 200);
        assert_eq!(stored_entries(&owner).len(), 1);
    }

    #[actix_web::test]
    async fn stranger_cannot_store_a_copy_over_http() {
        let owner = registered_owner();
        let stranger = MlDsaSigningProvider::generate();
        let entry = phone_copy();
        let signature = sign(&stranger, &add_vault_entry_message(&owner.did, &entry));
        let uri = format!("/api/v1/identity/{}/vault", owner.did);
        assert_eq!(post(&owner, &uri, add_body(&entry, signature)).await, 401);
        assert!(stored_entries(&owner).is_empty());
    }

    #[actix_web::test]
    async fn owner_revokes_a_device_copy_over_http() {
        let owner = registered_owner();
        let entry = phone_copy();
        let add_signature = sign(&owner.key, &add_vault_entry_message(&owner.did, &entry));
        let vault_uri = format!("/api/v1/identity/{}/vault", owner.did);
        assert_eq!(
            post(&owner, &vault_uri, add_body(&entry, add_signature)).await,
            201
        );

        let revoke_uri = format!("/api/v1/identity/{}/vault/0378ffe5/revoke", owner.did);
        let revoke_signature = sign(
            &owner.key,
            &revoke_vault_entry_message(&owner.did, "0378ffe5"),
        );
        let body = serde_json::json!({ "signature": revoke_signature });
        assert_eq!(post(&owner, &revoke_uri, body).await, 200);
        assert!(stored_entries(&owner)[0].revoked_at.is_some());
    }

    #[actix_web::test]
    async fn unknown_kind_is_rejected_over_http() {
        let owner = registered_owner();
        let mut body = add_body(&phone_copy(), "00".to_string());
        body["kind"] = serde_json::json!("laptop");
        let uri = format!("/api/v1/identity/{}/vault", owner.did);
        assert_eq!(post(&owner, &uri, body).await, 400);
    }
}
