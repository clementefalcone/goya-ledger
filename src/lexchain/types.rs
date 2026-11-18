use crate::signature::{BiometricEvidence, SignatureLevel, SignedEnvelope};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyDefinition {
    pub role: String,
    pub did: String,
    pub signature_level: SignatureLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDefinition {
    #[serde(rename = "type")]
    pub contract_type: String,
    pub parties: Vec<PartyDefinition>,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_commitment: Option<String>,
    #[serde(default)]
    pub require_notarization: bool,
    /// Seconds from deploy until the contract expires if not fully signed.
    /// `None` = no deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_secs: Option<u64>,
    /// Webhook URL to POST contract state changes to. Fire-and-forget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractState {
    PendingSignatures,
    FullySigned,
    Notarized,
    Delivered,
    Archived,
    Expired,
    Quarantined,
}

impl std::fmt::Display for ContractState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingSignatures => write!(f, "pending_signatures"),
            Self::FullySigned => write!(f, "fully_signed"),
            Self::Notarized => write!(f, "notarized"),
            Self::Delivered => write!(f, "delivered"),
            Self::Archived => write!(f, "archived"),
            Self::Expired => write!(f, "expired"),
            Self::Quarantined => write!(f, "quarantined"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyState {
    pub role: String,
    pub did: String,
    pub signature_level: SignatureLevel,
    pub signed: bool,
    pub envelope: Option<SignedEnvelope>,
}

impl PartyState {
    pub fn from_definition(def: &PartyDefinition) -> Self {
        Self {
            role: def.role.clone(),
            did: def.did.clone(),
            signature_level: def.signature_level,
            signed: false,
            envelope: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub recipient_did: String,
    pub sent_at: u64,
    pub received_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_tsa_token: Option<crate::tsa::TimeStampToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_tsa_token: Option<crate::tsa::TimeStampToken>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexContract {
    pub id: String,
    pub definition: ContractDefinition,
    pub state: ContractState,
    pub parties: Vec<PartyState>,
    pub created_at: u64,
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_token: Option<crate::tsa::TimeStampToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_receipts: Vec<DeliveryReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preservation_records: Vec<PreservationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_salt: Option<String>,
}

impl LexContract {
    pub fn public_view(&self) -> LexContract {
        let mut public = self.clone();
        public.definition.payload = serde_json::Value::Null;
        public.payload_salt = None;
        public
    }

    pub fn all_signed(&self) -> bool {
        self.parties.iter().all(|p| p.signed)
    }

    pub fn party_by_did(&self, did: &str) -> Option<&PartyState> {
        self.parties.iter().find(|p| p.did == did)
    }

    pub fn party_by_did_mut(&mut self, did: &str) -> Option<&mut PartyState> {
        self.parties.iter_mut().find(|p| p.did == did)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        if let Some(deadline) = self.definition.deadline_secs {
            self.state == ContractState::PendingSignatures && now > self.created_at + deadline
        } else {
            false
        }
    }
}

/// A reusable contract template. Developers instantiate with their own parties + payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTemplate {
    pub name: String,
    pub contract_type: String,
    /// Role definitions — the developer provides the DIDs, the template defines roles + sig levels.
    pub roles: Vec<RoleTemplate>,
    #[serde(default)]
    pub require_notarization: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleTemplate {
    pub role: String,
    pub signature_level: SignatureLevel,
}

/// Deploy request — either a full definition or a template reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeployRequest {
    Full(ContractDefinition),
    FromTemplate {
        template: String,
        /// DID assignments: role → DID
        parties: std::collections::HashMap<String, String>,
        #[serde(default)]
        payload: serde_json::Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreservationRecord {
    pub preserved_at: u64,
    pub original_algorithm: crate::identity::signing::SigningAlgorithm,
    pub new_algorithm: crate::identity::signing::SigningAlgorithm,
    pub new_signature: String,
    pub new_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_token: Option<crate::tsa::TimeStampToken>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub contract_id: String,
    pub event: String,
    pub state: ContractState,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub did: String,
    pub signature: String,
    pub public_key: String,
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}
