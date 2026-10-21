//! Input validation for store handlers.

use crate::api::errors::ApiError;

/// Maximum allowed length for string fields in store records.
const MAX_FIELD_LEN: usize = 256;

/// Validate a string field: reject null bytes, HTML/script tags, and excessive length.
pub fn validate_string_field(field_name: &str, value: &str) -> Result<(), ApiError> {
    if value.len() > MAX_FIELD_LEN {
        return Err(ApiError::ValidationError {
            field: field_name.to_string(),
            reason: format!("exceeds maximum length of {MAX_FIELD_LEN} characters"),
        });
    }
    if value.contains('\0') {
        return Err(ApiError::ValidationError {
            field: field_name.to_string(),
            reason: "contains null bytes".to_string(),
        });
    }
    if value.contains('<') || value.contains('>') {
        return Err(ApiError::ValidationError {
            field: field_name.to_string(),
            reason: "contains disallowed characters (< or >)".to_string(),
        });
    }
    Ok(())
}

/// Validate all string fields in a store transaction.
pub fn validate_store_transaction(
    tx: &crate::storage::traits::Transaction,
) -> Result<(), ApiError> {
    validate_string_field("id", &tx.id)?;
    validate_string_field("input_did", &tx.input_did)?;
    validate_string_field("output_recipient", &tx.output_recipient)?;
    validate_string_field("state", &tx.state)?;
    if tx.amount != 0 || tx.payload.is_some() {
        return Err(ApiError::ValidationError {
            field: "transaction".to_string(),
            reason: format!(
                "transaction {} moves value or carries a payload; use POST /transactions or /savings",
                tx.id
            ),
        });
    }
    Ok(())
}

/// Validate all string fields in a store identity record.
pub fn validate_store_identity(
    rec: &crate::storage::traits::IdentityRecord,
) -> Result<(), ApiError> {
    validate_string_field("did", &rec.did)?;
    validate_string_field("status", &rec.status)?;
    Ok(())
}

/// Validate all string fields in a store credential.
pub fn validate_store_credential(
    cred: &crate::storage::traits::Credential,
) -> Result<(), ApiError> {
    validate_string_field("id", &cred.id)?;
    validate_string_field("issuer_did", &cred.issuer_did)?;
    validate_string_field("subject_did", &cred.subject_did)?;
    validate_string_field("cred_type", &cred.cred_type)?;
    Ok(())
}
