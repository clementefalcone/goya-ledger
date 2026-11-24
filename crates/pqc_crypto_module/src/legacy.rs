//! Legacy non-approved algorithms.
//!
//! These algorithms are NOT part of the approved cryptographic boundary.
//! They exist solely for backwards compatibility with pre-PQC blocks and
//! legacy wallet operations.
//!
//! **Restrictions:**
//! - When the module is in `Approved` mode, guarded legacy functions return
//!   `Err(CryptoError::NonApprovedAlgorithm)`.
//! - When compiled with `--features approved-only`, the `legacy` module is
//!   entirely excluded (compile error if used).
//! - Raw re-exports remain available for type-level compatibility but
//!   production paths must use the guarded functions.
//!
//! **Do not use for new functionality.** Migrate to approved APIs.

#[cfg(feature = "approved-only")]
compile_error!(
    "Legacy crypto module is disabled in approved-only mode. \
     Remove usage of pqc_crypto_module::legacy::* or disable the approved-only feature."
);

use crate::approved_mode::{self, ModuleState};
use crate::errors::CryptoError;

/// Check that the module is NOT in Approved mode. Legacy operations
/// are only allowed before initialization or in non-approved contexts.
pub fn ensure_not_approved() -> Result<(), CryptoError> {
    match approved_mode::state() {
        ModuleState::Approved => Err(CryptoError::NonApprovedAlgorithm),
        _ => Ok(()),
    }
}

// ── Guarded legacy functions ────────────────────────────────────────

/// Legacy Ed25519 signature verification. Blocked in Approved mode.
pub fn legacy_ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    ensure_not_approved()?;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Legacy Ed25519 signing. Blocked in Approved mode.
pub fn legacy_ed25519_sign(
    signing_key: &ed25519_dalek::SigningKey,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    ensure_not_approved()?;
    use ed25519_dalek::Signer;
    Ok(signing_key.sign(message).to_bytes().to_vec())
}

/// Legacy SHA-256 hash. Blocked in Approved mode.
pub fn legacy_sha256(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    ensure_not_approved()?;
    use sha2::Digest;
    Ok(sha2::Sha256::digest(data).into())
}

/// Legacy HMAC-SHA256. Blocked in Approved mode.
pub fn legacy_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    ensure_not_approved()?;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ── Raw re-exports (OUTSIDE approved cryptographic boundary) ────────
// These expose types and functions from external crates for the DLT
// application layer to handle legacy data. They are NOT module-internal
// crypto operations and are NOT governed by the module FSM.
//
// FIPS 140-3 boundary note: operations performed via these re-exports
// occur OUTSIDE the cryptographic module boundary. The module's approved
// operations are exclusively those accessed through `pqc_crypto_module::api`.
//
// When compiled with `--features approved-only`, the entire `legacy`
// module is excluded via `compile_error!` above, blocking both guarded
// functions AND raw re-exports at compile time.

/// Legacy Ed25519 types (non-approved). Use guarded functions for operations.
pub mod ed25519 {
    pub use ed25519_dalek::{
        Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey,
    };
}

/// Legacy SHA-256 types (non-approved). Use `legacy_sha256()` for hashing.
pub mod sha256 {
    pub use sha2::{Digest, Sha256};
}

/// Legacy HMAC types (non-approved). Use `legacy_hmac_sha256()` for MAC.
pub mod hmac {
    pub use hmac::{Hmac, Mac};
    pub use sha2::Sha256;
    pub type HmacSha256 = Hmac<Sha256>;
}

/// Legacy RNG (non-approved).
pub mod rng {
    pub use rand::rngs::OsRng;
    pub use rand::seq::SliceRandom;
    pub use rand::Rng;
    pub use rand::RngCore;
    pub use rand_core;
}
