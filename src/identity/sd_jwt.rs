//! SD-JWT VC — Selective Disclosure JWT Verifiable Credentials.
//!
//! RFC 9901 (SD-JWT) + draft-ietf-oauth-sd-jwt-vc (VC profile).
//! No external JWT crate — JWT is base64url(header).base64url(payload).signature.
//!
//! SD-JWT format: `<issuer-jwt>~<disclosure1>~<disclosure2>~...~`
//! Each disclosure: base64url(json([salt, claim_name, claim_value]))
//! The JWT payload contains `_sd` array with SHA-256 hashes of disclosures.

use crate::crypto::hasher::{hash_with, HashAlgorithm};
use crate::identity::signing::{SigningAlgorithm, SigningProvider};
use serde::{Deserialize, Serialize};

/// SD-JWT VC — an issued credential with selective disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtVc {
    /// The compact serialization: `<jwt>~<disclosure1>~...~`
    pub compact: String,
    /// Individual disclosures (base64url encoded).
    pub disclosures: Vec<String>,
    /// The issuer JWT (first segment before ~).
    pub jwt: String,
}

/// Claims for an SD-JWT VC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcClaims {
    /// Issuer DID or URI.
    pub iss: String,
    /// Subject DID.
    pub sub: String,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Expiration (unix seconds).
    pub exp: u64,
    /// Credential type (e.g. "IdentityCredential").
    pub vct: String,
    /// Selectively disclosable claims (name → value).
    pub claims: Vec<(String, serde_json::Value)>,
    /// Confirmation key (holder's public key as JWK) for key binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
}

/// A single disclosure: [salt, claim_name, claim_value].
#[derive(Debug, Clone)]
pub struct Disclosure {
    pub salt: String,
    pub claim_name: String,
    pub claim_value: serde_json::Value,
    pub encoded: String,
    pub hash: String,
}

/// Verified SD-JWT VC fields.
#[derive(Debug, Clone)]
pub struct VerifiedSdJwt {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub vct: String,
    pub disclosed_claims: Vec<(String, serde_json::Value)>,
    pub algorithm: SigningAlgorithm,
    /// True when a valid Key Binding JWT was present and verified.
    pub kb_verified: bool,
    pub cnf: Option<serde_json::Value>,
}

fn base64url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s)
        .map_err(|e| e.to_string())
}

fn make_disclosure(salt: &str, name: &str, value: &serde_json::Value) -> Disclosure {
    let arr = serde_json::json!([salt, name, value]);
    let json_bytes = serde_json::to_vec(&arr).unwrap_or_default();
    let encoded = base64url_encode(&json_bytes);
    let hash_bytes = hash_with(HashAlgorithm::Sha256, encoded.as_bytes());
    let hash = base64url_encode(&hash_bytes);
    Disclosure {
        salt: salt.to_string(),
        claim_name: name.to_string(),
        claim_value: value.clone(),
        encoded,
        hash,
    }
}

fn generate_salt() -> String {
    use pqc_crypto_module::legacy::rng::OsRng;
    use rand_core::RngCore;
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    base64url_encode(&buf)
}

fn alg_to_jwt(alg: SigningAlgorithm) -> &'static str {
    match alg {
        SigningAlgorithm::Ed25519 => "EdDSA",
        SigningAlgorithm::MlDsa65 => "ML-DSA-65",
        SigningAlgorithm::Rsa => "RS256",
        SigningAlgorithm::EcdsaP256 => "ES256",
        SigningAlgorithm::SlhDsa128s => "SLH-DSA-SHAKE-128s",
    }
}

fn jwt_to_alg(s: &str) -> Option<SigningAlgorithm> {
    match s {
        "EdDSA" => Some(SigningAlgorithm::Ed25519),
        "ML-DSA-65" => Some(SigningAlgorithm::MlDsa65),
        "RS256" => Some(SigningAlgorithm::Rsa),
        "ES256" => Some(SigningAlgorithm::EcdsaP256),
        "SLH-DSA-SHAKE-128s" => Some(SigningAlgorithm::SlhDsa128s),
        _ => None,
    }
}

pub fn alg_to_jwt_pub(alg: SigningAlgorithm) -> &'static str {
    alg_to_jwt(alg)
}

pub fn jwt_to_alg_pub(s: &str) -> Option<SigningAlgorithm> {
    jwt_to_alg(s)
}

/// Compute kid from public key (first 8 bytes of SHA-256, base64url).
pub fn compute_kid(provider: &dyn SigningProvider) -> String {
    base64url_encode(&hash_with(HashAlgorithm::Sha256, &provider.public_key())[..8])
}

/// Issue an SD-JWT VC.
pub fn issue_sd_jwt_vc(
    claims: &VcClaims,
    provider: &dyn SigningProvider,
) -> Result<SdJwtVc, String> {
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (name, value) in &claims.claims {
        let salt = generate_salt();
        let d = make_disclosure(&salt, name, value);
        sd_hashes.push(serde_json::Value::String(d.hash.clone()));
        disclosures.push(d);
    }

    let header = serde_json::json!({
        "alg": alg_to_jwt(provider.algorithm()),
        "typ": "vc+sd-jwt",
        "kid": compute_kid(provider),
    });
    let mut payload = serde_json::json!({
        "iss": claims.iss,
        "sub": claims.sub,
        "iat": claims.iat,
        "exp": claims.exp,
        "vct": claims.vct,
        "_sd_alg": "sha-256",
        "_sd": sd_hashes,
    });
    if let Some(cnf) = &claims.cnf {
        payload["cnf"] = cnf.clone();
    }
    if let Some(status) = &claims.status {
        payload["status"] = status.clone();
    }

    let header_b64 = base64url_encode(&serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = provider
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    let sig_b64 = base64url_encode(&sig);

    let jwt = format!("{signing_input}.{sig_b64}");
    let disclosure_strs: Vec<String> = disclosures.iter().map(|d| d.encoded.clone()).collect();

    let mut compact = jwt.clone();
    for d in &disclosure_strs {
        compact.push('~');
        compact.push_str(d);
    }
    compact.push('~');

    Ok(SdJwtVc {
        compact,
        disclosures: disclosure_strs,
        jwt,
    })
}

/// Issue an SD-JWT VC with W3C vc wrapper (Partisia wallet format).
/// Claims go inside `vc.credentialSubject._sd`, not flat in the payload.
pub fn issue_sd_jwt_vc_w3c(
    claims: &VcClaims,
    provider: &dyn SigningProvider,
) -> Result<SdJwtVc, String> {
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (name, value) in &claims.claims {
        let salt = generate_salt();
        let d = make_disclosure(&salt, name, value);
        sd_hashes.push(serde_json::Value::String(d.hash.clone()));
        disclosures.push(d);
    }

    let header = serde_json::json!({
        "alg": alg_to_jwt(provider.algorithm()),
        "typ": "JWT",
    });

    let mut payload = serde_json::json!({
        "iss": claims.iss,
        "sub": claims.sub,
        "nbf": claims.iat,
        "exp": claims.exp,
        "vc": {
            "type": ["VerifiableCredential", claims.vct],
            "credentialSubject": {
                "id": claims.sub,
                "_sd": sd_hashes,
            }
        }
    });
    if let Some(status) = &claims.status {
        payload["vc"]["status"] = status.clone();
    }

    let header_b64 = base64url_encode(&serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = provider
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    let sig_b64 = base64url_encode(&sig);

    let jwt = format!("{signing_input}.{sig_b64}");
    let disclosure_strs: Vec<String> = disclosures.iter().map(|d| d.encoded.clone()).collect();

    let mut compact = jwt.clone();
    for d in &disclosure_strs {
        compact.push('~');
        compact.push_str(d);
    }
    compact.push('~');

    Ok(SdJwtVc {
        compact,
        disclosures: disclosure_strs,
        jwt,
    })
}

/// Create a presentation with only selected disclosures.
pub fn present_sd_jwt(sd_jwt: &SdJwtVc, disclosed_indices: &[usize]) -> String {
    let mut presentation = sd_jwt.jwt.clone();
    for &i in disclosed_indices {
        if let Some(d) = sd_jwt.disclosures.get(i) {
            presentation.push('~');
            presentation.push_str(d);
        }
    }
    presentation.push('~');
    presentation
}

/// Compute JWK thumbprint (RFC 7638) for a public key.
pub fn jwk_thumbprint(pubkey_hex: &str, alg: SigningAlgorithm) -> String {
    let jwk = match alg {
        SigningAlgorithm::Ed25519 => serde_json::json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": base64url_encode(&hex::decode(pubkey_hex).unwrap_or_default()),
        }),
        SigningAlgorithm::MlDsa65 => serde_json::json!({
            "alg": "ML-DSA-65",
            "kty": "AKP",
            "pub": base64url_encode(&hex::decode(pubkey_hex).unwrap_or_default()),
        }),
        SigningAlgorithm::Rsa => serde_json::json!({
            "kty": "RSA",
            "n": base64url_encode(&hex::decode(pubkey_hex).unwrap_or_default()),
        }),
        SigningAlgorithm::EcdsaP256 => {
            let pk_bytes = hex::decode(pubkey_hex).unwrap_or_default();
            // SEC1 uncompressed: 0x04 || x (32 bytes) || y (32 bytes)
            if pk_bytes.len() == 65 && pk_bytes[0] == 0x04 {
                serde_json::json!({
                    "crv": "P-256",
                    "kty": "EC",
                    "x": base64url_encode(&pk_bytes[1..33]),
                    "y": base64url_encode(&pk_bytes[33..65]),
                })
            } else {
                serde_json::json!({
                    "crv": "P-256",
                    "kty": "EC",
                    "x": base64url_encode(&pk_bytes),
                })
            }
        }
        SigningAlgorithm::SlhDsa128s => serde_json::json!({
            "alg": "SLH-DSA-SHAKE-128s",
            "kty": "AKP",
            "pub": base64url_encode(&hex::decode(pubkey_hex).unwrap_or_default()),
        }),
    };
    let canonical = serde_json::to_vec(&jwk).unwrap_or_default();
    base64url_encode(&hash_with(HashAlgorithm::Sha256, &canonical))
}

/// Issue an SD-JWT VC with holder key binding (`cnf` claim).
pub fn issue_sd_jwt_vc_with_kb(
    claims: &VcClaims,
    provider: &dyn SigningProvider,
    holder_pubkey_hex: &str,
    holder_alg: SigningAlgorithm,
) -> Result<SdJwtVc, String> {
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (name, value) in &claims.claims {
        let salt = generate_salt();
        let d = make_disclosure(&salt, name, value);
        sd_hashes.push(serde_json::Value::String(d.hash.clone()));
        disclosures.push(d);
    }

    let jkt = jwk_thumbprint(holder_pubkey_hex, holder_alg);

    let header = serde_json::json!({
        "alg": alg_to_jwt(provider.algorithm()),
        "typ": "vc+sd-jwt",
    });
    let payload = serde_json::json!({
        "iss": claims.iss,
        "sub": claims.sub,
        "iat": claims.iat,
        "exp": claims.exp,
        "vct": claims.vct,
        "_sd_alg": "sha-256",
        "_sd": sd_hashes,
        "cnf": { "jkt": jkt },
    });

    let header_b64 = base64url_encode(&serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    let payload_b64 = base64url_encode(&serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = provider
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    let sig_b64 = base64url_encode(&sig);

    let jwt = format!("{signing_input}.{sig_b64}");
    let disclosure_strs: Vec<String> = disclosures.iter().map(|d| d.encoded.clone()).collect();

    let mut compact = jwt.clone();
    for d in &disclosure_strs {
        compact.push('~');
        compact.push_str(d);
    }
    compact.push('~');

    Ok(SdJwtVc {
        compact,
        disclosures: disclosure_strs,
        jwt,
    })
}

/// Create a presentation with a Key Binding JWT (RFC 9901 §5.8).
///
/// The KB-JWT proves holder possession of the key bound via `cnf.jkt`.
/// Format: `<issuer-jwt>~<disc>~...~<kb-jwt>`
pub fn present_sd_jwt_with_kb(
    sd_jwt: &SdJwtVc,
    disclosed_indices: &[usize],
    holder_provider: &dyn SigningProvider,
    aud: &str,
    nonce: &str,
    iat: u64,
) -> Result<String, String> {
    // Build the SD-JWT prefix (everything before KB-JWT)
    let mut prefix = sd_jwt.jwt.clone();
    for &i in disclosed_indices {
        if let Some(d) = sd_jwt.disclosures.get(i) {
            prefix.push('~');
            prefix.push_str(d);
        }
    }
    prefix.push('~');

    // sd_hash = SHA-256 of the prefix (issuer JWT + disclosures + trailing ~)
    let sd_hash = base64url_encode(&hash_with(HashAlgorithm::Sha256, prefix.as_bytes()));

    let kb_header = serde_json::json!({
        "typ": "kb+jwt",
        "alg": alg_to_jwt(holder_provider.algorithm()),
    });
    let kb_payload = serde_json::json!({
        "iat": iat,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": sd_hash,
    });

    let h_b64 = base64url_encode(&serde_json::to_vec(&kb_header).map_err(|e| e.to_string())?);
    let p_b64 = base64url_encode(&serde_json::to_vec(&kb_payload).map_err(|e| e.to_string())?);
    let signing_input = format!("{h_b64}.{p_b64}");
    let sig = holder_provider
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    let kb_jwt = format!("{signing_input}.{}", base64url_encode(&sig));

    Ok(format!("{prefix}{kb_jwt}"))
}

/// Verify an SD-JWT VC presentation and extract disclosed claims.
pub fn verify_sd_jwt_vc(presentation: &str, public_key_hex: &str) -> Result<VerifiedSdJwt, String> {
    verify_sd_jwt_vc_full(presentation, public_key_hex, None)
}

/// Verify an SD-JWT VC with full KB-JWT cryptographic verification.
pub fn verify_sd_jwt_vc_with_holder(
    presentation: &str,
    issuer_pubkey_hex: &str,
    holder_pubkey_hex: &str,
) -> Result<VerifiedSdJwt, String> {
    verify_sd_jwt_vc_full(presentation, issuer_pubkey_hex, Some(holder_pubkey_hex))
}

fn verify_sd_jwt_vc_full(
    presentation: &str,
    public_key_hex: &str,
    holder_pubkey_hex: Option<&str>,
) -> Result<VerifiedSdJwt, String> {
    let parts: Vec<&str> = presentation.split('~').collect();
    if parts.is_empty() {
        return Err("empty presentation".into());
    }

    let jwt = parts[0];
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err("JWT must have 3 parts".into());
    }

    let header_bytes = base64url_decode(jwt_parts[0])?;
    let payload_bytes = base64url_decode(jwt_parts[1])?;
    let sig_bytes = base64url_decode(jwt_parts[2])?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;

    let alg_str = header["alg"].as_str().ok_or("missing alg")?;
    let algorithm = jwt_to_alg(alg_str).ok_or_else(|| format!("unknown alg: {alg_str}"))?;

    // Verify signature
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    let sig_hex = hex::encode(&sig_bytes);
    if !crate::signature::verify_signature(
        algorithm,
        public_key_hex,
        signing_input.as_bytes(),
        &sig_hex,
    ) {
        return Err("signature verification failed".into());
    }

    let iss = payload["iss"].as_str().unwrap_or("").to_string();
    let sub = payload["sub"].as_str().unwrap_or("").to_string();
    let iat = payload["iat"].as_u64().unwrap_or(0);
    let exp = payload["exp"].as_u64().unwrap_or(0);
    let vct = payload["vct"].as_str().unwrap_or("").to_string();

    // Reject expired credentials
    if exp > 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > exp {
            return Err(format!("credential expired: exp={exp}, now={now}"));
        }
    }

    let sd_hashes: Vec<String> = payload["_sd"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Separate disclosures from potential KB-JWT.
    // The last non-empty part might be a KB-JWT (contains dots, typ=kb+jwt).
    let tail_parts: Vec<&str> = parts[1..]
        .iter()
        .copied()
        .filter(|p| !p.is_empty())
        .collect();
    let (disclosure_parts, kb_jwt_str) = if let Some(last) = tail_parts.last() {
        if last.split('.').count() == 3 {
            if let Ok(hdr_bytes) = base64url_decode(last.split('.').next().unwrap_or("")) {
                if let Ok(hdr) = serde_json::from_slice::<serde_json::Value>(&hdr_bytes) {
                    if hdr.get("typ").and_then(|v| v.as_str()) == Some("kb+jwt") {
                        (&tail_parts[..tail_parts.len() - 1], Some(*last))
                    } else {
                        (&tail_parts[..], None)
                    }
                } else {
                    (&tail_parts[..], None)
                }
            } else {
                (&tail_parts[..], None)
            }
        } else {
            (&tail_parts[..], None)
        }
    } else {
        (&tail_parts[..], None)
    };

    // Process disclosed claims
    let mut disclosed_claims = Vec::new();
    for part in disclosure_parts {
        let decoded = base64url_decode(part)?;
        let arr: serde_json::Value = serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;
        let arr = arr.as_array().ok_or("disclosure not an array")?;
        if arr.len() != 3 {
            return Err("disclosure must have 3 elements".into());
        }

        let disclosure_hash_bytes = hash_with(HashAlgorithm::Sha256, part.as_bytes());
        let disclosure_hash = base64url_encode(&disclosure_hash_bytes);
        if !sd_hashes.contains(&disclosure_hash) {
            return Err(format!("disclosure hash not in _sd: {disclosure_hash}"));
        }

        let name = arr[1].as_str().ok_or("claim name not string")?;
        disclosed_claims.push((name.to_string(), arr[2].clone()));
    }

    // Verify KB-JWT if present and cnf.jkt exists in payload
    let kb_verified = if let Some(kb_jwt) = kb_jwt_str {
        let cnf_jkt = payload
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(|j| j.as_str());
        if let Some(expected_jkt) = cnf_jkt {
            verify_kb_jwt(kb_jwt, presentation, expected_jkt, holder_pubkey_hex)?
        } else {
            false
        }
    } else {
        false
    };

    Ok(VerifiedSdJwt {
        iss,
        sub,
        iat,
        exp,
        vct,
        disclosed_claims,
        algorithm,
        kb_verified,
        cnf: payload.get("cnf").cloned(),
    })
}

/// Verify a Key Binding JWT (RFC 9901 §5.8).
/// `holder_pubkey_hex`: if provided, verifies signature + jkt thumbprint match.
fn verify_kb_jwt(
    kb_jwt: &str,
    full_presentation: &str,
    expected_jkt: &str,
    holder_pubkey_hex: Option<&str>,
) -> Result<bool, String> {
    let kb_parts: Vec<&str> = kb_jwt.split('.').collect();
    if kb_parts.len() != 3 {
        return Err("KB-JWT must have 3 parts".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&base64url_decode(kb_parts[0])?).map_err(|e| e.to_string())?;
    let payload: serde_json::Value =
        serde_json::from_slice(&base64url_decode(kb_parts[1])?).map_err(|e| e.to_string())?;

    if header.get("typ").and_then(|v| v.as_str()) != Some("kb+jwt") {
        return Err("KB-JWT typ must be kb+jwt".into());
    }

    let alg_str = header["alg"].as_str().ok_or("KB-JWT missing alg")?;
    let algorithm = jwt_to_alg(alg_str).ok_or_else(|| format!("unknown KB alg: {alg_str}"))?;

    // Verify sd_hash: SHA-256 of everything before the KB-JWT
    let prefix_end = full_presentation.rfind(kb_jwt).unwrap_or(0);
    let prefix = &full_presentation[..prefix_end];
    let computed_sd_hash = base64url_encode(&hash_with(HashAlgorithm::Sha256, prefix.as_bytes()));
    let claimed_sd_hash = payload
        .get("sd_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if computed_sd_hash != claimed_sd_hash {
        return Err("KB-JWT sd_hash mismatch".into());
    }

    // Verify iat is present
    if payload.get("iat").and_then(|v| v.as_u64()).is_none() {
        return Err("KB-JWT missing iat".into());
    }

    // Verify KB-JWT signature if holder public key is available
    if let Some(pk_hex) = holder_pubkey_hex {
        let jkt = jwk_thumbprint(pk_hex, algorithm);
        if jkt != expected_jkt {
            return Err("KB-JWT jkt thumbprint mismatch".into());
        }
        let sig_bytes = base64url_decode(kb_parts[2])?;
        let signing_input = format!("{}.{}", kb_parts[0], kb_parts[1]);
        let sig_hex = hex::encode(&sig_bytes);
        if !crate::signature::verify_signature(
            algorithm,
            pk_hex,
            signing_input.as_bytes(),
            &sig_hex,
        ) {
            return Err("KB-JWT signature verification failed".into());
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::signing::SoftwareSigningProvider;

    fn test_claims() -> VcClaims {
        VcClaims {
            iss: "did:goya:issuer".to_string(),
            sub: "did:goya:subject".to_string(),
            iat: 1_700_000_000,
            exp: 2_000_000_000,
            vct: "IdentityCredential".to_string(),
            claims: vec![
                ("given_name".to_string(), serde_json::json!("Juan")),
                ("family_name".to_string(), serde_json::json!("Pérez")),
                ("birth_date".to_string(), serde_json::json!("1990-01-15")),
                ("nationality".to_string(), serde_json::json!("CL")),
            ],
            cnf: None,
            status: None,
        }
    }

    #[test]
    fn issue_and_verify_full() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        assert!(sd_jwt.compact.contains('~'));
        assert_eq!(sd_jwt.disclosures.len(), 4);

        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.iss, "did:goya:issuer");
        assert_eq!(verified.sub, "did:goya:subject");
        assert_eq!(verified.vct, "IdentityCredential");
        assert_eq!(verified.disclosed_claims.len(), 4);
        assert_eq!(verified.algorithm, SigningAlgorithm::Ed25519);
    }

    #[test]
    fn selective_disclosure() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        // Only disclose given_name (index 0) and nationality (index 3)
        let presentation = present_sd_jwt(&sd_jwt, &[0, 3]);
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&presentation, &pk_hex).unwrap();
        assert_eq!(verified.disclosed_claims.len(), 2);

        let names: Vec<&str> = verified
            .disclosed_claims
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert!(names.contains(&"given_name"));
        assert!(names.contains(&"nationality"));
        assert!(!names.contains(&"family_name"));
        assert!(!names.contains(&"birth_date"));
    }

    #[test]
    fn zero_disclosures() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        let presentation = present_sd_jwt(&sd_jwt, &[]);
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&presentation, &pk_hex).unwrap();
        assert!(verified.disclosed_claims.is_empty());
        // But metadata is still visible
        assert_eq!(verified.iss, "did:goya:issuer");
        assert_eq!(verified.vct, "IdentityCredential");
    }

    #[test]
    fn wrong_key_fails() {
        let provider = SoftwareSigningProvider::generate();
        let other = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        let wrong_pk = hex::encode(other.public_key());
        assert!(verify_sd_jwt_vc(&sd_jwt.compact, &wrong_pk).is_err());
    }

    #[test]
    fn tampered_disclosure_rejected() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();

        // Create a fake disclosure not in _sd
        let fake = base64url_encode(
            &serde_json::to_vec(&serde_json::json!(["fakesalt", "fake_claim", "fake_value"]))
                .unwrap(),
        );
        let tampered = format!("{}~{}~", sd_jwt.jwt, fake);
        let pk_hex = hex::encode(provider.public_key());
        assert!(verify_sd_jwt_vc(&tampered, &pk_hex).is_err());
    }

    #[test]
    fn jwt_has_correct_type() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let jwt_parts: Vec<&str> = sd_jwt.jwt.split('.').collect();
        let header_bytes = base64url_decode(jwt_parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "vc+sd-jwt");
        assert_eq!(header["alg"], "EdDSA");
    }

    #[test]
    fn payload_has_sd_array() {
        let provider = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let jwt_parts: Vec<&str> = sd_jwt.jwt.split('.').collect();
        let payload_bytes = base64url_decode(jwt_parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["_sd_alg"], "sha-256");
        assert_eq!(payload["_sd"].as_array().unwrap().len(), 4);
        assert_eq!(payload["vct"], "IdentityCredential");
    }

    #[test]
    fn mldsa65_roundtrip() {
        use crate::identity::signing::MlDsaSigningProvider;
        let provider = MlDsaSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.algorithm, SigningAlgorithm::MlDsa65);
        assert_eq!(verified.disclosed_claims.len(), 4);
    }

    #[test]
    fn rsa_roundtrip() {
        use crate::identity::signing::RsaSigningProvider;
        let provider = RsaSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &provider).unwrap();
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.algorithm, SigningAlgorithm::Rsa);
    }

    #[test]
    fn single_claim_disclosure() {
        let provider = SoftwareSigningProvider::generate();
        let claims = VcClaims {
            iss: "did:goya:i".to_string(),
            sub: "did:goya:s".to_string(),
            iat: 1_700_000_000,
            exp: 2_000_000_000,
            vct: "AgeVerification".to_string(),
            claims: vec![("age_over_18".to_string(), serde_json::json!(true))],
            cnf: None,
            status: None,
        };
        let sd_jwt = issue_sd_jwt_vc(&claims, &provider).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 1);

        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.disclosed_claims.len(), 1);
        assert_eq!(verified.disclosed_claims[0].0, "age_over_18");
        assert_eq!(verified.disclosed_claims[0].1, true);
    }

    #[test]
    fn empty_claims() {
        let provider = SoftwareSigningProvider::generate();
        let claims = VcClaims {
            iss: "did:goya:i".to_string(),
            sub: "did:goya:s".to_string(),
            iat: 1_700_000_000,
            exp: 2_000_000_000,
            vct: "EmptyVC".to_string(),
            claims: vec![],
            cnf: None,
            status: None,
        };
        let sd_jwt = issue_sd_jwt_vc(&claims, &provider).unwrap();
        assert!(sd_jwt.disclosures.is_empty());
        let pk_hex = hex::encode(provider.public_key());
        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert!(verified.disclosed_claims.is_empty());
        assert!(!verified.kb_verified);
    }

    #[test]
    fn kb_jwt_roundtrip() {
        let issuer = SoftwareSigningProvider::generate();
        let holder = SoftwareSigningProvider::generate();
        let holder_pk = hex::encode(holder.public_key());

        let sd_jwt = issue_sd_jwt_vc_with_kb(
            &test_claims(),
            &issuer,
            &holder_pk,
            SigningAlgorithm::Ed25519,
        )
        .unwrap();

        let presentation = present_sd_jwt_with_kb(
            &sd_jwt,
            &[0, 1],
            &holder,
            "verifier.example",
            "nonce-1",
            1_700_000_000,
        )
        .unwrap();

        let issuer_pk = hex::encode(issuer.public_key());
        let verified = verify_sd_jwt_vc(&presentation, &issuer_pk).unwrap();
        assert!(verified.kb_verified);
        assert_eq!(verified.disclosed_claims.len(), 2);
    }

    #[test]
    fn kb_jwt_sd_hash_tampered() {
        let issuer = SoftwareSigningProvider::generate();
        let holder = SoftwareSigningProvider::generate();
        let holder_pk = hex::encode(holder.public_key());

        let sd_jwt = issue_sd_jwt_vc_with_kb(
            &test_claims(),
            &issuer,
            &holder_pk,
            SigningAlgorithm::Ed25519,
        )
        .unwrap();

        let mut presentation =
            present_sd_jwt_with_kb(&sd_jwt, &[0], &holder, "aud", "n", 1_700_000_000).unwrap();

        // Tamper: insert an extra disclosure before KB-JWT to break sd_hash
        let last_tilde = presentation.rfind('~').unwrap();
        let kb = presentation[last_tilde + 1..].to_string();
        // Remove KB-JWT, add fake disclosure, re-add KB-JWT
        presentation.truncate(last_tilde + 1);
        let fake = base64url_encode(b"tampered");
        presentation.push_str(&fake);
        presentation.push('~');
        presentation.push_str(&kb);

        let issuer_pk = hex::encode(issuer.public_key());
        assert!(verify_sd_jwt_vc(&presentation, &issuer_pk).is_err());
    }

    #[test]
    fn kb_jwt_without_cnf_not_verified() {
        let issuer = SoftwareSigningProvider::generate();
        let holder = SoftwareSigningProvider::generate();

        // Issue without cnf (regular issue)
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &issuer).unwrap();

        // Manually append a KB-JWT anyway
        let presentation =
            present_sd_jwt_with_kb(&sd_jwt, &[0], &holder, "aud", "n", 1_700_000_000).unwrap();

        let issuer_pk = hex::encode(issuer.public_key());
        let verified = verify_sd_jwt_vc(&presentation, &issuer_pk).unwrap();
        // KB-JWT present but no cnf in payload → kb_verified = false
        assert!(!verified.kb_verified);
    }

    #[test]
    fn jwk_thumbprint_deterministic() {
        let provider = SoftwareSigningProvider::generate();
        let pk = hex::encode(provider.public_key());
        let t1 = jwk_thumbprint(&pk, SigningAlgorithm::Ed25519);
        let t2 = jwk_thumbprint(&pk, SigningAlgorithm::Ed25519);
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn issue_with_kb_has_cnf() {
        let issuer = SoftwareSigningProvider::generate();
        let holder = SoftwareSigningProvider::generate();
        let holder_pk = hex::encode(holder.public_key());

        let sd_jwt = issue_sd_jwt_vc_with_kb(
            &test_claims(),
            &issuer,
            &holder_pk,
            SigningAlgorithm::Ed25519,
        )
        .unwrap();

        let jwt_parts: Vec<&str> = sd_jwt.jwt.split('.').collect();
        let payload_bytes = base64url_decode(jwt_parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(payload.get("cnf").is_some());
        assert!(payload["cnf"]["jkt"].as_str().is_some());
    }

    // ── ES256 (EUDI interop) SD-JWT VC tests ───────────────────

    #[test]
    fn es256_sd_jwt_vc_issue_and_verify() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &issuer).unwrap();
        let pk_hex = hex::encode(issuer.public_key());

        let jwt_parts: Vec<&str> = sd_jwt.jwt.split('.').collect();
        let header_bytes = base64url_decode(jwt_parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "vc+sd-jwt");

        let verified = verify_sd_jwt_vc(&sd_jwt.compact, &pk_hex).unwrap();
        assert_eq!(verified.iss, "did:goya:issuer");
    }

    #[test]
    fn es256_sd_jwt_selective_disclosure() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &issuer).unwrap();
        let pk_hex = hex::encode(issuer.public_key());

        let presentation = present_sd_jwt(&sd_jwt, &[0]);
        let verified = verify_sd_jwt_vc(&presentation, &pk_hex).unwrap();
        assert_eq!(verified.disclosed_claims.len(), 1);
        assert_eq!(verified.disclosed_claims[0].0, "given_name");
    }

    #[test]
    fn es256_sd_jwt_with_holder_key_binding() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let holder = EcdsaP256SigningProvider::generate();
        let holder_pk_hex = hex::encode(holder.public_key());

        let sd_jwt = issue_sd_jwt_vc_with_kb(
            &test_claims(),
            &issuer,
            &holder_pk_hex,
            SigningAlgorithm::EcdsaP256,
        )
        .unwrap();

        let presentation = present_sd_jwt_with_kb(
            &sd_jwt,
            &[0, 1],
            &holder,
            "https://verifier.example.com",
            "nonce-123",
            1_700_000_000,
        )
        .unwrap();

        let issuer_pk_hex = hex::encode(issuer.public_key());
        let verified =
            verify_sd_jwt_vc_with_holder(&presentation, &issuer_pk_hex, &holder_pk_hex).unwrap();
        assert!(verified.kb_verified);
        assert_eq!(verified.disclosed_claims.len(), 2);
    }

    #[test]
    fn es256_sd_jwt_wrong_key_rejects() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let wrong = EcdsaP256SigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &issuer).unwrap();
        let wrong_pk = hex::encode(wrong.public_key());
        let result = verify_sd_jwt_vc(&sd_jwt.compact, &wrong_pk);
        assert!(result.is_err(), "wrong key must reject");
    }

    #[test]
    fn es256_sd_jwt_tampered_signature_rejects() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &issuer).unwrap();
        let pk_hex = hex::encode(issuer.public_key());

        // Tamper the signature (last component of JWT before ~)
        let mut parts: Vec<&str> = sd_jwt.compact.split('~').collect();
        let jwt = parts[0];
        let jwt_parts: Vec<&str> = jwt.split('.').collect();
        let mut sig_bytes = base64url_decode(jwt_parts[2]).unwrap();
        sig_bytes[0] ^= 0xff;
        let tampered_sig = base64url_encode(&sig_bytes);
        let tampered_jwt = format!("{}.{}.{}", jwt_parts[0], jwt_parts[1], tampered_sig);
        parts[0] = &tampered_jwt;
        let tampered_compact = parts.join("~");

        let result = verify_sd_jwt_vc(&tampered_compact, &pk_hex);
        assert!(result.is_err(), "tampered signature must reject");
    }

    #[test]
    fn es256_ed25519_cross_algorithm_sd_jwt_rejects() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let issuer = EcdsaP256SigningProvider::generate();
        let ed_key = SoftwareSigningProvider::generate();
        let sd_jwt = issue_sd_jwt_vc(&test_claims(), &issuer).unwrap();
        let ed_pk = hex::encode(ed_key.public_key());
        let result = verify_sd_jwt_vc(&sd_jwt.compact, &ed_pk);
        assert!(result.is_err(), "Ed25519 key must not verify ES256 JWT");
    }

    #[test]
    fn es256_jwk_thumbprint_p256_format() {
        use crate::identity::signing::EcdsaP256SigningProvider;
        let provider = EcdsaP256SigningProvider::generate();
        let pk_hex = hex::encode(provider.public_key());
        let jkt = jwk_thumbprint(&pk_hex, SigningAlgorithm::EcdsaP256);
        assert!(!jkt.is_empty());
        // JWK thumbprint should be deterministic
        let jkt2 = jwk_thumbprint(&pk_hex, SigningAlgorithm::EcdsaP256);
        assert_eq!(jkt, jkt2);
    }

    #[test]
    fn w3c_format_output() {
        let provider = SoftwareSigningProvider::generate();
        let claims = VcClaims {
            iss: "https://goyaledger.com".to_string(),
            sub: "did:jwk:eyJjcnYiOiJQLTI1NiJ9".to_string(),
            iat: 1726401039,
            exp: 1757937039,
            vct: "IdentityCredential".to_string(),
            claims: vec![
                ("given_name".into(), serde_json::json!("Jane")),
                ("family_name".into(), serde_json::json!("Doe")),
            ],
            cnf: None,
            status: None,
        };
        let result = issue_sd_jwt_vc_w3c(&claims, &provider).unwrap();
        let parts: Vec<&str> = result.jwt.split('.').collect();
        let header: serde_json::Value =
            serde_json::from_slice(&base64url_decode(parts[0]).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&base64url_decode(parts[1]).unwrap()).unwrap();
        println!("HEADER: {}", serde_json::to_string_pretty(&header).unwrap());
        println!(
            "PAYLOAD: {}",
            serde_json::to_string_pretty(&payload).unwrap()
        );
        println!("COMPACT: {}", &result.compact[..80]);
        println!("DISCLOSURES: {}", result.disclosures.len());
    }
}
