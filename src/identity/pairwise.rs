use crate::storage::traits::IdentityRecord;

pub const SUBJECT_PREFIX: &str = "pid:";
pub const MIN_SECRET_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    Research,
    Salud,
    Pet,
    Wallet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disclosure {
    Did,
    Subject,
}

impl Audience {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "research" => Some(Self::Research),
            "salud" => Some(Self::Salud),
            "pet" => Some(Self::Pet),
            "wallet" => Some(Self::Wallet),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Research => "research",
            Self::Salud => "salud",
            Self::Pet => "pet",
            Self::Wallet => "wallet",
        }
    }

    pub fn disclosure(self) -> Disclosure {
        match self {
            Self::Research | Self::Wallet => Disclosure::Did,
            Self::Salud | Self::Pet => Disclosure::Subject,
        }
    }
}

pub fn parse_secret(hex_text: &str) -> Result<Vec<u8>, String> {
    let secret =
        hex::decode(hex_text.trim()).map_err(|e| format!("PAIRWISE_SECRET must be hex: {e}"))?;
    if secret.len() < MIN_SECRET_BYTES {
        return Err(format!(
            "PAIRWISE_SECRET must be at least {MIN_SECRET_BYTES} bytes, got {}",
            secret.len()
        ));
    }
    Ok(secret)
}

pub fn subject_for(secret: &[u8], audience: Audience, did: &str) -> Result<String, String> {
    let message = format!("pairwise:v1:{}:{did}", audience.name());
    let mac = pqc_crypto_module::api::hmac_sha3_256(secret, message.as_bytes())
        .map_err(|e| format!("pairwise subject for {} not derived: {e}", audience.name()))?;
    Ok(format!("{SUBJECT_PREFIX}{}", hex::encode(mac.as_bytes())))
}

pub fn find_by_subject<'a>(
    secret: &[u8],
    audience: Audience,
    subject: &str,
    records: &'a [IdentityRecord],
) -> Result<Option<&'a IdentityRecord>, String> {
    for record in records {
        if subject_for(secret, audience, &record.did)? == subject {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7; 32];
    const DID: &str = "did:goya:aa";

    fn record(did: &str) -> IdentityRecord {
        IdentityRecord {
            did: did.to_string(),
            public_key: String::new(),
            created_at: 0,
            updated_at: 0,
            status: "active".to_string(),
            migrated_from: None,
            signature_algorithm: None,
            civil_anchor: None,
            recovery_commitment: None,
            vault_entries: Vec::new(),
        }
    }

    #[test]
    fn each_app_sees_a_different_stable_subject() {
        let pet = subject_for(&SECRET, Audience::Pet, DID).unwrap();
        let salud = subject_for(&SECRET, Audience::Salud, DID).unwrap();
        assert_ne!(pet, salud);
        assert_eq!(pet, subject_for(&SECRET, Audience::Pet, DID).unwrap());
        assert!(pet.starts_with(SUBJECT_PREFIX));
        assert_eq!(pet.len(), SUBJECT_PREFIX.len() + 64);
        assert!(!pet.contains(DID));
    }

    #[test]
    fn another_secret_gives_unrelated_subjects() {
        let other = [8u8; 32];
        assert_ne!(
            subject_for(&SECRET, Audience::Pet, DID).unwrap(),
            subject_for(&other, Audience::Pet, DID).unwrap()
        );
    }

    #[test]
    fn finds_the_identity_behind_a_subject_only_in_its_app() {
        let records = vec![record("did:goya:bb"), record(DID)];
        let pet = subject_for(&SECRET, Audience::Pet, DID).unwrap();
        let found = find_by_subject(&SECRET, Audience::Pet, &pet, &records).unwrap();
        assert_eq!(found.map(|r| r.did.as_str()), Some(DID));
        assert!(find_by_subject(&SECRET, Audience::Salud, &pet, &records)
            .unwrap()
            .is_none());
    }

    #[test]
    fn the_person_s_own_apps_see_the_did_and_services_see_subjects() {
        for audience in [Audience::Research, Audience::Wallet] {
            assert_eq!(audience.disclosure(), Disclosure::Did);
            assert_eq!(Audience::parse(audience.name()), Some(audience));
        }
        for audience in [Audience::Salud, Audience::Pet] {
            assert_eq!(audience.disclosure(), Disclosure::Subject);
            assert_eq!(Audience::parse(audience.name()), Some(audience));
        }
        assert_eq!(Audience::parse("evil"), None);
    }

    #[test]
    fn rejects_short_or_non_hex_secrets() {
        assert!(parse_secret(&"ab".repeat(31)).is_err());
        assert!(parse_secret("not hex").is_err());
        assert_eq!(parse_secret(&"ab".repeat(32)).unwrap().len(), 32);
    }
}
