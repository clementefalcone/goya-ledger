use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceFactor {
    Pin,
    Biometric,
}

impl DeviceFactor {
    fn key(self) -> &'static str {
        match self {
            DeviceFactor::Pin => "pin",
            DeviceFactor::Biometric => "biometric",
        }
    }
}

pub fn login_message(nonce: &str, device_factors: &[DeviceFactor]) -> String {
    if device_factors.is_empty() {
        return nonce.to_string();
    }
    let keys: Vec<&str> = device_factors.iter().map(|factor| factor.key()).collect();
    format!("identity:login:{nonce}:{}", keys.join(","))
}

pub fn has_repeated_factor(device_factors: &[DeviceFactor]) -> bool {
    device_factors
        .iter()
        .enumerate()
        .any(|(index, factor)| device_factors[..index].contains(factor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_without_factors_signs_bare_nonce() {
        assert_eq!(login_message("n1", &[]), "n1");
    }

    #[test]
    fn login_with_factors_binds_them_in_order() {
        let factors = [DeviceFactor::Biometric, DeviceFactor::Pin];
        assert_eq!(
            login_message("n1", &factors),
            "identity:login:n1:biometric,pin"
        );
    }

    #[test]
    fn factor_keys_match_wire_names() {
        let factors: Vec<DeviceFactor> = serde_json::from_str(r#"["pin","biometric"]"#).unwrap();
        assert_eq!(
            login_message("n", &factors),
            "identity:login:n:pin,biometric"
        );
    }

    #[test]
    fn unknown_factor_is_rejected() {
        assert!(serde_json::from_str::<Vec<DeviceFactor>>(r#"["retina"]"#).is_err());
    }

    #[test]
    fn repeated_factor_is_detected() {
        assert!(has_repeated_factor(&[DeviceFactor::Pin, DeviceFactor::Pin]));
        assert!(!has_repeated_factor(&[
            DeviceFactor::Pin,
            DeviceFactor::Biometric
        ]));
    }
}
