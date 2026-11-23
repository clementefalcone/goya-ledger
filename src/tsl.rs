//! Trust Service List (TSL) — ETSI TS 119 612.
//!
//! Publishes the list of trust services offered by this node:
//! which services are active, their policies, algorithms, and status.

use crate::identity::signing::SigningAlgorithm;
use crate::pki_policy;
use serde::{Deserialize, Serialize};

/// Status of a trust service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Active,
    Suspended,
    Revoked,
    Planned,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Revoked => write!(f, "revoked"),
            Self::Planned => write!(f, "planned"),
        }
    }
}

/// Type of trust service per ETSI classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// Certificate Authority — issues subscriber certificates.
    CertificateAuthority,
    /// Time Stamping Authority — RFC 3161 timestamps.
    TimeStampAuthority,
    /// OCSP Responder — certificate status.
    OcspResponder,
    /// Registration Authority — identity proofing.
    RegistrationAuthority,
    /// Electronic Signature — FES/FEA signing.
    ElectronicSignature,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateAuthority => write!(f, "certificate_authority"),
            Self::TimeStampAuthority => write!(f, "time_stamp_authority"),
            Self::OcspResponder => write!(f, "ocsp_responder"),
            Self::RegistrationAuthority => write!(f, "registration_authority"),
            Self::ElectronicSignature => write!(f, "electronic_signature"),
        }
    }
}

/// A single trust service entry in the TSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustService {
    pub service_type: ServiceType,
    pub name: String,
    pub status: ServiceStatus,
    pub policy_oid: String,
    pub algorithms: Vec<String>,
    pub formats: Vec<String>,
    pub endpoint: Option<String>,
}

/// The complete Trust Service List for this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustServiceList {
    /// TSL version.
    pub version: u32,
    /// Operator name.
    pub operator: String,
    /// Operator jurisdiction.
    pub jurisdiction: String,
    /// When this TSL was generated (UNIX seconds).
    pub issued_at: u64,
    /// Next scheduled update (UNIX seconds).
    pub next_update: u64,
    /// All trust services.
    pub services: Vec<TrustService>,
}

const OPERATOR: &str = "Goya Ledger";
const JURISDICTION: &str = "Chile";
const NODE_CERTIFICATE_ALGORITHM: &str = "ECDSA-P256";
const USER_SIGNATURE_ALGORITHMS: [SigningAlgorithm; 2] =
    [SigningAlgorithm::MlDsa65, SigningAlgorithm::SlhDsa128s];

/// Build the default Goya TSL from the current node configuration.
pub fn build_tsl(
    now_secs: u64,
    node_signing_algorithm: Option<SigningAlgorithm>,
) -> TrustServiceList {
    let update_interval = 30 * 24 * 3600; // 30 days
    let node_algorithms: Vec<String> = node_signing_algorithm
        .iter()
        .map(ToString::to_string)
        .collect();

    TrustServiceList {
        version: 1,
        operator: OPERATOR.to_string(),
        jurisdiction: JURISDICTION.to_string(),
        issued_at: now_secs,
        next_update: now_secs + update_interval,
        services: vec![
            TrustService {
                service_type: ServiceType::CertificateAuthority,
                name: "Goya Ledger CA".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::CP_OID.to_string(),
                algorithms: vec![NODE_CERTIFICATE_ALGORITHM.into()],
                formats: vec!["X.509v3".into()],
                endpoint: Some("/api/v1/policy/cp".into()),
            },
            TrustService {
                service_type: ServiceType::TimeStampAuthority,
                name: "Goya Ledger TSA".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::TSA_POLICY_OID.to_string(),
                algorithms: node_algorithms.clone(),
                formats: vec!["RFC 3161".into()],
                endpoint: Some("/api/v1/tsa/timestamp".into()),
            },
            TrustService {
                service_type: ServiceType::OcspResponder,
                name: "Goya Ledger OCSP".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::CP_OID.to_string(),
                algorithms: node_algorithms,
                formats: vec!["RFC 6960".into()],
                endpoint: Some("/api/v1/ocsp/query".into()),
            },
            TrustService {
                service_type: ServiceType::RegistrationAuthority,
                name: "Goya Ledger RA".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::CPS_OID.to_string(),
                algorithms: vec![],
                formats: vec!["Ley 19.799 Art. 15".into()],
                endpoint: Some("/api/v1/identity/proof".into()),
            },
            TrustService {
                service_type: ServiceType::ElectronicSignature,
                name: "Goya Ledger Signatures".into(),
                status: ServiceStatus::Active,
                policy_oid: pki_policy::SIGNATURE_POLICY_OID.to_string(),
                algorithms: USER_SIGNATURE_ALGORITHMS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                formats: vec!["XAdES-BES".into(), "CAdES-BES".into(), "PAdES-BES".into()],
                endpoint: Some("/api/v1/notarize".into()),
            },
        ],
    }
}

impl TrustServiceList {
    /// Export as ETSI TS 119 612 XML.
    pub fn to_xml(&self) -> String {
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#">
  <tsl:SchemeInformation>
"#,
        );
        xml.push_str(&format!(
            "    <tsl:TSLVersionIdentifier>{}</tsl:TSLVersionIdentifier>\n",
            self.version
        ));
        xml.push_str(&format!(
            "    <tsl:SchemeTerritory>{}</tsl:SchemeTerritory>\n",
            self.jurisdiction
        ));
        xml.push_str(&format!(
            "    <tsl:SchemeOperatorName><tsl:Name>{}</tsl:Name></tsl:SchemeOperatorName>\n",
            self.operator
        ));
        xml.push_str("  </tsl:SchemeInformation>\n");
        xml.push_str("  <tsl:TrustServiceProviderList>\n");
        xml.push_str("    <tsl:TrustServiceProvider>\n");
        xml.push_str(&format!(
            "      <tsl:TSPInformation><tsl:TSPName><tsl:Name>{}</tsl:Name></tsl:TSPName></tsl:TSPInformation>\n",
            self.operator
        ));
        xml.push_str("      <tsl:TSPServices>\n");

        for svc in &self.services {
            let stype_uri = service_type_uri(svc.service_type);
            let status_uri = service_status_uri(svc.status);
            xml.push_str("        <tsl:TSPService>\n");
            xml.push_str("          <tsl:ServiceInformation>\n");
            xml.push_str(&format!(
                "            <tsl:ServiceTypeIdentifier>{stype_uri}</tsl:ServiceTypeIdentifier>\n"
            ));
            xml.push_str(&format!(
                "            <tsl:ServiceName><tsl:Name>{}</tsl:Name></tsl:ServiceName>\n",
                svc.name
            ));
            xml.push_str(&format!(
                "            <tsl:ServiceStatus>{status_uri}</tsl:ServiceStatus>\n"
            ));
            xml.push_str("          </tsl:ServiceInformation>\n");
            xml.push_str("        </tsl:TSPService>\n");
        }

        xml.push_str("      </tsl:TSPServices>\n");
        xml.push_str("    </tsl:TrustServiceProvider>\n");
        xml.push_str("  </tsl:TrustServiceProviderList>\n");
        xml.push_str("</tsl:TrustServiceStatusList>\n");
        xml
    }
}

fn service_type_uri(st: ServiceType) -> &'static str {
    match st {
        ServiceType::CertificateAuthority => "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
        ServiceType::TimeStampAuthority => "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
        ServiceType::OcspResponder => "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
        ServiceType::RegistrationAuthority => "http://uri.etsi.org/TrstSvc/Svctype/RA",
        ServiceType::ElectronicSignature => "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q",
    }
}

fn service_status_uri(status: ServiceStatus) -> &'static str {
    match status {
        ServiceStatus::Active => "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
        ServiceStatus::Suspended => "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/suspended",
        ServiceStatus::Revoked => "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
        ServiceStatus::Planned => {
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tsl() -> TrustServiceList {
        build_tsl(1_700_000_000, Some(SigningAlgorithm::MlDsa65))
    }

    #[test]
    fn tsl_advertises_only_the_algorithms_services_sign_with() {
        let advertised: Vec<(ServiceType, Vec<String>)> = sample_tsl()
            .services
            .into_iter()
            .map(|service| (service.service_type, service.algorithms))
            .collect();
        assert_eq!(
            advertised,
            vec![
                (
                    ServiceType::CertificateAuthority,
                    vec!["ECDSA-P256".to_string()]
                ),
                (
                    ServiceType::TimeStampAuthority,
                    vec!["ML-DSA-65".to_string()]
                ),
                (ServiceType::OcspResponder, vec!["ML-DSA-65".to_string()]),
                (ServiceType::RegistrationAuthority, vec![]),
                (
                    ServiceType::ElectronicSignature,
                    vec!["ML-DSA-65".to_string(), "SLH-DSA-SHAKE-128s".to_string()]
                ),
            ]
        );
    }

    #[test]
    fn tsl_has_5_services() {
        let tsl = sample_tsl();
        assert_eq!(tsl.services.len(), 5);
    }

    #[test]
    fn tsl_has_ca_service() {
        let tsl = sample_tsl();
        let ca = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::CertificateAuthority);
        assert!(ca.is_some());
        assert_eq!(ca.unwrap().status, ServiceStatus::Active);
    }

    #[test]
    fn tsl_has_tsa_service() {
        let tsl = sample_tsl();
        let tsa = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::TimeStampAuthority);
        assert!(tsa.is_some());
        assert_eq!(tsa.unwrap().policy_oid, pki_policy::TSA_POLICY_OID);
    }

    #[test]
    fn tsl_has_ocsp_service() {
        let tsl = sample_tsl();
        let ocsp = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::OcspResponder);
        assert!(ocsp.is_some());
    }

    #[test]
    fn tsl_has_ra_service() {
        let tsl = sample_tsl();
        let ra = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::RegistrationAuthority);
        assert!(ra.is_some());
    }

    #[test]
    fn tsl_has_signature_service() {
        let tsl = sample_tsl();
        let sig = tsl
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::ElectronicSignature);
        assert!(sig.is_some());
        let formats = &sig.unwrap().formats;
        assert!(formats.contains(&"XAdES-BES".to_string()));
        assert!(formats.contains(&"CAdES-BES".to_string()));
        assert!(formats.contains(&"PAdES-BES".to_string()));
    }

    #[test]
    fn tsl_next_update_is_30_days() {
        let tsl = sample_tsl();
        assert_eq!(tsl.next_update - tsl.issued_at, 30 * 24 * 3600);
    }

    #[test]
    fn tsl_version_is_1() {
        let tsl = sample_tsl();
        assert_eq!(tsl.version, 1);
    }

    #[test]
    fn tsl_operator_and_jurisdiction() {
        let tsl = sample_tsl();
        assert_eq!(tsl.operator, "Goya Ledger");
        assert_eq!(tsl.jurisdiction, "Chile");
    }

    #[test]
    fn all_services_have_endpoints() {
        let tsl = sample_tsl();
        for svc in &tsl.services {
            assert!(
                svc.endpoint.is_some(),
                "service {} has no endpoint",
                svc.name
            );
        }
    }

    #[test]
    fn service_status_display() {
        assert_eq!(ServiceStatus::Active.to_string(), "active");
        assert_eq!(ServiceStatus::Suspended.to_string(), "suspended");
        assert_eq!(ServiceStatus::Planned.to_string(), "planned");
    }

    #[test]
    fn to_xml_valid_structure() {
        let tsl = sample_tsl();
        let xml = tsl.to_xml();
        assert!(xml.starts_with("<?xml version="));
        assert!(xml.contains("<tsl:TrustServiceStatusList"));
        assert!(xml.contains("</tsl:TrustServiceStatusList>"));
        assert!(xml.contains("<tsl:SchemeTerritory>Chile</tsl:SchemeTerritory>"));
        assert!(xml.contains("<tsl:TSLVersionIdentifier>1</tsl:TSLVersionIdentifier>"));
    }

    #[test]
    fn to_xml_contains_all_services() {
        let tsl = sample_tsl();
        let xml = tsl.to_xml();
        assert!(xml.contains("CA/QC"));
        assert!(xml.contains("TSA/QTST"));
        assert!(xml.contains("OCSP/QC"));
        assert!(xml.contains("EDS/Q"));
        assert!(xml.contains("Svcstatus/granted"));
    }

    #[test]
    fn to_xml_parseable_by_tsl_client() {
        let tsl = sample_tsl();
        let xml = tsl.to_xml();
        let parsed = crate::tsl_client::parse_trusted_list(&xml).unwrap();
        assert_eq!(parsed.territory, "Chile");
        assert!(!parsed.tsp_entries.is_empty());
        assert!(crate::tsl_client::is_qualified_tsp(
            &parsed,
            "Goya",
            crate::tsl_client::STYPE_CA_QC
        ));
    }

    #[test]
    fn service_type_display() {
        assert_eq!(
            ServiceType::CertificateAuthority.to_string(),
            "certificate_authority"
        );
        assert_eq!(
            ServiceType::TimeStampAuthority.to_string(),
            "time_stamp_authority"
        );
    }

    #[test]
    fn serialization_roundtrip() {
        let tsl = sample_tsl();
        let json = serde_json::to_string(&tsl).unwrap();
        let parsed: TrustServiceList = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.services.len(), 5);
        assert_eq!(parsed.operator, "Goya Ledger");
    }

    #[test]
    fn all_policy_oids_are_under_goya_root() {
        let tsl = sample_tsl();
        for svc in &tsl.services {
            assert!(
                svc.policy_oid.starts_with(pki_policy::GOYA_OID_ROOT),
                "service {} has OID {} not under Goya root",
                svc.name,
                svc.policy_oid,
            );
        }
    }
}
