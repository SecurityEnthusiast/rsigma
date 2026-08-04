//! §3.8.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Infrastructure, Vulnerability};
use rstix::model::sco::{DomainName, Ipv4Addr};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.8.4.1 non-normative example.
pub const EXAMPLE_VULNERABILITIES_IN_SCANS: &str =
    "examples/infrastructure/ex-3.8.4.1-vulnerabilities-discovered-in-scans.json";
/// OASIS §3.8.4.2 non-normative example.
pub const EXAMPLE_BOTNET_INFRASTRUCTURE: &str =
    "examples/infrastructure/ex-3.8.4.2-botnet-infrastructure.json";

/// REQ-3.8-EX-4.1 — §3.8.4.1 loads and passes the interop gate; Infrastructure `has` Vulnerability.
pub fn assert_vulnerabilities_discovered_in_scans() {
    let fixture = load_fixture(EXAMPLE_VULNERABILITIES_IN_SCANS);
    assert_eq!(fixture.provenance.source_section, "3.8.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.8.4.1 example must parse and pass interop gate");

    let infrastructure_id =
        StixId::parse("infrastructure--a927d4b3-3396-5c01-998b-08733784ab5e").expect("infra id");
    let infrastructure = bundle
        .get_typed::<Infrastructure>(&infrastructure_id)
        .expect("93.184.216.34 Infrastructure");
    assert_eq!(infrastructure.name, "93.184.216.34");
    assert_eq!(infrastructure.infrastructure_types, vec!["exfiltration".to_owned()]);

    let vulnerability_id =
        StixId::parse("vulnerability--fa4ca8dd-1248-5fef-8828-1bd2d935fa58").expect("vuln id");
    assert!(bundle.get_typed::<Vulnerability>(&vulnerability_id).is_some());

    let ipv4_id =
        StixId::parse("ipv4-addr--a927d4b3-3396-5c01-998b-08733784ab5e").expect("ipv4 id");
    assert!(bundle.get_typed::<Ipv4Addr>(&ipv4_id).is_some());

    let domain_id =
        StixId::parse("domain-name--98e751b4-e47f-56f1-9d5d-f60001e5ac84").expect("domain id");
    assert!(bundle.get_typed::<DomainName>(&domain_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 3);
    assert!(
        relationships
            .iter()
            .any(|rel| rel.relationship_type.as_str() == "has"
                && rel.source_ref == infrastructure_id
                && rel.target_ref == vulnerability_id)
    );
    assert!(
        relationships
            .iter()
            .any(|rel| rel.relationship_type.as_str() == "consists-of"
                && rel.source_ref == infrastructure_id
                && rel.target_ref == ipv4_id)
    );
    assert!(
        relationships
            .iter()
            .any(|rel| rel.relationship_type.as_str() == "resolves-to"
                && rel.source_ref == domain_id
                && rel.target_ref == ipv4_id)
    );
}

/// REQ-3.8-EX-4.2 — §3.8.4.2 loads and passes the interop gate; botnet Infrastructure graph.
pub fn assert_botnet_infrastructure() {
    let fixture = load_fixture(EXAMPLE_BOTNET_INFRASTRUCTURE);
    assert_eq!(fixture.provenance.source_section, "3.8.4.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.8.4.2 example must parse and pass interop gate");

    let infrastructure_id =
        StixId::parse("infrastructure--bb054b70-d97e-5451-aa68-e31c72c791d1").expect("infra id");
    let infrastructure = bundle
        .get_typed::<Infrastructure>(&infrastructure_id)
        .expect("C2 URL Infrastructure");
    assert_eq!(
        infrastructure.name,
        "c2--https://corpcougar.com/mexzi/Panel/five/fre.php"
    );
    assert_eq!(infrastructure.infrastructure_types, vec!["c2".to_owned()]);

    let malware_id =
        StixId::parse("malware--77362faf-ac50-5479-a9ec-d70dfc830850").expect("malware id");
    assert!(bundle.get(&malware_id).is_some());

    let url_id = StixId::parse("url--7c9374bc-0ccf-511d-a8f2-0af7965fe06e").expect("url id");
    assert!(bundle.get(&url_id).is_some());

    let indicator_id =
        StixId::parse("indicator--2b254bc2-5da2-56c0-9e24-d19342934f63").expect("indicator id");
    assert!(bundle.get(&indicator_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 3);
    assert!(
        relationships
            .iter()
            .any(|rel| rel.relationship_type.as_str() == "delivers"
                && rel.source_ref == malware_id
                && rel.target_ref == infrastructure_id)
    );
    assert!(
        relationships
            .iter()
            .any(|rel| rel.relationship_type.as_str() == "indicates"
                && rel.source_ref == indicator_id
                && rel.target_ref == infrastructure_id)
    );
    assert!(
        relationships
            .iter()
            .any(|rel| rel.relationship_type.as_str() == "consists-of"
                && rel.source_ref == infrastructure_id
                && rel.target_ref == url_id)
    );
}

interop_test!(
    "REQ-3.8-EX-4.1",
    "use_cases::infrastructure::examples::vulnerabilities_discovered_in_scans",
    vulnerabilities_discovered_in_scans,
    {
        assert_vulnerabilities_discovered_in_scans();
    }
);

interop_test!(
    "REQ-3.8-EX-4.2",
    "use_cases::infrastructure::examples::botnet_infrastructure",
    botnet_infrastructure,
    {
        assert_botnet_infrastructure();
    }
);
