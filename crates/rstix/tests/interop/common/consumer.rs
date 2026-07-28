//! §2.3 Consumer cross-cutting checks (REQ-2.3-C-01..C-06).
//!
//! Uses OASIS §3.1.3.2 normative test-case data where the interoperability document
//! publishes Identity + SDO + SRO content. Not §12.1 Consumer certification.

use rstix::core::StixId;
use rstix::model::sdo::{AttackPattern, Identity, Vulnerability};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};

const CANONICAL_IDENTITY_ID: &str = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff";
const OASIS_CONSUMER_FIXTURE: &str =
    "testcases/attack-pattern/tc-3.1.3.2-attack-pattern-targets-vulnerability.json";

fn load_oasis_consumer_bundle() -> rstix::model::Bundle {
    let fixture = load_fixture(OASIS_CONSUMER_FIXTURE);
    validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("OASIS §3.1.3.2 bundle must pass interop gate")
}

/// REQ-2.3-C-01 — Consumer parses normative Producer test-case data through the interop gate.
pub fn assert_consumer_conformance_12_1() {
    load_oasis_consumer_bundle();
}

/// REQ-2.3-C-02 — Consumer typed accessors expose Producer-required properties.
pub fn assert_consumer_supports_producer_props() {
    let fixture = load_fixture("testcases/attack-pattern/tc-3.1.3.1-create-attack-pattern.json");
    let bundle =
        validate_interop_json(&fixture.json, &InteropGateOptions::default()).expect("interop gate");
    let ap_id = StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
        .expect("attack-pattern id");
    let ap = bundle
        .get_typed::<AttackPattern>(&ap_id)
        .expect("typed attack-pattern");
    assert!(!ap.common.external_references.is_empty());
    assert!(!ap.kill_chain_phases.is_empty());
}

/// REQ-2.3-C-03 — Consumer receives Identity, use-case SDO(s), and SRO(s).
pub fn assert_consumer_receives_triad() {
    let bundle = load_oasis_consumer_bundle();
    let identity_id = StixId::parse(CANONICAL_IDENTITY_ID).expect("identity id");
    assert!(bundle.get_typed::<Identity>(&identity_id).is_some());
    assert_eq!(bundle.objects_of_type::<AttackPattern>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Vulnerability>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Relationship>().count(), 1);
}

/// REQ-2.3-C-04 — Consumer resolves `created_by_ref` Identity fields (§2.3.4).
pub fn assert_consumer_resolves_created_by_ref() {
    let bundle = load_oasis_consumer_bundle();
    let identity_id = StixId::parse(CANONICAL_IDENTITY_ID).expect("identity id");
    let ap_id = StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
        .expect("attack-pattern id");
    let ap = bundle
        .get_typed::<AttackPattern>(&ap_id)
        .expect("attack-pattern");
    let created_by = ap.common.created_by_ref.as_ref().expect("created_by_ref");
    assert_eq!(created_by.as_stix_id().as_str(), CANONICAL_IDENTITY_ID);
    let identity = bundle
        .get_typed::<Identity>(&identity_id)
        .expect("resolve identity");
    assert_eq!(identity.name, "ACME Corp, Inc.");
    assert_eq!(identity.identity_class.as_deref(), Some("organization"));
}

/// REQ-2.3-C-05 — Consumer can process use-case object fields without loss.
pub fn assert_consumer_processes_fields() {
    let bundle = load_oasis_consumer_bundle();
    let ap = bundle
        .objects_of_type::<AttackPattern>()
        .next()
        .expect("attack-pattern");
    assert_eq!(ap.name, "Spear Phishing");
    let vuln = bundle
        .objects_of_type::<Vulnerability>()
        .next()
        .expect("vulnerability");
    assert_eq!(vuln.name, "CVE-2017-0199");
    assert!(!vuln.common.external_references.is_empty());
}

/// REQ-2.3-C-06 — Consumer can process related SDOs/SROs and associated fields.
pub fn assert_consumer_processes_related() {
    let bundle = load_oasis_consumer_bundle();
    let relationship = bundle
        .objects_of_type::<Relationship>()
        .next()
        .expect("relationship");
    assert_eq!(relationship.relationship_type, "targets");
    let ap_id = StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061")
        .expect("attack-pattern id");
    let vuln_id = StixId::parse("vulnerability--99f01020-864f-4713-84d2-d1eff88a843f")
        .expect("vulnerability id");
    assert_eq!(relationship.source_ref.as_str(), ap_id.as_str());
    assert_eq!(relationship.target_ref.as_str(), vuln_id.as_str());
    let ap = bundle
        .get_typed::<AttackPattern>(&ap_id)
        .expect("related attack-pattern");
    assert_eq!(ap.name, "Spear Phishing");
}
