//! §3.1.7 Consumer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{AttackPattern, Identity};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.1.7.1 non-normative Consumer example (ATT&CK technique, no custom properties).
pub const EXAMPLE_INGEST: &str =
    "examples/attack-pattern/ex-3.1.7.1-ingest-external-framework.json";

/// REQ-3.1-EX-7.1 — Consumer can ingest external-framework Attack Pattern example (§3.1.7.1).
///
/// Doc: Consumer is not required to ingest custom properties (none present). Example uses a
/// distinct Identity (`identity--c78cb6e5-…`, MITRE), not the ACME Corp normative identity.
pub fn assert_ingest_external_framework() {
    let fixture = load_fixture(EXAMPLE_INGEST);
    assert_eq!(fixture.provenance.source_section, "3.1.7.1");

    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.1.7.1 example must parse and pass interop gate");

    let mitre = StixId::parse("identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5").expect("identity");
    let identity = bundle
        .get_typed::<Identity>(&mitre)
        .expect("MITRE Identity must parse");
    assert_eq!(identity.name, "The MITRE Corporation");

    let ap_id =
        StixId::parse("attack-pattern--b80d107d-fa0d-4b60-9684-b0433e8bdba0").expect("ap id");
    let ap = bundle
        .get_typed::<AttackPattern>(&ap_id)
        .expect("ATT&CK Attack Pattern must parse");
    assert_eq!(ap.name, "Data Encrypted for Impact");
    assert!(!ap.kill_chain_phases.is_empty());
    assert!(!ap.common.external_references.is_empty());
    assert!(
        ap.common
            .external_references
            .iter()
            .any(|r| { r.external_id.as_deref() == Some("T1486") }),
        "expected mitre-attack external_id T1486"
    );
}

interop_test!(
    "REQ-3.1-EX-7.1",
    "use_cases::attack_pattern::consumer_examples::ingest_external_framework",
    ingest_external_framework,
    {
        assert_ingest_external_framework();
    }
);
