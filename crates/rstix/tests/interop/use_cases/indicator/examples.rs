//! §3.7.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::Indicator;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.7.4.1 non-normative example.
pub const EXAMPLE_WITH_DESCRIPTION: &str =
    "examples/indicator/ex-3.7.4.1-indicator-with-description.json";

/// REQ-3.7-EX-4.1 — §3.7.4.1 loads and passes the interop gate; Indicator carries description.
pub fn assert_indicator_with_description() {
    let fixture = load_fixture(EXAMPLE_WITH_DESCRIPTION);
    assert_eq!(fixture.provenance.source_section, "3.7.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.7.4.1 example must parse and pass interop gate");

    let indicator_id =
        StixId::parse("indicator--0cddd4c0-411a-47a7-8ccc-d0473d690a6f").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("Bad File1 Indicator");
    assert_eq!(indicator.name.as_deref(), Some("Bad File1"));
    assert!(
        indicator
            .description
            .as_deref()
            .is_some_and(|d| d.contains("SHA-256 hash")),
        "§3.7.4.1 example must carry a human-readable description"
    );
    assert_eq!(indicator.pattern.pattern_type(), "stix");
    assert!(!indicator.indicator_types.is_empty());
}

interop_test!(
    "REQ-3.7-EX-4.1",
    "use_cases::indicator::examples::indicator_with_description",
    indicator_with_description,
    {
        assert_indicator_with_description();
    }
);
