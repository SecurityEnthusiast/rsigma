//! §3.1.4 Producer Example Data (non-gating).

use rstix::ParseError;
use rstix::core::{StixId, StixIdError};
use rstix::model::{Bundle, ParseOptions};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.1.4.1 non-normative example.
pub const EXAMPLE_CONTEXT: &str =
    "examples/attack-pattern/ex-3.1.4.1-add-context-to-indicator.json";
/// OASIS §3.1.4.2 non-normative example (published truncated UUID ids).
pub const EXAMPLE_FRAMEWORK: &str =
    "examples/attack-pattern/ex-3.1.4.2-leverage-externally-defined-frameworks.json";

/// Published truncated UUID ids retained from OASIS §3.1.4.2 (defect 21).
const TRUNCATED_FRAMEWORK_IDS: &[&str] = &[
    "malware--1121ffbc-364f-857a-9987-92fbcff24ab",
    "relationship--11220001-3940-0405-20ff-1029b0bc922",
];

/// REQ-3.1-EX-4.1 — §3.1.4.1 loads and passes the interop gate (examples are non-gating).
pub fn assert_add_context_to_indicator() {
    let fixture = load_fixture(EXAMPLE_CONTEXT);
    assert_eq!(fixture.provenance.source_section, "3.1.4.1");
    // Empty use-case ids: example is not a §3.1.3 normative Producer test case.
    validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.1.4.1 example must parse and pass interop gate");
}

/// REQ-3.1-EX-4.2 — §3.1.4.2 retains published truncated UUID ids; parse must reject them.
///
/// Pins the failure to the structured id boundary (no Display substring matching, no
/// invented repair UUIDs): each published truncated id is [`StixIdError::InvalidUuid`],
/// and bundle parse surfaces [`ParseError::InvalidStixId`] with that variant.
pub fn assert_framework_example_rejects_truncated_ids() {
    let fixture = load_fixture(EXAMPLE_FRAMEWORK);
    assert_eq!(fixture.provenance.source_section, "3.1.4.2");
    assert!(
        fixture
            .provenance
            .divergence_recorded
            .iter()
            .any(|d| d.defect == 21),
        "expected defect 21 recorded for truncated UUID ids"
    );

    for truncated in TRUNCATED_FRAMEWORK_IDS {
        assert!(
            fixture.json.contains(truncated),
            "fixture must retain published truncated id: {truncated}"
        );
        assert!(
            matches!(StixId::parse(truncated), Err(StixIdError::InvalidUuid(_))),
            "published truncated id must be StixIdError::InvalidUuid: {truncated}"
        );
    }

    let err = Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .expect_err("§3.1.4.2 truncated UUID ids must fail parse");
    match err {
        ParseError::InvalidStixId(StixIdError::InvalidUuid(_)) => {}
        other => panic!("expected ParseError::InvalidStixId(InvalidUuid), got: {other:?}"),
    }
}

interop_test!(
    "REQ-3.1-EX-4.1",
    "use_cases::attack_pattern::examples::add_context_to_indicator",
    add_context_to_indicator,
    {
        assert_add_context_to_indicator();
    }
);

interop_test!(
    "REQ-3.1-EX-4.2",
    "use_cases::attack_pattern::examples::framework_example_rejects_truncated_ids",
    framework_example_rejects_truncated_ids,
    {
        assert_framework_example_rejects_truncated_ids();
    }
);
