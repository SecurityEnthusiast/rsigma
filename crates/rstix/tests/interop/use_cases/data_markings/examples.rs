//! §3.5.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::meta::MarkingDefinition;
use rstix::model::sdo::Indicator;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.5.4.1 non-normative example.
pub const EXAMPLE_COPYRIGHT_STATEMENT: &str =
    "examples/data-markings/ex-3.5.4.1-copyright-statement.json";

/// REQ-3.5-EX-4.1 — §3.5.4.1 loads; Indicator references a Statement marking-definition.
pub fn assert_copyright_statement() {
    let fixture = load_fixture(EXAMPLE_COPYRIGHT_STATEMENT);
    assert_eq!(fixture.provenance.source_section, "3.5.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.5.4.1 example must parse and pass interop gate");

    let marking_id = StixId::parse("marking-definition--3556db42-ad8e-47ec-a696-9b1695d7760f")
        .expect("statement marking id");
    let marking = bundle
        .get_typed::<MarkingDefinition>(&marking_id)
        .expect("Copyright Statement marking-definition");
    assert_eq!(
        marking.definition_type.as_deref(),
        Some("statement"),
        "§3.5.4.1 marking must use statement definition_type"
    );
    let definition = marking
        .definition
        .as_ref()
        .expect("statement marking definition payload");
    assert_eq!(
        definition.get("statement").and_then(|value| value.as_str()),
        Some("Copyright 2021, Example Corp")
    );

    let indicator_id =
        StixId::parse("indicator--c6b3dbc6-f279-4193-90c2-2967a0a16485").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("Bad IPv6-1 Indicator");
    assert_eq!(indicator.common.object_marking_refs.len(), 1);
    assert_eq!(
        indicator.common.object_marking_refs[0].as_stix_id(),
        &marking_id
    );
}

interop_test!(
    "REQ-3.5-EX-4.1",
    "use_cases::data_markings::examples::copyright_statement",
    copyright_statement,
    {
        assert_copyright_statement();
    }
);
