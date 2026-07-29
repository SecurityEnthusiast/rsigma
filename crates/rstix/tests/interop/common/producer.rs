//! §2.3 Producer cross-cutting checks (REQ-2.3-P-01..P-03).

use crate::common::fixture_catalog::{
    object_ids_of_type, parse_fixture_objects, use_case_object_ids,
};
use crate::common::fixture_walk::for_each_suite_walk_fixture;
use crate::common::wire_preservation::assert_wire_object_preserved;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};

/// REQ-2.3-P-01 — conformance valid corpus and every walkable testcase pass the interop gate.
pub fn assert_producer_conformance_12_1() {
    crate::harness::interop_gate::assert_conformance_valid_corpus_passes_interop_gate()
        .expect("conformance valid corpus must pass interop gate");

    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative} failed interop producer gate: {err}"));
    });
}

/// REQ-2.3-P-02 — interop use-case rules are stricter than STIX §4.x where §3.x requires it.
pub fn assert_interop_stricter_than_spec() {
    let spec_fixture = load_fixture("testcases/common/tc-attack-pattern-spec-minimal.json");
    let objects = parse_fixture_objects(&spec_fixture.json).expect("parse spec-minimal");
    let ids = object_ids_of_type(&objects, "attack-pattern");
    assert!(
        validate_interop_json(
            &spec_fixture.json,
            &InteropGateOptions {
                use_case_object_ids: ids,
            },
        )
        .is_err(),
        "spec-minimal attack-pattern must fail interop use-case rules"
    );

    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: use-case object must satisfy interop rules: {err}")
        });
    });
}

/// REQ-2.3-P-03 — additional wire properties are permitted (subset/containment on re-serialize).
pub fn assert_additional_properties_permitted() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));

        for object_id in use_case_ids {
            let wire = objects
                .iter()
                .find(|obj| obj.get("id").and_then(|v| v.as_str()) == Some(object_id.as_str()))
                .unwrap_or_else(|| panic!("{relative}: wire object {object_id}"));
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}
