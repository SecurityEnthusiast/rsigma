//! Two-tier validation via the interop gate (REQ-2.3-X-03).

use crate::common::fixture_catalog::{object_ids_of_type, parse_fixture_objects};
use crate::common::fixture_walk::for_each_suite_walk_fixture;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};

/// Referenced objects stay spec-only; interop rules apply only to use-case object ids.
pub fn assert_referenced_obj_spec_only() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        validate_interop_json(&fixture.json, &InteropGateOptions::default())
            .unwrap_or_else(|err| panic!("{relative}: spec-only tier must pass: {err}"));
        validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: use-case tier must pass for interop objects: {err}")
        });
    });

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
        "spec-minimal use-case object must fail interop tier while referenced identity stays spec-valid"
    );
}
