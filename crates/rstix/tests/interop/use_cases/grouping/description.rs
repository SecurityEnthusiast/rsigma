//! §3.6.1 Description — Grouping Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::{Grouping, Indicator};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::grouping::FIXTURE_CREATE;

/// REQ-3.6-1 — §3.6.1 Description.
///
/// Doc: a Grouping explicitly asserts shared context among referenced STIX objects
/// (e.g. suspicious-activity clustering). This check binds that description to
/// normative §3.6.3.1: a typed Grouping SDO with `context` suspicious-activity and
/// a referenced Indicator in `object_refs` — not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.6.3.1 must parse for description-scope check");
    let grouping_id =
        StixId::parse("grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3").expect("grouping id");
    let grouping = bundle
        .get_typed::<Grouping>(&grouping_id)
        .expect("normative Grouping must be typed");
    assert_eq!(
        grouping.context, "suspicious-activity",
        "§3.6.1 / §3.6.3.1 running example context must be present on normative fixture"
    );
    let indicator_id =
        StixId::parse("indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2").expect("indicator id");
    assert!(
        grouping.object_refs.contains(&indicator_id),
        "§3.6.3.1 Grouping must reference the bundled Indicator"
    );
    assert!(
        bundle.get_typed::<Indicator>(&indicator_id).is_some(),
        "§3.6.3.1 referenced Indicator must parse as typed SDO"
    );
}

interop_test!(
    "REQ-3.6-1",
    "use_cases::grouping::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
