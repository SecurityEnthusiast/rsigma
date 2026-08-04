//! §3.10.1 Description — Location Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Location;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::location::FIXTURE_CREATE;

/// REQ-3.10-1 — §3.10.1 Description.
///
/// Doc: a Location represents a geographic place. This check binds that description
/// to normative §3.10.3.1: a typed Location SDO with the testcase region — not a
/// prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.10.3.1 must parse for description-scope check");
    let location_id =
        StixId::parse("location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64").expect("location id");
    let location = bundle
        .get_typed::<Location>(&location_id)
        .expect("normative Location must be typed");
    assert_eq!(
        location.region.as_deref(),
        Some("south-eastern-asia"),
        "§3.10.1 / §3.10.3.1 running example region must be present on normative fixture"
    );
}

interop_test!(
    "REQ-3.10-1",
    "use_cases::location::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
