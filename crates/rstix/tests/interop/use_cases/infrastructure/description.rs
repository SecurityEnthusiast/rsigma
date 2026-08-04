//! §3.8.1 Description — Infrastructure Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Infrastructure;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::infrastructure::FIXTURE_CREATE;

/// REQ-3.8-1 — §3.8.1 Description.
///
/// Doc: Infrastructure describes systems, software services, and associated resources
/// supporting some purpose (e.g., C2 servers). This check binds that description to
/// normative §3.8.3.1: a typed Infrastructure SDO with the testcase name — not a
/// prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.8.3.1 must parse for description-scope check");
    let infrastructure_id =
        StixId::parse("infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d").expect("infra id");
    let infrastructure = bundle
        .get_typed::<Infrastructure>(&infrastructure_id)
        .expect("normative Infrastructure must be typed");
    assert_eq!(
        infrastructure.name, "Poison Ivy C2",
        "§3.8.1 / §3.8.3.1 running example name must be present on normative fixture"
    );
    assert_eq!(
        infrastructure.infrastructure_types,
        vec!["command-and-control".to_owned()],
        "§3.8.3.1 C2 infrastructure_types must be present"
    );
}

interop_test!(
    "REQ-3.8-1",
    "use_cases::infrastructure::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
