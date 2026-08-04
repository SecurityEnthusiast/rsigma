//! §3.4.1 Description — Course Of Action Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::CourseOfAction;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::course_of_action::FIXTURE_CREATE;

/// REQ-3.4-1 — §3.4.1 Description.
///
/// Doc: a Course of Action is a recommendation for how to respond to threat intelligence;
/// the COA SDO primarily focuses on a textual description of a mitigating action. This
/// check binds that description to normative §3.4.3.1: a typed Course of Action SDO with
/// the testcase name — not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.4.3.1 must parse for description-scope check");
    let coa_id =
        StixId::parse("course-of-action--97250bf1-7ab6-4c79-b8c0-b59f6fc62e9d").expect("coa id");
    let course_of_action = bundle
        .get_typed::<CourseOfAction>(&coa_id)
        .expect("normative Course of Action must be typed");
    assert_eq!(
        course_of_action.name, "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        "§3.4.1 / §3.4.3.1 running example name must be present on normative fixture"
    );
}

interop_test!(
    "REQ-3.4-1",
    "use_cases::course_of_action::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
