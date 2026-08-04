//! §3.19.1 Description — Tool Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Tool;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::tool::FIXTURE_CREATE;

/// REQ-3.19-1 — §3.19.1 Description.
///
/// Doc: a Tool characterizes legitimate software that threat actors may abuse during
/// attacks (e.g. remote access tools). This check binds that description to normative
/// §3.19.3.1: a typed Tool SDO named VNC with remote-access tool_types — not a
/// prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.19.3.1 must parse for description-scope check");
    let tool_id = StixId::parse("tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").expect("tool id");
    let tool = bundle
        .get_typed::<Tool>(&tool_id)
        .expect("normative Tool must be typed");
    assert_eq!(tool.name, "VNC", "§3.19.1 / §3.19.3.1 running example name");
    assert_eq!(
        tool.tool_types,
        vec!["remote-access".to_string()],
        "§3.19.1 remote access tool example must carry tool_types"
    );
}

interop_test!(
    "REQ-3.19-1",
    "use_cases::tool::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
