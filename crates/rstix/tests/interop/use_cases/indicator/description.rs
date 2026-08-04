//! §3.7.1 Description — Indicator Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Indicator;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::indicator::FIXTURE_CREATE;

/// REQ-3.7-1 — §3.7.1 Description.
///
/// Doc: an Indicator identifies malicious content as a detection pattern; the running
/// example in §3.7.3.1 is “Bad IP1” (IPv4). This check binds that description to the
/// normative §3.7.3.1 fixture — not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.7.3.1 must parse for description-scope check");
    let indicator_id =
        StixId::parse("indicator--12fd1bad-8306-4ed4-8c9b-7dfdd8ad5eb8").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("normative Indicator must be typed");
    assert_eq!(
        indicator.name.as_deref(),
        Some("Bad IP1"),
        "§3.7.1 / §3.7.3.1 running example name must be present on normative fixture"
    );
    assert_eq!(
        indicator.pattern.raw(),
        "[ipv4-addr:value = '198.51.100.1']",
        "§3.7.3.1 must carry the IPv4 detection pattern described in §3.7.1"
    );
}

interop_test!(
    "REQ-3.7-1",
    "use_cases::indicator::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
