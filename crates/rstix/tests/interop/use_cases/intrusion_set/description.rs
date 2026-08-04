//! §3.9.1 Description — Intrusion Set Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::IntrusionSet;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::intrusion_set::FIXTURE_CREATE;

/// REQ-3.9-1 — §3.9.1 Description.
///
/// Doc: an Intrusion Set is the entire attack package that may span multiple Campaigns;
/// the running example in §3.9.3 is “Bobcat Breakin”. This check binds that description
/// to normative §3.9.3.1: a typed Intrusion Set SDO with that name — not a prose-only
/// REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.9.3.1 must parse for description-scope check");
    let intrusion_set_id =
        StixId::parse("intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29").expect("is id");
    let intrusion_set = bundle
        .get_typed::<IntrusionSet>(&intrusion_set_id)
        .expect("normative Intrusion Set must be typed");
    assert_eq!(
        intrusion_set.name, "Bobcat Breakin",
        "§3.9.1 / §3.9.3.1 running example name must be present on normative fixture"
    );
}

interop_test!(
    "REQ-3.9-1",
    "use_cases::intrusion_set::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
