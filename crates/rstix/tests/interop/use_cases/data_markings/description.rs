//! §3.5.1 Description — Data Markings Sharing scope.

use rstix::core::StixId;
use rstix::model::meta::TLP1_WHITE_ID;
use rstix::model::sdo::Indicator;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::data_markings::FIXTURE_CREATE;

/// REQ-3.5-1 — §3.5.1 Description.
///
/// Doc: object-level TLP markings on shared STIX content via predefined marking-definition
/// references; Indicators represent all SDOs in this use case. This check binds that
/// description to normative §3.5.3.1: a typed Indicator carrying a single TLP White
/// `object_marking_refs` entry — not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.5.3.1 must parse for description-scope check");
    let indicator_id =
        StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("TLP White Indicator must be typed");
    assert_eq!(indicator.name.as_deref(), Some("Bad IP1"));
    assert_eq!(indicator.common.object_marking_refs.len(), 1);
    assert_eq!(
        indicator.common.object_marking_refs[0].as_stix_id().as_str(),
        TLP1_WHITE_ID,
        "§3.5.3.1 must reference predefined TLP White marking-definition"
    );
}

interop_test!(
    "REQ-3.5-1",
    "use_cases::data_markings::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
