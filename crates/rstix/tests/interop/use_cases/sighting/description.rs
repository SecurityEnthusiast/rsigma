//! §3.17.1 Description — Sighting Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Indicator;
use rstix::model::sro::Sighting;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::sighting::FIXTURE_CREATE;

/// REQ-3.17-1 — §3.17.1 Description.
///
/// Doc: a Sighting denotes that an element of CTI (typically an Indicator) was seen.
/// This check binds that description to normative §3.17.3.1: a typed Sighting with
/// `count` 50 and a resolvable `sighting_of_ref` Indicator — not a prose-only
/// REPORT_ONLY placeholder. Distinct from C-05 relationship/endpoint processing.
pub fn assert_description_scope() {
    let bundle =
        validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json).unwrap();
    let id = StixId::parse("sighting--ee20065d-2555-424f-ad9e-0f8428623c75").unwrap();
    let sighting = bundle.get_typed::<Sighting>(&id).unwrap();
    assert_eq!(sighting.count, Some(50));
    let indicator_id =
        StixId::parse("indicator--12fd1bad-8306-4ed4-8c9b-7dfdd8ad5eb8").expect("indicator id");
    assert_eq!(sighting.sighting_of_ref, indicator_id);
    assert!(
        bundle.get_typed::<Indicator>(&indicator_id).is_some(),
        "§3.17.3.1 sighting_of_ref must resolve to a typed Indicator"
    );
}

interop_test!(
    "REQ-3.17-1",
    "use_cases::sighting::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
