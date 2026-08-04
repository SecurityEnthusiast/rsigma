//! §3.17.1 Description — Sighting Sharing scope.

use rstix::core::StixId;
use rstix::model::sro::Sighting;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::sighting::FIXTURE_CREATE;

pub fn assert_description_scope() {
    let bundle =
        validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json).unwrap();
    let id = StixId::parse("sighting--ee20065d-2555-424f-ad9e-0f8428623c75").unwrap();
    let sighting = bundle.get_typed::<Sighting>(&id).unwrap();
    assert_eq!(sighting.count, Some(50));
    assert_eq!(
        sighting.sighting_of_ref.as_str(),
        "indicator--12fd1bad-8306-4ed4-8c9b-7dfdd8ad5eb8"
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
