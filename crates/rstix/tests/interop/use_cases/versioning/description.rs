//! §3.20.1 Description — Versioning scope.

use rstix::core::StixId;
use rstix::model::sdo::Indicator;
use rstix::model::sro::Sighting;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::versioning::{FIXTURE_CREATE_INDICATOR, FIXTURE_CREATE_SIGHTING};

pub fn assert_description_scope() {
    let ind = validate_interop_fixture(
        FIXTURE_CREATE_INDICATOR,
        &load_fixture(FIXTURE_CREATE_INDICATOR).json,
    )
    .unwrap();
    let id = StixId::parse("indicator--6cd5cd4f-ff42-4d67-8402-02aad22f8b63").unwrap();
    assert!(ind.get_typed::<Indicator>(&id).is_some());

    let sight = validate_interop_fixture(
        FIXTURE_CREATE_SIGHTING,
        &load_fixture(FIXTURE_CREATE_SIGHTING).json,
    )
    .unwrap();
    assert_eq!(sight.objects_of_type::<Sighting>().count(), 1);
}

interop_test!(
    "REQ-3.20-1",
    "use_cases::versioning::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
