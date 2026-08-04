//! §3.15.1 Description — Opinion Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Opinion;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::opinion::{FIXTURE_CREATE, FIXTURE_MALWARE};

pub fn assert_description_scope() {
    let create = validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json).unwrap();
    let id = StixId::parse("opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7").unwrap();
    let opinion = create.get_typed::<Opinion>(&id).unwrap();
    assert_eq!(opinion.opinion.as_str(), "strongly-disagree");
    let malware = validate_interop_fixture(FIXTURE_MALWARE, &load_fixture(FIXTURE_MALWARE).json).unwrap();
    assert_eq!(malware.objects_of_type::<Opinion>().count(), 1);
}

interop_test!("REQ-3.15-1", "use_cases::opinion::description::description_scope", description_scope, { assert_description_scope(); });
