//! §3.18.1 Description — Threat Actor Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::{Campaign, ThreatActor};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::threat_actor::{FIXTURE_ATTRIBUTED, FIXTURE_CREATE};

pub fn assert_description_scope() {
    let create = validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json).unwrap();
    let id = StixId::parse("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();
    let ta = create.get_typed::<ThreatActor>(&id).unwrap();
    assert_eq!(ta.name, "Evil Org");

    let attributed = validate_interop_fixture(FIXTURE_ATTRIBUTED, &load_fixture(FIXTURE_ATTRIBUTED).json).unwrap();
    assert_eq!(attributed.objects_of_type::<ThreatActor>().count(), 1);
    assert_eq!(attributed.objects_of_type::<Campaign>().count(), 1);
}

interop_test!("REQ-3.18-1", "use_cases::threat_actor::description::description_scope", description_scope, { assert_description_scope(); });
