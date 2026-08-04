//! §3.16.1 Description — Report Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Report;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::report::{working_json, FIXTURE_CREATE};

pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    assert_eq!(fixture.provenance.blocked_by, Some(16));
    let json = working_json(&fixture.json);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &json).unwrap();
    let id = StixId::parse("report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcbd").unwrap();
    let report = bundle.get_typed::<Report>(&id).unwrap();
    assert_eq!(report.name, "Glass Gazelle Campaign");
}

interop_test!("REQ-3.16-1", "use_cases::report::description::description_scope", description_scope, { assert_description_scope(); });
