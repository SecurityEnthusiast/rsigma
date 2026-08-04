//! §3.14.1 Description — Observed Data Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::ObservedData;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::observed_data::{FIXTURE_CREATE, FIXTURE_DOMAIN};

/// REQ-3.14-1 — §3.14.1 Description.
pub fn assert_description_scope() {
    let create = load_fixture(FIXTURE_CREATE);
    let create_bundle =
        validate_interop_fixture(FIXTURE_CREATE, &create.json).expect("§3.14.3.1 must parse");
    let od_id = StixId::parse("observed-data--cf8eaa41-6f4c-482e-89b9-9cd2d6a83cb1").expect("id");
    let od = create_bundle
        .get_typed::<ObservedData>(&od_id)
        .expect("typed ObservedData");
    assert_eq!(od.number_observed, 1);

    let domain = load_fixture(FIXTURE_DOMAIN);
    let domain_bundle = validate_interop_fixture(FIXTURE_DOMAIN, &domain.json).expect("§3.14.3.2");
    assert_eq!(domain_bundle.objects_of_type::<ObservedData>().count(), 1);
}

interop_test!(
    "REQ-3.14-1",
    "use_cases::observed_data::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
