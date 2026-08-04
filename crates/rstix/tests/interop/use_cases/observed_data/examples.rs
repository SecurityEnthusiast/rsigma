//! §3.14.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::ObservedData;
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_SEVERAL_SCOS: &str =
    "examples/observed-data/ex-3.14.4.1-observed-data-with-several-scos.json";

pub fn assert_observed_data_with_several_scos() {
    let fixture = load_fixture(EXAMPLE_SEVERAL_SCOS);
    assert_eq!(fixture.provenance.source_section, "3.14.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.14.4.1 must pass");
    let od_id = StixId::parse("observed-data--359d9ff7-1d08-4af6-92e4-e9df5b1bad88").expect("id");
    let od = bundle
        .get_typed::<ObservedData>(&od_id)
        .expect("ObservedData");
    assert_eq!(od.number_observed, 50);
    assert_eq!(bundle.objects_of_type::<Relationship>().count(), 1);
}

interop_test!(
    "REQ-3.14-EX-4.1",
    "use_cases::observed_data::examples::observed_data_with_several_scos",
    observed_data_with_several_scos,
    {
        assert_observed_data_with_several_scos();
    }
);
