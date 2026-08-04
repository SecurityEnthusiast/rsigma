//! §3.17.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::ObservedData;
use rstix::model::sro::Sighting;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_WITH_OD: &str =
    "examples/sighting/ex-3.17.4.1-sighting-of-indicator-with-observed-data.json";

pub fn assert_sighting_with_observed_data() {
    let fixture = load_fixture(EXAMPLE_WITH_OD);
    assert_eq!(fixture.provenance.source_section, "3.17.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap();
    let id = StixId::parse("sighting--ee20065d-2555-424f-ad9e-0f8428623c75").unwrap();
    let sighting = bundle.get_typed::<Sighting>(&id).unwrap();
    assert_eq!(sighting.count, Some(50));
    assert_eq!(sighting.observed_data_refs.len(), 1);
    let od_id = StixId::parse("observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf").unwrap();
    assert!(bundle.get_typed::<ObservedData>(&od_id).is_some());
}

interop_test!("REQ-3.17-EX-4.1", "use_cases::sighting::examples::sighting_with_observed_data", sighting_with_observed_data, { assert_sighting_with_observed_data(); });
