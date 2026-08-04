//! §3.15.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::Opinion;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_EXPLANATION: &str =
    "examples/opinion/ex-3.15.4.1-opinion-with-explanation-and-authors.json";

pub fn assert_opinion_with_explanation() {
    let fixture = load_fixture(EXAMPLE_EXPLANATION);
    assert_eq!(fixture.provenance.source_section, "3.15.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap();
    let id = StixId::parse("opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7").unwrap();
    let opinion = bundle.get_typed::<Opinion>(&id).unwrap();
    assert_eq!(opinion.opinion.as_str(), "strongly-disagree");
    assert!(opinion.explanation.as_ref().unwrap().contains("PandaCat"));
    assert_eq!(
        opinion.authors,
        vec!["Alice".to_string(), "Bob".to_string()]
    );
}

interop_test!(
    "REQ-3.15-EX-4.1",
    "use_cases::opinion::examples::opinion_with_explanation",
    opinion_with_explanation,
    {
        assert_opinion_with_explanation();
    }
);
