//! §3.4.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{CourseOfAction, Indicator};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.4.4.1 non-normative example.
pub const EXAMPLE_MITIGATES_INDICATOR: &str =
    "examples/course-of-action/ex-3.4.4.1-coa-mitigates-indicator.json";

/// REQ-3.4-EX-4.1 — §3.4.4.1 loads and passes the interop gate; COA `mitigates` Indicator.
pub fn assert_coa_mitigates_indicator() {
    let fixture = load_fixture(EXAMPLE_MITIGATES_INDICATOR);
    assert_eq!(fixture.provenance.source_section, "3.4.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.4.4.1 example must parse and pass interop gate");

    let coa_id =
        StixId::parse("course-of-action--17ce1618-0aab-4366-a93a-9d290282995e").expect("coa id");
    let course_of_action = bundle
        .get_typed::<CourseOfAction>(&coa_id)
        .expect("Add TCP port 80 Filter Rule Course of Action");
    assert_eq!(
        course_of_action.name,
        "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter"
    );

    let indicator_id =
        StixId::parse("indicator--bc7a2301-d711-465d-a8bf-97d50e1cb68f").expect("indicator id");
    assert!(bundle.get_typed::<Indicator>(&indicator_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "mitigates");
    assert_eq!(relationships[0].source_ref, coa_id);
    assert_eq!(relationships[0].target_ref, indicator_id);
}

interop_test!(
    "REQ-3.4-EX-4.1",
    "use_cases::course_of_action::examples::coa_mitigates_indicator",
    coa_mitigates_indicator,
    {
        assert_coa_mitigates_indicator();
    }
);
