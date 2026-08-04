//! §3.3.1 Description — Confidence Sharing scope.

use rstix::core::{Confidence, StixId};
use rstix::model::sdo::Indicator;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::confidence::FIXTURE_CREATE;

/// REQ-3.3-1 — §3.3.1 Description.
///
/// Doc: confidence is a common property (0–100 integer), not a standalone SDO. This check
/// binds that description to normative §3.3.3.1: a typed Indicator carrying `confidence: 85`
/// on the external-validation testcase — not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.3.3.1 must parse for description-scope check");
    let indicator_id =
        StixId::parse("indicator--76fa276c-1984-4bb1-938f-7834a6b30090").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("Benign site Indicator must be typed");
    assert_eq!(indicator.name.as_deref(), Some("Benign site"));
    let confidence = indicator
        .common
        .confidence
        .expect("§3.3.3.1 must carry confidence on the Indicator");
    assert_eq!(confidence, Confidence::new(85).expect("valid confidence"));
}

interop_test!(
    "REQ-3.3-1",
    "use_cases::confidence::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
