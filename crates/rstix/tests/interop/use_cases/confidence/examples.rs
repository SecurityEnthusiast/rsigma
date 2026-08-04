//! §3.3.4 Producer Example Data (non-gating).

use rstix::core::{Confidence, StixId};
use rstix::model::meta::LanguageContent;
use rstix::model::sdo::{Indicator, Malware};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_INTERNAL_VALIDATION: &str =
    "examples/confidence/ex-3.3.4.1-confidence-indicator-internal-validation.json";
pub const EXAMPLE_ON_TRANSLATION: &str =
    "examples/confidence/ex-3.3.4.2-confidence-on-translation.json";

/// REQ-3.3-EX-4.1 — §3.3.4.1 loads; Indicator, Relationship, and Malware carry confidence.
pub fn assert_indicator_internal_validation() {
    let fixture = load_fixture(EXAMPLE_INTERNAL_VALIDATION);
    assert_eq!(fixture.provenance.source_section, "3.3.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.3.4.1 example must parse and pass interop gate");

    let indicator_id =
        StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .expect("Poison Ivy Indicator");
    assert_eq!(
        indicator.common.confidence,
        Some(Confidence::new(95).expect("valid confidence"))
    );

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(
        relationships[0].common.confidence,
        Some(Confidence::new(90).expect("valid confidence"))
    );

    let malware_id =
        StixId::parse("malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b").expect("malware id");
    assert!(bundle.get_typed::<Malware>(&malware_id).is_some());
}

/// REQ-3.3-EX-4.2 — §3.3.4.2 loads; Language Content carries translation confidence.
pub fn assert_confidence_on_translation() {
    let fixture = load_fixture(EXAMPLE_ON_TRANSLATION);
    assert_eq!(fixture.provenance.source_section, "3.3.4.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.3.4.2 example must parse and pass interop gate");

    let lc_id =
        StixId::parse("language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d").expect("lc id");
    let lc = bundle
        .get_typed::<LanguageContent>(&lc_id)
        .expect("German translation Language Content");
    assert_eq!(
        lc.common.confidence,
        Some(Confidence::new(100).expect("valid confidence"))
    );
}

interop_test!(
    "REQ-3.3-EX-4.1",
    "use_cases::confidence::examples::indicator_internal_validation",
    indicator_internal_validation,
    {
        assert_indicator_internal_validation();
    }
);

interop_test!(
    "REQ-3.3-EX-4.2",
    "use_cases::confidence::examples::confidence_on_translation",
    confidence_on_translation,
    {
        assert_confidence_on_translation();
    }
);
