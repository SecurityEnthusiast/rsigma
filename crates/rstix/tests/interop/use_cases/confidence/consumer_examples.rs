//! §3.3.7 Consumer Example Data (non-gating).

use rstix::core::{AdmiraltyScale, Confidence, ConfidenceScale, StixId, WepScale};
use rstix::model::sdo::Campaign;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_CONVERT_SCALES: &str =
    "examples/confidence/ex-3.3.7.1-convert-confidence-scales.json";

/// REQ-3.3-EX-7.1 — Consumer maps STIX confidence 70 to Appendix A scales (§3.3.7.1).
pub fn assert_convert_confidence_scales() {
    let fixture = load_fixture(EXAMPLE_CONVERT_SCALES);
    assert_eq!(fixture.provenance.source_section, "3.3.7.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.3.7.1 example must parse and pass interop gate");

    let campaign_id =
        StixId::parse("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").expect("campaign id");
    let campaign = bundle
        .get_typed::<Campaign>(&campaign_id)
        .expect("Green Group Campaign");
    let confidence = campaign
        .common
        .confidence
        .expect("example carries confidence 70");
    assert_eq!(confidence, Confidence::new(70).expect("valid confidence"));

    let admiralty = AdmiraltyScale.from_stix(confidence);
    assert_eq!(
        admiralty, "2",
        "70 maps to Admiralty 2 - Probably True band"
    );

    let wep = WepScale.from_stix(confidence);
    assert_eq!(wep, "Likely", "70 maps to WEP Likely / Probable band");
}

interop_test!(
    "REQ-3.3-EX-7.1",
    "use_cases::confidence::consumer_examples::convert_confidence_scales",
    convert_confidence_scales,
    {
        assert_convert_confidence_scales();
    }
);
