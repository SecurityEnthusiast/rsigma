//! §2.3 Producer cross-cutting checks (REQ-2.3-P-01..P-03).

use crate::harness::containment::assert_json_contains;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use rstix::core::StixId;

const ATTACK_PATTERN_ID: &str = "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061";
const OASIS_ATTACK_PATTERN_FIXTURE: &str =
    "testcases/attack-pattern/tc-3.1.3.1-create-attack-pattern.json";

fn attack_pattern_gate_opts() -> InteropGateOptions {
    InteropGateOptions {
        use_case_object_ids: vec![ATTACK_PATTERN_ID.into()],
    }
}

/// Cross-check `tests/fixtures/conformance/valid/` under the interop gate (§12.1 delegate).
pub fn assert_producer_conformance_12_1() {
    crate::harness::interop_gate::assert_conformance_valid_corpus_passes_interop_gate()
        .expect("conformance valid corpus must pass interop gate");
}

/// Interop gate rejects spec-minimal attack-pattern when use-case rules apply; accepts interop-ok.
pub fn assert_interop_stricter_than_spec() {
    let spec_fixture = load_fixture("testcases/common/tc-attack-pattern-spec-minimal.json");
    assert!(
        validate_interop_json(&spec_fixture.json, &attack_pattern_gate_opts()).is_err(),
        "spec-minimal attack-pattern must fail interop use-case rules"
    );

    let ok_fixture = load_fixture(OASIS_ATTACK_PATTERN_FIXTURE);
    validate_interop_json(&ok_fixture.json, &attack_pattern_gate_opts())
        .expect("OASIS §3.1.3.1 attack-pattern must pass interop gate");
}

/// Subset/containment on a parsed object (§2.3.3 MAY — additional properties permitted).
pub fn assert_additional_properties_permitted() {
    let fixture = load_fixture(OASIS_ATTACK_PATTERN_FIXTURE);
    let bundle = validate_interop_json(&fixture.json, &attack_pattern_gate_opts())
        .expect("interop gate must parse attack-pattern bundle");
    let ap_id = StixId::parse(ATTACK_PATTERN_ID).expect("attack-pattern id");
    let ap = bundle.get(&ap_id).expect("attack-pattern object");
    let actual = serde_json::to_value(ap).expect("serialize parsed object");
    let expected = serde_json::json!({
        "type": "attack-pattern",
        "name": "Spear Phishing"
    });
    assert_json_contains(&actual, &expected, "attack-pattern");
}
