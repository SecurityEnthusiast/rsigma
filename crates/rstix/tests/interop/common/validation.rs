//! Two-tier validation via the interop gate (REQ-2.3-X-03).

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};

const ATTACK_PATTERN_ID: &str = "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061";

const OASIS_ATTACK_PATTERN_FIXTURE: &str =
    "testcases/attack-pattern/tc-3.1.3.1-create-attack-pattern.json";

/// Referenced identity stays spec-only; interop rules apply only to listed use-case object ids.
pub fn assert_referenced_obj_spec_only() {
    let fixture = load_fixture(OASIS_ATTACK_PATTERN_FIXTURE);

    validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("bundle passes when no use-case interop rules are applied");

    validate_interop_json(
        &fixture.json,
        &InteropGateOptions {
            use_case_object_ids: vec![ATTACK_PATTERN_ID.into()],
        },
    )
    .expect("use-case attack-pattern satisfies interop rules");

    let spec_fixture = load_fixture("testcases/common/tc-attack-pattern-spec-minimal.json");
    assert!(
        validate_interop_json(
            &spec_fixture.json,
            &InteropGateOptions {
                use_case_object_ids: vec![ATTACK_PATTERN_ID.into()],
            },
        )
        .is_err(),
        "spec-minimal use-case object must fail interop tier while referenced identity stays spec-valid"
    );
}
