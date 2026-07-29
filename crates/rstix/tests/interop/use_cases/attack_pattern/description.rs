//! §3.1.1 Description — Attack Pattern Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::AttackPattern;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::attack_pattern::{FIXTURE_CREATE, FIXTURE_TARGETS};

/// REQ-3.1-1 — §3.1.1 Description.
///
/// Doc: Attack Patterns are TTPs that describe ways adversaries attempt to compromise targets;
/// spear phishing is the running example. This check binds that description to normative
/// §3.1.3 Producer fixtures: typed Attack Pattern SDOs with identifying names (including the
/// doc’s “Spear Phishing” example), not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let create = load_fixture(FIXTURE_CREATE);
    let create_bundle = validate_interop_fixture(FIXTURE_CREATE, &create.json)
        .expect("§3.1.3.1 must parse for description-scope check");
    let spear_id =
        StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").expect("ap id");
    let spear = create_bundle
        .get_typed::<AttackPattern>(&spear_id)
        .expect("Spear Phishing Attack Pattern must be typed");
    assert_eq!(
        spear.name, "Spear Phishing",
        "§3.1.1 description example name must be present on normative fixture"
    );
    assert!(
        !spear.common.external_references.is_empty(),
        "Attack Pattern TTP context includes external_references in normative data"
    );

    let targets = load_fixture(FIXTURE_TARGETS);
    let targets_bundle = validate_interop_fixture(FIXTURE_TARGETS, &targets.json)
        .expect("§3.1.3.2 must parse for description-scope check");
    assert_eq!(
        targets_bundle.objects_of_type::<AttackPattern>().count(),
        1,
        "§3.1.3.2 must carry an Attack Pattern SDO as described in §3.1.1"
    );
}

interop_test!(
    "REQ-3.1-1",
    "use_cases::attack_pattern::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
