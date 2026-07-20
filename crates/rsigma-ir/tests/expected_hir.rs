//! Expected HIR shapes for Phase 0.0 (fixtures-first).
//!
//! These hand-built [`IrCondition`] / metadata stubs are the contract that
//! Phase 0.2 `lower_rule` must satisfy. Match oracles live in the sibling
//! test binaries; this file freezes the *structural* IR expectation.
//!
//! Parity tests that call [`rsigma_ir::lower::lower_rule`] are `#[ignore]`
//! until Phase 0.2 implements lowering. Un-ignore them when wiring 0.2.

mod common;

use common::rule_from;
use rsigma_ir::lower::{lower_rule, LowerOptions};
use rsigma_ir::{IrCondition, IrRuleMetadata};

/// Vacuous `all of selection_*` with zero matching detection names → empty And.
pub fn expected_vacuous_all_of_conditions() -> Vec<IrCondition> {
    vec![IrCondition::And(vec![])]
}

/// `1 of them` over `selection` + `_internal` → only `selection`.
pub fn expected_them_skip_underscore_conditions() -> Vec<IrCondition> {
    vec![IrCondition::Or(vec![IrCondition::Detection(
        "selection".into(),
    )])]
}

/// `all of them` over `selection` + `_internal` → And over non-`_` names only.
pub fn expected_all_of_them_skip_underscore_conditions() -> Vec<IrCondition> {
    vec![IrCondition::And(vec![IrCondition::Detection(
        "selection".into(),
    )])]
}

/// `1 of _*` over `selection_main` + `_internal` → only `_internal`.
pub fn expected_glob_underscore_conditions() -> Vec<IrCondition> {
    vec![IrCondition::Or(vec![IrCondition::Detection(
        "_internal".into(),
    )])]
}

/// `all of selection_a* and all of selection_b*` with zero matches each.
pub fn expected_vacuous_all_of_multiple_conditions() -> Vec<IrCondition> {
    vec![IrCondition::And(vec![
        IrCondition::And(vec![]),
        IrCondition::And(vec![]),
    ])]
}

#[test]
fn expected_hir_stubs_are_well_formed() {
    // Construction itself is the Phase 0.0 deliverable: these shapes must
    // compile and stay stable as the lowering contract.
    assert_eq!(
        expected_vacuous_all_of_conditions(),
        vec![IrCondition::And(vec![])]
    );
    assert_eq!(
        expected_them_skip_underscore_conditions(),
        vec![IrCondition::Or(vec![IrCondition::Detection(
            "selection".into()
        )])]
    );
    assert_eq!(
        expected_all_of_them_skip_underscore_conditions(),
        vec![IrCondition::And(vec![IrCondition::Detection(
            "selection".into()
        )])]
    );
    assert_eq!(
        expected_glob_underscore_conditions(),
        vec![IrCondition::Or(vec![IrCondition::Detection(
            "_internal".into()
        )])]
    );
    assert_eq!(
        expected_vacuous_all_of_multiple_conditions(),
        vec![IrCondition::And(vec![
            IrCondition::And(vec![]),
            IrCondition::And(vec![]),
        ])]
    );

    let meta = IrRuleMetadata {
        title: "stub".into(),
        ..IrRuleMetadata::default()
    };
    assert_eq!(meta.title, "stub");
}

// =============================================================================
// Phase 0.2 parity (ignored until lower_rule is implemented)
// =============================================================================

#[test]
#[ignore = "phase 0.2: enable when lower_rule collapses selectors"]
fn lower_vacuous_all_of_matches_expected_hir() {
    let rule = rule_from(
        r#"
title: Vacuous All Of Zero
logsource: { category: test }
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: all of selection_*
"#,
    );
    let ir = lower_rule(&rule, &LowerOptions::default()).expect("lower");
    assert_eq!(ir.conditions, expected_vacuous_all_of_conditions());
    assert_eq!(ir.metadata.title, "Vacuous All Of Zero");
}

#[test]
#[ignore = "phase 0.2: enable when lower_rule collapses selectors"]
fn lower_them_skip_underscore_matches_expected_hir() {
    let rule = rule_from(
        r#"
title: Them Skip Prefix
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of them
"#,
    );
    let ir = lower_rule(&rule, &LowerOptions::default()).expect("lower");
    assert_eq!(ir.conditions, expected_them_skip_underscore_conditions());
}

#[test]
#[ignore = "phase 0.2: enable when lower_rule collapses selectors"]
fn lower_all_of_them_skip_underscore_matches_expected_hir() {
    let rule = rule_from(
        r#"
title: Them All Skip
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: all of them
"#,
    );
    let ir = lower_rule(&rule, &LowerOptions::default()).expect("lower");
    assert_eq!(
        ir.conditions,
        expected_all_of_them_skip_underscore_conditions()
    );
}

#[test]
#[ignore = "phase 0.2: enable when lower_rule collapses selectors"]
fn lower_glob_underscore_matches_expected_hir() {
    let rule = rule_from(
        r#"
title: Glob Matches Underscore
logsource: { category: test }
detection:
    selection_main:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of _*
"#,
    );
    let ir = lower_rule(&rule, &LowerOptions::default()).expect("lower");
    assert_eq!(ir.conditions, expected_glob_underscore_conditions());
}

#[test]
#[ignore = "phase 0.2: enable when lower_rule collapses selectors"]
fn lower_vacuous_all_of_multiple_matches_expected_hir() {
    let rule = rule_from(
        r#"
title: Vacuous All Of Multiple
logsource: { category: test }
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: all of selection_a* and all of selection_b*
"#,
    );
    let ir = lower_rule(&rule, &LowerOptions::default()).expect("lower");
    assert_eq!(ir.conditions, expected_vacuous_all_of_multiple_conditions());
}
