//! Expected HIR shapes for selector lowering and metadata projection.
//!
//! Lowering keeps quantified selectors intact (as [`IrCondition::Selector`]) so
//! eval evaluates them natively; this file freezes that structural expectation.

mod common;

use common::rule_from;
use rsigma_ir::lower::{LowerOptions, lower_rule};
use rsigma_ir::{IrCondition, IrRuleMetadata};
use rsigma_parser::{Quantifier, SelectorPattern};

fn selector(quantifier: Quantifier, pattern: SelectorPattern) -> IrCondition {
    IrCondition::Selector {
        quantifier,
        pattern,
    }
}

#[test]
fn expected_hir_stubs_are_well_formed() {
    let meta = IrRuleMetadata {
        title: "stub".into(),
        ..IrRuleMetadata::default()
    };
    assert_eq!(meta.title, "stub");
}

// =============================================================================
// lower_rule selector-preservation parity
// =============================================================================

#[test]
fn lower_vacuous_all_of_preserves_selector() {
    // `all of selection_*` with zero matching names stays a selector; eval
    // resolves the empty set to vacuous truth at match time.
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
    assert_eq!(
        ir.conditions,
        vec![selector(
            Quantifier::All,
            SelectorPattern::Pattern("selection_*".into())
        )]
    );
    assert_eq!(ir.metadata.title, "Vacuous All Of Zero");
}

#[test]
fn lower_them_preserves_selector() {
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
    assert_eq!(
        ir.conditions,
        vec![selector(Quantifier::Any, SelectorPattern::Them)]
    );
}

#[test]
fn lower_all_of_them_preserves_selector() {
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
        vec![selector(Quantifier::All, SelectorPattern::Them)]
    );
}

#[test]
fn lower_glob_underscore_preserves_selector() {
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
    assert_eq!(
        ir.conditions,
        vec![selector(
            Quantifier::Any,
            SelectorPattern::Pattern("_*".into())
        )]
    );
}

#[test]
fn lower_multiple_selectors_under_and() {
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
    assert_eq!(
        ir.conditions,
        vec![IrCondition::And(vec![
            selector(
                Quantifier::All,
                SelectorPattern::Pattern("selection_a*".into())
            ),
            selector(
                Quantifier::All,
                SelectorPattern::Pattern("selection_b*".into())
            ),
        ])]
    );
}

#[test]
fn lower_count_selector_preserved_not_expanded() {
    // `2 of selection_*` must not expand combinatorially; it stays a selector.
    let rule = rule_from(
        r#"
title: Count Of
logsource: { category: test }
detection:
    selection_a:
        Image: 'a.exe'
    selection_b:
        Image: 'b.exe'
    selection_c:
        Image: 'c.exe'
    condition: 2 of selection_*
"#,
    );
    let ir = lower_rule(&rule, &LowerOptions::default()).expect("lower");
    assert_eq!(
        ir.conditions,
        vec![selector(
            Quantifier::Count(2),
            SelectorPattern::Pattern("selection_*".into())
        )]
    );
}
