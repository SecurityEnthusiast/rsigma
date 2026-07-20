//! Pure-data optimization passes over an [`IrRule`].
//!
//! Every pass here is a total function on the HIR that preserves match
//! semantics: the set of events a rule matches, and the detection names it
//! reports as matched, are identical before and after. The passes are **opt-in**
//! and are deliberately not run by the default eval or convert paths, so
//! compiled-matcher behavior and byte-identical backend output stay unchanged.
//! They exist for offline tooling (pack building, analysis) that wants a smaller
//! or normalized rule.
//!
//! Three passes ship:
//!
//! - [`flatten_condition`] normalizes a condition tree: nested same-kind boolean
//!   groups are merged, `Not(Not(x))` collapses to `x`, single-child `And`/`Or`
//!   groups unwrap, and idempotent duplicate siblings are dropped.
//! - [`eliminate_dead_detections`] removes detections that no condition can
//!   reference, accounting for `them`/glob selector patterns, and recurses into
//!   `Conditional` bodies.
//! - [`common_subexpressions`] is a non-mutating analysis that reports detection
//!   items appearing more than once, the candidates a consumer could evaluate
//!   once and share.
//!
//! [`optimize_rule`] applies the two structural passes in order.

use std::collections::HashSet;

use rsigma_parser::SelectorPattern;

use crate::hir::{IrCondition, IrDetection, IrDetectionItem, IrRule};

/// Apply every semantics-preserving structural pass to a rule, in order:
/// condition flattening, then dead-detection elimination.
pub fn optimize_rule(mut rule: IrRule) -> IrRule {
    rule.conditions = rule.conditions.into_iter().map(flatten_condition).collect();
    eliminate_dead_detections(&mut rule);
    rule
}

// =============================================================================
// Condition flattening
// =============================================================================

/// Normalize a condition tree without changing the boolean it computes.
///
/// - `And`/`Or` children are recursively flattened; a nested group of the same
///   kind is merged into its parent (`a AND (b AND c)` -> `a AND b AND c`).
/// - Idempotent duplicate siblings are removed (`a AND a` -> `a`).
/// - A single-child `And`/`Or` unwraps to that child.
/// - `Not(Not(x))` collapses to `x`.
///
/// `Detection` and `Selector` leaves are returned unchanged.
pub fn flatten_condition(cond: IrCondition) -> IrCondition {
    match cond {
        IrCondition::And(children) => flatten_bool(children, true),
        IrCondition::Or(children) => flatten_bool(children, false),
        IrCondition::Not(inner) => match flatten_condition(*inner) {
            IrCondition::Not(doubly) => *doubly,
            other => IrCondition::Not(Box::new(other)),
        },
        leaf @ (IrCondition::Detection(_) | IrCondition::Selector { .. }) => leaf,
    }
}

fn flatten_bool(children: Vec<IrCondition>, is_and: bool) -> IrCondition {
    let mut flat: Vec<IrCondition> = Vec::with_capacity(children.len());
    for child in children {
        match flatten_condition(child) {
            IrCondition::And(inner) if is_and => flat.extend(inner),
            IrCondition::Or(inner) if !is_and => flat.extend(inner),
            other => flat.push(other),
        }
    }

    // Drop idempotent duplicates while preserving first-seen order.
    let mut deduped: Vec<IrCondition> = Vec::with_capacity(flat.len());
    for c in flat {
        if !deduped.contains(&c) {
            deduped.push(c);
        }
    }

    if deduped.len() == 1 {
        return deduped.into_iter().next().unwrap();
    }
    if is_and {
        IrCondition::And(deduped)
    } else {
        IrCondition::Or(deduped)
    }
}

// =============================================================================
// Dead-detection elimination
// =============================================================================

/// Remove detections that no condition can reference.
///
/// A detection is live if some condition names it directly or a selector
/// pattern (`them`, `selection_*`, ...) matches its name. Dead detections never
/// contribute to a match decision or the reported matched-selection set, so
/// dropping them is semantics-preserving. `Conditional` bodies are pruned
/// against their own inner condition recursively.
pub fn eliminate_dead_detections(rule: &mut IrRule) {
    prune_named(&mut rule.detections, &rule.conditions);
    for det in rule.detections.values_mut() {
        prune_detection_tree(det);
    }
}

fn prune_named(
    named: &mut std::collections::HashMap<String, IrDetection>,
    conditions: &[IrCondition],
) {
    let names: Vec<String> = named.keys().cloned().collect();
    let mut live: HashSet<String> = HashSet::new();
    for cond in conditions {
        collect_referenced(cond, &names, &mut live);
    }
    named.retain(|name, _| live.contains(name));
}

fn collect_referenced(cond: &IrCondition, names: &[String], out: &mut HashSet<String>) {
    match cond {
        IrCondition::Detection(name) => {
            out.insert(name.clone());
        }
        IrCondition::And(children) | IrCondition::Or(children) => {
            for c in children {
                collect_referenced(c, names, out);
            }
        }
        IrCondition::Not(inner) => collect_referenced(inner, names, out),
        IrCondition::Selector { pattern, .. } => {
            for name in names {
                if selector_matches(pattern, name) {
                    out.insert(name.clone());
                }
            }
        }
    }
}

fn selector_matches(pattern: &SelectorPattern, name: &str) -> bool {
    pattern.matches_detection_name(name)
}

/// Recurse into nested `Conditional` bodies, pruning each against its own
/// condition, and walk the other container shapes to reach them.
fn prune_detection_tree(det: &mut IrDetection) {
    match det {
        IrDetection::Conditional { named, condition } => {
            prune_named(named, std::slice::from_ref(condition));
            for inner in named.values_mut() {
                prune_detection_tree(inner);
            }
        }
        IrDetection::AnyOf(children) | IrDetection::And(children) => {
            for child in children {
                prune_detection_tree(child);
            }
        }
        IrDetection::ArrayMatch { body, .. } => prune_detection_tree(body),
        IrDetection::AllOf(_) | IrDetection::Keywords(_) => {}
    }
}

// =============================================================================
// Common-subexpression analysis
// =============================================================================

/// A detection item that appears more than once across a rule's detections.
#[derive(Debug, Clone, PartialEq)]
pub struct RepeatedItem {
    pub item: IrDetectionItem,
    pub count: usize,
}

/// The result of the common-subexpression analysis.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CseReport {
    /// Detection items occurring at least twice, in first-seen order.
    pub repeated_items: Vec<RepeatedItem>,
}

/// Report detection items that occur more than once across all of a rule's
/// detections (including nested `AnyOf`/`And`/`ArrayMatch`/`Conditional`
/// bodies). Non-mutating: a consumer decides whether to share the evaluation.
///
/// `IrDetectionItem` carries an `f64` (via `IrNumber`) and so is not `Hash`;
/// counting is by structural equality, which is adequate for rule-sized inputs.
pub fn common_subexpressions(rule: &IrRule) -> CseReport {
    let mut items: Vec<&IrDetectionItem> = Vec::new();
    for det in rule.detections.values() {
        collect_items(det, &mut items);
    }

    let mut counts: Vec<(IrDetectionItem, usize)> = Vec::new();
    for it in items {
        if let Some(entry) = counts.iter_mut().find(|(existing, _)| existing == it) {
            entry.1 += 1;
        } else {
            counts.push((it.clone(), 1));
        }
    }

    let repeated_items = counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(item, count)| RepeatedItem { item, count })
        .collect();

    CseReport { repeated_items }
}

fn collect_items<'a>(det: &'a IrDetection, out: &mut Vec<&'a IrDetectionItem>) {
    match det {
        IrDetection::AllOf(items) => out.extend(items.iter()),
        IrDetection::AnyOf(children) | IrDetection::And(children) => {
            for child in children {
                collect_items(child, out);
            }
        }
        IrDetection::ArrayMatch { body, .. } => collect_items(body, out),
        IrDetection::Conditional { named, .. } => {
            for inner in named.values() {
                collect_items(inner, out);
            }
        }
        IrDetection::Keywords(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rsigma_parser::{LogSource, Quantifier, SelectorPattern};

    use super::*;
    use crate::hir::{IrMatcher, IrPattern, IrPatternPart, IrRuleMetadata, IrStrOp};

    fn cond_det(name: &str) -> IrCondition {
        IrCondition::Detection(name.to_string())
    }

    fn str_item(field: &str, literal: &str) -> IrDetectionItem {
        IrDetectionItem {
            field: Some(field.to_string()),
            matcher: IrMatcher::Str {
                op: IrStrOp::Exact,
                pattern: IrPattern {
                    parts: vec![IrPatternPart::Literal(literal.to_string())],
                },
                case_insensitive: true,
            },
            exists: None,
        }
    }

    fn rule(detections: HashMap<String, IrDetection>, conditions: Vec<IrCondition>) -> IrRule {
        IrRule {
            metadata: IrRuleMetadata::default(),
            logsource: LogSource::default(),
            sigma_version: None,
            detections,
            conditions,
        }
    }

    #[test]
    fn flatten_merges_nested_same_kind() {
        let cond = IrCondition::And(vec![
            cond_det("a"),
            IrCondition::And(vec![cond_det("b"), cond_det("c")]),
        ]);
        assert_eq!(
            flatten_condition(cond),
            IrCondition::And(vec![cond_det("a"), cond_det("b"), cond_det("c")])
        );
    }

    #[test]
    fn flatten_dedups_idempotent_siblings() {
        let cond = IrCondition::Or(vec![cond_det("a"), cond_det("a"), cond_det("b")]);
        assert_eq!(
            flatten_condition(cond),
            IrCondition::Or(vec![cond_det("a"), cond_det("b")])
        );
    }

    #[test]
    fn flatten_unwraps_singletons_and_double_not() {
        assert_eq!(
            flatten_condition(IrCondition::And(vec![cond_det("only")])),
            cond_det("only")
        );
        assert_eq!(
            flatten_condition(IrCondition::Not(Box::new(IrCondition::Not(Box::new(
                cond_det("x")
            ))))),
            cond_det("x")
        );
    }

    #[test]
    fn flatten_preserves_selector_leaves() {
        let cond = IrCondition::Selector {
            quantifier: Quantifier::All,
            pattern: SelectorPattern::Them,
        };
        assert_eq!(flatten_condition(cond.clone()), cond);
    }

    #[test]
    fn dead_elimination_drops_unreferenced() {
        let mut detections = HashMap::new();
        detections.insert(
            "used".to_string(),
            IrDetection::AllOf(vec![str_item("a", "x")]),
        );
        detections.insert(
            "orphan".to_string(),
            IrDetection::AllOf(vec![str_item("b", "y")]),
        );
        let mut r = rule(detections, vec![cond_det("used")]);
        eliminate_dead_detections(&mut r);
        assert!(r.detections.contains_key("used"));
        assert!(!r.detections.contains_key("orphan"));
    }

    #[test]
    fn dead_elimination_keeps_selector_matched() {
        let mut detections = HashMap::new();
        detections.insert(
            "selection_a".to_string(),
            IrDetection::AllOf(vec![str_item("a", "x")]),
        );
        detections.insert(
            "_internal".to_string(),
            IrDetection::AllOf(vec![str_item("b", "y")]),
        );
        // `them` matches selection_a but skips the `_`-prefixed name.
        let mut r = rule(
            detections,
            vec![IrCondition::Selector {
                quantifier: Quantifier::All,
                pattern: SelectorPattern::Them,
            }],
        );
        eliminate_dead_detections(&mut r);
        assert!(r.detections.contains_key("selection_a"));
        assert!(!r.detections.contains_key("_internal"));
    }

    #[test]
    fn cse_reports_repeated_items() {
        let mut detections = HashMap::new();
        detections.insert(
            "sel1".to_string(),
            IrDetection::AllOf(vec![str_item("Image", "\\cmd.exe")]),
        );
        detections.insert(
            "sel2".to_string(),
            IrDetection::AllOf(vec![str_item("Image", "\\cmd.exe")]),
        );
        let r = rule(
            detections,
            vec![IrCondition::Or(vec![cond_det("sel1"), cond_det("sel2")])],
        );
        let report = common_subexpressions(&r);
        assert_eq!(report.repeated_items.len(), 1);
        assert_eq!(report.repeated_items[0].count, 2);
        assert_eq!(
            report.repeated_items[0].item,
            str_item("Image", "\\cmd.exe")
        );
    }
}
