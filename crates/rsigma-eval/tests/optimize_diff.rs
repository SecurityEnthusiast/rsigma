//! Differential test: `rsigma_ir::optimize_rule` must preserve match semantics.
//!
//! For each rule, we lower to HIR, compile the original and the optimized HIR
//! through `compile_to_compiled`, and assert both agree for every event.
//!
//! The optimizer's contract is the match decision and the *set* of matched
//! selections and fields, not their reported order or multiplicity. Dropping a
//! duplicate condition reference legitimately reports a selection once instead
//! of twice, and pruning a dead detection can reorder a `them`/glob selector's
//! reported names (that order follows `HashMap` iteration and is not a stable
//! eval contract). So we compare a normalized projection: whether the rule
//! matched, plus the sorted, de-duplicated matched-selection and matched-field
//! sets.

use std::collections::BTreeSet;

use rsigma_eval::{JsonEvent, compile_to_compiled, evaluate_rule};
use rsigma_ir::{LowerOptions, lower_rule, optimize_rule};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

/// `(matched, sorted-unique selections, sorted-unique "field=value" pairs)`.
fn projection(result: Option<Value>) -> (bool, BTreeSet<String>, BTreeSet<String>) {
    let Some(v) = result else {
        return (false, BTreeSet::new(), BTreeSet::new());
    };
    let selections = v
        .get("matched_selections")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let fields = v
        .get("matched_fields")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|f| {
                    format!(
                        "{}={}",
                        f.get("field").and_then(Value::as_str).unwrap_or_default(),
                        f.get("value").and_then(Value::as_str).unwrap_or_default()
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    (true, selections, fields)
}

fn assert_parity(yaml: &str, events: &[Value]) {
    let collection = parse_sigma_yaml(yaml).expect("parse");
    let rule = collection.rules.first().expect("one rule");

    let ir = lower_rule(rule, &LowerOptions::default()).expect("lower");
    let compiled_orig = compile_to_compiled(&ir).expect("compile original");
    let optimized = optimize_rule(ir.clone());
    let compiled_opt = compile_to_compiled(&optimized).expect("compile optimized");

    for ev in events {
        let event = JsonEvent::borrow(ev);
        let orig = projection(
            evaluate_rule(&compiled_orig, &event).map(|r| serde_json::to_value(&r).unwrap()),
        );
        let opt = projection(
            evaluate_rule(&compiled_opt, &event).map(|r| serde_json::to_value(&r).unwrap()),
        );
        assert_eq!(orig, opt, "match parity mismatch for event {ev}");
    }
}

#[test]
fn redundant_and_duplicate_condition() {
    let yaml = r#"
title: Redundant condition
logsource: { category: process_creation }
detection:
    selection:
        Image|endswith: '\cmd.exe'
    other:
        CommandLine|contains: 'whoami'
    condition: (selection and selection) and (other or other)
"#;
    assert_parity(
        yaml,
        &[
            json!({"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}),
            json!({"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "dir"}),
            json!({"Image": "notepad.exe", "CommandLine": "whoami"}),
            json!({"Unrelated": "x"}),
        ],
    );
}

#[test]
fn dead_detection_is_dropped() {
    let yaml = r#"
title: Dead detection
logsource: { category: process_creation }
detection:
    selection:
        Image|endswith: '\powershell.exe'
    unused:
        CommandLine|contains: 'never-referenced'
    condition: selection
"#;
    assert_parity(
        yaml,
        &[
            json!({"Image": "C:\\powershell.exe", "CommandLine": "never-referenced"}),
            json!({"Image": "C:\\powershell.exe"}),
            json!({"CommandLine": "never-referenced"}),
        ],
    );
}

#[test]
fn selector_them_skips_underscore_names() {
    let yaml = r#"
title: Them selector with helper
logsource: { category: process_creation }
detection:
    selection_a:
        Image|endswith: '\cmd.exe'
    selection_b:
        User: 'SYSTEM'
    _helper:
        CommandLine|contains: 'ignored'
    condition: all of them
"#;
    assert_parity(
        yaml,
        &[
            json!({"Image": "x\\cmd.exe", "User": "SYSTEM", "CommandLine": "ignored"}),
            json!({"Image": "x\\cmd.exe", "User": "SYSTEM"}),
            json!({"Image": "x\\cmd.exe"}),
            json!({"User": "SYSTEM"}),
        ],
    );
}

#[test]
fn glob_selector_and_count() {
    let yaml = r#"
title: N-of selector
logsource: { category: process_creation }
detection:
    sel_first:
        Image|endswith: '\a.exe'
    sel_second:
        Image|endswith: '\b.exe'
    sel_third:
        Image|endswith: '\c.exe'
    condition: 1 of sel_*
"#;
    assert_parity(
        yaml,
        &[
            json!({"Image": "x\\a.exe"}),
            json!({"Image": "x\\b.exe"}),
            json!({"Image": "x\\z.exe"}),
        ],
    );
}

#[test]
fn keywords_and_unrelated_detection() {
    let yaml = r#"
title: Keywords with dead sibling
logsource: { category: process_creation }
detection:
    keywords:
        - 'mimikatz'
        - 'sekurlsa'
    dead:
        Image|endswith: '\x.exe'
    condition: keywords
"#;
    assert_parity(
        yaml,
        &[
            json!({"CommandLine": "run mimikatz now"}),
            json!({"CommandLine": "sekurlsa::logonpasswords"}),
            json!({"CommandLine": "benign"}),
        ],
    );
}
