//! Dual-path differential: IR compile vs legacy `compile_rule_legacy`.
//!
//! Asserts match/no-match parity (not `CompiledRule` structural equality).

mod common;

use common::{collection_from, rule_from};
use rsigma_eval::{JsonEvent, compile_rule, compile_rule_legacy, evaluate_rule};
use serde_json::{Value, json};

fn assert_match_parity(yaml: &str, events: &[Value]) {
    let rule = rule_from(yaml);
    let ir = compile_rule(&rule).expect("IR compile");
    let legacy = compile_rule_legacy(&rule).expect("legacy compile");
    for event in events {
        let ir_hit = evaluate_rule(&ir, &JsonEvent::borrow(event)).is_some();
        let legacy_hit = evaluate_rule(&legacy, &JsonEvent::borrow(event)).is_some();
        assert_eq!(
            ir_hit, legacy_hit,
            "match parity failed for event {event}: ir={ir_hit} legacy={legacy_hit}"
        );
    }
}

#[test]
fn differential_baselines() {
    assert_match_parity(
        r#"
title: Simple And
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
        User: 'alice'
    condition: selection
"#,
        &[
            json!({"Image": "notepad.exe", "User": "alice"}),
            json!({"Image": "notepad.exe", "User": "bob"}),
            json!({"Image": "calc.exe", "User": "alice"}),
        ],
    );
}

#[test]
fn differential_vacuous_all_of() {
    assert_match_parity(
        r#"
title: Vacuous All Of Zero
logsource: { category: test }
detection:
    filter_main:
        Image: 'notepad.exe'
    condition: all of selection_*
"#,
        &[
            json!({"Image": "notepad.exe"}),
            json!({"Image": "other.exe"}),
        ],
    );
}

#[test]
fn differential_them_skip_underscore() {
    assert_match_parity(
        r#"
title: Them Skip
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of them
"#,
        &[
            json!({"Image": "notepad.exe"}),
            json!({"Image": "evil.exe"}),
        ],
    );
}

#[test]
fn differential_modifiers_encoding() {
    assert_match_parity(
        r#"
title: Contains
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        &[
            json!({"CommandLine": "cmd /c whoami"}),
            json!({"CommandLine": "cmd /c dir"}),
        ],
    );
}

#[test]
fn differential_cidr() {
    assert_match_parity(
        r#"
title: Cidr
logsource: { category: test }
detection:
    selection:
        DestinationIp|cidr: '192.168.0.0/16'
    condition: selection
"#,
        &[
            json!({"DestinationIp": "192.168.1.10"}),
            json!({"DestinationIp": "10.0.0.1"}),
        ],
    );
}

#[test]
fn differential_keywords() {
    assert_match_parity(
        r#"
title: Keywords
logsource: { category: test }
detection:
    keywords:
        - whoami
        - mimikatz
    condition: keywords
"#,
        &[
            json!({"msg": "user ran whoami"}),
            json!({"msg": "nothing here"}),
        ],
    );
}

#[test]
fn differential_include_event_attr() {
    let yaml = r#"
title: Include Event
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
    condition: selection
rsigma.include_event: "true"
"#;
    let rule = rule_from(yaml);
    let ir = compile_rule(&rule).expect("IR");
    let legacy = compile_rule_legacy(&rule).expect("legacy");
    assert!(ir.include_event);
    assert!(legacy.include_event);
    let event = json!({"Image": "notepad.exe"});
    let ir_res = evaluate_rule(&ir, &JsonEvent::borrow(&event)).expect("ir match");
    let legacy_res = evaluate_rule(&legacy, &JsonEvent::borrow(&event)).expect("legacy match");
    assert!(ir_res.as_detection().unwrap().event.is_some());
    assert!(legacy_res.as_detection().unwrap().event.is_some());
}

#[test]
fn differential_contradictions_both_reject() {
    let yaml = r#"
title: Cidr Contains
logsource: { category: test }
detection:
    selection:
        Address|cidr|contains: "192.168.0.0/16"
    condition: selection
"#;
    let rule = rule_from(yaml);
    assert!(compile_rule(&rule).is_err());
    assert!(compile_rule_legacy(&rule).is_err());
}

#[test]
fn differential_collection_parses() {
    // Smoke: multi-document collection still parses under both paths via Engine.
    let _ = collection_from(
        r#"
title: Login
id: login-rule
logsource: { category: auth }
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
"#,
    );
}
