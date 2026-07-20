//! Behavior-driving `rsigma.*` custom-attribute fixtures.
//!
//! These keys must survive into `IrRuleMetadata.custom_attributes` once
//! lowering exists; today we lock the legacy compile/evaluate behavior.

mod common;

use common::{engine_from, titles_for};
use rsigma_eval::JsonEvent;
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

#[test]
fn include_event_true_attaches_event_json() {
    let engine = engine_from(
        r#"
title: Include Event
logsource: { category: test }
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
custom_attributes:
    rsigma.include_event: "true"
"#,
    );
    let results = engine.evaluate(&JsonEvent::borrow(&json!({"Image": "cmd.exe"})));
    assert_eq!(
        titles_for(&engine, &json!({"Image": "cmd.exe"})),
        vec!["Include Event".to_string()]
    );
    let event = results[0]
        .as_detection()
        .expect("detection body")
        .event
        .as_ref()
        .expect("rsigma.include_event=true must attach the event");
    assert_eq!(event.get("Image").and_then(|v| v.as_str()), Some("cmd.exe"));
}

#[test]
fn include_event_false_omits_event_json() {
    let engine = engine_from(
        r#"
title: No Include
logsource: { category: test }
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
custom_attributes:
    rsigma.include_event: "false"
"#,
    );
    let results = engine.evaluate(&JsonEvent::borrow(&json!({"Image": "cmd.exe"})));
    assert!(
        results[0]
            .as_detection()
            .map(|d| d.event.is_none())
            .unwrap_or(true),
        "rsigma.include_event=false must omit the event"
    );
}

#[test]
fn top_level_rsigma_include_event_is_honored() {
    // Flat top-level keys merge into custom_attributes the same way.
    let engine = engine_from(
        r#"
title: Top Level Include
logsource: { category: test }
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
rsigma.include_event: "true"
"#,
    );
    let results = engine.evaluate(&JsonEvent::borrow(&json!({"Image": "cmd.exe"})));
    assert!(
        results[0]
            .as_detection()
            .expect("detection body")
            .event
            .is_some()
    );
}

#[test]
fn other_rsigma_keys_parse_and_compile() {
    let yaml = r#"
title: Rsigma Keys
logsource: { category: test }
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
custom_attributes:
    rsigma.suppress: "true"
    rsigma.timestamp_field: "TimeGenerated"
    rsigma.action: "flag"
    rsigma.correlation_event_mode: "all"
    rsigma.max_entries: "1000"
"#;
    let collection = parse_sigma_yaml(yaml).expect("parse");
    let rule = collection.rules.first().expect("one rule");
    for key in [
        "rsigma.suppress",
        "rsigma.timestamp_field",
        "rsigma.action",
        "rsigma.correlation_event_mode",
        "rsigma.max_entries",
    ] {
        assert!(
            rule.custom_attributes.contains_key(key),
            "missing custom attribute {key}"
        );
    }
    let mut engine = rsigma_eval::Engine::new();
    engine
        .add_collection(&collection)
        .expect("rsigma.* keys must not break compile");
}

#[test]
fn non_rsigma_custom_attributes_survive_parse() {
    let collection = parse_sigma_yaml(
        r#"
title: Custom Attrs
logsource: { category: test }
detection:
    selection:
        Image: 'evil.exe'
    condition: selection
custom_attributes:
    foo.bar: "baz"
    my_key: 123
"#,
    )
    .expect("parse");
    let rule = collection.rules.first().expect("one rule");
    assert!(rule.custom_attributes.contains_key("foo.bar"));
    assert!(rule.custom_attributes.contains_key("my_key"));
}
