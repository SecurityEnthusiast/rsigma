//! Array object-scope fixtures (`ArrayMatch`, `Conditional`, heterogeneous And).
//!
//! Requires `sigma-version: 3` so bracket quantifiers are active.

mod common;

use common::{engine_from, matches};
use serde_json::json;

#[test]
fn array_object_scope_any_correlates_same_element() {
    let engine = engine_from(
        r#"
title: Array Any
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [
            {"protocol": "UDP", "ip": "123.1.5.5"},
            {"protocol": "TCP", "ip": "123.1.9.9"}
        ]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [
            {"protocol": "TCP", "ip": "10.0.0.1"},
            {"protocol": "UDP", "ip": "123.1.9.9"}
        ]})
    ));
}

#[test]
fn array_object_scope_all_requires_every_member() {
    let engine = engine_from(
        r#"
title: Array All
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}, {"protocol": "TCP"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}, {"protocol": "UDP"}]})
    ));
    assert!(!matches(&engine, &json!({"connections": []})));
}

#[test]
fn array_object_scope_all_or_empty_matches_empty() {
    let engine = engine_from(
        r#"
title: Array AllOrEmpty
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all_or_empty]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"connections": []})));
    assert!(matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [{"protocol": "UDP"}]})
    ));
}

#[test]
fn array_object_scope_none() {
    let engine = engine_from(
        r#"
title: Array None
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[none]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [{"protocol": "UDP"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}]})
    ));
    // Empty / missing arrays are vacuous `none` (same as AllOrEmpty for emptiness).
    assert!(matches(&engine, &json!({"connections": []})));
    assert!(matches(&engine, &json!({})));
}

#[test]
fn array_conditional_body() {
    let engine = engine_from(
        r#"
title: Array Conditional
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            tcp:
                protocol: 'TCP'
            local:
                ip|startswith: '10.'
            condition: tcp and local
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [
            {"protocol": "UDP", "ip": "10.0.0.1"},
            {"protocol": "TCP", "ip": "10.1.2.3"}
        ]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [
            {"protocol": "TCP", "ip": "192.168.1.1"},
            {"protocol": "UDP", "ip": "10.0.0.1"}
        ]})
    ));
}

#[test]
fn heterogeneous_and_mixes_plain_item_with_array_match() {
    // Mapping that mixes a plain field with an array object-scope block
    // lowers to CompiledDetection::And today; HIR must keep IrDetection::And.
    let engine = engine_from(
        r#"
title: Hetero And
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        Image: 'powershell.exe'
        connections[any]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({
            "Image": "powershell.exe",
            "connections": [{"protocol": "TCP"}]
        })
    ));
    assert!(!matches(
        &engine,
        &json!({
            "Image": "powershell.exe",
            "connections": [{"protocol": "UDP"}]
        })
    ));
    assert!(!matches(
        &engine,
        &json!({
            "Image": "cmd.exe",
            "connections": [{"protocol": "TCP"}]
        })
    ));
}

#[test]
fn allof_and_anyof_plain() {
    let engine = engine_from(
        r#"
title: AllOf Plain
logsource: { category: test }
detection:
    selection:
        Image: 'cmd.exe'
        CommandLine|contains: '/c'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"Image": "cmd.exe", "CommandLine": "/c whoami"})
    ));
    assert!(!matches(
        &engine,
        &json!({"Image": "cmd.exe", "CommandLine": "whoami"})
    ));

    let engine = engine_from(
        r#"
title: AnyOf
logsource: { category: test }
detection:
    selection:
        - Image: 'evil1.exe'
        - Image: 'evil2.exe'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Image": "evil1.exe"})));
    assert!(matches(&engine, &json!({"Image": "evil2.exe"})));
    assert!(!matches(&engine, &json!({"Image": "normal.exe"})));
}
