//! Subset / containment assertions (REQ-2.3-P-03).

use serde_json::Value;

/// Assert that `actual` contains at least every key/value from `expected`.
///
/// Additional properties in `actual` are permitted per §2.3.3 Producer MAY rules.
pub fn assert_json_contains(actual: &Value, expected: &Value, path: &str) {
    match (actual, expected) {
        (Value::Object(actual_map), Value::Object(expected_map)) => {
            for (key, expected_child) in expected_map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let actual_child = actual_map.get(key).unwrap_or_else(|| {
                    panic!("missing key at {child_path}");
                });
                assert_json_contains(actual_child, expected_child, &child_path);
            }
        }
        (Value::Array(actual_items), Value::Array(expected_items)) => {
            assert!(
                actual_items.len() >= expected_items.len(),
                "array at {path} shorter than expected"
            );
            for (idx, expected_child) in expected_items.iter().enumerate() {
                assert_json_contains(
                    &actual_items[idx],
                    expected_child,
                    &format!("{path}[{idx}]"),
                );
            }
        }
        _ => assert_eq!(actual, expected, "value mismatch at {path}"),
    }
}

/// Superset properties pass containment checks (§2.3.3).
pub fn assert_superset_allowed() {
    let expected = serde_json::json!({
        "type": "identity",
        "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "name": "ACME Corp, Inc."
    });
    let actual = serde_json::json!({
        "type": "identity",
        "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "name": "ACME Corp, Inc.",
        "description": "extra property permitted"
    });
    assert_json_contains(&actual, &expected, "root");
}
