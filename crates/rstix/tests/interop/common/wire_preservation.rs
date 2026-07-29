//! Wire → parse field preservation for §2.3 P-03 / C-05.

use rstix::core::StixId;
use rstix::model::Bundle;
use serde_json::Value;

use crate::harness::containment::assert_json_contains;

const SKIP_WIRE_COMPARE: &[&str] = &["spec_version"];

fn wire_value_meaningful(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

/// Assert parsed serialization contains every meaningful wire property (no silent field drop).
pub fn assert_wire_object_preserved(
    relative: &str,
    wire: &Value,
    bundle: &Bundle,
    object_id: &str,
) {
    let stix_id = StixId::parse(object_id)
        .unwrap_or_else(|err| panic!("{relative}: invalid object id {object_id}: {err}"));
    let parsed = bundle
        .get(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: object {object_id} must parse"));
    let actual = serde_json::to_value(parsed).expect("serialize parsed object");

    let Some(wire_map) = wire.as_object() else {
        panic!("{relative}: wire object {object_id} must be a JSON object");
    };
    let mut expected = serde_json::Map::new();
    for (key, value) in wire_map {
        if SKIP_WIRE_COMPARE.contains(&key.as_str()) || !wire_value_meaningful(value) {
            continue;
        }
        expected.insert(key.clone(), value.clone());
    }
    if expected.is_empty() {
        return;
    }
    assert_json_contains(
        &actual,
        &Value::Object(expected),
        &format!("{relative}:{object_id}"),
    );
}

/// Assert Identity fields referenced by §2.3.4 are preserved on parse.
pub fn assert_identity_fields_preserved(
    relative: &str,
    wire: &Value,
    bundle: &Bundle,
    identity_id: &str,
) {
    assert_wire_object_preserved(relative, wire, bundle, identity_id);
    for key in ["name", "identity_class"] {
        let wire_value = wire.get(key).unwrap_or_else(|| {
            panic!("{relative}: identity {identity_id} missing wire field {key}")
        });
        let stix_id = StixId::parse(identity_id).expect("identity id");
        let parsed = bundle
            .get(&stix_id)
            .unwrap_or_else(|| panic!("{relative}: identity {identity_id} must parse"));
        let actual = serde_json::to_value(parsed).expect("serialize identity");
        assert_eq!(
            actual.get(key),
            Some(wire_value),
            "{relative}: identity field {key} mismatch"
        );
    }
}
