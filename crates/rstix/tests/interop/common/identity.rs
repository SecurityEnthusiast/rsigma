//! §2.3.4 Identity property shape checks (REQ-2.3-X-05/06).

use serde_json::Value;

use crate::harness::fixture::interop_fixtures_root;

/// Load the §2.3.4 property-set schema (not a canonical Identity instance).
pub fn load_identity_shape() -> Value {
    let path = interop_fixtures_root().join("common/identity-shape.json");
    let text = std::fs::read_to_string(&path).expect("read identity-shape.json");
    serde_json::from_str(&text).expect("parse identity-shape.json")
}

/// Assert an Identity object carries the §2.3.4 property set.
pub fn assert_identity_shape(identity: &Value) {
    let shape = load_identity_shape();
    let required = shape["required_properties"]
        .as_array()
        .expect("required_properties array");
    for key in required {
        let key = key.as_str().expect("property name");
        assert!(
            identity.get(key).is_some(),
            "identity missing required property {key}"
        );
    }
    assert_eq!(
        identity.get("type"),
        Some(&Value::String("identity".into()))
    );
    assert_eq!(
        identity.get("identity_class"),
        Some(&Value::String("organization".into()))
    );
    assert_eq!(
        identity.get("spec_version"),
        Some(&Value::String("2.1".into()))
    );

    if let (Some(id), Some(created_by_ref)) = (
        identity.get("id").and_then(Value::as_str),
        identity.get("created_by_ref").and_then(Value::as_str),
    ) {
        assert_eq!(
            id, created_by_ref,
            "identity created_by_ref must self-reference per §2.3.4"
        );
    }
}

/// Smoke-check the identity shape fixture and §2.3.4 property rules on a sample Identity.
pub fn assert_identity_shape_fixture_valid() {
    let shape = load_identity_shape();
    assert!(shape.get("required_properties").is_some());

    let sample = serde_json::json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2020-01-20T12:34:56.000Z",
        "modified": "2020-01-20T12:34:56.000Z",
        "name": "ACME Corp, Inc.",
        "identity_class": "organization",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    });
    assert_identity_shape(&sample);
}
