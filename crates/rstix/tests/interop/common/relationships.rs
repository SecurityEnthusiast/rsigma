//! Relationship object shape checks (REQ-2.3-X-08).

use serde_json::Value;

/// Assert a Relationship object carries the §5.1 fields required by §2.3.6.
pub fn assert_relationship_shape(relationship: &Value) {
    assert_eq!(
        relationship.get("type"),
        Some(&Value::String("relationship".into()))
    );
    assert!(
        relationship.get("relationship_type").is_some(),
        "relationship_type is mandatory"
    );
    assert!(relationship.get("source_ref").is_some());
    assert!(relationship.get("target_ref").is_some());
}

/// Smoke check for §2.3.6 relationship object shape.
pub fn assert_relationship_module_ready() {
    let sample = serde_json::json!({
        "type": "relationship",
        "id": "relationship--bc7677e3-3418-4d3f-87e2-66b4b5b7b9ba",
        "relationship_type": "related-to",
        "source_ref": "malware--11111111-1111-4111-8111-111111111111",
        "target_ref": "indicator--22222222-2222-4222-8222-222222222222"
    });
    assert_relationship_shape(&sample);
}
