//! Relationship object shape checks (REQ-2.3-X-08).

use rstix::model::sro::Relationship;
use serde_json::Value;

use crate::common::fixture_walk::for_each_suite_walk_fixture;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;

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

/// REQ-2.3-X-08 — parsed Relationship objects comply with §5.1 mandatory fields.
pub fn assert_relationship_shape_on_parsed() {
    let mut checked = 0usize;
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate failed: {err}"));
        for relationship in bundle.objects_of_type::<Relationship>() {
            assert!(!relationship.relationship_type.is_empty());
            assert!(!relationship.source_ref.as_str().is_empty());
            assert!(!relationship.target_ref.as_str().is_empty());
            let wire = serde_json::to_value(relationship).expect("serialize relationship");
            assert_relationship_shape(&wire);
            checked += 1;
        }
    });
    assert!(
        checked > 0,
        "expected at least one relationship in normative testcase fixtures"
    );
}
