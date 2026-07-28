//! §2.3.4 Identity property shape checks (REQ-2.3-X-05/06).
//!
//! The interoperability document uses multiple distinct Identity instances across test cases
//! (STIX 2.1 Interoperability §2.3.4). Assert the §2.3.4 property set on whichever Identity
//! each normative testcase bundle carries — not one shared canonical instance.

use rstix::core::StixId;
use rstix::model::Bundle;
use rstix::model::ParseOptions;
use rstix::model::sdo::Identity;
use serde_json::Value;

use crate::common::fixture_walk::for_each_testcase_fixture;
use crate::harness::fixture::{interop_fixtures_root, load_fixture};

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

/// Millisecond timestamp granularity on parsed Identity (§2.3.4 SHOULD).
pub fn assert_identity_millisecond_timestamps(identity: &Identity) {
    let created = identity.common.created.to_rfc3339();
    let modified = identity.common.modified.to_rfc3339();
    assert!(
        created.contains('.') && created.ends_with('Z'),
        "created must be millisecond RFC 3339: {created}"
    );
    assert!(
        modified.contains('.') && modified.ends_with('Z'),
        "modified must be millisecond RFC 3339: {modified}"
    );
}

fn wire_identity_by_id<'a>(objects: &'a [Value], id: &str) -> Option<&'a Value> {
    objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(id))
}

fn assert_identities_in_fixture(relative: &str, check_timestamps: bool) {
    let fixture = load_fixture(relative);
    let parse_opts = ParseOptions::new().interop_bundle();
    let bundle = Bundle::parse_with_options(&fixture.json, &parse_opts)
        .unwrap_or_else(|err| panic!("{relative}: interop parse failed: {err}"));
    let root: Value = serde_json::from_str(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: invalid JSON: {err}"));
    let objects = root["objects"]
        .as_array()
        .unwrap_or_else(|| panic!("{relative}: bundle must contain objects array"));

    let mut checked = 0usize;
    for object in objects {
        let Some(created_by_ref) = object.get("created_by_ref").and_then(Value::as_str) else {
            continue;
        };
        let identity_id = StixId::parse(created_by_ref)
            .unwrap_or_else(|err| panic!("{relative}: invalid created_by_ref: {err}"));
        let identity = bundle
            .get_typed::<Identity>(&identity_id)
            .unwrap_or_else(|| {
                panic!(
                    "{relative}: created_by_ref `{created_by_ref}` must resolve to an Identity in the bundle"
                )
            });
        let wire = wire_identity_by_id(objects, created_by_ref).unwrap_or_else(|| {
            panic!(
                "{relative}: created_by_ref `{created_by_ref}` must resolve to a wire Identity object"
            )
        });
        assert_identity_shape(wire);
        if check_timestamps {
            assert_identity_millisecond_timestamps(identity);
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "{relative}: expected at least one object with created_by_ref"
    );
}

/// REQ-2.3-X-05 — each normative testcase resolves `created_by_ref` to an in-bundle Identity.
pub fn assert_identity_present_in_fixture() {
    for_each_testcase_fixture(|relative| {
        assert_identities_in_fixture(relative, false);
    });
}

/// REQ-2.3-X-06 — parsed Identity objects satisfy §2.3.4 shape and millisecond timestamps.
pub fn assert_identity_shape_on_parsed() {
    for_each_testcase_fixture(|relative| {
        assert_identities_in_fixture(relative, true);
    });
}
