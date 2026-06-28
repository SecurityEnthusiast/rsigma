//! Integration tests for STIX bundle parsing.

#![cfg(feature = "serde")]

#[path = "support/fixtures.rs"]
mod fixtures;

use fixtures::load_spec_fixture;
use rstix::core::{QueryableStixObject, StixId};
use rstix::model::sdo::AttackPattern;
use rstix::model::{Bundle, StixObject};
use rstix::{ParseError, parse_bundle};

#[test]
fn bundle_minimal_parses_three_objects() {
    let raw = load_spec_fixture("bundle/bundle-minimal.json");
    let bundle = parse_bundle(&raw).expect("parse bundle");
    assert_eq!(bundle.objects().len(), 3);

    let attack_id = StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").unwrap();
    let attack = bundle.get(&attack_id).expect("attack-pattern present");
    assert!(matches!(attack, StixObject::Sdo(_)));
    assert_eq!(
        QueryableStixObject::type_name(attack),
        AttackPattern::TYPE_NAME
    );

    let extra = bundle
        .extra_properties(&attack_id)
        .expect("x_* properties captured");
    assert_eq!(
        extra.get("x_custom_prop"),
        Some(&serde_json::Value::String("preserved".into()))
    );
    let raw_object = bundle.raw_object(&attack_id).expect("raw object stored");
    assert_eq!(
        raw_object.get("x_custom_prop"),
        Some(&serde_json::Value::String("preserved".into()))
    );
}

#[test]
fn bundle_with_relationship_refs_validates() {
    let raw = load_spec_fixture("bundle/bundle-with-relationship-refs.json");
    let bundle = Bundle::parse(&raw).expect("parse bundle");
    assert_eq!(bundle.objects().len(), 3);
    bundle.validate_refs().expect("refs resolve");
}

#[test]
fn bundle_missing_ref_rejects() {
    let raw = load_spec_fixture("bundle/bundle-missing-ref.json");
    let err = parse_bundle(&raw).unwrap_err();
    assert!(matches!(
        err,
        ParseError::Model(rstix::model::ModelError::BundleReferenceMissing { .. })
    ));
}

#[test]
fn bundle_serializes_without_empty_objects_key() {
    let raw = load_spec_fixture("bundle/bundle-minimal.json");
    let bundle = parse_bundle(&raw).expect("parse bundle");
    let value = serde_json::to_value(&bundle).expect("serialize");
    assert!(value.get("objects").is_some());

    let empty =
        Bundle::parse(r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000"}"#)
            .expect("empty bundle");
    let empty_value = serde_json::to_value(&empty).expect("serialize empty");
    assert!(empty_value.get("objects").is_none());
}
