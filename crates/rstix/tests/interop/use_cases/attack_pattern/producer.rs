//! §3.1.2 Required Producer Persona Support (REQ-3.1-P-01..P-13).

use crate::interop_test;
use rstix::core::{SpecVersion, StixId};
use rstix::model::sdo::AttackPattern;
use serde_json::Value;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};
use crate::use_cases::attack_pattern::FIXTURE_CREATE;

fn load_attack_pattern(relative: &str) -> (AttackPattern, String) {
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one attack-pattern use-case object"
    );
    let object_id = use_case_ids.into_iter().next().expect("attack-pattern id");
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let stix_id = StixId::parse(&object_id).expect("attack-pattern id");
    let ap = bundle
        .get_typed::<AttackPattern>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed attack-pattern {object_id}"))
        .clone();
    (ap, object_id)
}

/// REQ-3.1-P-01 — Producer creates Attack Pattern content (§3.1.3.1).
pub fn assert_create_attack_pattern() {
    validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json)
        .expect("§3.1.3.1 must pass interop producer gate");
}

/// REQ-3.1-P-02 — Caller-selected object set parses and re-validates (not UI-level select/specify).
pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let mut root: Value = serde_json::from_str(&fixture.json).expect("parse bundle JSON");
    let objects = root
        .get_mut("objects")
        .and_then(Value::as_array_mut)
        .expect("objects array");
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("attack-pattern") {
            object["name"] = Value::String("Caller-selected Attack Pattern name".into());
        }
    }
    let json = serde_json::to_string(&root).expect("serialize caller-selected bundle");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &parse_fixture_objects(&json).unwrap());
    validate_interop_json(
        &json,
        &InteropGateOptions {
            use_case_object_ids: use_case_ids,
        },
    )
    .expect("caller-selected bundle must pass interop gate");
}

/// REQ-3.1-P-03 — Identity in bundle complies with §2.3.4 (fixture-scoped; not a duplicate §2.3 proof).
pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let identities: Vec<_> = objects
        .iter()
        .filter(|obj| obj.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert_eq!(identities.len(), 1, "{relative}: expected one Identity");
    assert_identity_shape(relative, identities[0]);
}

/// REQ-3.1-P-04 — Attack Pattern conforms to STIX §4.1 via interop gate on §3.1.3.1.
pub fn assert_spec_conformance() {
    assert_create_attack_pattern();
}

/// REQ-3.1-P-05 — `type` is `attack-pattern`.
pub fn assert_prop_type() {
    let (_ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert_eq!(AttackPattern::TYPE_NAME, "attack-pattern");
}

/// REQ-3.1-P-06 — `spec_version` is `2.1`.
pub fn assert_prop_spec_version() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert_eq!(ap.common.spec_version, SpecVersion::V2_1);
}

/// REQ-3.1-P-07 — `id` is a UUID with `attack-pattern--` prefix.
pub fn assert_prop_id() {
    let (_, object_id) = load_attack_pattern(FIXTURE_CREATE);
    assert!(
        object_id.starts_with("attack-pattern--"),
        "id must use attack-pattern-- prefix: {object_id}"
    );
    assert!(
        StixId::parse(&object_id).is_ok(),
        "id must be valid STIX id"
    );
}

/// REQ-3.1-P-08 — `created_by_ref` points at the Producer Identity.
pub fn assert_prop_created_by_ref() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    let created_by = ap
        .common
        .created_by_ref
        .as_ref()
        .expect("interop-mandatory created_by_ref");
    assert!(
        created_by.as_stix_id().as_str().starts_with("identity--"),
        "created_by_ref must reference Identity: {}",
        created_by.as_stix_id().as_str()
    );
}

/// REQ-3.1-P-09 — `external_references` is present and non-empty.
pub fn assert_prop_external_references() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert!(
        !ap.common.external_references.is_empty(),
        "interop-mandatory external_references"
    );
}

/// REQ-3.1-P-10 — `kill_chain_phases` is present and non-empty.
pub fn assert_prop_kill_chain_phases() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert!(
        !ap.kill_chain_phases.is_empty(),
        "interop-mandatory kill_chain_phases"
    );
}

/// REQ-3.1-P-11 — `created` timestamp is present (millisecond RFC 3339 on wire).
pub fn assert_prop_created() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_attack_pattern(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire attack-pattern");
    let created = wire
        .get("created")
        .and_then(Value::as_str)
        .expect("created timestamp");
    assert!(
        created.contains('.') && created.ends_with('Z'),
        "created must be millisecond RFC 3339: {created}"
    );
}

/// REQ-3.1-P-12 — `modified` timestamp is present (millisecond RFC 3339 on wire).
pub fn assert_prop_modified() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_attack_pattern(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire attack-pattern");
    let modified = wire
        .get("modified")
        .and_then(Value::as_str)
        .expect("modified timestamp");
    assert!(
        modified.contains('.') && modified.ends_with('Z'),
        "modified must be millisecond RFC 3339: {modified}"
    );
}

/// REQ-3.1-P-13 — `name` identifies the Attack Pattern.
pub fn assert_prop_name() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert!(!ap.name.is_empty(), "interop-mandatory name");
}

