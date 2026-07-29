//! §2.3 Consumer cross-cutting checks (REQ-2.3-C-01..C-06).

use rstix::core::StixId;
use rstix::model::sdo::{AttackPattern, Identity};
use rstix::model::sro::{Relationship, Sighting};
use serde_json::Value;

use crate::common::fixture_catalog::{
    fixture_expects_sro, parse_fixture_objects, summarize_fixture_wire, use_case_object_ids,
};
use crate::common::fixture_walk::for_each_suite_walk_fixture;
use crate::common::wire_preservation::{
    assert_identity_fields_preserved, assert_wire_object_preserved,
};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;

/// REQ-2.3-C-01 — every walkable normative testcase passes the interop consumer gate.
pub fn assert_consumer_conformance_12_1() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative} failed interop consumer gate: {err}"));
    });
}

/// REQ-2.3-C-02 — typed accessors expose §3.x Required Producer Persona Support properties.
pub fn assert_consumer_supports_producer_props() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));

        for object_id in &use_case_ids {
            let wire = objects
                .iter()
                .find(|obj| obj.get("id").and_then(|v| v.as_str()) == Some(object_id.as_str()))
                .unwrap_or_else(|| panic!("{relative}: wire object {object_id}"));
            let object_type = wire.get("type").and_then(Value::as_str).unwrap_or("object");
            let stix_id = StixId::parse(object_id).expect("object id");
            assert!(
                bundle.get(&stix_id).is_some(),
                "{relative}: typed access for {object_type} {object_id}"
            );
            if object_type == "attack-pattern" {
                let ap = bundle
                    .get_typed::<AttackPattern>(&stix_id)
                    .expect("typed attack-pattern");
                assert!(!ap.common.external_references.is_empty());
                assert!(!ap.kill_chain_phases.is_empty());
            }
            assert_wire_object_preserved(relative, wire, &bundle, object_id);
        }
    });
}

/// REQ-2.3-C-03 — Consumer receives Identity, use-case SDO(s), and SRO(s) when expected.
pub fn assert_consumer_receives_triad() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let summary = summarize_fixture_wire(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
        assert!(
            !summary.identity_ids.is_empty(),
            "{relative}: expected at least one Identity"
        );
        assert!(
            summary.primary_sdo_count > 0,
            "{relative}: expected at least one use-case SDO"
        );

        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
        for identity_id in &summary.identity_ids {
            let id = StixId::parse(identity_id).expect("identity id");
            assert!(
                bundle.get_typed::<Identity>(&id).is_some(),
                "{relative}: Identity {identity_id} must parse"
            );
        }
        if fixture_expects_sro(relative, &summary) {
            assert!(
                summary.relationship_count > 0 || summary.sighting_count > 0,
                "{relative}: expected relationship or sighting SRO content"
            );
            if summary.relationship_count > 0 {
                assert_eq!(
                    bundle.objects_of_type::<Relationship>().count(),
                    summary.relationship_count,
                    "{relative}: relationship count mismatch"
                );
            }
            if summary.sighting_count > 0 {
                assert_eq!(
                    bundle.objects_of_type::<Sighting>().count(),
                    summary.sighting_count,
                    "{relative}: sighting count mismatch"
                );
            }
        }
    });
}

/// REQ-2.3-C-04 — Consumer resolves `created_by_ref` and §2.3.4 Identity fields.
pub fn assert_consumer_resolves_created_by_ref() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));

        let mut checked = 0usize;
        for object in &objects {
            let Some(created_by_ref) = object.get("created_by_ref").and_then(Value::as_str) else {
                continue;
            };
            let identity_id = StixId::parse(created_by_ref)
                .unwrap_or_else(|err| panic!("{relative}: invalid created_by_ref: {err}"));
            let wire_identity = objects
                .iter()
                .find(|obj| obj.get("id").and_then(Value::as_str) == Some(created_by_ref))
                .unwrap_or_else(|| {
                    panic!(
                        "{relative}: created_by_ref `{created_by_ref}` must resolve to wire Identity"
                    )
                });
            assert!(
                bundle.get_typed::<Identity>(&identity_id).is_some(),
                "{relative}: created_by_ref `{created_by_ref}` must resolve to Identity"
            );
            assert_identity_fields_preserved(relative, wire_identity, &bundle, created_by_ref);
            checked += 1;
        }
        assert!(
            checked > 0,
            "{relative}: expected at least one object with created_by_ref"
        );
    });
}

/// REQ-2.3-C-05 — Consumer preserves use-case object wire fields without loss.
pub fn assert_consumer_processes_fields() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));

        for object_id in use_case_ids {
            let wire = objects
                .iter()
                .find(|obj| obj.get("id").and_then(|v| v.as_str()) == Some(object_id.as_str()))
                .unwrap_or_else(|| panic!("{relative}: wire object {object_id}"));
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-2.3-C-06 — Consumer resolves relationship endpoints and related bundle members.
pub fn assert_consumer_processes_related() {
    let mut checked = 0usize;
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
        for relationship in bundle.objects_of_type::<Relationship>() {
            assert!(
                bundle.get(&relationship.source_ref).is_some(),
                "{relative}: source_ref {} must resolve",
                relationship.source_ref.as_str()
            );
            assert!(
                bundle.get(&relationship.target_ref).is_some(),
                "{relative}: target_ref {} must resolve",
                relationship.target_ref.as_str()
            );
            assert!(!relationship.relationship_type.is_empty());
            checked += 1;
        }
    });
    assert!(
        checked > 0,
        "expected at least one relationship across normative testcase fixtures"
    );
}
