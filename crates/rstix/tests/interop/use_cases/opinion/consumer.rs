//! §3.15.5 Required Consumer Persona Support.

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::Opinion;
use rstix::model::sdo::Identity;
use rstix::model::sro::Relationship;
use serde_json::Value;

use crate::common::fixture_catalog::{
    parse_fixture_objects, summarize_fixture_wire, use_case_object_ids,
};
use crate::common::wire_preservation::{
    assert_identity_fields_preserved, assert_wire_object_preserved,
};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::opinion::{FIXTURE_CREATE, PRODUCER_FIXTURES};


pub fn assert_supports_producer_props() {
    for relative in PRODUCER_FIXTURES {
        let json = load_fixture(relative).json.clone();
        let objects = parse_fixture_objects(&json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &json).unwrap();
        for object_id in use_case_ids {
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            let stix_id = StixId::parse(&object_id).unwrap();
            let obj = bundle.get_typed::<Opinion>(&stix_id).unwrap();
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("opinion"));
            assert!(obj.common.created_by_ref.is_some());
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    }
}

pub fn assert_receives_triad() {
    let relative = FIXTURE_CREATE;
    let json = load_fixture(FIXTURE_CREATE).json.clone();
    let summary = summarize_fixture_wire(&json).unwrap();
    assert!(!summary.identity_ids.is_empty());
    let bundle = validate_interop_fixture(relative, &json).unwrap();
    assert!(bundle.objects_of_type::<Opinion>().count() >= 1);

}

pub fn assert_resolves_created_by_ref() {
    let relative = FIXTURE_CREATE;
    let json = load_fixture(FIXTURE_CREATE).json.clone();
    let bundle = validate_interop_fixture(relative, &json).unwrap();
    let objects = parse_fixture_objects(&json).unwrap();
    let mut checked = 0usize;
    for object in &objects {
        let Some(cbr) = object.get("created_by_ref").and_then(Value::as_str) else { continue; };
        let identity_id = StixId::parse(cbr).unwrap();
        let wire_identity = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(cbr)).unwrap();
        assert!(bundle.get_typed::<Identity>(&identity_id).is_some());
        assert_identity_fields_preserved(relative, wire_identity, &bundle, cbr);
        checked += 1;
    }
    assert!(checked > 0);
}

pub fn assert_processes_fields() {
    let relative = FIXTURE_CREATE;
    let json = load_fixture(FIXTURE_CREATE).json.clone();
    let objects = parse_fixture_objects(&json).unwrap();
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &json).unwrap();
    assert_eq!(use_case_ids.len(), 1);
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).unwrap();
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
    let obj = bundle.get_typed::<Opinion>(&stix_id).unwrap();
    obj.validate().unwrap();
    match obj.get_field(&["opinion"]) {
        Some(QueryValue::Str(v)) => {
            assert_eq!(v, obj.opinion.as_str());
            assert_eq!(Some(v), wire.get("opinion").and_then(Value::as_str));
        }
        other => panic!("expected Str for opinion, got {other:?}"),
    }

    let created_by = obj.common.created_by_ref.as_ref().unwrap();
    match obj.get_field(&["created_by_ref"]) {
        Some(QueryValue::Id(id)) => {
            assert_eq!(id, created_by.as_stix_id());
            assert_eq!(Some(id.as_str()), wire.get("created_by_ref").and_then(Value::as_str));
        }
        other => panic!("expected Id, got {other:?}"),
    }
}

pub fn assert_processes_related() {
    let relative = FIXTURE_CREATE;
    let json = load_fixture(FIXTURE_CREATE).json.clone();
    let bundle = validate_interop_fixture(relative, &json).unwrap();
    assert_eq!(bundle.objects_of_type::<Relationship>().count(), 0);
    let opinion = bundle.objects_of_type::<Opinion>().next().unwrap();
    assert_eq!(opinion.object_refs.len(), 1);
    assert!(bundle.get(&opinion.object_refs[0]).is_some());

}

pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let json = load_fixture(relative).json.clone();
        let objects = parse_fixture_objects(&json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &json).unwrap();
        assert!(!use_case_ids.is_empty());
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).unwrap();
            let obj = bundle.get_typed::<Opinion>(&stix_id).unwrap();
            let created_by = obj.common.created_by_ref.as_ref().unwrap();
            assert!(bundle.get_typed::<Identity>(created_by.as_stix_id()).is_some());
        }
    }
}

interop_test!("REQ-3.15-C-01", "use_cases::opinion::consumer::supports_producer_props", supports_producer_props, { assert_supports_producer_props(); });
interop_test!("REQ-3.15-C-02", "use_cases::opinion::consumer::receives_triad", receives_triad, { assert_receives_triad(); });
interop_test!("REQ-3.15-C-03", "use_cases::opinion::consumer::resolves_created_by_ref", resolves_created_by_ref, { assert_resolves_created_by_ref(); });
interop_test!("REQ-3.15-C-04", "use_cases::opinion::consumer::processes_fields", processes_fields, { assert_processes_fields(); });
interop_test!("REQ-3.15-C-05", "use_cases::opinion::consumer::processes_related", processes_related, { assert_processes_related(); });
interop_test!("REQ-CHK-SXC-3.15", "use_cases::opinion::consumer::handles_producer_testcases", handles_producer_testcases, { assert_handles_producer_testcases(); });
