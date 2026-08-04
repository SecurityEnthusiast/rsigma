//! §3.14.5 Required Consumer Persona Support (REQ-3.14-C-01..C-05).

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{Identity, ObservedData};
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
use crate::use_cases::observed_data::{FIXTURE_DOMAIN, PRODUCER_FIXTURES};

pub fn assert_supports_producer_props() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
        for object_id in use_case_ids {
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            let stix_id = StixId::parse(&object_id).unwrap();
            let od = bundle.get_typed::<ObservedData>(&stix_id).unwrap();
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("observed-data"));
            assert!(od.common.created_by_ref.is_some());
            assert!(od.number_observed >= 1);
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    }
}

pub fn assert_receives_triad() {
    let relative = FIXTURE_DOMAIN;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json).unwrap();
    assert_eq!(summary.identity_ids.len(), 1);
    assert_eq!(summary.primary_sdo_count, 1);
    assert_eq!(summary.relationship_count, 1);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    assert_eq!(bundle.objects_of_type::<ObservedData>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Relationship>().count(), 1);
}

pub fn assert_resolves_created_by_ref() {
    let relative = FIXTURE_DOMAIN;
    let fixture = load_fixture(relative);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    let objects = parse_fixture_objects(&fixture.json).unwrap();
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
    let relative = FIXTURE_DOMAIN;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).unwrap();
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    assert_eq!(use_case_ids.len(), 1);
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).unwrap();
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
    let od = bundle.get_typed::<ObservedData>(&stix_id).unwrap();
    od.validate().unwrap();
    match od.get_field(&["number_observed"]) {
        Some(QueryValue::Int(n)) => {
            assert_eq!(n, od.number_observed);
            assert_eq!(Some(n), wire.get("number_observed").and_then(Value::as_i64));
        }
        other => panic!("expected Int for number_observed, got {other:?}"),
    }
    let created_by = od.common.created_by_ref.as_ref().unwrap();
    match od.get_field(&["created_by_ref"]) {
        Some(QueryValue::Id(id)) => {
            assert_eq!(id, created_by.as_stix_id());
            assert_eq!(Some(id.as_str()), wire.get("created_by_ref").and_then(Value::as_str));
        }
        other => panic!("expected Id for created_by_ref, got {other:?}"),
    }
}

pub fn assert_processes_related() {
    let relative = FIXTURE_DOMAIN;
    let bundle = validate_interop_fixture(relative, &load_fixture(relative).json).unwrap();
    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "resolves-to");
    assert!(bundle.get(&relationships[0].source_ref).is_some());
    assert!(bundle.get(&relationships[0].target_ref).is_some());
}

pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
        assert!(!use_case_ids.is_empty());
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).unwrap();
            let od = bundle.get_typed::<ObservedData>(&stix_id).unwrap();
            let created_by = od.common.created_by_ref.as_ref().unwrap();
            assert!(bundle.get_typed::<Identity>(created_by.as_stix_id()).is_some());
        }
    }
}

interop_test!("REQ-3.14-C-01", "use_cases::observed_data::consumer::supports_producer_props", supports_producer_props, { assert_supports_producer_props(); });
interop_test!("REQ-3.14-C-02", "use_cases::observed_data::consumer::receives_triad", receives_triad, { assert_receives_triad(); });
interop_test!("REQ-3.14-C-03", "use_cases::observed_data::consumer::resolves_created_by_ref", resolves_created_by_ref, { assert_resolves_created_by_ref(); });
interop_test!("REQ-3.14-C-04", "use_cases::observed_data::consumer::processes_fields", processes_fields, { assert_processes_fields(); });
interop_test!("REQ-3.14-C-05", "use_cases::observed_data::consumer::processes_related", processes_related, { assert_processes_related(); });
interop_test!("REQ-CHK-SXC-3.14", "use_cases::observed_data::consumer::handles_producer_testcases", handles_producer_testcases, { assert_handles_producer_testcases(); });
