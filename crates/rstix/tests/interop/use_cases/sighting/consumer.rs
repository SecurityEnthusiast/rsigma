//! §3.17.5 Required Consumer Persona Support.

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{Identity, Indicator};
use rstix::model::sro::Sighting;
use serde_json::Value;

use crate::common::fixture_catalog::{
    parse_fixture_objects, summarize_fixture_wire, use_case_object_ids,
};
use crate::common::wire_preservation::{
    assert_identity_fields_preserved, assert_wire_object_preserved,
};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::sighting::{FIXTURE_CREATE, PRODUCER_FIXTURES};

pub fn assert_supports_producer_props() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
        for object_id in use_case_ids {
            let wire = objects
                .iter()
                .find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
                .unwrap();
            let stix_id = StixId::parse(&object_id).unwrap();
            let sighting = bundle.get_typed::<Sighting>(&stix_id).unwrap();
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("sighting"));
            assert!(sighting.common.created_by_ref.is_some());
            assert!(sighting.count.is_some());
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    }
}

pub fn assert_receives_triad() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json).unwrap();
    assert_eq!(summary.identity_ids.len(), 2);
    assert_eq!(summary.sighting_count, 1);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    assert_eq!(bundle.objects_of_type::<Sighting>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Indicator>().count(), 1);
}

pub fn assert_resolves_created_by_ref() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    let objects = parse_fixture_objects(&fixture.json).unwrap();
    let mut checked = 0usize;
    for object in &objects {
        let Some(cbr) = object.get("created_by_ref").and_then(Value::as_str) else {
            continue;
        };
        let identity_id = StixId::parse(cbr).unwrap();
        let wire_identity = objects
            .iter()
            .find(|o| o.get("id").and_then(Value::as_str) == Some(cbr))
            .unwrap();
        assert!(bundle.get_typed::<Identity>(&identity_id).is_some());
        assert_identity_fields_preserved(relative, wire_identity, &bundle, cbr);
        checked += 1;
    }
    assert!(checked > 0);
}

pub fn assert_processes_fields() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).unwrap();
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    assert_eq!(use_case_ids.len(), 1);
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).unwrap();
    let wire = objects
        .iter()
        .find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .unwrap();
    let sighting = bundle.get_typed::<Sighting>(&stix_id).unwrap();
    sighting.validate().unwrap();
    match sighting.get_field(&["count"]) {
        Some(QueryValue::Int(n)) => {
            assert_eq!(n as u32, sighting.count.unwrap());
            assert_eq!(Some(n), wire.get("count").and_then(Value::as_i64));
        }
        other => panic!("expected Int for count, got {other:?}"),
    }
    let created_by = sighting.common.created_by_ref.as_ref().unwrap();
    match sighting.get_field(&["created_by_ref"]) {
        Some(QueryValue::Id(id)) => {
            assert_eq!(id, created_by.as_stix_id());
            assert_eq!(
                Some(id.as_str()),
                wire.get("created_by_ref").and_then(Value::as_str)
            );
        }
        other => panic!("expected Id, got {other:?}"),
    }
}

pub fn assert_processes_related() {
    let relative = FIXTURE_CREATE;
    let bundle = validate_interop_fixture(relative, &load_fixture(relative).json).unwrap();
    let sighting = bundle.objects_of_type::<Sighting>().next().unwrap();
    assert!(
        bundle
            .get_typed::<Indicator>(&sighting.sighting_of_ref)
            .is_some()
    );
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
            let sighting = bundle.get_typed::<Sighting>(&stix_id).unwrap();
            let created_by = sighting.common.created_by_ref.as_ref().unwrap();
            assert!(
                bundle
                    .get_typed::<Identity>(created_by.as_stix_id())
                    .is_some()
            );
        }
    }
}

interop_test!(
    "REQ-3.17-C-01",
    "use_cases::sighting::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);
interop_test!(
    "REQ-3.17-C-02",
    "use_cases::sighting::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);
interop_test!(
    "REQ-3.17-C-03",
    "use_cases::sighting::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);
interop_test!(
    "REQ-3.17-C-04",
    "use_cases::sighting::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);
interop_test!(
    "REQ-3.17-C-05",
    "use_cases::sighting::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);
interop_test!(
    "REQ-CHK-SXC-3.17",
    "use_cases::sighting::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
