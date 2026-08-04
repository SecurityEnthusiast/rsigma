//! §3.20 Versioning revocation consumer support.

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
use crate::use_cases::versioning::{REVOCATION_FIXTURES, FIXTURE_REV_SIGHTING};

pub fn assert_supports_producer_props() {
    for relative in REVOCATION_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
        for object_id in use_case_ids {
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            let stix_id = StixId::parse(&object_id).unwrap();
            let ty = wire.get("type").and_then(Value::as_str).unwrap();
            match ty {
                "indicator" => {
                    let obj = bundle.get_typed::<Indicator>(&stix_id).unwrap();
                    assert!(obj.common.created_by_ref.is_some());
                }
                "sighting" => {
                    let obj = bundle.get_typed::<Sighting>(&stix_id).unwrap();
                    assert!(obj.common.created_by_ref.is_some());
                }
                other => panic!("unexpected use-case type {other}"),
            }
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    }
}

pub fn assert_receives_content() {
    let relative = FIXTURE_REV_SIGHTING;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json).unwrap();
    assert!(!summary.identity_ids.is_empty());
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    assert!(bundle.objects_of_type::<Indicator>().count() + bundle.objects_of_type::<Sighting>().count() >= 1);
}

pub fn assert_resolves_created_by_ref() {
    let relative = FIXTURE_REV_SIGHTING;
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
    let relative = FIXTURE_REV_SIGHTING;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).unwrap();
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
    assert!(!use_case_ids.is_empty());
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).unwrap();
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
    let ty = wire.get("type").and_then(Value::as_str).unwrap();
    match ty {
        "indicator" => {
            let obj = bundle.get_typed::<Indicator>(&stix_id).unwrap();
            obj.validate().unwrap();
            match obj.get_field(&["name"]) {
                Some(QueryValue::Str(name)) => assert_eq!(Some(name), wire.get("name").and_then(Value::as_str)),
                other => panic!("expected name Str, got {other:?}"),
            }
            let created_by = obj.common.created_by_ref.as_ref().unwrap();
            match obj.get_field(&["created_by_ref"]) {
                Some(QueryValue::Id(id)) => assert_eq!(id, created_by.as_stix_id()),
                other => panic!("expected Id, got {other:?}"),
            }
        }
        "sighting" => {
            let obj = bundle.get_typed::<Sighting>(&stix_id).unwrap();
            obj.validate().unwrap();
            match obj.get_field(&["count"]) {
                Some(QueryValue::Int(n)) => assert_eq!(Some(n), wire.get("count").and_then(Value::as_i64)),
                other => panic!("expected count Int, got {other:?}"),
            }
            let created_by = obj.common.created_by_ref.as_ref().unwrap();
            match obj.get_field(&["created_by_ref"]) {
                Some(QueryValue::Id(id)) => assert_eq!(id, created_by.as_stix_id()),
                other => panic!("expected Id, got {other:?}"),
            }
        }
        other => panic!("unexpected {other}"),
    }
}

pub fn assert_processes_related() {
    let relative = FIXTURE_REV_SIGHTING;
    let bundle = validate_interop_fixture(relative, &load_fixture(relative).json).unwrap();
    let sighting = bundle.objects_of_type::<Sighting>().next().expect("sighting");
    assert_eq!(sighting.common.revoked, Some(true));
    assert!(bundle.get_typed::<Indicator>(&sighting.sighting_of_ref).is_some());

}

pub fn assert_handles_producer_testcases() {
    for relative in REVOCATION_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap();
        assert!(!use_case_ids.is_empty());
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).unwrap();
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            let created_by = match wire.get("type").and_then(Value::as_str) {
                Some("indicator") => bundle.get_typed::<Indicator>(&stix_id).unwrap().common.created_by_ref.clone(),
                Some("sighting") => bundle.get_typed::<Sighting>(&stix_id).unwrap().common.created_by_ref.clone(),
                other => panic!("unexpected {other:?}"),
            };
            let created_by = created_by.as_ref().unwrap();
            assert!(bundle.get_typed::<Identity>(created_by.as_stix_id()).is_some());
        }
    }
}

interop_test!("REQ-3.20-C-R-01", "use_cases::versioning::consumer_revocation::supports_producer_props", supports_producer_props, { assert_supports_producer_props(); });
interop_test!("REQ-3.20-C-R-02", "use_cases::versioning::consumer_revocation::receives_content", receives_content, { assert_receives_content(); });
interop_test!("REQ-3.20-C-R-03", "use_cases::versioning::consumer_revocation::resolves_created_by_ref", resolves_created_by_ref, { assert_resolves_created_by_ref(); });
interop_test!("REQ-3.20-C-R-04", "use_cases::versioning::consumer_revocation::processes_fields", processes_fields, { assert_processes_fields(); });
interop_test!("REQ-3.20-C-R-05", "use_cases::versioning::consumer_revocation::processes_related", processes_related, { assert_processes_related(); });
interop_test!("REQ-CHK-SXC-3.20-R", "use_cases::versioning::consumer_revocation::handles_producer_testcases", handles_producer_testcases, { assert_handles_producer_testcases(); });
