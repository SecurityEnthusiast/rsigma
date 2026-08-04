//! §3.14.2 Required Producer Persona Support (REQ-3.14-P-01..P-14).

use crate::interop_test;
use rstix::core::{SpecVersion, StixId};
use rstix::model::sdo::ObservedData;
use rstix::model::{Bundle, ParseOptions};
use rstix::validate::{Leniency, Validator};
use serde_json::Value;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::common::timestamp::assert_millisecond_rfc3339;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};
use crate::use_cases::observed_data::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn load_observed_data(relative: &str) -> (ObservedData, String) {
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(use_case_ids.len(), 1, "{relative}: expected one observed-data use-case object");
    let object_id = use_case_ids.into_iter().next().expect("observed-data id");
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let stix_id = StixId::parse(&object_id).expect("observed-data id");
    let od = bundle
        .get_typed::<ObservedData>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed observed-data {object_id}"))
        .clone();
    (od, object_id)
}

pub fn assert_create_observed_data() {
    validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json)
        .expect("§3.14.3.1 must pass interop producer gate");
}

pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let mut root: Value = serde_json::from_str(&fixture.json).expect("parse");
    let objects = root.get_mut("objects").and_then(Value::as_array_mut).expect("objects");
    let mut mutated = 0usize;
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("observed-data") {
            object["number_observed"] = Value::from(42);
            mutated += 1;
        }
    }
    assert_eq!(mutated, 1);
    let json = serde_json::to_string(&root).expect("serialize");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &parse_fixture_objects(&json).unwrap());
    let bundle = validate_interop_json(
        &json,
        &InteropGateOptions { use_case_object_ids: use_case_ids.clone() },
    )
    .expect("caller-selected bundle must pass");
    assert_eq!(use_case_ids.len(), 1);
    let stix_id = StixId::parse(&use_case_ids[0]).expect("id");
    let od = bundle.get_typed::<ObservedData>(&stix_id).expect("typed");
    assert_eq!(od.number_observed, 42);
}

pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE;
    let objects = parse_fixture_objects(&load_fixture(relative).json).expect("parse");
    let identities: Vec<_> = objects
        .iter()
        .filter(|obj| obj.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert_eq!(identities.len(), 1);
    assert_identity_shape(relative, identities[0]);
}

pub fn assert_spec_conformance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let bundle = Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .unwrap_or_else(|err| panic!("{relative}: parse: {err}"));
    let objects = parse_fixture_objects(&fixture.json).expect("objects");
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(use_case_ids.len(), 1);
    let object_id = &use_case_ids[0];
    let od_id = StixId::parse(object_id).expect("id");
    let od = bundle.get_typed::<ObservedData>(&od_id).expect("typed");
    od.validate().unwrap_or_else(|err| panic!("{relative}: validate: {err}"));
    let report = Validator::interop_bundle_strict().validate_bundle(&bundle);
    assert!(report.errors().next().is_none());
    let scoped: Vec<_> = report
        .diagnostics()
        .filter(|d| d.object_id.as_ref() == Some(&od_id) && Leniency::Zero.fails_validation(d.severity))
        .collect();
    assert!(scoped.is_empty(), "{scoped:?}");
    // Bundle-level STIX-W0002 on embedded File SCOs is outside ObservedData P-04 scope;
    // OASIS §3.14.3 fixtures use non-deterministic SCO ids. Do not require report.is_valid().
}

pub fn assert_prop_type() {
    let (_, object_id) = load_observed_data(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&load_fixture(FIXTURE_CREATE).json).unwrap();
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
    assert_eq!(wire.get("type").and_then(Value::as_str), Some("observed-data"));
}

pub fn assert_prop_spec_version() {
    let (od, _) = load_observed_data(FIXTURE_CREATE);
    assert_eq!(od.common.spec_version, SpecVersion::V2_1);
}

pub fn assert_prop_id() {
    let objects = parse_fixture_objects(&load_fixture(FIXTURE_CREATE).json).unwrap();
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &objects);
    assert_eq!(use_case_ids.len(), 1);
    let wire_id = &use_case_ids[0];
    assert!(wire_id.starts_with("observed-data--"));
    StixId::parse(wire_id).expect("valid id");
}

pub fn assert_prop_created_by_ref() {
    let (od, _) = load_observed_data(FIXTURE_CREATE);
    let created_by = od.common.created_by_ref.as_ref().expect("created_by_ref");
    assert!(created_by.as_stix_id().as_str().starts_with("identity--"));
}

fn wire_ts(field: &str) {
    let (_, object_id) = load_observed_data(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&load_fixture(FIXTURE_CREATE).json).unwrap();
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
    let v = wire.get(field).and_then(Value::as_str).expect(field);
    assert_millisecond_rfc3339(field, v);
}

pub fn assert_prop_created() { wire_ts("created"); }
pub fn assert_prop_modified() { wire_ts("modified"); }
pub fn assert_prop_first_observed() { wire_ts("first_observed"); }
pub fn assert_prop_last_observed() { wire_ts("last_observed"); }

pub fn assert_prop_number_observed() {
    let (od, _) = load_observed_data(FIXTURE_CREATE);
    assert_eq!(od.number_observed, 1);
}

pub fn assert_prop_object_refs() {
    let (od, _) = load_observed_data(FIXTURE_CREATE);
    match &od.form {
        rstix::model::sdo::ObservedDataForm::ObjectRefs(refs) => {
            assert!(!refs.is_empty(), "object_refs required");
        }
        other => panic!("expected ObjectRefs form, got {other:?}"),
    }
}

pub fn assert_producer_testcase_data() {
    for relative in PRODUCER_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|err| {
            panic!("{relative}: §3.14.3 producer test case must pass: {err}")
        });
    }
}

macro_rules! t {
    ($req:literal, $name:ident, $assert:ident) => {
        interop_test!($req, concat!("use_cases::observed_data::producer::", stringify!($name)), $name, { $assert(); });
    };
}
t!("REQ-3.14-P-01", create_observed_data, assert_create_observed_data);
t!("REQ-3.14-P-02", select_content, assert_select_content);
t!("REQ-3.14-P-03", identity_compliance, assert_identity_compliance);
t!("REQ-3.14-P-04", spec_conformance, assert_spec_conformance);
t!("REQ-3.14-P-05", prop_type, assert_prop_type);
t!("REQ-3.14-P-06", prop_spec_version, assert_prop_spec_version);
t!("REQ-3.14-P-07", prop_id, assert_prop_id);
t!("REQ-3.14-P-08", prop_created_by_ref, assert_prop_created_by_ref);
t!("REQ-3.14-P-09", prop_created, assert_prop_created);
t!("REQ-3.14-P-10", prop_modified, assert_prop_modified);
t!("REQ-3.14-P-11", prop_first_observed, assert_prop_first_observed);
t!("REQ-3.14-P-12", prop_last_observed, assert_prop_last_observed);
t!("REQ-3.14-P-13", prop_number_observed, assert_prop_number_observed);
t!("REQ-3.14-P-14", prop_object_refs, assert_prop_object_refs);
interop_test!("REQ-CHK-SXP-3.14", "use_cases::observed_data::producer::producer_testcase_data", producer_testcase_data, { assert_producer_testcase_data(); });
