//! §3.16.2 Required Producer Persona Support (REQ-3.16-P-01..P-14).

use crate::interop_test;
use rstix::core::{SpecVersion, StixId};
use rstix::model::sdo::Report;
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
use crate::use_cases::report::{working_json, FIXTURE_CREATE};


fn load_report(relative: &str) -> (Report, String) {
    let fixture = load_fixture(relative);
    let json = working_json(&fixture.json);
    let objects = parse_fixture_objects(&json)
        .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(use_case_ids.len(), 1, "{relative}: expected one report use-case object");
    let object_id = use_case_ids.into_iter().next().expect("report id");
    let bundle = validate_interop_fixture(relative, &json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let stix_id = StixId::parse(&object_id).expect("report id");
    let obj = bundle
        .get_typed::<Report>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed report {object_id}"))
        .clone();
    (obj, object_id)
}


pub fn assert_create_report() {
    validate_interop_fixture(FIXTURE_CREATE, &working_json(&load_fixture(FIXTURE_CREATE).json))
        .expect("§3.16.3.1 must pass interop producer gate");
}

pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let mut root: Value = serde_json::from_str(&working_json(&fixture.json)).expect("parse");
    let objects = root.get_mut("objects").and_then(Value::as_array_mut).expect("objects");
    let mut renamed = 0usize;
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("report") {
            object["name"] = Value::String("Caller-selected Report name".into());
            renamed += 1;
        }
    }
    assert_eq!(renamed, 1, "expected exactly one report mutated");
    let json = serde_json::to_string(&root).expect("serialize");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &parse_fixture_objects(&json).unwrap());
    let bundle = validate_interop_json(
        &json,
        &InteropGateOptions { use_case_object_ids: use_case_ids.clone() },
    )
    .expect("caller-selected bundle must pass");
    assert_eq!(use_case_ids.len(), 1);
    let stix_id = StixId::parse(&use_case_ids[0]).expect("id");
    let obj = bundle.get_typed::<Report>(&stix_id).expect("typed after selection");
    assert_eq!(obj.name, "Caller-selected Report name");
}

pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE;
    let json = working_json(&load_fixture(relative).json);
    let objects = parse_fixture_objects(&json).expect("parse");
    let identities: Vec<_> = objects
        .iter()
        .filter(|obj| obj.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert_eq!(identities.len(), 1, "{relative}: expected one Identity");
    assert_identity_shape(relative, identities[0]);
}

pub fn assert_spec_conformance() {
    let relative = FIXTURE_CREATE;
    let json = working_json(&load_fixture(relative).json);
    let bundle = Bundle::parse_with_options(&json, &ParseOptions::new().interop_bundle())
        .unwrap_or_else(|err| panic!("{relative}: parse for §4.16: {err}"));
    let objects = parse_fixture_objects(&json).expect("objects");
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(use_case_ids.len(), 1);
    let object_id = &use_case_ids[0];
    let id = StixId::parse(object_id).expect("id");
    let obj = bundle.get_typed::<Report>(&id).expect("typed");
    obj.validate().unwrap_or_else(|err| panic!("{relative}: validate: {err}"));
    let report = Validator::interop_bundle_strict().validate_bundle(&bundle);
    assert!(report.errors().next().is_none(), "{:?}", report.errors().collect::<Vec<_>>());
    let scoped: Vec<_> = report.diagnostics().filter(|d| {
        d.object_id.as_ref() == Some(&id) && Leniency::Zero.fails_validation(d.severity)
    }).collect();
    assert!(scoped.is_empty(), "{scoped:?}");
    assert!(report.is_valid());
}

pub fn assert_prop_type() {
    let json = working_json(&load_fixture(FIXTURE_CREATE).json);
    let objects = parse_fixture_objects(&json).expect("parse");
    let (_obj, object_id) = load_report(FIXTURE_CREATE);
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).expect("wire");
    assert_eq!(wire.get("type").and_then(Value::as_str), Some("report"));
}

pub fn assert_prop_spec_version() {
    let (obj, _) = load_report(FIXTURE_CREATE);
    assert_eq!(obj.common.spec_version, SpecVersion::V2_1);
}

pub fn assert_prop_id() {
    let json = working_json(&load_fixture(FIXTURE_CREATE).json);
    let objects = parse_fixture_objects(&json).expect("parse");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &objects);
    assert_eq!(use_case_ids.len(), 1);
    let wire_id = &use_case_ids[0];
    assert!(wire_id.starts_with("report--"), "id must use report-- prefix: {wire_id}");
    StixId::parse(wire_id).expect("wire id must be valid STIX id");
}

pub fn assert_prop_created_by_ref() {
    let (obj, _) = load_report(FIXTURE_CREATE);
    let created_by = obj.common.created_by_ref.as_ref().expect("created_by_ref");
    assert!(created_by.as_stix_id().as_str().starts_with("identity--"));
}

fn wire_ts(field: &str) {
    let json = working_json(&load_fixture(FIXTURE_CREATE).json);
    let objects = parse_fixture_objects(&json).expect("parse");
    let (_, object_id) = load_report(FIXTURE_CREATE);
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).expect("wire");
    let v = wire.get(field).and_then(Value::as_str).expect(field);
    assert_millisecond_rfc3339(field, v);
}

pub fn assert_prop_created() { wire_ts("created"); }
pub fn assert_prop_modified() { wire_ts("modified"); }


pub fn assert_prop_name() {
    let (obj, _) = load_report(FIXTURE_CREATE);
    assert_eq!(obj.name, "Glass Gazelle Campaign");
}
pub fn assert_prop_published() {
    let json = working_json(&load_fixture(FIXTURE_CREATE).json);
    let objects = parse_fixture_objects(&json).unwrap();
    let (_, object_id) = load_report(FIXTURE_CREATE);
    let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
    let published = wire.get("published").and_then(Value::as_str).expect("published");
    assert_millisecond_rfc3339("published", published);
}
pub fn assert_prop_object_refs() {
    let (obj, _) = load_report(FIXTURE_CREATE);
    assert!(!obj.object_refs.is_empty());
}
pub fn assert_prop_report_types() {
    let (obj, _) = load_report(FIXTURE_CREATE);
    assert_eq!(obj.report_types, vec!["campaign".to_string()]);
}


macro_rules! t {
    ($req:literal, $name:ident, $assert:ident) => {
        interop_test!($req, concat!("use_cases::report::producer::", stringify!($name)), $name, { $assert(); });
    };
}
t!("REQ-3.16-P-01", create_report, assert_create_report);
t!("REQ-3.16-P-02", select_content, assert_select_content);
t!("REQ-3.16-P-03", identity_compliance, assert_identity_compliance);
t!("REQ-3.16-P-04", spec_conformance, assert_spec_conformance);
t!("REQ-3.16-P-05", prop_type, assert_prop_type);
t!("REQ-3.16-P-06", prop_spec_version, assert_prop_spec_version);
t!("REQ-3.16-P-07", prop_id, assert_prop_id);
t!("REQ-3.16-P-08", prop_created_by_ref, assert_prop_created_by_ref);
t!("REQ-3.16-P-09", prop_created, assert_prop_created);
t!("REQ-3.16-P-10", prop_modified, assert_prop_modified);
t!("REQ-3.16-P-11", prop_name, assert_prop_name);
t!("REQ-3.16-P-12", prop_published, assert_prop_published);
t!("REQ-3.16-P-13", prop_object_refs, assert_prop_object_refs);
t!("REQ-3.16-P-14", prop_report_types, assert_prop_report_types);

