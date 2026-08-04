//! §3.20.6–3.20.7 Versioning Modification producer support.

use crate::interop_test;
use serde_json::Value;
use time::OffsetDateTime;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::versioning::{
    FIXTURE_CREATE_INDICATOR, FIXTURE_MOD_INDICATOR, MODIFICATION_FIXTURES,
};

fn parse_ts(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).expect(s)
}

pub fn assert_select_content() {
    validate_interop_fixture(FIXTURE_MOD_INDICATOR, &load_fixture(FIXTURE_MOD_INDICATOR).json).unwrap();
}

pub fn assert_identity_compliance() {
    let relative = FIXTURE_MOD_INDICATOR;
    let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
    let identities: Vec<_> = objects.iter().filter(|o| o.get("type").and_then(Value::as_str) == Some("identity")).collect();
    assert!(identities.len() >= 1);
    for identity in identities {
        assert_identity_shape(relative, identity);
    }
}

pub fn assert_modified_after_created() {
    for relative in MODIFICATION_FIXTURES {
        let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        assert!(!use_case_ids.is_empty());
        for object_id in use_case_ids {
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            let created = parse_ts(wire.get("created").and_then(Value::as_str).unwrap());
            let modified = parse_ts(wire.get("modified").and_then(Value::as_str).unwrap());
            assert!(modified > created, "{relative}: modified must be later than created");
        }
    }
}

pub fn assert_created_preserved() {
    let create_objects = parse_fixture_objects(&load_fixture(FIXTURE_CREATE_INDICATOR).json).unwrap();
    let mod_objects = parse_fixture_objects(&load_fixture(FIXTURE_MOD_INDICATOR).json).unwrap();
    let id = "indicator--6cd5cd4f-ff42-4d67-8402-02aad22f8b63";
    let create_wire = create_objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(id)).unwrap();
    let mod_wire = mod_objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(id)).unwrap();
    assert_eq!(
        create_wire.get("created").and_then(Value::as_str),
        mod_wire.get("created").and_then(Value::as_str),
        "created must be preserved across versions"
    );
}

pub fn assert_producer_testcase_data() {
    for relative in MODIFICATION_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|e| panic!("{relative}: {e}"));
    }
}

interop_test!("REQ-3.20-P-M-01", "use_cases::versioning::producer_modification::select_content", select_content, { assert_select_content(); });
interop_test!("REQ-3.20-P-M-02", "use_cases::versioning::producer_modification::identity_compliance", identity_compliance, { assert_identity_compliance(); });
interop_test!("REQ-3.20-P-M-03", "use_cases::versioning::producer_modification::modified_after_created", modified_after_created, { assert_modified_after_created(); });
interop_test!("REQ-3.20-P-M-04", "use_cases::versioning::producer_modification::created_preserved", created_preserved, { assert_created_preserved(); });
interop_test!("REQ-CHK-SXP-3.20-M", "use_cases::versioning::producer_modification::producer_testcase_data", producer_testcase_data, { assert_producer_testcase_data(); });
