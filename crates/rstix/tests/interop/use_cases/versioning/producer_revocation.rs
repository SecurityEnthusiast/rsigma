//! §3.20.10–3.20.11 Versioning Revocation producer support.

use crate::interop_test;
use serde_json::Value;
use time::OffsetDateTime;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::versioning::{
    FIXTURE_CREATE_INDICATOR, FIXTURE_REV_INDICATOR, REVOCATION_FIXTURES,
};

fn parse_ts(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).expect(s)
}

pub fn assert_select_content() {
    validate_interop_fixture(FIXTURE_REV_INDICATOR, &load_fixture(FIXTURE_REV_INDICATOR).json).unwrap();
}

pub fn assert_identity_compliance() {
    let relative = FIXTURE_REV_INDICATOR;
    let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
    let identities: Vec<_> = objects.iter().filter(|o| o.get("type").and_then(Value::as_str) == Some("identity")).collect();
    assert!(identities.len() >= 1);
    for identity in identities {
        assert_identity_shape(relative, identity);
    }
}

pub fn assert_revoked_true() {
    for relative in REVOCATION_FIXTURES {
        let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        assert!(!use_case_ids.is_empty());
        for object_id in use_case_ids {
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            assert_eq!(wire.get("revoked").and_then(Value::as_bool), Some(true), "{relative}: revoked must be true");
        }
    }
}

pub fn assert_modified_after_created() {
    for relative in REVOCATION_FIXTURES {
        let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
        for object_id in use_case_object_ids(relative, &objects) {
            let wire = objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str())).unwrap();
            let created = parse_ts(wire.get("created").and_then(Value::as_str).unwrap());
            let modified = parse_ts(wire.get("modified").and_then(Value::as_str).unwrap());
            assert!(modified > created);
        }
    }
}

pub fn assert_created_preserved() {
    let create_objects = parse_fixture_objects(&load_fixture(FIXTURE_CREATE_INDICATOR).json).unwrap();
    let rev_objects = parse_fixture_objects(&load_fixture(FIXTURE_REV_INDICATOR).json).unwrap();
    let id = "indicator--6cd5cd4f-ff42-4d67-8402-02aad22f8b63";
    let create_wire = create_objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(id)).unwrap();
    let rev_wire = rev_objects.iter().find(|o| o.get("id").and_then(Value::as_str) == Some(id)).unwrap();
    assert_eq!(
        create_wire.get("created").and_then(Value::as_str),
        rev_wire.get("created").and_then(Value::as_str)
    );
}

/// REQ-3.20-REV-X-01 — revoked id must not get a newer non-revoked version in the fixture.
pub fn assert_no_new_version_of_revoked_id() {
    for relative in REVOCATION_FIXTURES {
        let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
        let use_case_ids = use_case_object_ids(relative, &objects);
        for object_id in &use_case_ids {
            let same_id: Vec<_> = objects
                .iter()
                .filter(|o| o.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
                .collect();
            assert_eq!(same_id.len(), 1, "{relative}: revoked id must appear once");
            assert_eq!(same_id[0].get("revoked").and_then(Value::as_bool), Some(true));
            let non_revoked_same = objects.iter().any(|o| {
                o.get("id").and_then(Value::as_str) == Some(object_id.as_str())
                    && o.get("revoked").and_then(Value::as_bool) != Some(true)
            });
            assert!(!non_revoked_same, "{relative}: no non-revoked sibling for revoked id");
        }
    }
}

pub fn assert_producer_testcase_data() {
    for relative in REVOCATION_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|e| panic!("{relative}: {e}"));
    }
}

interop_test!("REQ-3.20-P-R-01", "use_cases::versioning::producer_revocation::select_content", select_content, { assert_select_content(); });
interop_test!("REQ-3.20-P-R-02", "use_cases::versioning::producer_revocation::identity_compliance", identity_compliance, { assert_identity_compliance(); });
interop_test!("REQ-3.20-P-R-03", "use_cases::versioning::producer_revocation::revoked_true", revoked_true, { assert_revoked_true(); });
interop_test!("REQ-3.20-P-R-04", "use_cases::versioning::producer_revocation::modified_after_created", modified_after_created, { assert_modified_after_created(); });
interop_test!("REQ-3.20-P-R-05", "use_cases::versioning::producer_revocation::created_preserved", created_preserved, { assert_created_preserved(); });
interop_test!("REQ-3.20-REV-X-01", "use_cases::versioning::producer_revocation::no_new_version_of_revoked_id", no_new_version_of_revoked_id, { assert_no_new_version_of_revoked_id(); });
interop_test!("REQ-CHK-SXP-3.20-R", "use_cases::versioning::producer_revocation::producer_testcase_data", producer_testcase_data, { assert_producer_testcase_data(); });
