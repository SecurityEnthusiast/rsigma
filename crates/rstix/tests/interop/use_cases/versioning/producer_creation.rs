//! §3.20.2–3.20.3 Versioning Creation producer support.

use crate::interop_test;
use rstix::core::StixId;
use rstix::model::sdo::Indicator;
use serde_json::Value;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};
use crate::use_cases::versioning::{
    CREATION_FIXTURES, FIXTURE_CREATE_INDICATOR, FIXTURE_CREATE_SIGHTING,
};

pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE_INDICATOR);
    let mut root: Value = serde_json::from_str(&fixture.json).unwrap();
    let objects = root
        .get_mut("objects")
        .and_then(Value::as_array_mut)
        .unwrap();
    let mut renamed = 0usize;
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("indicator") {
            object["name"] = Value::String("Caller-selected versioning Indicator".into());
            renamed += 1;
        }
    }
    assert_eq!(renamed, 1);
    let json = serde_json::to_string(&root).unwrap();
    let use_case_ids = use_case_object_ids(
        FIXTURE_CREATE_INDICATOR,
        &parse_fixture_objects(&json).unwrap(),
    );
    let bundle = validate_interop_json(
        &json,
        &InteropGateOptions {
            use_case_object_ids: use_case_ids.clone(),
        },
    )
    .unwrap();
    let stix_id = StixId::parse(&use_case_ids[0]).unwrap();
    let indicator = bundle.get_typed::<Indicator>(&stix_id).unwrap();
    assert_eq!(
        indicator.name.as_deref(),
        Some("Caller-selected versioning Indicator")
    );
}

pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE_INDICATOR;
    let objects = parse_fixture_objects(&load_fixture(relative).json).unwrap();
    let identities: Vec<_> = objects
        .iter()
        .filter(|o| o.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert!(!identities.is_empty());
    for identity in identities {
        assert_identity_shape(relative, identity);
    }
}

pub fn assert_create_indicator() {
    validate_interop_fixture(
        FIXTURE_CREATE_INDICATOR,
        &load_fixture(FIXTURE_CREATE_INDICATOR).json,
    )
    .unwrap();
}

pub fn assert_create_sighting() {
    validate_interop_fixture(
        FIXTURE_CREATE_SIGHTING,
        &load_fixture(FIXTURE_CREATE_SIGHTING).json,
    )
    .unwrap();
}

pub fn assert_producer_testcase_data() {
    for relative in CREATION_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json)
            .unwrap_or_else(|e| panic!("{relative}: {e}"));
    }
}

interop_test!(
    "REQ-3.20-P-C-01",
    "use_cases::versioning::producer_creation::select_content",
    select_content,
    {
        assert_select_content();
    }
);
interop_test!(
    "REQ-3.20-P-C-02",
    "use_cases::versioning::producer_creation::identity_compliance",
    identity_compliance,
    {
        assert_identity_compliance();
    }
);
interop_test!(
    "REQ-3.20-P-C-03",
    "use_cases::versioning::producer_creation::create_indicator",
    create_indicator,
    {
        assert_create_indicator();
    }
);
interop_test!(
    "REQ-3.20-P-C-04",
    "use_cases::versioning::producer_creation::create_sighting",
    create_sighting,
    {
        assert_create_sighting();
    }
);
interop_test!(
    "REQ-CHK-SXP-3.20-C",
    "use_cases::versioning::producer_creation::producer_testcase_data",
    producer_testcase_data,
    {
        assert_producer_testcase_data();
    }
);
