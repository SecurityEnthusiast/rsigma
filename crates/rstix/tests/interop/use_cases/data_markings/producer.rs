//! §3.5.2 Required Producer Persona Support (REQ-3.5-P-01..P-04).
//!
//! Table 10 (CSD01) consolidates data-markings producer requirements: apply object-level TLP
//! markings to Indicators, Identity §2.3.4 compliance, and STIX §4.7 Indicator conformance —
//! no per-property Table rows.

use crate::interop_test;
use rstix::core::StixId;
use rstix::model::meta::TLP1_WHITE_ID;
use rstix::model::sdo::Indicator;
use rstix::model::{Bundle, ParseOptions};
use rstix::validate::{Leniency, Validator};
use serde_json::Value;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};
use crate::use_cases::data_markings::{FIXTURE_CREATE, PRODUCER_FIXTURES};

/// REQ-3.5-P-01 — Producer creates STIX content with object-level TLP marking (§3.5.3.1).
pub fn assert_create_content() {
    validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json)
        .expect("§3.5.3.1 must pass interop producer gate");
}

/// REQ-3.5-P-02 — Caller-selected object set parses and re-validates.
pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let mut root: Value = serde_json::from_str(&fixture.json).expect("parse bundle JSON");
    let objects = root
        .get_mut("objects")
        .and_then(Value::as_array_mut)
        .expect("objects array");
    let mut renamed = 0usize;
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("indicator") {
            object["name"] = Value::String("Caller-selected Indicator name".into());
            renamed += 1;
        }
    }
    assert_eq!(
        renamed, 1,
        "expected exactly one indicator object renamed by caller selection"
    );
    let json = serde_json::to_string(&root).expect("serialize caller-selected bundle");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &parse_fixture_objects(&json).unwrap());
    let bundle = validate_interop_json(
        &json,
        &InteropGateOptions {
            use_case_object_ids: use_case_ids.clone(),
        },
    )
    .expect("caller-selected bundle must pass interop gate");
    assert_eq!(
        use_case_ids.len(),
        1,
        "caller-selected bundle must expose one indicator use-case id"
    );
    let stix_id = StixId::parse(&use_case_ids[0]).expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&stix_id)
        .expect("typed indicator after caller selection");
    assert_eq!(
        indicator.name.as_deref(),
        Some("Caller-selected Indicator name"),
        "caller-selected name must survive parse and re-validation"
    );
    assert_eq!(
        indicator.common.object_marking_refs.len(),
        1,
        "caller-selected indicator must retain exactly one TLP object_marking_refs entry"
    );
}

/// REQ-3.5-P-03 — Identity in bundle complies with §2.3.4.
pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let identities: Vec<_> = objects
        .iter()
        .filter(|obj| obj.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert_eq!(
        identities.len(),
        2,
        "{relative}: expected two Identity objects"
    );
    for identity in identities {
        assert_identity_shape(relative, identity);
    }
}

/// REQ-3.5-P-04 — Indicator with TLP marking conforms to STIX §4.7 (typed validate + strict report).
///
/// Distinct from P-01: does **not** call the interop gate/overlay.
pub fn assert_spec_conformance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let bundle = Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .unwrap_or_else(|err| panic!("{relative}: parse for §4.7 check: {err}"));

    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture objects");
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one indicator use-case id"
    );
    let object_id = &use_case_ids[0];
    let indicator_id = StixId::parse(object_id).expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&indicator_id)
        .unwrap_or_else(|| panic!("{relative}: typed indicator {object_id}"));
    indicator
        .validate()
        .unwrap_or_else(|err| panic!("{relative}: Indicator::validate (§4.7): {err}"));
    assert_eq!(
        indicator.common.object_marking_refs.len(),
        1,
        "{relative}: exactly one TLP object_marking_refs entry required for §3.5 conformance"
    );
    assert_eq!(
        indicator.common.object_marking_refs[0]
            .as_stix_id()
            .as_str(),
        TLP1_WHITE_ID
    );

    let report = Validator::interop_bundle_strict().validate_bundle(&bundle);
    let errors: Vec<_> = report.errors().collect();
    assert!(
        errors.is_empty(),
        "{relative}: MUST Error diagnostics present: {errors:?}"
    );

    let scoped_zero_failures: Vec<_> = report
        .diagnostics()
        .filter(|d| {
            d.object_id.as_ref() == Some(&indicator_id)
                && Leniency::Zero.fails_validation(d.severity)
                // §3.5 normative fixtures use TLP 1.x marking-definition ids; STIX-W0031 is expected.
                && d.code.as_str() != "STIX-W0031"
        })
        .collect();
    assert!(
        scoped_zero_failures.is_empty(),
        "{relative}: Zero-failing diagnostics on Indicator {object_id}: {scoped_zero_failures:?}"
    );
}

/// REQ-CHK-SXP-3.5 / §4.2 Table 56 — Producer test case data (§3.5.3.1..3.5.3.4).
pub fn assert_producer_testcase_data() {
    for relative in PRODUCER_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|err| {
            panic!("{relative}: §3.5.3 producer test case must pass interop gate: {err}")
        });
    }
}

interop_test!(
    "REQ-3.5-P-01",
    "use_cases::data_markings::producer::create_content",
    create_content,
    {
        assert_create_content();
    }
);

interop_test!(
    "REQ-3.5-P-02",
    "use_cases::data_markings::producer::select_content",
    select_content,
    {
        assert_select_content();
    }
);

interop_test!(
    "REQ-3.5-P-03",
    "use_cases::data_markings::producer::identity_compliance",
    identity_compliance,
    {
        assert_identity_compliance();
    }
);

interop_test!(
    "REQ-3.5-P-04",
    "use_cases::data_markings::producer::spec_conformance",
    spec_conformance,
    {
        assert_spec_conformance();
    }
);

interop_test!(
    "REQ-CHK-SXP-3.5",
    "use_cases::data_markings::producer::producer_testcase_data",
    producer_testcase_data,
    {
        assert_producer_testcase_data();
    }
);
