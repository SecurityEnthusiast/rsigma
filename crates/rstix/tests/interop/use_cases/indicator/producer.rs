//! §3.7.2 Required Producer Persona Support (REQ-3.7-P-01..P-15).
//!
//! Table 14 (CSD01) lists Indicator producer properties in STIX §4.7 field order.

use crate::interop_test;
use rstix::core::{SpecVersion, StixId};
use rstix::model::sdo::Indicator;
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
use crate::use_cases::indicator::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn load_indicator(relative: &str) -> (Indicator, String) {
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one indicator use-case object for primary property checks"
    );
    let object_id = use_case_ids.into_iter().next().expect("indicator id");
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let stix_id = StixId::parse(&object_id).expect("indicator id");
    let indicator = bundle
        .get_typed::<Indicator>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed indicator {object_id}"))
        .clone();
    (indicator, object_id)
}

/// REQ-3.7-P-01 — Producer creates Indicator content (§3.7.3.1).
pub fn assert_create_indicator() {
    validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json)
        .expect("§3.7.3.1 must pass interop producer gate");
}

/// REQ-3.7-P-02 — Caller-selected object set parses and re-validates (not UI-level select/specify).
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
}

/// REQ-3.7-P-03 — Identity in bundle complies with §2.3.4 (fixture-scoped; not a duplicate §2.3 proof).
pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let identities: Vec<_> = objects
        .iter()
        .filter(|obj| obj.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert_eq!(identities.len(), 1, "{relative}: expected one Identity");
    assert_identity_shape(relative, identities[0]);
}

/// REQ-3.7-P-04 — Indicator conforms to STIX §4.7 (typed validate + strict report).
///
/// Distinct from P-01: does **not** call the interop gate/overlay. Parses the fixture,
/// runs [`Indicator::validate`], then requires [`Validator::interop_bundle_strict`]
/// to report valid under Zero leniency (no MUST Error / Zero-failing Warning), including
/// any diagnostic scoped to this Indicator id.
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
        })
        .collect();
    assert!(
        scoped_zero_failures.is_empty(),
        "{relative}: Zero-failing diagnostics on Indicator {object_id}: {scoped_zero_failures:?}"
    );

    assert!(
        report.is_valid(),
        "{relative}: interop_bundle_strict (no overlay) must be valid: {:?}",
        report.diagnostics().collect::<Vec<_>>()
    );
}

/// REQ-3.7-P-05 — wire `type` is `indicator`.
pub fn assert_prop_type() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_indicator, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    assert_eq!(
        wire.get("type").and_then(Value::as_str),
        Some("indicator"),
        "wire type must be indicator (STIX §4.7)"
    );
}

/// REQ-3.7-P-06 — `spec_version` is `2.1`.
pub fn assert_prop_spec_version() {
    let (indicator, _) = load_indicator(FIXTURE_CREATE);
    assert_eq!(indicator.common.spec_version, SpecVersion::V2_1);
}

/// REQ-3.7-P-07 — `id` is a UUID with `indicator--` prefix.
pub fn assert_prop_id() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{FIXTURE_CREATE}: expected one indicator use-case id"
    );
    let wire_id = &use_case_ids[0];
    assert!(
        wire_id.starts_with("indicator--"),
        "id must use indicator-- prefix: {wire_id}"
    );
    StixId::parse(wire_id).expect("wire id must be valid STIX id");
}

/// REQ-3.7-P-08 — `created_by_ref` points at the Producer Identity.
pub fn assert_prop_created_by_ref() {
    let (indicator, _) = load_indicator(FIXTURE_CREATE);
    let created_by = indicator
        .common
        .created_by_ref
        .as_ref()
        .expect("interop-mandatory created_by_ref");
    assert!(
        created_by.as_stix_id().as_str().starts_with("identity--"),
        "created_by_ref must reference Identity: {}",
        created_by.as_stix_id().as_str()
    );
}

/// REQ-3.7-P-09 — `created` timestamp is present (exactly three subsecond digits).
pub fn assert_prop_created() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    let created = wire
        .get("created")
        .and_then(Value::as_str)
        .expect("created timestamp");
    assert_millisecond_rfc3339("created", created);
}

/// REQ-3.7-P-10 — `modified` timestamp is present (exactly three subsecond digits).
pub fn assert_prop_modified() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    let modified = wire
        .get("modified")
        .and_then(Value::as_str)
        .expect("modified timestamp");
    assert_millisecond_rfc3339("modified", modified);
}

/// REQ-3.7-P-11 — `valid_from` is the validity start for the Indicator.
pub fn assert_prop_valid_from() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (indicator, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    let wire_valid_from = wire
        .get("valid_from")
        .and_then(Value::as_str)
        .expect("valid_from timestamp");
    assert_millisecond_rfc3339("valid_from", wire_valid_from);
    assert_eq!(
        indicator.valid_from.to_rfc3339(),
        wire_valid_from,
        "typed valid_from must match wire"
    );
}

/// REQ-3.7-P-12 — `name` identifies the Indicator.
pub fn assert_prop_name() {
    let (indicator, _) = load_indicator(FIXTURE_CREATE);
    assert_eq!(
        indicator.name.as_deref(),
        Some("Bad IP1"),
        "interop-mandatory name from §3.7.3.1"
    );
}

/// REQ-3.7-P-13 — `pattern` is the detection pattern for the Indicator.
pub fn assert_prop_pattern() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (indicator, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    let wire_pattern = wire
        .get("pattern")
        .and_then(Value::as_str)
        .expect("pattern");
    assert_eq!(
        indicator.pattern.raw(),
        wire_pattern,
        "typed pattern must match wire"
    );
    assert!(
        !wire_pattern.is_empty(),
        "interop-mandatory non-empty pattern"
    );
}

/// REQ-3.7-P-14 — `pattern_type` is the pattern language used in the Indicator.
pub fn assert_prop_pattern_type() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (indicator, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    assert_eq!(
        indicator.pattern.pattern_type(),
        wire
            .get("pattern_type")
            .and_then(Value::as_str)
            .expect("pattern_type"),
        "typed pattern_type must match wire"
    );
    assert_eq!(indicator.pattern.pattern_type(), "stix");
}

/// REQ-3.7-P-15 — `indicator_types` categorizes the Indicator (indicator-type-ov).
pub fn assert_prop_indicator_types() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (indicator, object_id) = load_indicator(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire indicator");
    let wire_types: Vec<_> = wire
        .get("indicator_types")
        .and_then(Value::as_array)
        .expect("indicator_types array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !indicator.indicator_types.is_empty(),
        "interop-mandatory non-empty indicator_types"
    );
    assert_eq!(indicator.indicator_types, wire_types);
    assert_eq!(indicator.indicator_types, vec!["malicious-activity"]);
}

/// REQ-CHK-SXP-3.7 / §4.2 Table 56 — Producer test case data (§3.7.3.1–§3.7.3.10).
pub fn assert_producer_testcase_data() {
    for relative in PRODUCER_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|err| {
            panic!("{relative}: §3.7.3 producer test case must pass interop gate: {err}")
        });
    }
}

interop_test!(
    "REQ-3.7-P-01",
    "use_cases::indicator::producer::create_indicator",
    create_indicator,
    {
        assert_create_indicator();
    }
);

interop_test!(
    "REQ-3.7-P-02",
    "use_cases::indicator::producer::select_content",
    select_content,
    {
        assert_select_content();
    }
);

interop_test!(
    "REQ-3.7-P-03",
    "use_cases::indicator::producer::identity_compliance",
    identity_compliance,
    {
        assert_identity_compliance();
    }
);

interop_test!(
    "REQ-3.7-P-04",
    "use_cases::indicator::producer::spec_conformance",
    spec_conformance,
    {
        assert_spec_conformance();
    }
);

interop_test!(
    "REQ-3.7-P-05",
    "use_cases::indicator::producer::prop_type",
    prop_type,
    {
        assert_prop_type();
    }
);

interop_test!(
    "REQ-3.7-P-06",
    "use_cases::indicator::producer::prop_spec_version",
    prop_spec_version,
    {
        assert_prop_spec_version();
    }
);

interop_test!(
    "REQ-3.7-P-07",
    "use_cases::indicator::producer::prop_id",
    prop_id,
    {
        assert_prop_id();
    }
);

interop_test!(
    "REQ-3.7-P-08",
    "use_cases::indicator::producer::prop_created_by_ref",
    prop_created_by_ref,
    {
        assert_prop_created_by_ref();
    }
);

interop_test!(
    "REQ-3.7-P-09",
    "use_cases::indicator::producer::prop_created",
    prop_created,
    {
        assert_prop_created();
    }
);

interop_test!(
    "REQ-3.7-P-10",
    "use_cases::indicator::producer::prop_modified",
    prop_modified,
    {
        assert_prop_modified();
    }
);

interop_test!(
    "REQ-3.7-P-11",
    "use_cases::indicator::producer::prop_valid_from",
    prop_valid_from,
    {
        assert_prop_valid_from();
    }
);

interop_test!(
    "REQ-3.7-P-12",
    "use_cases::indicator::producer::prop_name",
    prop_name,
    {
        assert_prop_name();
    }
);

interop_test!(
    "REQ-3.7-P-13",
    "use_cases::indicator::producer::prop_pattern",
    prop_pattern,
    {
        assert_prop_pattern();
    }
);

interop_test!(
    "REQ-3.7-P-14",
    "use_cases::indicator::producer::prop_pattern_type",
    prop_pattern_type,
    {
        assert_prop_pattern_type();
    }
);

interop_test!(
    "REQ-3.7-P-15",
    "use_cases::indicator::producer::prop_indicator_types",
    prop_indicator_types,
    {
        assert_prop_indicator_types();
    }
);

interop_test!(
    "REQ-CHK-SXP-3.7",
    "use_cases::indicator::producer::producer_testcase_data",
    producer_testcase_data,
    {
        assert_producer_testcase_data();
    }
);
