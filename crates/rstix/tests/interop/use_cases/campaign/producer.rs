//! §3.2.2 Required Producer Persona Support (REQ-3.2-P-01..P-11).
//!
//! Table 4 (CSD01) lists Campaign producer properties. The published table text
//! erroneously says `type` must be `threat-actor`; STIX §4.2 and the Campaign
//! test cases require `campaign`. Tests enforce `campaign`.

use crate::interop_test;
use rstix::core::{SpecVersion, StixId};
use rstix::model::sdo::Campaign;
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
use crate::use_cases::campaign::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn load_campaign(relative: &str) -> (Campaign, String) {
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one campaign use-case object"
    );
    let object_id = use_case_ids.into_iter().next().expect("campaign id");
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let stix_id = StixId::parse(&object_id).expect("campaign id");
    let campaign = bundle
        .get_typed::<Campaign>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed campaign {object_id}"))
        .clone();
    (campaign, object_id)
}

/// REQ-3.2-P-01 — Producer creates Campaign content (§3.2.3.1).
pub fn assert_create_campaign() {
    validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json)
        .expect("§3.2.3.1 must pass interop producer gate");
}

/// REQ-3.2-P-02 — Caller-selected object set parses and re-validates (not UI-level select/specify).
pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let mut root: Value = serde_json::from_str(&fixture.json).expect("parse bundle JSON");
    let objects = root
        .get_mut("objects")
        .and_then(Value::as_array_mut)
        .expect("objects array");
    let mut renamed = 0usize;
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("campaign") {
            object["name"] = Value::String("Caller-selected Campaign name".into());
            renamed += 1;
        }
    }
    assert_eq!(
        renamed, 1,
        "expected exactly one campaign object renamed by caller selection"
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
        "caller-selected bundle must expose one campaign use-case id"
    );
    let stix_id = StixId::parse(&use_case_ids[0]).expect("campaign id");
    let campaign = bundle
        .get_typed::<Campaign>(&stix_id)
        .expect("typed campaign after caller selection");
    assert_eq!(
        campaign.name, "Caller-selected Campaign name",
        "caller-selected name must survive parse and re-validation"
    );
}

/// REQ-3.2-P-03 — Identity in bundle complies with §2.3.4 (fixture-scoped; not a duplicate §2.3 proof).
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

/// REQ-3.2-P-04 — Campaign conforms to STIX §4.2 (typed validate + strict report).
///
/// Distinct from P-01: does **not** call the interop gate/overlay. Parses the fixture,
/// runs [`Campaign::validate`], then requires [`Validator::interop_bundle_strict`]
/// to report valid under Zero leniency (no MUST Error / Zero-failing Warning), including
/// any diagnostic scoped to this Campaign id.
pub fn assert_spec_conformance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let bundle = Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .unwrap_or_else(|err| panic!("{relative}: parse for §4.2 check: {err}"));

    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture objects");
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one campaign use-case id"
    );
    let object_id = &use_case_ids[0];
    let campaign_id = StixId::parse(object_id).expect("campaign id");
    let campaign = bundle
        .get_typed::<Campaign>(&campaign_id)
        .unwrap_or_else(|| panic!("{relative}: typed campaign {object_id}"));
    campaign
        .validate()
        .unwrap_or_else(|err| panic!("{relative}: Campaign::validate (§4.2): {err}"));

    let report = Validator::interop_bundle_strict().validate_bundle(&bundle);

    let errors: Vec<_> = report.errors().collect();
    assert!(
        errors.is_empty(),
        "{relative}: MUST Error diagnostics present: {errors:?}"
    );

    // Scoped Zero failures only via structured `object_id` (no Display/message matching).
    let scoped_zero_failures: Vec<_> = report
        .diagnostics()
        .filter(|d| {
            d.object_id.as_ref() == Some(&campaign_id)
                && Leniency::Zero.fails_validation(d.severity)
        })
        .collect();
    assert!(
        scoped_zero_failures.is_empty(),
        "{relative}: Zero-failing diagnostics on Campaign {object_id}: {scoped_zero_failures:?}"
    );

    assert!(
        report.is_valid(),
        "{relative}: interop_bundle_strict (no overlay) must be valid: {:?}",
        report.diagnostics().collect::<Vec<_>>()
    );
}

/// REQ-3.2-P-05 — wire `type` is `campaign` (OASIS Table 4 typo says `threat-actor`).
pub fn assert_prop_type() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_campaign, object_id) = load_campaign(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire campaign");
    assert_eq!(
        wire.get("type").and_then(Value::as_str),
        Some("campaign"),
        "wire type must be campaign (STIX §4.2; Table 4 CSD01 typo ignored)"
    );
}

/// REQ-3.2-P-06 — `spec_version` is `2.1`.
pub fn assert_prop_spec_version() {
    let (campaign, _) = load_campaign(FIXTURE_CREATE);
    assert_eq!(campaign.common.spec_version, SpecVersion::V2_1);
}

/// REQ-3.2-P-07 — `id` is a UUID with `campaign--` prefix.
pub fn assert_prop_id() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{FIXTURE_CREATE}: expected one campaign use-case id"
    );
    let wire_id = &use_case_ids[0];
    assert!(
        wire_id.starts_with("campaign--"),
        "id must use campaign-- prefix: {wire_id}"
    );
    StixId::parse(wire_id).expect("wire id must be valid STIX id");
}

/// REQ-3.2-P-08 — `created_by_ref` points at the Producer Identity.
pub fn assert_prop_created_by_ref() {
    let (campaign, _) = load_campaign(FIXTURE_CREATE);
    let created_by = campaign
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

/// REQ-3.2-P-09 — `created` timestamp is present (exactly three subsecond digits).
pub fn assert_prop_created() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_campaign(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire campaign");
    let created = wire
        .get("created")
        .and_then(Value::as_str)
        .expect("created timestamp");
    assert_millisecond_rfc3339("created", created);
}

/// REQ-3.2-P-10 — `modified` timestamp is present (exactly three subsecond digits).
pub fn assert_prop_modified() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_campaign(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire campaign");
    let modified = wire
        .get("modified")
        .and_then(Value::as_str)
        .expect("modified timestamp");
    assert_millisecond_rfc3339("modified", modified);
}

/// REQ-3.2-P-11 — `name` identifies the Campaign.
pub fn assert_prop_name() {
    let (campaign, _) = load_campaign(FIXTURE_CREATE);
    assert!(!campaign.name.is_empty(), "interop-mandatory name");
}

/// REQ-CHK-SXP-3.2 / §4.2 Table 56 — Producer test case data (§3.2.3.1 and §3.2.3.2).
pub fn assert_producer_testcase_data() {
    for relative in PRODUCER_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|err| {
            panic!("{relative}: §3.2.3 producer test case must pass interop gate: {err}")
        });
    }
}

interop_test!(
    "REQ-3.2-P-01",
    "use_cases::campaign::producer::create_campaign",
    create_campaign,
    {
        assert_create_campaign();
    }
);

interop_test!(
    "REQ-3.2-P-02",
    "use_cases::campaign::producer::select_content",
    select_content,
    {
        assert_select_content();
    }
);

interop_test!(
    "REQ-3.2-P-03",
    "use_cases::campaign::producer::identity_compliance",
    identity_compliance,
    {
        assert_identity_compliance();
    }
);

interop_test!(
    "REQ-3.2-P-04",
    "use_cases::campaign::producer::spec_conformance",
    spec_conformance,
    {
        assert_spec_conformance();
    }
);

interop_test!(
    "REQ-3.2-P-05",
    "use_cases::campaign::producer::prop_type",
    prop_type,
    {
        assert_prop_type();
    }
);

interop_test!(
    "REQ-3.2-P-06",
    "use_cases::campaign::producer::prop_spec_version",
    prop_spec_version,
    {
        assert_prop_spec_version();
    }
);

interop_test!(
    "REQ-3.2-P-07",
    "use_cases::campaign::producer::prop_id",
    prop_id,
    {
        assert_prop_id();
    }
);

interop_test!(
    "REQ-3.2-P-08",
    "use_cases::campaign::producer::prop_created_by_ref",
    prop_created_by_ref,
    {
        assert_prop_created_by_ref();
    }
);

interop_test!(
    "REQ-3.2-P-09",
    "use_cases::campaign::producer::prop_created",
    prop_created,
    {
        assert_prop_created();
    }
);

interop_test!(
    "REQ-3.2-P-10",
    "use_cases::campaign::producer::prop_modified",
    prop_modified,
    {
        assert_prop_modified();
    }
);

interop_test!(
    "REQ-3.2-P-11",
    "use_cases::campaign::producer::prop_name",
    prop_name,
    {
        assert_prop_name();
    }
);

interop_test!(
    "REQ-CHK-SXP-3.2",
    "use_cases::campaign::producer::producer_testcase_data",
    producer_testcase_data,
    {
        assert_producer_testcase_data();
    }
);
