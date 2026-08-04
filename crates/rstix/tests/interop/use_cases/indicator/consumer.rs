//! §3.7.5 Required Consumer Persona Support (REQ-3.7-C-01..C-05).

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{Identity, Indicator};
use rstix::model::sro::Relationship;
use serde_json::Value;

use crate::common::fixture_catalog::{
    parse_fixture_objects, summarize_fixture_wire, use_case_object_ids,
};
use crate::common::wire_preservation::{
    assert_identity_fields_preserved, assert_wire_object_preserved,
};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::indicator::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn for_each_fixture(mut f: impl FnMut(&str)) {
    for relative in PRODUCER_FIXTURES {
        f(relative);
    }
}

/// REQ-3.7-C-01 — Consumer supports §3.7.2 Producer Persona properties on normative fixtures.
pub fn assert_supports_producer_props() {
    for_each_fixture(|relative| {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));

        for object_id in use_case_ids {
            let wire = objects
                .iter()
                .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
                .unwrap_or_else(|| panic!("{relative}: wire object {object_id}"));
            let stix_id = StixId::parse(&object_id).expect("object id");
            let indicator = bundle
                .get_typed::<Indicator>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed indicator {object_id}"));
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("indicator"));
            assert_eq!(
                wire.get("spec_version").and_then(Value::as_str),
                Some("2.1")
            );
            assert!(
                indicator.common.created_by_ref.is_some(),
                "{relative}: created_by_ref required"
            );
            assert!(
                indicator.name.is_some(),
                "{relative}: name required on normative indicator fixtures"
            );
            assert!(
                !indicator.indicator_types.is_empty(),
                "{relative}: indicator_types required"
            );
            assert_eq!(
                indicator.pattern.raw(),
                wire.get("pattern").and_then(Value::as_str).unwrap_or(""),
                "{relative}: pattern must match wire"
            );
            assert_eq!(
                indicator.pattern.pattern_type(),
                wire.get("pattern_type")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "{relative}: pattern_type must match wire"
            );
            assert_eq!(
                indicator.valid_from.to_rfc3339(),
                wire.get("valid_from").and_then(Value::as_str).unwrap_or(""),
                "{relative}: valid_from must match wire"
            );
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-3.7-C-02 — Consumer receives Identity and Indicator(s) (§3.7.3.1).
pub fn assert_receives_triad() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
    assert_eq!(summary.identity_ids.len(), 1);
    assert_eq!(summary.primary_sdo_count, 1, "single Indicator SDO");
    assert_eq!(summary.relationship_count, 0);

    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    for identity_id in &summary.identity_ids {
        let id = StixId::parse(identity_id).expect("identity id");
        assert!(
            bundle.get_typed::<Identity>(&id).is_some(),
            "{relative}: Identity {identity_id} must parse"
        );
    }
    assert_eq!(bundle.objects_of_type::<Indicator>().count(), 1);
}

/// REQ-3.7-C-03 — Consumer resolves `created_by_ref` Identity fields (§3.7.3.1).
pub fn assert_resolves_created_by_ref() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");

    let mut checked = 0usize;
    for object in &objects {
        let Some(created_by_ref) = object.get("created_by_ref").and_then(Value::as_str) else {
            continue;
        };
        let identity_id = StixId::parse(created_by_ref).expect("created_by_ref");
        let wire_identity = objects
            .iter()
            .find(|obj| obj.get("id").and_then(Value::as_str) == Some(created_by_ref))
            .expect("wire Identity for created_by_ref");
        assert!(
            bundle.get_typed::<Identity>(&identity_id).is_some(),
            "{relative}: created_by_ref `{created_by_ref}` must resolve"
        );
        assert_identity_fields_preserved(relative, wire_identity, &bundle, created_by_ref);
        checked += 1;
    }
    assert!(checked > 0, "{relative}: expected created_by_ref usage");
}

/// REQ-3.7-C-04 — Consumer processes Indicator fields via query + typed validate.
///
/// Distinct from C-01 (wire re-serialize preservation of Table 14 props): uses
/// [`QueryableStixObject::get_field`] for `pattern` / `valid_from` and runs
/// [`Indicator::validate`], matching query results to the wire object.
pub fn assert_processes_fields() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).expect("interop gate");

    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: one indicator use-case id"
    );
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).expect("indicator id");
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .unwrap_or_else(|| panic!("{relative}: wire indicator {object_id}"));
    let indicator = bundle
        .get_typed::<Indicator>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed indicator {object_id}"));

    indicator
        .validate()
        .unwrap_or_else(|err| panic!("{relative}: Indicator::validate: {err}"));

    match indicator.get_field(&["pattern"]) {
        Some(QueryValue::Str(pattern)) => {
            assert_eq!(
                pattern,
                indicator.pattern.raw(),
                "{relative}: get_field(pattern) mismatch"
            );
            assert_eq!(
                Some(pattern),
                wire.get("pattern").and_then(Value::as_str),
                "{relative}: get_field(pattern) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Str for pattern, got {other:?}"),
    }
    match indicator.get_field(&["valid_from"]) {
        Some(QueryValue::Timestamp(ts)) => {
            let typed = ts.to_rfc3339();
            assert_eq!(
                typed,
                indicator.valid_from.to_rfc3339(),
                "{relative}: get_field(valid_from) mismatch"
            );
            assert_eq!(
                Some(typed.as_str()),
                wire.get("valid_from").and_then(Value::as_str),
                "{relative}: get_field(valid_from) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Timestamp for valid_from, got {other:?}"),
    }
}

/// REQ-3.7-C-05 — Consumer processes related SDOs/SROs when present (§3.7.3.1 has none).
///
/// Distinct from description scope: asserts the consumer path when no SROs are bundled —
/// relationship count is zero and the Indicator pattern still resolves.
pub fn assert_processes_related() {
    let relative = FIXTURE_CREATE;
    let bundle =
        validate_interop_fixture(relative, &load_fixture(relative).json).expect("interop gate");
    assert_eq!(
        bundle.objects_of_type::<Relationship>().count(),
        0,
        "{relative}: normative fixture has no SROs"
    );
    let indicator = bundle
        .objects_of_type::<Indicator>()
        .next()
        .expect("indicator");
    assert_eq!(
        indicator.pattern.raw(),
        "[ipv4-addr:value = '198.51.100.1']",
        "{relative}: pattern must remain available when no related SROs are bundled"
    );
    assert_eq!(indicator.pattern.pattern_type(), "stix");
}

/// REQ-CHK-SXC-3.7 / §4.2 Table 55 — Consumer handles §3.7.3 Producer test case data.
pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: §3.7 consumer must handle producer test case: {err}")
        });

        assert!(
            !use_case_ids.is_empty(),
            "{relative}: expected indicator use-case object(s)"
        );
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).expect("indicator id");
            let indicator = bundle
                .get_typed::<Indicator>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed indicator {object_id}"));
            assert!(
                indicator.name.is_some(),
                "{relative}: name must survive consumer close"
            );
            assert!(
                !indicator.indicator_types.is_empty(),
                "{relative}: indicator_types must survive consumer close"
            );
            let created_by = indicator.common.created_by_ref.as_ref().unwrap_or_else(|| {
                panic!("{relative}: created_by_ref required for consumer close")
            });
            assert!(
                bundle
                    .get_typed::<Identity>(created_by.as_stix_id())
                    .is_some(),
                "{relative}: created_by_ref must resolve to typed Identity"
            );
        }
    }
}

interop_test!(
    "REQ-3.7-C-01",
    "use_cases::indicator::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);

interop_test!(
    "REQ-3.7-C-02",
    "use_cases::indicator::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);

interop_test!(
    "REQ-3.7-C-03",
    "use_cases::indicator::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-3.7-C-04",
    "use_cases::indicator::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);

interop_test!(
    "REQ-3.7-C-05",
    "use_cases::indicator::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);

interop_test!(
    "REQ-CHK-SXC-3.7",
    "use_cases::indicator::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
