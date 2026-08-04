//! §3.6.5 Required Consumer Persona Support (REQ-3.6-C-01..C-05).

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{Grouping, Identity, Indicator};
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
use crate::use_cases::grouping::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn for_each_fixture(mut f: impl FnMut(&str)) {
    for relative in PRODUCER_FIXTURES {
        f(relative);
    }
}

/// REQ-3.6-C-01 — Consumer supports §3.6.2 Producer Persona properties on normative fixtures.
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
            let grouping = bundle
                .get_typed::<Grouping>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed grouping {object_id}"));
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("grouping"));
            assert_eq!(
                wire.get("spec_version").and_then(Value::as_str),
                Some("2.1")
            );
            assert!(
                grouping.common.created_by_ref.is_some(),
                "{relative}: created_by_ref required"
            );
            assert!(!grouping.context.is_empty(), "{relative}: context required");
            assert!(
                !grouping.object_refs.is_empty(),
                "{relative}: object_refs required"
            );
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-3.6-C-02 — Consumer receives Identity, Grouping, and referenced SDO(s) (§3.6.3.1).
pub fn assert_receives_triad() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
    assert_eq!(summary.identity_ids.len(), 1);
    assert_eq!(
        summary.primary_sdo_count, 2,
        "grouping + referenced indicator SDO"
    );
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
    assert_eq!(bundle.objects_of_type::<Grouping>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Indicator>().count(), 1);
}

/// REQ-3.6-C-03 — Consumer resolves `created_by_ref` Identity fields (§3.6.3.1).
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

/// REQ-3.6-C-04 — Consumer processes Grouping fields via query + typed validate.
///
/// Distinct from C-01 (wire re-serialize preservation of Table 12 props): uses
/// [`QueryableStixObject::get_field`] for `context` / `created_by_ref` and runs
/// [`Grouping::validate`], matching query results to the wire object.
pub fn assert_processes_fields() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).expect("interop gate");

    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: one grouping use-case id"
    );
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).expect("grouping id");
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .unwrap_or_else(|| panic!("{relative}: wire grouping {object_id}"));
    let grouping = bundle
        .get_typed::<Grouping>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed grouping {object_id}"));

    grouping
        .validate()
        .unwrap_or_else(|err| panic!("{relative}: Grouping::validate: {err}"));

    match grouping.get_field(&["context"]) {
        Some(QueryValue::Str(context)) => {
            assert_eq!(
                context,
                grouping.context.as_str(),
                "{relative}: get_field(context) mismatch"
            );
            assert_eq!(
                Some(context),
                wire.get("context").and_then(Value::as_str),
                "{relative}: get_field(context) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Str for context, got {other:?}"),
    }
    let created_by = grouping
        .common
        .created_by_ref
        .as_ref()
        .unwrap_or_else(|| panic!("{relative}: created_by_ref required for field processing"));
    match grouping.get_field(&["created_by_ref"]) {
        Some(QueryValue::Id(id)) => {
            assert_eq!(
                id,
                created_by.as_stix_id(),
                "{relative}: get_field(created_by_ref) mismatch"
            );
            assert_eq!(
                Some(id.as_str()),
                wire.get("created_by_ref").and_then(Value::as_str),
                "{relative}: get_field(created_by_ref) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Id for created_by_ref, got {other:?}"),
    }
}

/// REQ-3.6-C-05 — Consumer resolves related SDOs referenced in `object_refs` (§3.6.3.1).
///
/// Distinct from description scope: asserts the consumer path when no SROs are bundled —
/// the referenced Indicator must resolve and `object_refs` must match the wire bundle.
pub fn assert_processes_related() {
    let relative = FIXTURE_CREATE;
    let bundle =
        validate_interop_fixture(relative, &load_fixture(relative).json).expect("interop gate");
    assert_eq!(
        bundle.objects_of_type::<Relationship>().count(),
        0,
        "{relative}: normative fixture has no SROs"
    );
    let grouping = bundle
        .objects_of_type::<Grouping>()
        .next()
        .expect("grouping");
    assert_eq!(grouping.context, "suspicious-activity");
    assert_eq!(grouping.object_refs.len(), 1);
    let indicator_id = grouping.object_refs[0].clone();
    assert!(
        bundle.get_typed::<Indicator>(&indicator_id).is_some(),
        "{relative}: object_refs indicator must resolve to typed Indicator"
    );
}

/// REQ-CHK-SXC-3.6 / §4.2 Table 55 — Consumer handles §3.6.3 Producer test case data.
pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: §3.6 consumer must handle producer test case: {err}")
        });

        assert!(
            !use_case_ids.is_empty(),
            "{relative}: expected grouping use-case object(s)"
        );
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).expect("grouping id");
            let grouping = bundle
                .get_typed::<Grouping>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed grouping {object_id}"));
            let created_by = grouping.common.created_by_ref.as_ref().unwrap_or_else(|| {
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
    "REQ-3.6-C-01",
    "use_cases::grouping::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);

interop_test!(
    "REQ-3.6-C-02",
    "use_cases::grouping::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);

interop_test!(
    "REQ-3.6-C-03",
    "use_cases::grouping::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-3.6-C-04",
    "use_cases::grouping::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);

interop_test!(
    "REQ-3.6-C-05",
    "use_cases::grouping::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);

interop_test!(
    "REQ-CHK-SXC-3.6",
    "use_cases::grouping::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
