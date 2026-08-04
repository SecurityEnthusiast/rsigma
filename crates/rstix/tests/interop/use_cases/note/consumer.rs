//! §3.13.5 Required Consumer Persona Support (REQ-3.13-C-01..C-05).

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{Identity, Note, ThreatActor};
use rstix::model::sro::{Relationship, Sighting};
use serde_json::Value;

use crate::common::fixture_catalog::{
    parse_fixture_objects, summarize_fixture_wire, use_case_object_ids,
};
use crate::common::wire_preservation::{
    assert_identity_fields_preserved, assert_wire_object_preserved,
};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::note::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn for_each_fixture(mut f: impl FnMut(&str)) {
    for relative in PRODUCER_FIXTURES {
        f(relative);
    }
}

/// REQ-3.13-C-01 — Consumer supports §3.13.2 Producer Persona properties on normative fixtures.
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
            let note = bundle
                .get_typed::<Note>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed note {object_id}"));
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("note"));
            assert_eq!(
                wire.get("spec_version").and_then(Value::as_str),
                Some("2.1")
            );
            assert!(
                note.common.created_by_ref.is_some(),
                "{relative}: created_by_ref required"
            );
            assert!(!note.content.is_empty(), "{relative}: content required");
            assert!(!note.object_refs.is_empty(), "{relative}: object_refs required");
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-3.13-C-02 — Consumer receives Identity, Note(s), and referenced SDOs (§3.13.3.1).
pub fn assert_receives_triad() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
    assert_eq!(summary.identity_ids.len(), 1);
    assert_eq!(summary.primary_sdo_count, 2, "note + threat-actor");
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
    assert_eq!(bundle.objects_of_type::<Note>().count(), 1);
    assert_eq!(bundle.objects_of_type::<ThreatActor>().count(), 1);
}

/// REQ-3.13-C-03 — Consumer resolves `created_by_ref` Identity fields (§3.13.3.1).
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

/// REQ-3.13-C-04 — Consumer processes Note fields via query + typed validate.
pub fn assert_processes_fields() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).expect("interop gate");

    assert_eq!(use_case_ids.len(), 1, "{relative}: one note use-case id");
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).expect("note id");
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .unwrap_or_else(|| panic!("{relative}: wire note {object_id}"));
    let note = bundle
        .get_typed::<Note>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed note {object_id}"));

    note.validate()
        .unwrap_or_else(|err| panic!("{relative}: Note::validate: {err}"));

    match note.get_field(&["content"]) {
        Some(QueryValue::Str(content)) => {
            assert_eq!(
                content,
                note.content.as_str(),
                "{relative}: get_field(content) mismatch"
            );
            assert_eq!(
                Some(content),
                wire.get("content").and_then(Value::as_str),
                "{relative}: get_field(content) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Str for content, got {other:?}"),
    }
    match note.get_field(&["created_by_ref"]) {
        Some(QueryValue::Id(id)) => {
            let created_by = note
                .common
                .created_by_ref
                .as_ref()
                .expect("created_by_ref required");
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

/// REQ-3.13-C-05 — Consumer resolves related SDOs referenced by `object_refs` (§3.13.3.1).
pub fn assert_processes_related() {
    let relative = FIXTURE_CREATE;
    let bundle =
        validate_interop_fixture(relative, &load_fixture(relative).json).expect("interop gate");
    assert_eq!(
        bundle.objects_of_type::<Relationship>().count(),
        0,
        "{relative}: normative fixture has no SRO relationships"
    );
    assert_eq!(
        bundle.objects_of_type::<Sighting>().count(),
        0,
        "{relative}: normative fixture has no sightings"
    );
    let note = bundle.objects_of_type::<Note>().next().expect("note");
    assert_eq!(note.object_refs.len(), 1);
    let target_id = &note.object_refs[0];
    let threat_actor = bundle
        .get_typed::<ThreatActor>(target_id)
        .expect("object_refs threat-actor must resolve");
    assert_eq!(threat_actor.name, "Evil Org");
}

/// REQ-CHK-SXC-3.13 / §4.2 Table 55 — Consumer handles §3.13.3 Producer test case data.
pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: §3.13 consumer must handle producer test case: {err}")
        });

        assert!(
            !use_case_ids.is_empty(),
            "{relative}: expected note use-case object(s)"
        );
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).expect("note id");
            let note = bundle
                .get_typed::<Note>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed note {object_id}"));
            let created_by = note.common.created_by_ref.as_ref().unwrap_or_else(|| {
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
    "REQ-3.13-C-01",
    "use_cases::note::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);

interop_test!(
    "REQ-3.13-C-02",
    "use_cases::note::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);

interop_test!(
    "REQ-3.13-C-03",
    "use_cases::note::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-3.13-C-04",
    "use_cases::note::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);

interop_test!(
    "REQ-3.13-C-05",
    "use_cases::note::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);

interop_test!(
    "REQ-CHK-SXC-3.13",
    "use_cases::note::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
