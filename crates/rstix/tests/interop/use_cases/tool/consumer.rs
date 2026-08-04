//! §3.19.5 Required Consumer Persona Support (REQ-3.19-C-01..C-05).

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{Identity, Tool};
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
use crate::use_cases::tool::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn for_each_fixture(mut f: impl FnMut(&str)) {
    for relative in PRODUCER_FIXTURES {
        f(relative);
    }
}

/// REQ-3.19-C-01 — Consumer supports §3.19.2 Producer Persona properties on normative fixtures.
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
            let tool = bundle
                .get_typed::<Tool>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed tool {object_id}"));
            assert_eq!(wire.get("type").and_then(Value::as_str), Some("tool"));
            assert_eq!(
                wire.get("spec_version").and_then(Value::as_str),
                Some("2.1")
            );
            assert!(
                tool.common.created_by_ref.is_some(),
                "{relative}: created_by_ref required"
            );
            assert!(!tool.name.is_empty(), "{relative}: name required");
            assert_eq!(
                tool.tool_types,
                wire.get("tool_types")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                "{relative}: tool_types must match wire"
            );
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-3.19-C-02 — Consumer receives Identity and Tool(s) (§3.19.3.1).
pub fn assert_receives_triad() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
    assert_eq!(summary.identity_ids.len(), 1);
    assert_eq!(summary.primary_sdo_count, 1, "single Tool SDO");
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
    assert_eq!(bundle.objects_of_type::<Tool>().count(), 1);
}

/// REQ-3.19-C-03 — Consumer resolves `created_by_ref` Identity fields (§3.19.3.1).
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

/// REQ-3.19-C-04 — Consumer processes Tool fields via query + typed validate.
///
/// Distinct from C-01 (wire re-serialize preservation of Table 38 props): uses
/// [`QueryableStixObject::get_field`] for `name` / `created_by_ref` and runs
/// [`Tool::validate`], matching query results to the wire object.
pub fn assert_processes_fields() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).expect("interop gate");

    assert_eq!(use_case_ids.len(), 1, "{relative}: one tool use-case id");
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).expect("tool id");
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .unwrap_or_else(|| panic!("{relative}: wire tool {object_id}"));
    let tool = bundle
        .get_typed::<Tool>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed tool {object_id}"));

    tool.validate()
        .unwrap_or_else(|err| panic!("{relative}: Tool::validate: {err}"));

    match tool.get_field(&["name"]) {
        Some(QueryValue::Str(name)) => {
            assert_eq!(
                name,
                tool.name.as_str(),
                "{relative}: get_field(name) mismatch"
            );
            assert_eq!(
                Some(name),
                wire.get("name").and_then(Value::as_str),
                "{relative}: get_field(name) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Str for name, got {other:?}"),
    }
    let created_by = tool
        .common
        .created_by_ref
        .as_ref()
        .unwrap_or_else(|| panic!("{relative}: created_by_ref required for field processing"));
    match tool.get_field(&["created_by_ref"]) {
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

/// REQ-3.19-C-05 — Consumer processes related SDOs/SROs when present (§3.19.3.1 has none).
///
/// Distinct from description scope: asserts the consumer path when no SROs are bundled —
/// relationship count is zero and the Tool name still resolves.
pub fn assert_processes_related() {
    let relative = FIXTURE_CREATE;
    let bundle =
        validate_interop_fixture(relative, &load_fixture(relative).json).expect("interop gate");
    assert_eq!(
        bundle.objects_of_type::<Relationship>().count(),
        0,
        "{relative}: normative fixture has no SROs"
    );
    let tool = bundle.objects_of_type::<Tool>().next().expect("tool");
    assert_eq!(tool.name, "VNC");
}

/// REQ-CHK-SXC-3.19 / §4.2 Table 55 — Consumer handles §3.19.3 Producer test case data.
pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: §3.19 consumer must handle producer test case: {err}")
        });

        assert!(
            !use_case_ids.is_empty(),
            "{relative}: expected tool use-case object(s)"
        );
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).expect("tool id");
            let tool = bundle
                .get_typed::<Tool>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed tool {object_id}"));
            let created_by = tool.common.created_by_ref.as_ref().unwrap_or_else(|| {
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
    "REQ-3.19-C-01",
    "use_cases::tool::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);

interop_test!(
    "REQ-3.19-C-02",
    "use_cases::tool::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);

interop_test!(
    "REQ-3.19-C-03",
    "use_cases::tool::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-3.19-C-04",
    "use_cases::tool::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);

interop_test!(
    "REQ-3.19-C-05",
    "use_cases::tool::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);

interop_test!(
    "REQ-CHK-SXC-3.19",
    "use_cases::tool::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
