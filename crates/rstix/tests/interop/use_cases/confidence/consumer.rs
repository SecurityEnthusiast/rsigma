//! §3.3.5 Required Consumer Persona Support (REQ-3.3-C-01..C-05).

use crate::interop_test;
use rstix::core::{Confidence, StixId};
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
use crate::use_cases::confidence::{FIXTURE_CREATE, PRODUCER_FIXTURES};

fn for_each_fixture(mut f: impl FnMut(&str)) {
    for relative in PRODUCER_FIXTURES {
        f(relative);
    }
}

/// REQ-3.3-C-01 — Consumer supports §3.3.2 Producer Persona properties on normative fixtures.
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
                indicator.common.confidence.is_some(),
                "{relative}: confidence required"
            );
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-3.3-C-02 — Consumer receives Identity and Indicator(s) with confidence (§3.3.3.1).
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
    let indicator = bundle.objects_of_type::<Indicator>().next().expect("indicator");
    assert!(indicator.common.confidence.is_some());
}

/// REQ-3.3-C-03 — Consumer resolves `created_by_ref` Identity fields (§3.3.3.1).
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

/// REQ-3.3-C-04 — Consumer processes Indicator confidence against wire (distinct from C-01).
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

    let typed_confidence = indicator
        .common
        .confidence
        .expect("{relative}: typed confidence required");
    let wire_confidence = wire
        .get("confidence")
        .and_then(Value::as_u64)
        .expect("wire confidence");
    assert_eq!(
        typed_confidence,
        Confidence::new(wire_confidence as u8).expect("valid confidence"),
        "{relative}: typed confidence must match wire"
    );
}

/// REQ-3.3-C-05 — Consumer processes related SDOs/SROs when present (§3.3.3.1 has none).
///
/// Distinct from description scope: asserts the consumer path when no SROs are bundled —
/// relationship count is zero and confidence on the Indicator still resolves.
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
        indicator.common.confidence,
        Some(Confidence::new(85).expect("valid confidence"))
    );
}

/// REQ-CHK-SXC-3.3 / §4.2 Table 55 — Consumer handles §3.3.3 Producer test case data.
pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: §3.3 consumer must handle producer test case: {err}")
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
                indicator.common.confidence.is_some(),
                "{relative}: confidence must survive consumer close"
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
    "REQ-3.3-C-01",
    "use_cases::confidence::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);

interop_test!(
    "REQ-3.3-C-02",
    "use_cases::confidence::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);

interop_test!(
    "REQ-3.3-C-03",
    "use_cases::confidence::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-3.3-C-04",
    "use_cases::confidence::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);

interop_test!(
    "REQ-3.3-C-05",
    "use_cases::confidence::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);

interop_test!(
    "REQ-CHK-SXC-3.3",
    "use_cases::confidence::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
