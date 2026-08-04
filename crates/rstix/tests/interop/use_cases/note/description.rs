//! §3.13.1 Description — Note Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::Note;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::note::FIXTURE_CREATE;

/// REQ-3.13-1 — §3.13.1 Description.
///
/// Doc: a Note conveys informative analyst commentary about related STIX objects.
/// This check binds that description to normative §3.13.3.1: a typed Note SDO with
/// the testcase content — not a prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let bundle = validate_interop_fixture(FIXTURE_CREATE, &fixture.json)
        .expect("§3.13.3.1 must parse for description-scope check");
    let note_id = StixId::parse("note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").expect("note id");
    let note = bundle
        .get_typed::<Note>(&note_id)
        .expect("normative Note must be typed");
    assert!(
        note.content
            .starts_with("This note indicates the various steps"),
        "§3.13.1 / §3.13.3.1 running example content must be present on normative fixture"
    );
    assert_eq!(note.object_refs.len(), 1);
}

interop_test!(
    "REQ-3.13-1",
    "use_cases::note::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
