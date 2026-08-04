//! §3.13.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Malware, Note};
use rstix::model::sro::Sighting;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.13.4.1 non-normative example.
pub const EXAMPLE_SIGHTING_NOTE: &str =
    "examples/note/ex-3.13.4.1-note-on-sighting-of-malware.json";

/// REQ-3.13-EX-4.1 — §3.13.4.1 loads; Note references Sighting of Malware.
pub fn assert_note_on_sighting_of_malware() {
    let fixture = load_fixture(EXAMPLE_SIGHTING_NOTE);
    assert_eq!(fixture.provenance.source_section, "3.13.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.13.4.1 example must parse and pass interop gate");

    let note_id =
        StixId::parse("note--8db2245f-5a15-723d-8bb3-7dcc5d1600cc").expect("note id");
    let note = bundle
        .get_typed::<Note>(&note_id)
        .expect("Note on Sighting");
    assert!(
        note.content.starts_with("This is a high-priority sighting"),
        "expected high-priority sighting note content"
    );
    assert_eq!(note.object_refs.len(), 1);

    let sighting_id =
        StixId::parse("sighting--779c4ae8-e134-4180-baa4-03141095d971").expect("sighting id");
    let sighting = bundle
        .get_typed::<Sighting>(&sighting_id)
        .expect("referenced Sighting");
    assert_eq!(note.object_refs[0], sighting_id);

    let malware_id =
        StixId::parse("malware--ae560258-a5cb-4be8-8f05-013d6712295f").expect("malware id");
    assert_eq!(sighting.sighting_of_ref, malware_id);
    assert!(bundle.get_typed::<Malware>(&malware_id).is_some());
}

interop_test!(
    "REQ-3.13-EX-4.1",
    "use_cases::note::examples::note_on_sighting_of_malware",
    note_on_sighting_of_malware,
    {
        assert_note_on_sighting_of_malware();
    }
);
