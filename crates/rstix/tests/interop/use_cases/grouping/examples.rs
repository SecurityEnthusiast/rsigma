//! §3.6.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Grouping, Malware, MalwareAnalysis, ObservedData};
use rstix::model::sro::{Relationship, Sighting};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.6.4.1 non-normative example.
pub const EXAMPLE_SUSPICIOUS_EVENT: &str =
    "examples/grouping/ex-3.6.4.1-suspicious-event-grouping.json";
/// OASIS §3.6.4.2 non-normative example.
pub const EXAMPLE_MALWARE_ANALYSIS: &str =
    "examples/grouping/ex-3.6.4.2-malware-analysis-grouping.json";
/// OASIS §3.6.4.3 non-normative example.
pub const EXAMPLE_DUPLICATE_SIGHTINGS: &str =
    "examples/grouping/ex-3.6.4.3-duplicate-sightings-grouping.json";

/// REQ-3.6-EX-4.1 — §3.6.4.1 loads and passes the interop gate; UEBA-style suspicious-event Grouping.
pub fn assert_suspicious_event_grouping() {
    let fixture = load_fixture(EXAMPLE_SUSPICIOUS_EVENT);
    assert_eq!(fixture.provenance.source_section, "3.6.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.6.4.1 example must parse and pass interop gate");

    let grouping_id =
        StixId::parse("grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3").expect("grouping id");
    let grouping = bundle
        .get_typed::<Grouping>(&grouping_id)
        .expect("Suspicious event Grouping");
    assert_eq!(grouping.name.as_deref(), Some("Suspicious event Grouping"));
    assert_eq!(grouping.context, "suspicious-activity");
    assert_eq!(grouping.object_refs.len(), 2);

    assert_eq!(bundle.objects_of_type::<ObservedData>().count(), 2);
    let sightings: Vec<_> = bundle.objects_of_type::<Sighting>().collect();
    assert_eq!(sightings.len(), 1);
    assert_eq!(sightings[0].sighting_of_ref, grouping_id);
}

/// REQ-3.6-EX-4.2 — §3.6.4.2 loads and passes the interop gate; malware-analysis context Grouping.
pub fn assert_malware_analysis_grouping() {
    let fixture = load_fixture(EXAMPLE_MALWARE_ANALYSIS);
    assert_eq!(fixture.provenance.source_section, "3.6.4.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.6.4.2 example must parse and pass interop gate");

    let grouping_id =
        StixId::parse("grouping--83745900-3485-4204-a495-34958ff94b22").expect("grouping id");
    let grouping = bundle
        .get_typed::<Grouping>(&grouping_id)
        .expect("Malware Analysis Grouping");
    assert_eq!(grouping.context, "malware-analysis");
    assert_eq!(grouping.object_refs.len(), 3);

    let malware_id =
        StixId::parse("malware--bd839453-0334-42bb-bcde-8473be4d73fa").expect("malware id");
    assert!(bundle.get_typed::<Malware>(&malware_id).is_some());
    let analysis_id = StixId::parse("malware-analysis--8475bdef-0345-34be-3921-3847bef26a78")
        .expect("analysis id");
    assert!(bundle.get_typed::<MalwareAnalysis>(&analysis_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(
        relationships[0].relationship_type.as_str(),
        "static-analysis-of"
    );
    assert_eq!(relationships[0].source_ref, analysis_id);
    assert_eq!(relationships[0].target_ref, malware_id);
}

/// REQ-3.6-EX-4.3 — §3.6.4.3 loads and passes the interop gate; duplicate Sightings Grouping.
pub fn assert_duplicate_sightings_grouping() {
    let fixture = load_fixture(EXAMPLE_DUPLICATE_SIGHTINGS);
    assert_eq!(fixture.provenance.source_section, "3.6.4.3");
    assert!(
        fixture
            .provenance
            .divergence_recorded
            .iter()
            .any(|d| d.defect == 20),
        "expected defect 20 recorded for em-dash indicator ids"
    );
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.6.4.3 example must parse and pass interop gate");

    let grouping_id =
        StixId::parse("grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3").expect("grouping id");
    let grouping = bundle
        .get_typed::<Grouping>(&grouping_id)
        .expect("Sighting Grouping");
    assert_eq!(grouping.context, "duplicate-of");
    assert_eq!(grouping.object_refs.len(), 4);
    assert_eq!(bundle.objects_of_type::<Sighting>().count(), 4);
}

interop_test!(
    "REQ-3.6-EX-4.1",
    "use_cases::grouping::examples::suspicious_event_grouping",
    suspicious_event_grouping,
    {
        assert_suspicious_event_grouping();
    }
);

interop_test!(
    "REQ-3.6-EX-4.2",
    "use_cases::grouping::examples::malware_analysis_grouping",
    malware_analysis_grouping,
    {
        assert_malware_analysis_grouping();
    }
);

interop_test!(
    "REQ-3.6-EX-4.3",
    "use_cases::grouping::examples::duplicate_sightings_grouping",
    duplicate_sightings_grouping,
    {
        assert_duplicate_sightings_grouping();
    }
);
