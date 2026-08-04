//! §3.10.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Campaign, Location, Malware, ThreatActor};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.10.4.1 non-normative example.
pub const EXAMPLE_THREAT_ACTOR_LOCATION: &str =
    "examples/location/ex-3.10.4.1-threat-actor-location.json";
/// OASIS §3.10.4.2 non-normative example.
pub const EXAMPLE_MALWARE_ORIGINATES: &str =
    "examples/location/ex-3.10.4.2-malware-originates-from-location.json";
/// OASIS §3.10.4.3 non-normative example.
pub const EXAMPLE_CAMPAIGN_TARGETS: &str =
    "examples/location/ex-3.10.4.3-campaign-targets-location.json";

/// REQ-3.10-EX-4.1 — §3.10.4.1 loads; Threat Actor `targets` Location.
pub fn assert_threat_actor_location() {
    let fixture = load_fixture(EXAMPLE_THREAT_ACTOR_LOCATION);
    assert_eq!(fixture.provenance.source_section, "3.10.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.10.4.1 example must parse and pass interop gate");

    let location_id =
        StixId::parse("location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64").expect("location id");
    let location = bundle
        .get_typed::<Location>(&location_id)
        .expect("Threat Actor Location");
    assert_eq!(location.region.as_deref(), Some("south-eastern-asia"));
    assert_eq!(location.country.as_deref(), Some("TH"));

    let actor_id = StixId::parse("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        .expect("threat actor id");
    assert!(bundle.get_typed::<ThreatActor>(&actor_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "targets");
    assert_eq!(relationships[0].source_ref, actor_id);
    assert_eq!(relationships[0].target_ref, location_id);
}

/// REQ-3.10-EX-4.2 — §3.10.4.2 loads; Malware `originates-from` Location.
pub fn assert_malware_originates_from_location() {
    let fixture = load_fixture(EXAMPLE_MALWARE_ORIGINATES);
    assert_eq!(fixture.provenance.source_section, "3.10.4.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.10.4.2 example must parse and pass interop gate");

    let location_id =
        StixId::parse("location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64").expect("location id");
    let location = bundle
        .get_typed::<Location>(&location_id)
        .expect("Malware origin Location");
    assert_eq!(location.country.as_deref(), Some("CN"));

    let malware_id =
        StixId::parse("malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").expect("malware id");
    assert!(bundle.get_typed::<Malware>(&malware_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(
        relationships[0].relationship_type.as_str(),
        "originates-from"
    );
    assert_eq!(relationships[0].source_ref, malware_id);
    assert_eq!(relationships[0].target_ref, location_id);
}

/// REQ-3.10-EX-4.3 — §3.10.4.3 loads; Campaign `targets` Location.
pub fn assert_campaign_targets_location() {
    let fixture = load_fixture(EXAMPLE_CAMPAIGN_TARGETS);
    assert_eq!(fixture.provenance.source_section, "3.10.4.3");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.10.4.3 example must parse and pass interop gate");

    let location_id =
        StixId::parse("location--b222345f-5a15-4c29-8bb3-7dcc5d168d64").expect("location id");
    let location = bundle
        .get_typed::<Location>(&location_id)
        .expect("Campaign target Location");
    assert_eq!(location.country.as_deref(), Some("US"));

    let campaign_id =
        StixId::parse("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").expect("campaign id");
    assert!(bundle.get_typed::<Campaign>(&campaign_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "targets");
    assert_eq!(relationships[0].source_ref, campaign_id);
    assert_eq!(relationships[0].target_ref, location_id);
}

interop_test!(
    "REQ-3.10-EX-4.1",
    "use_cases::location::examples::threat_actor_location",
    threat_actor_location,
    {
        assert_threat_actor_location();
    }
);

interop_test!(
    "REQ-3.10-EX-4.2",
    "use_cases::location::examples::malware_originates_from_location",
    malware_originates_from_location,
    {
        assert_malware_originates_from_location();
    }
);

interop_test!(
    "REQ-3.10-EX-4.3",
    "use_cases::location::examples::campaign_targets_location",
    campaign_targets_location,
    {
        assert_campaign_targets_location();
    }
);
