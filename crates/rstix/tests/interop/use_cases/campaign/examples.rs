//! §3.2.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{AttackPattern, Campaign, ThreatActor};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.2.4.1 non-normative example.
pub const EXAMPLE_USES_ATTACK_PATTERN: &str =
    "examples/campaign/ex-3.2.4.1-campaign-uses-an-attack-pattern.json";
/// OASIS §3.2.4.2 non-normative example.
pub const EXAMPLE_ATTRIBUTED_THREAT_ACTOR: &str =
    "examples/campaign/ex-3.2.4.2-campaign-attributed-to-threat-actor.json";

/// REQ-3.2-EX-4.1 — §3.2.4.1 loads and passes the interop gate; Campaign `uses` Attack Pattern.
pub fn assert_campaign_uses_attack_pattern() {
    let fixture = load_fixture(EXAMPLE_USES_ATTACK_PATTERN);
    assert_eq!(fixture.provenance.source_section, "3.2.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.2.4.1 example must parse and pass interop gate");

    let campaign_id =
        StixId::parse("campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e").expect("campaign id");
    let campaign = bundle
        .get_typed::<Campaign>(&campaign_id)
        .expect("Operation Bran Flakes Campaign");
    assert_eq!(campaign.name, "Operation Bran Flakes");

    let ap_id =
        StixId::parse("attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a").expect("ap id");
    assert!(bundle.get_typed::<AttackPattern>(&ap_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "uses");
    assert_eq!(relationships[0].source_ref, campaign_id);
    assert_eq!(relationships[0].target_ref, ap_id);
}

/// REQ-3.2-EX-4.2 — §3.2.4.2 loads and passes the interop gate; Campaign `attributed-to` Threat Actor.
pub fn assert_campaign_attributed_to_threat_actor() {
    let fixture = load_fixture(EXAMPLE_ATTRIBUTED_THREAT_ACTOR);
    assert_eq!(fixture.provenance.source_section, "3.2.4.2");
    assert!(
        fixture
            .provenance
            .divergence_recorded
            .iter()
            .any(|d| d.defect == 20),
        "expected defect 20 recorded for malformed relationship id key"
    );
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.2.4.2 example must parse and pass interop gate");

    let campaign_id =
        StixId::parse("campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e").expect("campaign id");
    assert!(bundle.get_typed::<Campaign>(&campaign_id).is_some());

    let ta_id = StixId::parse("threat-actor--9a8a0d25-7636-429b-a99e-b2a73cd0f11f")
        .expect("threat-actor id");
    assert!(bundle.get_typed::<ThreatActor>(&ta_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "attributed-to");
    assert_eq!(relationships[0].source_ref, campaign_id);
    assert_eq!(relationships[0].target_ref, ta_id);
}

interop_test!(
    "REQ-3.2-EX-4.1",
    "use_cases::campaign::examples::campaign_uses_attack_pattern",
    campaign_uses_attack_pattern,
    {
        assert_campaign_uses_attack_pattern();
    }
);

interop_test!(
    "REQ-3.2-EX-4.2",
    "use_cases::campaign::examples::campaign_attributed_to_threat_actor",
    campaign_attributed_to_threat_actor,
    {
        assert_campaign_attributed_to_threat_actor();
    }
);
