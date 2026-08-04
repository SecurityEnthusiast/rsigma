//! §3.18.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sdo::{Identity, Malware, ThreatActor};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

pub const EXAMPLE_ATTRIBUTED: &str =
    "examples/threat-actor/ex-3.18.4.1-threat-actor-attributed-to-an-identity.json";
pub const EXAMPLE_USES_MALWARE: &str =
    "examples/threat-actor/ex-3.18.4.2-threat-actor-uses-malware.json";

pub fn assert_threat_actor_attributed_to_identity() {
    let fixture = load_fixture(EXAMPLE_ATTRIBUTED);
    assert_eq!(fixture.provenance.source_section, "3.18.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap();
    let ta_id = StixId::parse("threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500").unwrap();
    assert!(bundle.get_typed::<ThreatActor>(&ta_id).is_some());
    let identity_id = StixId::parse("identity--8c6af861-7b20-41ef-9b59-6344fd872a8f").unwrap();
    assert!(bundle.get_typed::<Identity>(&identity_id).is_some());
    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "attributed-to");
}

pub fn assert_threat_actor_uses_malware() {
    let fixture = load_fixture(EXAMPLE_USES_MALWARE);
    assert_eq!(fixture.provenance.source_section, "3.18.4.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap();
    let ta_id = StixId::parse("threat-actor--9a8a0d25-7636-429b-a99e-b2a73cd0f11f").unwrap();
    let malware_id = StixId::parse("malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4").unwrap();
    assert!(bundle.get_typed::<ThreatActor>(&ta_id).is_some());
    assert!(bundle.get_typed::<Malware>(&malware_id).is_some());
    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(relationships[0].relationship_type.as_str(), "uses");
}

interop_test!("REQ-3.18-EX-4.1", "use_cases::threat_actor::examples::threat_actor_attributed_to_identity", threat_actor_attributed_to_identity, { assert_threat_actor_attributed_to_identity(); });
interop_test!("REQ-3.18-EX-4.2", "use_cases::threat_actor::examples::threat_actor_uses_malware", threat_actor_uses_malware, { assert_threat_actor_uses_malware(); });
