//! §3.9.4 Producer Example Data (non-gating).

use rstix::core::StixId;
use rstix::model::sco::Ipv4Addr;
use rstix::model::sdo::{Infrastructure, IntrusionSet, Location};
use rstix::model::sro::Relationship;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.9.4.1 non-normative example.
pub const EXAMPLE_OWNS_INFRASTRUCTURE: &str =
    "examples/intrusion-set/ex-3.9.4.1-intrusion-set-owns-infrastructure.json";
/// OASIS §3.9.4.2 non-normative example.
pub const EXAMPLE_ORIGINATES_FROM_LOCATION: &str =
    "examples/intrusion-set/ex-3.9.4.2-intrusion-set-originates-from-location.json";

/// REQ-3.9-EX-4.1 — §3.9.4.1 loads and passes the interop gate; Intrusion Set `owns` Infrastructure.
pub fn assert_intrusion_set_owns_infrastructure() {
    let fixture = load_fixture(EXAMPLE_OWNS_INFRASTRUCTURE);
    assert_eq!(fixture.provenance.source_section, "3.9.4.1");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.9.4.1 example must parse and pass interop gate");

    let intrusion_set_id =
        StixId::parse("intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29").expect("is id");
    let intrusion_set = bundle
        .get_typed::<IntrusionSet>(&intrusion_set_id)
        .expect("Bobcat Breakin Intrusion Set");
    assert_eq!(intrusion_set.name, "Bobcat Breakin");

    let infrastructure_id =
        StixId::parse("infrastructure--e5268b6e-4931-42f1-b379-87f48eb41b1e").expect("infra id");
    assert!(
        bundle
            .get_typed::<Infrastructure>(&infrastructure_id)
            .is_some()
    );

    let ipv4_id =
        StixId::parse("ipv4-addr--b4e29b62-2053-47c4-bab4-bbce39e5ed67").expect("ipv4 id");
    assert!(bundle.get_typed::<Ipv4Addr>(&ipv4_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 2);
    let owns = relationships
        .iter()
        .find(|rel| rel.relationship_type.as_str() == "owns")
        .expect("owns relationship");
    assert_eq!(owns.source_ref, intrusion_set_id);
    assert_eq!(owns.target_ref, infrastructure_id);

    let consists_of = relationships
        .iter()
        .find(|rel| rel.relationship_type.as_str() == "consists-of")
        .expect("consists-of relationship");
    assert_eq!(consists_of.source_ref, infrastructure_id);
    assert_eq!(consists_of.target_ref, ipv4_id);
}

/// REQ-3.9-EX-4.2 — §3.9.4.2 loads and passes the interop gate; Intrusion Set `originates-from` Location.
pub fn assert_intrusion_set_originates_from_location() {
    let fixture = load_fixture(EXAMPLE_ORIGINATES_FROM_LOCATION);
    assert_eq!(fixture.provenance.source_section, "3.9.4.2");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.9.4.2 example must parse and pass interop gate");

    let intrusion_set_id =
        StixId::parse("intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29").expect("is id");
    assert!(
        bundle
            .get_typed::<IntrusionSet>(&intrusion_set_id)
            .is_some()
    );

    let location_id =
        StixId::parse("location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64").expect("location id");
    assert!(bundle.get_typed::<Location>(&location_id).is_some());

    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(relationships.len(), 1);
    assert_eq!(
        relationships[0].relationship_type.as_str(),
        "originates-from"
    );
    assert_eq!(relationships[0].source_ref, intrusion_set_id);
    assert_eq!(relationships[0].target_ref, location_id);
}

interop_test!(
    "REQ-3.9-EX-4.1",
    "use_cases::intrusion_set::examples::intrusion_set_owns_infrastructure",
    intrusion_set_owns_infrastructure,
    {
        assert_intrusion_set_owns_infrastructure();
    }
);

interop_test!(
    "REQ-3.9-EX-4.2",
    "use_cases::intrusion_set::examples::intrusion_set_originates_from_location",
    intrusion_set_originates_from_location,
    {
        assert_intrusion_set_originates_from_location();
    }
);
