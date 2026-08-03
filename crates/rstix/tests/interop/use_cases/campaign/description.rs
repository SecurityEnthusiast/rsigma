//! §3.2.1 Description — Campaign Sharing scope.

use rstix::core::StixId;
use rstix::model::sdo::{Campaign, IntrusionSet};

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::campaign::{FIXTURE_ATTRIBUTED, FIXTURE_CREATE};

/// REQ-3.2-1 — §3.2.1 Description.
///
/// Doc: a Campaign groups adversarial behaviors over time against a set of targets;
/// campaigns are often attributed to an intrusion set / threat actor. The running
/// example name in §3.2.3 is “Green Group Attacks Against Finance”. This check binds
/// that description to normative §3.2.3 Producer fixtures: typed Campaign SDOs with
/// that name, plus §3.2.3.2 carrying an Intrusion Set attribution path — not a
/// prose-only REPORT_ONLY placeholder.
pub fn assert_description_scope() {
    let create = load_fixture(FIXTURE_CREATE);
    let create_bundle = validate_interop_fixture(FIXTURE_CREATE, &create.json)
        .expect("§3.2.3.1 must parse for description-scope check");
    let campaign_id =
        StixId::parse("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").expect("campaign id");
    let campaign = create_bundle
        .get_typed::<Campaign>(&campaign_id)
        .expect("Green Group Campaign must be typed");
    assert_eq!(
        campaign.name, "Green Group Attacks Against Finance",
        "§3.2.1 / §3.2.3 running example name must be present on normative fixture"
    );

    let attributed = load_fixture(FIXTURE_ATTRIBUTED);
    let attributed_bundle = validate_interop_fixture(FIXTURE_ATTRIBUTED, &attributed.json)
        .expect("§3.2.3.2 must parse for description-scope check");
    assert_eq!(
        attributed_bundle.objects_of_type::<Campaign>().count(),
        1,
        "§3.2.3.2 must carry a Campaign SDO as described in §3.2.1"
    );
    assert_eq!(
        attributed_bundle.objects_of_type::<IntrusionSet>().count(),
        1,
        "§3.2.3.2 must carry an Intrusion Set SDO for the attribution path in §3.2.1"
    );
}

interop_test!(
    "REQ-3.2-1",
    "use_cases::campaign::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
