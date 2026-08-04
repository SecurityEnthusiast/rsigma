//! §3.20.1 Description — Versioning scope.

use rstix::core::StixId;
use rstix::model::sdo::Indicator;
use rstix::model::sro::Sighting;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::interop_test;
use crate::use_cases::versioning::{FIXTURE_CREATE_INDICATOR, FIXTURE_CREATE_SIGHTING};

/// REQ-3.20-1 — §3.20.1 Description.
///
/// Doc: versioning covers creation, modification, and revocation of STIX content.
/// This check binds that description to the normative creation fixtures: a typed
/// Indicator on §3.20.3.1 and a typed Sighting on §3.20.3.2 — not a prose-only
/// REPORT_ONLY placeholder. Modification/revocation phases are covered by their
/// dedicated producer rows, not this description scope.
pub fn assert_description_scope() {
    let ind = validate_interop_fixture(
        FIXTURE_CREATE_INDICATOR,
        &load_fixture(FIXTURE_CREATE_INDICATOR).json,
    )
    .unwrap();
    let id = StixId::parse("indicator--6cd5cd4f-ff42-4d67-8402-02aad22f8b63").unwrap();
    let indicator = ind
        .get_typed::<Indicator>(&id)
        .expect("§3.20.3.1 Indicator must be typed");
    assert_eq!(indicator.name.as_deref(), Some("Bad IP1"));

    let sight = validate_interop_fixture(
        FIXTURE_CREATE_SIGHTING,
        &load_fixture(FIXTURE_CREATE_SIGHTING).json,
    )
    .unwrap();
    assert_eq!(
        sight.objects_of_type::<Sighting>().count(),
        1,
        "§3.20.3.2 must carry a Sighting for the versioning creation path"
    );
}

interop_test!(
    "REQ-3.20-1",
    "use_cases::versioning::description::description_scope",
    description_scope,
    {
        assert_description_scope();
    }
);
