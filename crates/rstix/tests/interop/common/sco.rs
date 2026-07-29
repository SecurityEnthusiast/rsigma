//! §2.3 SCO cross-cutting invariant (REQ-2.3-X-10).

use rstix::core::StixId;
use rstix::model::sco::{DomainName, File, Ipv4Addr};

use crate::common::fixture_catalog::summarize_fixture_wire;
use crate::common::fixture_walk::for_each_suite_walk_fixture;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;

/// REQ-2.3-X-10 — SCO objects in normative fixtures comply with STIX §6 via typed access.
pub fn assert_sco_spec_conformance() {
    let mut checked = 0usize;
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        let summary = summarize_fixture_wire(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
        if summary.sco_objects.is_empty() {
            return;
        }

        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));

        for sco in &summary.sco_objects {
            let id = StixId::parse(&sco.id)
                .unwrap_or_else(|err| panic!("{relative}: invalid SCO id {}: {err}", sco.id));
            match sco.object_type.as_str() {
                "ipv4-addr" => {
                    bundle
                        .get_typed::<Ipv4Addr>(&id)
                        .unwrap_or_else(|| panic!("{relative}: typed ipv4-addr {}", sco.id));
                }
                "domain-name" => {
                    bundle
                        .get_typed::<DomainName>(&id)
                        .unwrap_or_else(|| panic!("{relative}: typed domain-name {}", sco.id));
                }
                "file" => {
                    bundle
                        .get_typed::<File>(&id)
                        .unwrap_or_else(|| panic!("{relative}: typed file {}", sco.id));
                }
                other => panic!("{relative}: unsupported SCO type {other}"),
            }
            checked += 1;
        }
    });
    assert!(
        checked > 0,
        "expected at least one SCO object across normative testcase fixtures"
    );
}
