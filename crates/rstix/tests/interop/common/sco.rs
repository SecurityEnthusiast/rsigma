//! §2.3 SCO cross-cutting invariant (REQ-2.3-X-10).

use rstix::core::StixId;
use rstix::model::sco::Ipv4Addr;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};

/// REQ-2.3-X-10 — SCO objects comply with STIX §6 via the interop gate.
/// Uses OASIS §3.14.3.2 observed-data bundle (ipv4-addr SCO member).
pub fn assert_sco_spec_conformance() {
    let fixture = load_fixture(
        "testcases/observed-data/tc-3.14.3.2-observed-data-domain-name-and-ip-address.json",
    );
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("SCO bundle must pass interop gate");
    let sco_id =
        StixId::parse("ipv4-addr--efcd5e80-570d-4131-b213-62cb18eaa6a8").expect("sco id");
    let sco = bundle
        .get_typed::<Ipv4Addr>(&sco_id)
        .expect("typed ipv4-addr");
    assert_eq!(sco.value, "198.51.100.3");
}
