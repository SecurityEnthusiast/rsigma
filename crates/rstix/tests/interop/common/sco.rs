//! §2.3 SCO cross-cutting invariant (REQ-2.3-X-10).

use rstix::core::StixId;
use rstix::model::sco::Ipv4Addr;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};

/// REQ-2.3-X-10 — SCO objects comply with STIX §6 via the interop gate.
/// Standalone SCO test-case data is not published until §3.14; uses synthetic ipv4-addr
/// bundle until that normative fixture lands.
pub fn assert_sco_spec_conformance() {
    let fixture = load_fixture("testcases/common/tc-sco-ipv4.json");
    let bundle = validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("SCO bundle must pass interop gate");
    let sco_id = StixId::parse("ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4").expect("sco id");
    let sco = bundle
        .get_typed::<Ipv4Addr>(&sco_id)
        .expect("typed ipv4-addr");
    assert_eq!(sco.value, "198.51.100.3");
}
