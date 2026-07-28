//! Bundle reference-closure suite-wide checks (REQ-2.3-X-01/02/03/04).

use rstix::model::{Bundle, ParseOptions};

use crate::common::fixture_walk::for_each_suite_walk_fixture;
use crate::harness::closure::{missing_closure_ids_from_json, tlp_exempt_ids};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};

/// REQ-2.3-X-01 — every normative testcase bundle passes closure + interop gate (spec tier).
pub fn assert_suite_wide_bundle_closure() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        validate_interop_json(&fixture.json, &InteropGateOptions::default()).unwrap_or_else(
            |err| panic!("{relative} failed interop gate (closure + parse + validation): {err}"),
        );
    });
}

/// TLP predefined markings are exempt from bundle closure and interop parse.
pub fn assert_tlp_exemption_with_fixture() {
    let exempt = tlp_exempt_ids();
    assert_eq!(exempt.len(), 9, "nine predefined TLP marking ids");

    let fixture = load_fixture("testcases/data-markings/tc-3.5.3.1-tlp-white-indicator-ipv4.json");
    let missing = missing_closure_ids_from_json(&fixture.json);
    assert!(
        missing.is_empty(),
        "TLP white reference must be exempt from closure; missing: {missing:?}"
    );

    Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .expect("interop bundle parse must accept TLP marking ref without bundle member");
}
