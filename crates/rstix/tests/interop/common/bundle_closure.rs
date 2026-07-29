//! Bundle reference-closure suite-wide checks (REQ-2.3-X-01/04).

use rstix::model::{Bundle, ParseOptions};

use crate::common::fixture_walk::{for_each_suite_walk_fixture, normalize_fixture_path};
use crate::harness::closure::{missing_closure_ids_from_json, tlp_exempt_ids};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;

/// REQ-2.3-X-01 — every normative testcase bundle passes closure + interop gate (spec tier).
pub fn assert_suite_wide_bundle_closure() {
    for_each_suite_walk_fixture(|relative| {
        let fixture = load_fixture(relative);
        validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative} failed interop gate (closure + parse + validation): {err}")
        });
    });
}

/// REQ-2.3-X-04 — predefined TLP markings are exempt from bundle closure across §3.5 fixtures.
pub fn assert_tlp_exemption_with_fixture() {
    let exempt = tlp_exempt_ids();
    assert_eq!(exempt.len(), 9, "nine predefined TLP marking ids");

    let mut checked = 0usize;
    for_each_suite_walk_fixture(|relative| {
        if !normalize_fixture_path(relative).starts_with("testcases/data-markings/") {
            return;
        }
        let fixture = load_fixture(relative);
        let missing = missing_closure_ids_from_json(&fixture.json);
        assert!(
            missing.is_empty(),
            "{relative}: TLP marking refs must be exempt from closure; missing: {missing:?}"
        );

        Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
            .unwrap_or_else(|err| {
                panic!("{relative}: interop bundle parse must accept TLP marking ref: {err}")
            });
        checked += 1;
    });
    assert!(
        checked > 0,
        "expected at least one data-markings testcase fixture"
    );
}
