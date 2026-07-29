//! OASIS STIX 2.1 Interop test suite entry point.

mod common;
mod harness;

use harness::manifest::load_manifest;

// --- Interop harness infrastructure ---

interop_test!(
    "REQ-HARNESS-MANIFEST-01",
    "harness::manifest_parses_and_validates",
    manifest_parses_and_validates,
    {
        harness::manifest::assert_manifest_valid();
    }
);

interop_test!(
    "REQ-HARNESS-MANIFEST-02",
    "harness::checklist_rows_are_unique",
    checklist_rows_are_unique,
    {
        harness::manifest::assert_checklist_rows_unique();
    }
);

interop_test!(
    "REQ-HARNESS-FIXTURE-01",
    "harness::rejects_missing_provenance_sidecar",
    rejects_missing_provenance_sidecar,
    {
        harness::fixture::assert_rejects_missing_provenance();
    }
);

interop_test!(
    "REQ-HARNESS-FIXTURE-02",
    "harness::loads_fixture_with_provenance",
    loads_fixture_with_provenance,
    {
        let fixture =
            harness::fixture::load_fixture("testcases/harness/tc-harness-closure-smoke.json");
        assert!(fixture.json.contains("bundle"));
    }
);

interop_test!(
    "REQ-HARNESS-PROFILE-01",
    "harness::should_downgrades_i0002",
    should_downgrades_i0002,
    {
        harness::profile::assert_i0002_downgraded();
    }
);

interop_test!(
    "REQ-HARNESS-CONTAIN-01",
    "harness::superset_properties_pass_containment",
    superset_properties_pass_containment,
    {
        harness::containment::assert_superset_allowed();
    }
);

interop_test!(
    "REQ-HARNESS-CLOSURE-01",
    "harness::reference_closed_bundle_passes",
    reference_closed_bundle_passes,
    {
        let fixture =
            harness::fixture::load_fixture("testcases/harness/tc-harness-closure-smoke.json");
        harness::closure::assert_bundle_reference_closed(&fixture.json);
    }
);

interop_test!(
    "REQ-HARNESS-VALIDATOR-01",
    "harness::interop_strict_profile_available",
    interop_strict_profile_available,
    {
        let validator = rstix::validate::Validator::interop_strict();
        let json =
            harness::fixture::load_fixture("testcases/harness/tc-harness-closure-smoke.json").json;
        let report = validator.validate_json_str(&json);
        assert!(report.is_valid(), "smoke bundle must pass interop_strict");
    }
);

interop_test!(
    "REQ-HARNESS-FIXTURE-03",
    "harness::blocked_gating_fixtures_load",
    blocked_gating_fixtures_load,
    {
        harness::fixture::assert_blocked_gating_fixtures_load();
    }
);

// --- §2.3 cross-cutting (executable over walkable normative fixtures) ---

interop_test!(
    "REQ-2.3-P-01",
    "common::producer::producer_conformance_12_1",
    producer_conformance_12_1,
    {
        common::producer::assert_producer_conformance_12_1();
    }
);

interop_test!(
    "REQ-2.3-P-02",
    "common::producer::interop_stricter_than_spec",
    interop_stricter_than_spec,
    {
        common::producer::assert_interop_stricter_than_spec();
    }
);

interop_test!(
    "REQ-2.3-P-03",
    "common::producer::additional_properties_permitted",
    additional_properties_permitted,
    {
        common::producer::assert_additional_properties_permitted();
    }
);

interop_test!(
    "REQ-2.3-C-01",
    "common::consumer::consumer_conformance_12_1",
    consumer_conformance_12_1,
    {
        common::consumer::assert_consumer_conformance_12_1();
    }
);

interop_test!(
    "REQ-2.3-C-02",
    "common::consumer::consumer_supports_producer_props",
    consumer_supports_producer_props,
    {
        common::consumer::assert_consumer_supports_producer_props();
    }
);

interop_test!(
    "REQ-2.3-C-03",
    "common::consumer::consumer_receives_triad",
    consumer_receives_triad,
    {
        common::consumer::assert_consumer_receives_triad();
    }
);

interop_test!(
    "REQ-2.3-C-04",
    "common::consumer::consumer_resolves_created_by_ref",
    consumer_resolves_created_by_ref,
    {
        common::consumer::assert_consumer_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-2.3-C-05",
    "common::consumer::consumer_processes_fields",
    consumer_processes_fields,
    {
        common::consumer::assert_consumer_processes_fields();
    }
);

interop_test!(
    "REQ-2.3-C-06",
    "common::consumer::consumer_processes_related",
    consumer_processes_related,
    {
        common::consumer::assert_consumer_processes_related();
    }
);

interop_test!(
    "REQ-2.3-X-01",
    "common::bundle_closure::suite_wide_closure",
    suite_wide_closure,
    {
        common::bundle_closure::assert_suite_wide_bundle_closure();
    }
);

interop_test!(
    "REQ-2.3-X-02",
    "common::gating::testcases_use_bundle_wrapper",
    testcases_use_bundle_wrapper,
    {
        common::gating::assert_testcases_use_bundle_wrapper();
    }
);

interop_test!(
    "REQ-2.3-X-03",
    "common::validation::referenced_obj_spec_only",
    referenced_obj_spec_only,
    {
        common::validation::assert_referenced_obj_spec_only();
    }
);

interop_test!(
    "REQ-2.3-X-04",
    "common::bundle_closure::tlp_exemption_with_fixture",
    tlp_exemption_with_fixture,
    {
        common::bundle_closure::assert_tlp_exemption_with_fixture();
    }
);

interop_test!(
    "REQ-2.3-X-05",
    "common::identity::identity_present_in_fixture",
    identity_present_in_fixture,
    {
        common::identity::assert_identity_present_in_fixture();
    }
);

interop_test!(
    "REQ-2.3-X-06",
    "common::identity::identity_shape_on_parsed",
    identity_shape_on_parsed,
    {
        common::identity::assert_identity_shape_on_parsed();
    }
);

interop_test!(
    "REQ-2.3-X-08",
    "common::relationships::relationship_shape_on_parsed",
    relationship_shape_on_parsed,
    {
        common::relationships::assert_relationship_shape_on_parsed();
    }
);

interop_test!(
    "REQ-2.3-X-09",
    "common::gating::gating_directory_layout",
    gating_directory_layout,
    {
        common::gating::assert_gating_directory_layout();
    }
);

interop_test!(
    "REQ-2.3-X-10",
    "common::sco::sco_spec_conformance",
    sco_spec_conformance,
    {
        common::sco::assert_sco_spec_conformance();
    }
);

fn main() {
    harness::run_all();
    let manifest = load_manifest();
    harness::certification::finalize(&manifest);
}
