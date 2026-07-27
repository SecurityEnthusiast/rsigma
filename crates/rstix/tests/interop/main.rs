//! OASIS STIX 2.1 Interop golden suite entry point.

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

// --- §2.3 cross-cutting smoke checks ---

interop_test!(
    "REQ-2.3-X-09",
    "common::gating::testcases_and_examples_directories_exist",
    testcases_and_examples_directories_exist,
    {
        common::gating::assert_testcases_directory_exists();
        common::gating::assert_examples_directory_exists();
        common::gating::assert_examples_not_normative_prefix();
    }
);

interop_test!(
    "REQ-2.3-X-04",
    "common::bundle_closure::tlp_exemption_whitelist",
    tlp_exemption_whitelist,
    {
        common::bundle_closure::assert_tlp_exemption_whitelist();
    }
);

interop_test!(
    "REQ-2.3-X-05",
    "common::identity::identity_shape_fixture_valid",
    identity_shape_fixture_valid,
    {
        common::identity::assert_identity_shape_fixture_valid();
    }
);

interop_test!(
    "REQ-2.3-X-08",
    "common::relationships::relationship_shape_ready",
    relationship_shape_ready,
    {
        common::relationships::assert_relationship_module_ready();
    }
);

/// Coverage gate + certification report generation (§6 guard 1).
///
/// Named with `zzz_` prefix so `--test-threads=1` runs it after requirement tests.
#[test]
fn zzz_interop_certification_finalize() {
    let manifest = load_manifest();
    harness::certification::finalize(&manifest);
}
