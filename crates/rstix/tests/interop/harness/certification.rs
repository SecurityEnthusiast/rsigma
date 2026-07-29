//! Certification outcomes, coverage gate, and §4.2 report generation.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::manifest::{Disposition, Manifest, RequirementRow};
use super::registry::INTEROP_TESTS;

static OUTCOMES: OnceLock<Mutex<HashMap<&'static str, Outcome>>> = OnceLock::new();

fn outcomes() -> &'static Mutex<HashMap<&'static str, Outcome>> {
    OUTCOMES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Per-requirement test result for the certification report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    #[expect(dead_code, reason = "used when interop tests record explicit failures")]
    Fail,
    /// Covered requirement with no passing path from unrepaired OASIS data (§5.2).
    Blocked,
    /// Harness-only smoke check; does not count as normative requirement proof.
    HarnessSmoke,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
            Self::Fail => "Fail",
            Self::Blocked => "BLOCKED",
            Self::HarnessSmoke => "HARNESS_SMOKE",
        }
    }
}

/// Record a requirement outcome (called by each interop test).
pub fn record_outcome(req_id: &'static str, outcome: Outcome) {
    outcomes()
        .lock()
        .expect("interop outcomes lock")
        .insert(req_id, outcome);
}

fn report_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/interop-report")
}

/// Finalize the certification run: drift checks, coverage gate, artifact generation.
pub fn finalize(manifest: &Manifest) {
    verify_registry_drift(manifest);
    verify_coverage(manifest);
    write_report_artifacts(manifest);
}

fn verify_registry_drift(manifest: &Manifest) {
    let registered: HashSet<&str> = INTEROP_TESTS
        .iter()
        .map(|entry| entry.descriptor.test_id)
        .collect();
    let manifest_test_ids: HashSet<&str> = manifest
        .registered_test_ids()
        .filter_map(|row| row.test_id.as_deref())
        .collect();

    let missing_tests: Vec<_> = manifest_test_ids.difference(&registered).copied().collect();
    assert!(
        missing_tests.is_empty(),
        "manifest rows without registered tests: {missing_tests:?}"
    );

    let orphan_tests: Vec<_> = registered.difference(&manifest_test_ids).copied().collect();
    assert!(
        orphan_tests.is_empty(),
        "registered tests without manifest rows: {orphan_tests:?}"
    );
}

fn verify_coverage(manifest: &Manifest) {
    let (missing_tested, missing_smoke, failed_tested) = {
        let recorded = outcomes().lock().expect("interop outcomes lock");
        let missing_tested = manifest
            .testable_requirements()
            .filter(|row| !recorded.contains_key(row.req_id.as_str()))
            .map(|row| row.req_id.clone())
            .collect::<Vec<_>>();
        let missing_smoke = manifest
            .requirements
            .iter()
            .filter(|row| row.disposition == Disposition::HarnessSmoke)
            .filter(|row| recorded.get(row.req_id.as_str()) != Some(&Outcome::HarnessSmoke))
            .map(|row| row.req_id.clone())
            .collect::<Vec<_>>();
        let failed_tested = manifest
            .testable_requirements()
            .filter(|row| {
                recorded
                    .get(row.req_id.as_str())
                    .is_some_and(|o| *o != Outcome::Pass)
            })
            .map(|row| row.req_id.clone())
            .collect::<Vec<_>>();
        (missing_tested, missing_smoke, failed_tested)
    };

    assert!(
        missing_tested.is_empty(),
        "TESTED manifest rows without recorded outcomes: {missing_tested:?}"
    );
    assert!(
        missing_smoke.is_empty(),
        "HARNESS_SMOKE manifest rows without harness-smoke outcomes: {missing_smoke:?}"
    );
    assert!(
        failed_tested.is_empty(),
        "TESTED manifest rows without Pass outcome: {failed_tested:?}"
    );
}

fn row_is_covered(row: &RequirementRow, recorded: &HashMap<&'static str, Outcome>) -> bool {
    match row.disposition {
        Disposition::Tested => recorded.contains_key(row.req_id.as_str()),
        Disposition::HarnessSmoke => recorded.contains_key(row.req_id.as_str()),
        Disposition::ReportOnly | Disposition::ApiSurface => true,
        Disposition::Blocked => row.blocked_by.is_some(),
    }
}

fn write_report_artifacts(manifest: &Manifest) {
    let dir = report_dir();
    fs::create_dir_all(&dir).expect("create interop-report directory");

    let recorded = outcomes().lock().expect("interop outcomes lock");
    let summary = build_summary(manifest, &recorded);
    fs::write(
        dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("serialize summary.json"),
    )
    .expect("write summary.json");

    fs::write(
        dir.join("traceability.csv"),
        render_traceability_csv(manifest, &recorded),
    )
    .expect("write traceability.csv");

    let consumer_rows = manifest.checklist_rows_consumer();
    fs::write(
        dir.join("sxc-table-55.md"),
        render_checklist_table(
            "STIX 2.1 Consumer (SXC) — §4.2 Table 55",
            &consumer_rows,
            &recorded,
        ),
    )
    .expect("write sxc-table-55.md");

    let producer_rows = manifest.checklist_rows_producer();
    fs::write(
        dir.join("sxp-table-56.md"),
        render_checklist_table(
            "STIX 2.1 Producer (SXP) — §4.2 Table 56",
            &producer_rows,
            &recorded,
        ),
    )
    .expect("write sxp-table-56.md");

    fs::write(dir.join("risks.md"), render_risks(manifest, &recorded)).expect("write risks.md");
}

#[derive(serde::Serialize)]
struct SummaryJson {
    document: &'static str,
    document_stage: &'static str,
    /// Personas this harness is built to support (not a certification claim).
    personas_target: Vec<&'static str>,
    /// OASIS interoperability spec defines 21 use cases; normative tests not all present yet.
    oasis_use_cases_in_spec: u32,
    manifest_rows_total: usize,
    manifest_rows_by_disposition: ManifestDispositionCounts,
    /// Executable manifest rows with disposition `TESTED` that recorded `Pass`.
    tested_rows_passed: usize,
    /// Rows with disposition `HARNESS_SMOKE` that executed (partial checks only).
    harness_smoke_executed: usize,
    /// Checklist/framework placeholders — no automated test in this PR.
    report_only_rows: usize,
    /// Rows blocked because published OASIS test-case bytes cannot be repaired without inventing data.
    blocked_rows: usize,
    features_enabled: FeaturesEnabled,
}

#[derive(Clone, Copy, serde::Serialize)]
struct ManifestDispositionCounts {
    tested: usize,
    harness_smoke: usize,
    report_only: usize,
    blocked: usize,
    api_surface: usize,
}

#[derive(serde::Serialize)]
struct FeaturesEnabled {
    validate: bool,
    marking: bool,
    graph: bool,
}

fn build_summary(manifest: &Manifest, recorded: &HashMap<&'static str, Outcome>) -> SummaryJson {
    let disposition_counts = count_by_disposition(manifest);
    let tested_rows_passed = manifest
        .testable_requirements()
        .filter(|row| row.disposition == Disposition::Tested)
        .filter(|row| recorded.get(row.req_id.as_str()) == Some(&Outcome::Pass))
        .count();
    let harness_smoke = manifest
        .requirements
        .iter()
        .filter(|row| row.disposition == Disposition::HarnessSmoke)
        .filter(|row| recorded.get(row.req_id.as_str()) == Some(&Outcome::HarnessSmoke))
        .count();

    SummaryJson {
        document: "STIX 2.1 Interoperability v1.0 CSD01 (stix-2.1-interop-v1.0-csd01)",
        document_stage: "Committee Specification Draft 01 (2021-10-23)",
        personas_target: vec!["SXP", "SXC"],
        oasis_use_cases_in_spec: 21,
        manifest_rows_total: manifest.requirements.len(),
        manifest_rows_by_disposition: disposition_counts,
        tested_rows_passed,
        harness_smoke_executed: harness_smoke,
        report_only_rows: disposition_counts.report_only,
        blocked_rows: disposition_counts.blocked,
        features_enabled: FeaturesEnabled {
            validate: cfg!(feature = "validate"),
            marking: cfg!(feature = "marking"),
            graph: cfg!(feature = "graph"),
        },
    }
}

fn count_by_disposition(manifest: &Manifest) -> ManifestDispositionCounts {
    let mut counts = ManifestDispositionCounts {
        tested: 0,
        harness_smoke: 0,
        report_only: 0,
        blocked: 0,
        api_surface: 0,
    };
    for row in &manifest.requirements {
        match row.disposition {
            Disposition::Tested => counts.tested += 1,
            Disposition::HarnessSmoke => counts.harness_smoke += 1,
            Disposition::ReportOnly => counts.report_only += 1,
            Disposition::Blocked => counts.blocked += 1,
            Disposition::ApiSurface => counts.api_surface += 1,
        }
    }
    counts
}

fn render_traceability_csv(
    manifest: &Manifest,
    recorded: &HashMap<&'static str, Outcome>,
) -> String {
    let mut lines =
        vec!["req_id,test_id,fixture,role,level,doc_page,disposition,outcome".to_owned()];
    for row in manifest.requirements.iter() {
        let outcome = match row.disposition {
            Disposition::Tested => recorded
                .get(row.req_id.as_str())
                .map(|o| o.as_str())
                .unwrap_or("MISSING"),
            Disposition::HarnessSmoke => recorded
                .get(row.req_id.as_str())
                .map(|o| o.as_str())
                .unwrap_or("MISSING"),
            Disposition::Blocked => "BLOCKED",
            Disposition::ReportOnly => "REPORT_ONLY",
            Disposition::ApiSurface => "API_SURFACE",
        };
        lines.push(format!(
            "{},{},{},{},{},{},{},{}",
            row.req_id,
            row.test_id.as_deref().unwrap_or(""),
            row.fixture.as_deref().unwrap_or(""),
            row.role.as_deref().unwrap_or(""),
            row.level,
            row.doc_page
                .map(|page| page.to_string())
                .unwrap_or_default(),
            row.disposition.as_str(),
            outcome
        ));
    }
    lines.join("\n")
}

fn render_checklist_table(
    title: &str,
    rows: &[&RequirementRow],
    recorded: &HashMap<&'static str, Outcome>,
) -> String {
    let mut out = format!("# {title}\n\n");
    out.push_str("| Use case | Section | Verification | Result |\n");
    out.push_str("|---|---|---|---|\n");
    for row in rows {
        let result = checklist_result(row, recorded);
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            row.use_case_label(),
            row.section.as_deref().unwrap_or(""),
            row.verification_label(),
            result
        ));
    }
    out
}

fn checklist_result(row: &RequirementRow, recorded: &HashMap<&'static str, Outcome>) -> String {
    if row.disposition == Disposition::Blocked {
        return "BLOCKED (unrepairable published test data)".to_owned();
    }
    if row.disposition == Disposition::ReportOnly {
        return "Pending (checklist report only)".to_owned();
    }
    if row.disposition == Disposition::HarnessSmoke {
        return match recorded.get(row.req_id.as_str()) {
            Some(Outcome::HarnessSmoke) => "Harness smoke (not normative verification)".to_owned(),
            Some(Outcome::Fail) => "Fail".to_owned(),
            None => "Pending".to_owned(),
            Some(Outcome::Pass) | Some(Outcome::Blocked) => "Invalid outcome".to_owned(),
        };
    }
    match recorded.get(row.req_id.as_str()) {
        Some(Outcome::Pass) => "Pass".to_owned(),
        Some(Outcome::Fail) => "Fail".to_owned(),
        Some(Outcome::Blocked) => "BLOCKED (unrepairable published test data)".to_owned(),
        Some(Outcome::HarnessSmoke) => "Harness smoke (misconfigured disposition)".to_owned(),
        None => "Pending".to_owned(),
    }
}

fn render_risks(manifest: &Manifest, recorded: &HashMap<&'static str, Outcome>) -> String {
    let mut out = String::from("# Interop certification risks\n\n");
    out.push_str("## SHOULD-level downgrades\n\n");
    out.push_str(
        "- `STIX-I0002` (relationship matrix) downgraded to non-gating in interop overlay per §2.3.6 SHOULD.\n",
    );
    out.push_str(
        "- `STIX-W0002` (SCO deterministic id) downgraded — OASIS interop test-case JSON uses publisher-assigned SCO ids.\n",
    );
    out.push_str("\n## BLOCKED rows\n\n");
    for row in manifest
        .in_scope_rows()
        .filter(|r| r.disposition == Disposition::Blocked)
    {
        out.push_str(&format!(
            "- `{}` blocked ({}/§{}): unrepairable published test data\n",
            row.req_id,
            row.checklist_role.as_deref().unwrap_or(""),
            row.checklist_row.as_deref().unwrap_or(""),
        ));
    }
    if recorded.values().any(|o| *o == Outcome::Blocked) {
        out.push_str("\n## Runtime BLOCKED outcomes\n\n");
        for (req_id, outcome) in recorded.iter() {
            if *outcome == Outcome::Blocked {
                out.push_str(&format!("- `{req_id}`\n"));
            }
        }
    }
    out
}

/// Helper assertions for `harness = false` runner.
pub fn run_helper_self_tests() {
    let row = RequirementRow {
        req_id: "REQ-TEST-BLOCKED".to_owned(),
        use_case: None,
        section: None,
        doc_page: None,
        role: None,
        level: "MUST".to_owned(),
        gating: true,
        test_id: None,
        fixture: None,
        checklist_row: None,
        checklist_role: None,
        verification: None,
        disposition: Disposition::Blocked,
        blocked_by: Some(19),
    };
    let recorded = HashMap::new();
    assert!(row_is_covered(&row, &recorded));
}
