//! Certification outcomes, coverage gate, and §4.2 report generation.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::manifest::{Disposition, Manifest, RequirementRow};
use super::registry::INTEROP_TEST_DESCRIPTORS;

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
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "Pass",
            Self::Fail => "Fail",
            Self::Blocked => "BLOCKED",
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
    let registered: HashSet<&str> = INTEROP_TEST_DESCRIPTORS.iter().map(|d| d.test_id).collect();
    let manifest_test_ids: HashSet<&str> = manifest
        .testable_requirements()
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
    let recorded = outcomes().lock().expect("interop outcomes lock");
    let mut missing_outcomes = Vec::new();

    for row in manifest.testable_requirements() {
        if !recorded.contains_key(row.req_id.as_str()) {
            missing_outcomes.push(row.req_id.clone());
        }
    }

    assert!(
        missing_outcomes.is_empty(),
        "testable manifest requirements without recorded outcomes: {missing_outcomes:?}"
    );

    let in_scope = manifest.in_scope_rows().count();
    let covered = manifest
        .in_scope_rows()
        .filter(|row| row_is_covered(row, &recorded))
        .count();

    assert_eq!(
        covered, in_scope,
        "coverage gate: {covered}/{in_scope} in-scope manifest rows covered"
    );
}

fn row_is_covered(row: &RequirementRow, recorded: &HashMap<&'static str, Outcome>) -> bool {
    match row.disposition {
        Disposition::Tested => recorded.contains_key(row.req_id.as_str()),
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
    personas_claimed: Vec<&'static str>,
    use_cases_claimed: u32,
    in_scope_requirements: usize,
    covered_requirements: usize,
    passed_requirements: usize,
    blocked_requirements: usize,
    features_enabled: FeaturesEnabled,
}

#[derive(serde::Serialize)]
struct FeaturesEnabled {
    validate: bool,
    marking: bool,
    graph: bool,
}

fn build_summary(manifest: &Manifest, recorded: &HashMap<&'static str, Outcome>) -> SummaryJson {
    let in_scope: Vec<_> = manifest.in_scope_rows().collect();
    let covered = in_scope
        .iter()
        .filter(|row| row_is_covered(row, recorded))
        .count();
    let passed = recorded.values().filter(|o| **o == Outcome::Pass).count();
    let blocked = manifest
        .in_scope_rows()
        .filter(|row| row.disposition == Disposition::Blocked)
        .count();

    SummaryJson {
        document: "STIX 2.1 Interoperability v1.0 CSD01 (stix-2.1-interop-v1.0-csd01)",
        document_stage: "Committee Specification Draft 01 (2021-10-23)",
        personas_claimed: vec!["SXP", "SXC"],
        use_cases_claimed: 21,
        in_scope_requirements: in_scope.len(),
        covered_requirements: covered,
        passed_requirements: passed,
        blocked_requirements: blocked,
        features_enabled: FeaturesEnabled {
            validate: cfg!(feature = "validate"),
            marking: cfg!(feature = "marking"),
            graph: cfg!(feature = "graph"),
        },
    }
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
        return format!("BLOCKED (defect {})", row.blocked_by.unwrap_or(0));
    }
    if row.disposition == Disposition::ReportOnly {
        return "Pending (Phase 7)".to_owned();
    }
    match recorded.get(row.req_id.as_str()) {
        Some(Outcome::Pass) => "Pass".to_owned(),
        Some(Outcome::Fail) => "Fail".to_owned(),
        Some(Outcome::Blocked) => format!("BLOCKED (defect {})", row.blocked_by.unwrap_or(0)),
        None => "Pending".to_owned(),
    }
}

fn render_risks(manifest: &Manifest, recorded: &HashMap<&'static str, Outcome>) -> String {
    let mut out = String::from("# Interop certification risks\n\n");
    out.push_str("## SHOULD-level downgrades\n\n");
    out.push_str(
        "- `STIX-I0002` (relationship matrix) downgraded to non-gating in interop overlay per §2.3.6 SHOULD.\n",
    );
    out.push_str("\n## BLOCKED rows\n\n");
    for row in manifest
        .in_scope_rows()
        .filter(|r| r.disposition == Disposition::Blocked)
    {
        out.push_str(&format!(
            "- `{}` blocked by defect {}\n",
            row.req_id,
            row.blocked_by.unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_counts_as_covered_not_passed() {
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
        let mut recorded = HashMap::new();
        assert!(row_is_covered(&row, &recorded));
        recorded.insert("REQ-TEST-BLOCKED", Outcome::Blocked);
        assert_ne!(recorded.get("REQ-TEST-BLOCKED"), Some(&Outcome::Pass));
    }
}
