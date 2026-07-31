//! Integration coverage for `rsigma rule tune` boundaries.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const FILTER_GOLDEN: &str = include_str!("golden/tune_filter.yaml");
const EXPECTATION_DIFF_GOLDEN: &str = include_str!("golden/tune_expectation_diff.txt");

const RULE: &str = r#"
title: Suspicious Backup Tool
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\backup.exe'
    condition: selection
level: medium
"#;

const FALSE_POSITIVES: &str = concat!(
    r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
    "\n",
    r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
    "\n",
);

const TRUE_POSITIVES: &str = concat!(
    r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#,
    "\n"
);

fn normalize_id(yaml: &str) -> String {
    yaml.lines()
        .map(|line| {
            if line.starts_with("id: ") {
                "id: <ID>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tune_from_files_matches_golden() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);

    let output = rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .output()
        .expect("run tune");

    assert!(output.status.success());
    let yaml = String::from_utf8(output.stdout).expect("utf8");
    assert_eq!(
        normalize_id(&yaml).trim_end(),
        FILTER_GOLDEN.trim_end(),
        "filter YAML drifted from golden"
    );
}

#[test]
fn emitted_filter_lints_and_suppresses_only_false_positives() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);
    let output = rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .output()
        .expect("run tune");
    assert!(output.status.success());
    let filter = temp_file(".yml", &String::from_utf8(output.stdout).unwrap());

    rsigma()
        .args(["rule", "lint", filter.path().to_str().unwrap()])
        .assert()
        .success();

    let rules = tempfile::tempdir().unwrap();
    std::fs::copy(rule.path(), rules.path().join("rule.yml")).unwrap();
    std::fs::copy(filter.path(), rules.path().join("filter.yml")).unwrap();
    let all_events = temp_file(".ndjson", &format!("{FALSE_POSITIVES}{TRUE_POSITIVES}"));
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rules.path().to_str().unwrap(),
            "--event",
            &format!("@{}", all_events.path().display()),
            "--include-event",
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("attacker"))
        .stdout(predicate::str::contains("svc_backup").not());
}

#[test]
fn report_json_contains_closed_verification() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
            "--emit",
            "report",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"false_positives_after\": 0"))
        .stdout(predicate::str::contains("\"true_positives_after\": 1"));
}

#[test]
fn pipeline_mapped_fields_are_emitted_and_verified() {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(
        ".yml",
        r#"
name: ecs-ish
priority: 10
transformations:
  - id: rename_image
    type: field_name_mapping
    mapping:
      Image: process.executable
"#,
    );
    let fp = temp_file(
        ".ndjson",
        concat!(
            r#"{"process":{"executable":"C:\\Program Files\\Veeam\\backup.exe"},"User":"svc_backup"}"#,
            "\n",
            r#"{"process":{"executable":"C:\\Program Files\\Veeam\\backup.exe"},"User":"svc_backup"}"#,
            "\n",
        ),
    );
    let tp = temp_file(
        ".ndjson",
        concat!(
            r#"{"process":{"executable":"C:\\Temp\\backup.exe"},"User":"svc_backup"}"#,
            "\n",
        ),
    );

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("process.executable"))
        .stdout(predicate::str::contains("\n        Image:").not());
}

#[test]
fn expectations_report_contains_paste_ready_golden_diff() {
    let rule = temp_file(".yml", RULE);
    let expectations = temp_file(
        ".yml",
        r#"
expectations:
  - rule: 929a690e-bef0-4204-a928-ef5e620d6fcc
    at_least: 1
"#,
    );
    let output = rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--tp",
            r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#,
            "--expectations",
            expectations.path().to_str().unwrap(),
            "--emit",
            "report",
            "--output-format",
            "table",
        ])
        .write_stdin(FALSE_POSITIVES)
        .output()
        .expect("run tune expectation diff");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let diff = stdout
        .split_once("# Backtest expectation diff\n")
        .map(|(_, diff)| diff)
        .expect("expectation diff marker");
    assert_eq!(diff.trim_end(), EXPECTATION_DIFF_GOLDEN.trim_end());
}

#[test]
fn multiple_rules_require_an_explicit_target() {
    let rules = temp_file(
        ".yml",
        &format!(
            "{RULE}\n---\n{}",
            RULE.replace("Suspicious Backup Tool", "Other Rule")
                .replace("929a690e-bef0-4204-a928-ef5e620d6fcc", "other-rule")
        ),
    );
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rules.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --rule"));
}

#[test]
fn malformed_corpus_record_fails_closed() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(
        ".ndjson",
        concat!(
            r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#,
            "\nnot-json\n",
        ),
    );

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "tuning requires the complete corpus",
        ));
}
