//! Integration tests for the per-sink `?format=` parameter: the channels that
//! accept it, the specs that reject it at startup, and the byte-for-byte
//! neutrality of the default NDJSON path.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::str::contains;

const MATCHING_EVENT: &str = "{\"CommandLine\":\"run malware.exe\"}\n";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// Run a stdin-fed daemon with the given extra args and return the assertion.
fn daemon_with(args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ])
    .args(args)
    .timeout(COMMAND_TIMEOUT)
    .write_stdin(stdin.to_string())
    .assert()
}

/// Run a daemon expected to reject its configuration before reading events.
fn daemon_startup_failure(args: &[&str]) -> assert_cmd::assert::Assert {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ])
    .args(args)
    .timeout(COMMAND_TIMEOUT)
    .assert()
}

#[test]
fn explicit_ndjson_format_is_accepted_on_a_findings_sink() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=ndjson", out.path().display());
    daemon_with(&["--output", &spec], MATCHING_EVENT).success();

    let written = std::fs::read_to_string(out.path()).unwrap();
    assert!(
        written.contains("Test Rule"),
        "an explicit ndjson sink must still deliver detections: {written}",
    );
}

/// Naming the default must not change it: a spec with no `format` parameter and
/// a spec that names `ndjson` must produce the same bytes.
#[test]
fn explicit_ndjson_matches_the_default_byte_for_byte() {
    let implicit = temp_file(".ndjson", "");
    let explicit = temp_file(".ndjson", "");
    let implicit_spec = format!("file://{}", implicit.path().display());
    let explicit_spec = format!("file://{}?format=ndjson", explicit.path().display());

    daemon_with(&["--output", &implicit_spec], MATCHING_EVENT).success();
    daemon_with(&["--output", &explicit_spec], MATCHING_EVENT).success();

    let implicit = std::fs::read_to_string(implicit.path()).unwrap();
    let explicit = std::fs::read_to_string(explicit.path()).unwrap();
    assert_eq!(
        implicit, explicit,
        "?format=ndjson must be the default path"
    );
    assert!(
        !implicit.is_empty(),
        "the run should have emitted a finding"
    );
}

#[test]
fn unknown_format_value_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=bogus", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[test]
fn bare_format_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[test]
fn duplicate_format_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ndjson&format=ndjson",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("may be specified only once"));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn format_on_an_otlp_sink_is_a_startup_error() {
    daemon_startup_failure(&["--output", "otlphttp://127.0.0.1:1?format=ndjson"])
        .failure()
        .stderr(contains("not supported on OTLP sinks"));
}

#[test]
fn format_on_the_dlq_spec_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let dlq = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let dlq_spec = format!("file://{}?format=ndjson", dlq.path().display());
    daemon_startup_failure(&["--output", &out_spec, "--dlq", &dlq_spec])
        .failure()
        .stderr(contains("only supported on findings sinks"));
}

#[test]
fn format_on_the_audit_sink_spec_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let audit_out = dir.path().join("audit.ndjson");
    let audit_spec = format!("file://{}?format=ndjson", audit_out.display());
    let audit_spec = format!("'{}'", audit_spec.replace('\'', "''"));
    let config = temp_file(
        ".yaml",
        &format!("daemon:\n  api:\n    audit:\n      enabled: true\n      sink: {audit_spec}\n"),
    );

    daemon_startup_failure(&[
        "--config",
        config.path().to_str().unwrap(),
        "--state-db",
        db.to_str().unwrap(),
    ])
    .failure()
    .stderr(contains("only supported on findings sinks"));
}
