//! Tests for the pipeline-embedded `sources:` deprecation warning.
//!
//! Phase 1 ([issue #135]) introduced a `tracing::warn!` at parse time when a
//! pipeline file declares a `sources:` block. Phase 3 ([issue #136]) makes
//! that warning louder by also emitting a `warning:` line on stderr, and
//! de-duplicates by canonical pipeline path so daemon hot-reloads do not
//! re-spam the message. These tests pin both behaviours.
//!
//! Phase 4 ([issue #137]) replaces the warning with a hard parse error at
//! v1.0, at which point this file is rewritten to assert the error message.
//!
//! [issue #135]: https://github.com/timescale/rsigma/issues/135
//! [issue #136]: https://github.com/timescale/rsigma/issues/136
//! [issue #137]: https://github.com/timescale/rsigma/issues/137

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

const PIPELINE_WITH_INLINE_SOURCES: &str = r#"
name: legacy_with_sources
priority: 50
sources:
  - id: threat_feed
    type: file
    path: /tmp/threat.json
    format: json
transformations:
  - type: value_placeholders
"#;

const PIPELINE_NO_SOURCES: &str = r#"
name: simple_mapping
priority: 10
transformations:
  - id: map_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#;

const DEPRECATION_NEEDLE: &str =
    "declares an inline 'sources:' block, which is deprecated and will be removed in v1.0";

fn rules_dir(contents: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), contents).unwrap();
    dir
}

#[test]
fn pipeline_sources_emits_stderr_deprecation_warning_via_validate() {
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline.path().to_str().unwrap(),
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("warning:"))
        .stderr(predicate::str::contains(DEPRECATION_NEEDLE))
        .stderr(predicate::str::contains("rsigma rule migrate-sources"))
        .stderr(predicate::str::contains("--source"));
}

#[test]
fn pipeline_sources_emits_stderr_deprecation_warning_via_eval() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "benign"}"#,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_NEEDLE));
}

#[cfg(feature = "daemon")]
#[test]
fn pipeline_sources_emits_stderr_deprecation_warning_via_resolve() {
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    // `pipeline resolve` will fail because the dummy file source path does not
    // exist; we only care that the deprecation warning surfaces on stderr
    // before the failure.
    rsigma()
        .args([
            "pipeline",
            "resolve",
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .assert()
        .stderr(predicate::str::contains(DEPRECATION_NEEDLE));
}

#[test]
fn pipeline_without_sources_does_not_emit_deprecation_warning() {
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_NO_SOURCES);

    rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline.path().to_str().unwrap(),
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_NEEDLE).not());
}

#[test]
fn deprecation_warning_dedupes_across_multiple_pipeline_args() {
    // Passing the same pipeline file twice on the command line still warns
    // exactly once thanks to the canonical-path dedup set in
    // `warn_pipeline_inline_sources`.
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);
    let pipeline_path = pipeline.path().to_str().unwrap();

    let assert = rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline_path,
            "-p",
            pipeline_path,
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_NEEDLE));

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    let occurrences = stderr.matches(DEPRECATION_NEEDLE).count();
    assert_eq!(
        occurrences, 1,
        "deprecation warning should be emitted exactly once per canonical \
         pipeline path even when the file is passed twice. stderr:\n{stderr}"
    );
}

#[test]
fn deprecation_warning_includes_migration_command() {
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);
    let pipeline_path = pipeline.path().to_str().unwrap();

    rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline_path,
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        // The warning should embed the actual pipeline path in the suggested
        // `rsigma rule migrate-sources -p ...` invocation, so an operator can
        // copy-paste it.
        .stderr(predicate::str::contains(pipeline_path));
}
