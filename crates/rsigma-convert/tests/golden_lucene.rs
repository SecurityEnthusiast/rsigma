//! Golden tests for the Lucene reverse frontend.
//!
//! Each case is a `.lucene` query and a `.yml` expected Sigma rule in
//! `tests/golden/lucene/`. The test drives the query through the same
//! `reverse_collection` entry point the `rsigma rule from-lucene` CLI uses (with
//! a fixed title and logsource) and asserts exact equality with the expected
//! Sigma YAML.

use rsigma_convert::{LuceneFrontend, ReverseCtx, reverse_collection};
use std::fs;
use std::path::Path;

fn run_golden(name: &str) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/lucene");
    let query_path = base.join(format!("{name}.lucene"));
    let expected_path = base.join(format!("{name}.yml"));

    let query = fs::read_to_string(&query_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", query_path.display()))
        .trim()
        .to_string();
    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", expected_path.display()));

    let ctx = ReverseCtx {
        title: Some("Golden Test".to_string()),
        product: Some("windows".to_string()),
        ..Default::default()
    };

    let output = reverse_collection(&LuceneFrontend, std::slice::from_ref(&query), &ctx);
    assert!(
        output.errors.is_empty(),
        "\n\nreverse errors for '{name}':\n  {:#?}",
        output.errors
    );

    let actual = &output.rules[0].yaml;
    assert_eq!(
        actual.trim_end(),
        expected.trim_end(),
        "\n\nGolden mismatch for '{name}':\n--- actual ---\n{actual}\n--- expected ---\n{expected}\n"
    );
}

#[test]
fn golden_simple_eq() {
    run_golden("simple_eq");
}

#[test]
fn golden_and_not() {
    run_golden("and_not");
}

#[test]
fn golden_or_value_list() {
    run_golden("or_value_list");
}

#[test]
fn golden_regex() {
    run_golden("regex");
}

#[test]
fn golden_range_and_compare() {
    run_golden("range_and_compare");
}

#[test]
fn golden_value_group() {
    run_golden("value_group");
}

#[test]
fn golden_exists() {
    run_golden("exists");
}

#[test]
fn golden_keywords() {
    run_golden("keywords");
}
