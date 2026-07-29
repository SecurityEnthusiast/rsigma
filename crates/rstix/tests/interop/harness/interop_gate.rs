//! Interop bundle gate: parse (with TLP exemption), `interop_strict`, overlay, use-case rules.

use std::path::{Path, PathBuf};

use rstix::model::{Bundle, ParseOptions};
use rstix::validate::Validator;

use super::closure::missing_closure_ids_from_json;
use super::profile::InteropOverlay;
use super::use_case::validate_use_case_objects;

use crate::common::fixture_catalog::parse_fixture_objects;

/// Options for the interop bundle gate (two-tier validation).
#[derive(Clone, Debug, Default)]
pub struct InteropGateOptions {
    /// Object ids that receive interop use-case rules (referenced objects are spec-only).
    pub use_case_object_ids: Vec<String>,
}

/// Result of running the interop gate on wire JSON.
pub type InteropGateResult = Result<Bundle, String>;

fn interop_parse_options() -> ParseOptions {
    ParseOptions::new().interop_bundle()
}

/// Parse + validate for interop bundles (closure, strict validator, optional use-case rules).
pub fn validate_interop_json(json: &str, opts: &InteropGateOptions) -> InteropGateResult {
    let missing = missing_closure_ids_from_json(json);
    if !missing.is_empty() {
        return Err(format!(
            "bundle not reference-closed; missing ids: {missing:?}"
        ));
    }

    let bundle = Bundle::parse_with_options(json, &interop_parse_options())
        .map_err(|err| format!("interop bundle parse failed: {err}"))?;

    let wire_objects = parse_fixture_objects(json)?;

    let report = Validator::interop_bundle_strict().validate_bundle(&bundle);
    let overlay = InteropOverlay::default().apply_overlay(report);
    if !overlay.is_valid() {
        return Err("interop_strict validation failed (after overlay)".into());
    }

    validate_use_case_objects(&bundle, &opts.use_case_object_ids, &wire_objects)?;
    Ok(bundle)
}

/// Parse + validate a normative fixture with use-case ids inferred from its path.
pub fn validate_interop_fixture(relative: &str, json: &str) -> InteropGateResult {
    let use_case_object_ids =
        crate::common::fixture_catalog::use_case_object_ids_for_fixture(relative, json)?;
    validate_interop_json(
        json,
        &InteropGateOptions {
            use_case_object_ids,
        },
    )
}

fn conformance_valid_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/conformance/valid")
}

fn collect_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in std::fs::read_dir(dir).expect("read conformance dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// Cross-check `tests/fixtures/conformance/valid/` under the interop gate (spec-only tier).
pub fn assert_conformance_valid_corpus_passes_interop_gate() -> Result<(), String> {
    let files = collect_json_files(&conformance_valid_dir());
    if files.is_empty() {
        return Err("no valid conformance fixtures".into());
    }
    for file in files {
        let json = std::fs::read_to_string(&file)
            .map_err(|err| format!("read {}: {err}", file.display()))?;
        validate_interop_json(&json, &InteropGateOptions::default()).map_err(|err| {
            format!(
                "conformance valid {} failed interop gate: {err}",
                file.display()
            )
        })?;
    }
    Ok(())
}
