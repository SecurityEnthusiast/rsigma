//! Structural gating invariants: `testcases/` gate, `examples/` do not (REQ-2.3-X-02/09).

use serde_json::Value;

use crate::common::fixture_walk::for_each_testcase_fixture;
use crate::harness::fixture::{interop_fixtures_root, load_fixture};

/// REQ-2.3-X-09 — normative fixtures live under `testcases/`.
pub fn assert_testcases_directory_exists() {
    let dir = interop_fixtures_root().join("testcases");
    assert!(dir.is_dir(), "missing fixtures/interop/testcases/");
}

/// Example fixtures are non-gating by directory placement.
pub fn assert_examples_directory_exists() {
    let dir = interop_fixtures_root().join("examples");
    assert!(dir.is_dir(), "missing fixtures/interop/examples/");
}

/// Paths under `examples/` must not use the `tc-` prefix reserved for normative data.
pub fn assert_examples_not_normative_prefix() {
    let examples = interop_fixtures_root().join("examples");
    if !examples.exists() {
        return;
    }
    walk_json_files(&examples, &mut |path| {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert!(
            !name.starts_with("tc-"),
            "examples fixture must not use tc- prefix: {}",
            path.display()
        );
    });
}

/// REQ-2.3-X-02 — normative fixtures use Bundle wrappers (authorized by interop spec).
pub fn assert_testcases_use_bundle_wrapper() {
    for_each_testcase_fixture(|relative| {
        let fixture = load_fixture(relative);
        let value: Value = serde_json::from_str(&fixture.json)
            .unwrap_or_else(|e| panic!("{relative} must be valid JSON: {e}"));
        assert_eq!(
            value.get("type"),
            Some(&Value::String("bundle".into())),
            "{relative} must use a bundle wrapper"
        );
        let objects = value
            .get("objects")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{relative} bundle must contain objects array"));
        assert!(
            !objects.is_empty(),
            "{relative}: bundle wrapper must contain objects"
        );
    });
}

/// REQ-2.3-X-09 — combined gating directory invariant.
pub fn assert_gating_directory_layout() {
    assert_testcases_directory_exists();
    assert_examples_directory_exists();
    assert_examples_not_normative_prefix();
}

fn walk_json_files(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path)) {
    if !dir.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_json_files(&path, f);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            f(&path);
        }
    }
}
