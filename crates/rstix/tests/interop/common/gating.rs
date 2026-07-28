//! Structural gating invariant: `testcases/` gate, `examples/` do not (REQ-2.3-X-09).

use std::path::Path;

use crate::harness::fixture::interop_fixtures_root;

/// Every normative fixture lives under `testcases/`.
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

fn walk_json_files(dir: &Path, f: &mut dyn FnMut(&Path)) {
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
