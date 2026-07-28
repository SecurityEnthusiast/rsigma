//! Shared walk over normative interop fixtures (JSON + provenance sidecar).

use std::path::Path;

use crate::harness::fixture::interop_fixtures_root;

/// Invoke `f` for each `testcases/**/*.json` that has a `.provenance.toml` sidecar.
pub fn for_each_testcase_fixture(mut f: impl FnMut(&str)) {
    walk_dir(interop_fixtures_root().join("testcases").as_path(), &mut f);
}

fn walk_dir(dir: &Path, f: &mut dyn FnMut(&str)) {
    if !dir.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, f);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            let sidecar = path.with_extension("provenance.toml");
            if !sidecar.exists() {
                continue;
            }
            let relative = path
                .strip_prefix(interop_fixtures_root())
                .expect("under interop root")
                .to_string_lossy()
                .into_owned();
            f(&relative);
        }
    }
}
