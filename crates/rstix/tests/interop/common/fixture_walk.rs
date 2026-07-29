//! Shared walk over normative interop fixtures (JSON + provenance sidecar).

use std::path::Path;

use crate::harness::fixture::{interop_fixtures_root, testcase_is_blocked};

/// Invoke `f` for each `testcases/**/*.json` that has a `.provenance.toml` sidecar.
pub fn for_each_testcase_fixture(mut f: impl FnMut(&str)) {
    walk_dir(
        interop_fixtures_root().join("testcases").as_path(),
        &mut f,
        WalkFilter::All,
    );
}

/// Like [`for_each_testcase_fixture`], but skips blocked fixtures and harness/common synthetics.
pub fn for_each_suite_walk_fixture(mut f: impl FnMut(&str)) {
    walk_dir(
        interop_fixtures_root().join("testcases").as_path(),
        &mut f,
        WalkFilter::SuiteWalk,
    );
}

fn is_non_normative_testcase(relative_path: &str) -> bool {
    relative_path.starts_with("testcases/harness/")
        || relative_path.starts_with("testcases/common/")
}

#[derive(Clone, Copy)]
enum WalkFilter {
    All,
    SuiteWalk,
}

impl WalkFilter {
    const fn excludes_blocked(self) -> bool {
        matches!(self, WalkFilter::SuiteWalk)
    }

    const fn excludes_non_normative(self) -> bool {
        matches!(self, WalkFilter::SuiteWalk)
    }
}

fn walk_dir(dir: &Path, f: &mut dyn FnMut(&str), filter: WalkFilter) {
    if !dir.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, f, filter);
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
            if filter.excludes_blocked() && testcase_is_blocked(&relative) {
                continue;
            }
            if filter.excludes_non_normative() && is_non_normative_testcase(&relative) {
                continue;
            }
            f(&relative);
        }
    }
}
