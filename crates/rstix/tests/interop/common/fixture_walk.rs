//! Shared walk over normative interop fixtures (JSON + provenance sidecar).

use std::path::Path;

use crate::harness::fixture::{interop_fixtures_root, testcase_is_blocked};

/// Normative gating fixtures under `testcases/` (excludes harness/common synthetics).
pub const EXPECTED_GATING_FIXTURE_COUNT: usize = 44;
/// Gating fixtures exercised by suite-wide §2.3 rows (excludes `BLOCKED` defects).
pub const EXPECTED_SUITE_WALK_FIXTURE_COUNT: usize = 42;
/// Gating fixtures recorded as `BLOCKED` on unrepairable OASIS §9.1 publisher defects.
pub const EXPECTED_BLOCKED_FIXTURE_COUNT: usize = 2;

const DELIBERATE_MISSING_SIDECAR: &str = "testcases/harness/missing-sidecar.json";

/// Normalize fixture paths to forward slashes for cross-platform comparisons.
pub fn normalize_fixture_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// Invoke `f` for each `testcases/**/*.json` that has a `.provenance.toml` sidecar.
pub fn for_each_testcase_fixture(mut f: impl FnMut(&str)) {
    for relative in collect_testcase_fixtures(WalkFilter::All) {
        f(&relative);
    }
}

/// Like [`for_each_testcase_fixture`], but skips blocked fixtures and harness/common synthetics.
pub fn for_each_suite_walk_fixture(mut f: impl FnMut(&str)) {
    for relative in collect_testcase_fixtures(WalkFilter::SuiteWalk) {
        f(&relative);
    }
}

/// Collect testcase fixture paths for the given walk filter.
fn collect_testcase_fixtures(filter: WalkFilter) -> Vec<String> {
    let mut paths = Vec::new();
    walk_dir(
        interop_fixtures_root().join("testcases").as_path(),
        &mut |relative| paths.push(relative.to_owned()),
        filter,
    );
    paths.sort();
    paths
}

/// Fail if the on-disk fixture inventory shrinks or grows without an explicit update.
pub fn assert_fixture_inventory_counts() {
    let gating = collect_testcase_fixtures(WalkFilter::GatingInventory);
    let suite = collect_testcase_fixtures(WalkFilter::SuiteWalk);
    let blocked = gating
        .iter()
        .filter(|relative| testcase_is_blocked(relative))
        .count();

    assert_eq!(
        gating.len(),
        EXPECTED_GATING_FIXTURE_COUNT,
        "gating fixture inventory drift: expected {EXPECTED_GATING_FIXTURE_COUNT}, walked {}; paths={gating:?}",
        gating.len()
    );
    assert_eq!(
        suite.len(),
        EXPECTED_SUITE_WALK_FIXTURE_COUNT,
        "suite-walk fixture inventory drift: expected {EXPECTED_SUITE_WALK_FIXTURE_COUNT}, walked {}; paths={suite:?}",
        suite.len()
    );
    assert_eq!(
        blocked, EXPECTED_BLOCKED_FIXTURE_COUNT,
        "blocked fixture count drift: expected {EXPECTED_BLOCKED_FIXTURE_COUNT}, found {blocked}"
    );
    assert_eq!(
        gating.len().saturating_sub(blocked),
        suite.len(),
        "suite walk must equal gating inventory minus blocked fixtures"
    );
}

fn is_non_normative_testcase(relative_path: &str) -> bool {
    let relative = normalize_fixture_path(relative_path);
    relative.starts_with("testcases/harness/") || relative.starts_with("testcases/common/")
}

#[derive(Clone, Copy)]
enum WalkFilter {
    All,
    GatingInventory,
    SuiteWalk,
}

impl WalkFilter {
    const fn excludes_non_normative(self) -> bool {
        matches!(self, WalkFilter::GatingInventory | WalkFilter::SuiteWalk)
    }

    const fn excludes_blocked(self) -> bool {
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
            let relative = normalize_fixture_path(
                &path
                    .strip_prefix(interop_fixtures_root())
                    .expect("under interop root")
                    .to_string_lossy(),
            );
            let sidecar = path.with_extension("provenance.toml");
            if !sidecar.exists() {
                if relative == DELIBERATE_MISSING_SIDECAR {
                    continue;
                }
                panic!(
                    "testcase JSON missing provenance sidecar: {relative} (expected {})",
                    sidecar.display()
                );
            }
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
