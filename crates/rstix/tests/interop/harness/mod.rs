pub mod certification;
pub mod closure;
pub mod containment;
pub mod fixture;
pub mod manifest;
pub mod profile;
pub mod registry;

/// Register a test at compile time and expose a deterministic runner (no `#[test]`).
///
/// `$test_id` must match the `test_id` column in `fixtures/interop/manifest.toml`.
/// Default outcome is [`certification::Outcome::Pass`]; use the `smoke` form for
/// harness-only checks that do not verify OASIS normative fixtures yet.
#[macro_export]
macro_rules! interop_test {
    ($req_id:expr, $test_id:expr, $name:ident, smoke, $body:block) => {
        $crate::interop_test!(@internal $req_id, $test_id, $name, HarnessSmoke, $body);
    };
    ($req_id:expr, $test_id:expr, $name:ident, $body:block) => {
        $crate::interop_test!(@internal $req_id, $test_id, $name, Pass, $body);
    };
    (@internal $req_id:expr, $test_id:expr, $name:ident, $outcome:ident, $body:block) => {
        ::pastey::paste! {
            fn $name() {
                $body
                $crate::harness::certification::record_outcome(
                    $req_id,
                    $crate::harness::certification::Outcome::$outcome,
                );
            }

            #[linkme::distributed_slice($crate::harness::registry::INTEROP_TESTS)]
            static [<INTEROP_TEST_ $name:upper>]: $crate::harness::registry::InteropTestEntry =
                $crate::harness::registry::InteropTestEntry {
                    descriptor: $crate::harness::registry::TestDescriptor {
                        req_id: $req_id,
                        test_id: $test_id,
                    },
                    run: $name,
                };
        }
    };
}

/// Run registered interop tests in stable `test_id` order, then helper self-checks.
pub fn run_all() {
    let mut tests: Vec<_> = registry::INTEROP_TESTS.iter().copied().collect();
    tests.sort_by_key(|entry| entry.descriptor.test_id);
    for entry in tests {
        (entry.run)();
    }
    fixture::run_helper_self_tests();
    certification::run_helper_self_tests();
}
