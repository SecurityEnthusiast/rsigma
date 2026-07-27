pub mod certification;
pub mod closure;
pub mod containment;
pub mod fixture;
pub mod manifest;
pub mod profile;
pub mod registry;

/// Register a test descriptor at compile time and expose a `#[test]` wrapper.
///
/// `$test_id` must match the `test_id` column in `fixtures/interop/manifest.toml`.
#[macro_export]
macro_rules! interop_test {
    ($req_id:expr, $test_id:expr, $name:ident, $body:block) => {
        ::paste::paste! {
            #[linkme::distributed_slice($crate::harness::registry::INTEROP_TEST_DESCRIPTORS)]
            static [<INTEROP_DESCRIPTOR_ $name:upper>]: $crate::harness::registry::TestDescriptor =
                $crate::harness::registry::TestDescriptor {
                    req_id: $req_id,
                    test_id: $test_id,
                };
        }

        #[test]
        fn $name() {
            $body
            $crate::harness::certification::record_outcome(
                $req_id,
                $crate::harness::certification::Outcome::Pass,
            );
        }
    };
}
