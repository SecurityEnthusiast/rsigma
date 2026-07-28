//! Guard against silently skipping the OASIS interop certification suite.
//!
//! This target is intentionally **ungated** (no `required-features`). When the interop
//! suite's three features are disabled, Cargo does not build `tests/interop/main.rs` at all
//! and `cargo test` would otherwise report green. See `plan/Golden-Test-layout.md` §6.

#[test]
#[allow(
    clippy::assertions_on_constants,
    reason = "cfg!(feature) is compile-time; the assertion must fail the test binary when features are off"
)]
fn interop_suite_was_not_silently_skipped() {
    assert!(
        cfg!(feature = "validate") && cfg!(feature = "marking") && cfg!(feature = "graph"),
        "the interop target's required-features are off, so Cargo did not build it at all; \
         run: cargo test -p rstix --test interop --features validate,marking,graph"
    );
}
