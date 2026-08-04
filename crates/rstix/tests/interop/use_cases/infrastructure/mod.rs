//! §3.8 Infrastructure Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.8.3.1 Producer test case.
pub const FIXTURE_CREATE: &str =
    "testcases/infrastructure/tc-3.8.3.1-infrastructure-test-case.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
