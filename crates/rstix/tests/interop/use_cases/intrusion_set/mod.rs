//! §3.9 Intrusion Set Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.9.3.1 Producer test case.
pub const FIXTURE_CREATE: &str =
    "testcases/intrusion-set/tc-3.9.3.1-intrusion-set-test-case.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
