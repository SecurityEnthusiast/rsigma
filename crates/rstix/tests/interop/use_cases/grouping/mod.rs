//! §3.6 Grouping Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.6.3.1 Producer test case.
pub const FIXTURE_CREATE: &str = "testcases/grouping/tc-3.6.3.1-grouping-test-case.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
