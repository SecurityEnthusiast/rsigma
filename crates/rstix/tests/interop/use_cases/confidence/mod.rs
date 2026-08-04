//! §3.3 Confidence Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod consumer_examples;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.3.3.1 Producer test case.
pub const FIXTURE_CREATE: &str =
    "testcases/confidence/tc-3.3.3.1-confidence-about-indicator-external-validation.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
