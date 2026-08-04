//! §3.17 Sighting Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

pub const FIXTURE_CREATE: &str = "testcases/sighting/tc-3.17.3.1-sighting-of-indicator.json";
pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
