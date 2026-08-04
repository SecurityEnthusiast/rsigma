//! §3.19 Tool Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.19.3.1 Producer test case.
pub const FIXTURE_CREATE: &str = "testcases/tool/tc-3.19.3.1-remote-access-tool.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
