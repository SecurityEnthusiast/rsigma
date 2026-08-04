//! §3.13 Note Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.13.3.1 Producer test case.
pub const FIXTURE_CREATE: &str = "testcases/note/tc-3.13.3.1-note-on-threat-actor.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
