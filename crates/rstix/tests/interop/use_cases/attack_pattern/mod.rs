//! §3.1 Attack Pattern Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod consumer_examples;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.1.3.1 Producer test case.
pub const FIXTURE_CREATE: &str = "testcases/attack-pattern/tc-3.1.3.1-create-attack-pattern.json";
/// OASIS §3.1.3.2 Producer test case (also Consumer triad fixture).
pub const FIXTURE_TARGETS: &str =
    "testcases/attack-pattern/tc-3.1.3.2-attack-pattern-targets-vulnerability.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE, FIXTURE_TARGETS];
