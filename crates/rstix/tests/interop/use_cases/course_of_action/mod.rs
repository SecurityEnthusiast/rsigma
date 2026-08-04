//! §3.4 Course Of Action Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.4.3.1 Producer test case.
pub const FIXTURE_CREATE: &str =
    "testcases/course-of-action/tc-3.4.3.1-create-course-of-action.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];
