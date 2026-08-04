//! §3.15 Opinion Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

pub const FIXTURE_CREATE: &str =
    "testcases/opinion/tc-3.15.3.1-opinion-on-indicator-different-identity.json";
pub const FIXTURE_MALWARE: &str =
    "testcases/opinion/tc-3.15.3.2-opinion-on-malware-different-identity.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE, FIXTURE_MALWARE];
