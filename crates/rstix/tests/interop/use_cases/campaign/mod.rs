//! §3.2 Campaign Sharing — Producer and Consumer tests against normative fixtures.

pub mod description;
pub mod producer;

/// OASIS §3.2.3.1 Producer test case.
pub const FIXTURE_CREATE: &str = "testcases/campaign/tc-3.2.3.1-campaign-test-case.json";
/// OASIS §3.2.3.2 Producer test case (also Consumer triad fixture).
pub const FIXTURE_ATTRIBUTED: &str =
    "testcases/campaign/tc-3.2.3.2-campaign-attributed-to-intrusion-set.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE, FIXTURE_ATTRIBUTED];
