//! §3.10 Location Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.10.3.1 Producer test case.
pub const FIXTURE_CREATE: &str = "testcases/location/tc-3.10.3.1-producing-location-object.json";
/// OASIS §3.10.3.2 Producer test case (also Consumer triad fixture).
pub const FIXTURE_HOSTING: &str =
    "testcases/location/tc-3.10.3.2-location-hosting-infrastructure.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE, FIXTURE_HOSTING];
