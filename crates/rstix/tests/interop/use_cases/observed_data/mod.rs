//! §3.14 Observed Data Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.14.3.1 Producer test case.
pub const FIXTURE_CREATE: &str =
    "testcases/observed-data/tc-3.14.3.1-observed-data-of-file-hash.json";
/// OASIS §3.14.3.2 Producer test case (Consumer triad / relationship fixture).
pub const FIXTURE_DOMAIN: &str =
    "testcases/observed-data/tc-3.14.3.2-observed-data-domain-name-and-ip-address.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE, FIXTURE_DOMAIN];
