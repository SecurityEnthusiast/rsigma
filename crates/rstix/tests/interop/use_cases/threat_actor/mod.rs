//! §3.18 Threat Actor Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

pub const FIXTURE_CREATE: &str = "testcases/threat-actor/tc-3.18.3.1-threat-actor-test-case.json";
pub const FIXTURE_ATTRIBUTED: &str =
    "testcases/threat-actor/tc-3.18.3.2-campaign-attributed-to-threat-actor.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE, FIXTURE_ATTRIBUTED];
