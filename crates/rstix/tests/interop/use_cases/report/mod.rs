//! §3.16 Report Sharing — Producer and Consumer tests against normative fixtures.
//!
//! `REQ-CHK-SXP-3.16` stays BLOCKED (defect 16). TESTED rows use in-memory `published` repair.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

pub const FIXTURE_CREATE: &str = "testcases/report/tc-3.16.3.1-create-report-object.json";
pub(crate) const PRODUCER_FIXTURES: &[&str] = &[FIXTURE_CREATE];

pub(crate) fn working_json(json: &str) -> String {
    json.replace("2020-01-201T17:00:00Z", "2020-01-20T17:00:00.000Z")
}
