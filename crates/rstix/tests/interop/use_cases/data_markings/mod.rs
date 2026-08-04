//! §3.5 Data Markings Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.5.3.1 Producer test case (TLP White + Indicator IPv4).
pub const FIXTURE_CREATE: &str =
    "testcases/data-markings/tc-3.5.3.1-tlp-white-indicator-ipv4.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[
    FIXTURE_CREATE,
    "testcases/data-markings/tc-3.5.3.2-tlp-green-indicator-ipv4.json",
    "testcases/data-markings/tc-3.5.3.3-tlp-amber-indicator-ipv4-cidr.json",
    "testcases/data-markings/tc-3.5.3.4-tlp-red-indicator-ipv6.json",
];
