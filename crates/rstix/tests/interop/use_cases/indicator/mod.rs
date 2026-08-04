//! §3.7 Indicator Sharing — Producer and Consumer tests against normative fixtures.

pub mod consumer;
pub mod consumer_examples;
pub mod description;
pub mod examples;
pub mod producer;

/// OASIS §3.7.3.1 Producer test case (primary fixture for Table 14 property checks).
pub const FIXTURE_CREATE: &str = "testcases/indicator/tc-3.7.3.1-indicator-ipv4-address.json";

pub(crate) const PRODUCER_FIXTURES: &[&str] = &[
    FIXTURE_CREATE,
    "testcases/indicator/tc-3.7.3.2-indicator-ipv4-address-cidr.json",
    "testcases/indicator/tc-3.7.3.3-indicator-two-ipv4-cidrs.json",
    "testcases/indicator/tc-3.7.3.4-indicator-ipv6-address.json",
    "testcases/indicator/tc-3.7.3.5-indicator-ipv6-cidr.json",
    "testcases/indicator/tc-3.7.3.6-multiple-indicators.json",
    "testcases/indicator/tc-3.7.3.7-indicator-fqdn.json",
    "testcases/indicator/tc-3.7.3.8-indicator-url.json",
    "testcases/indicator/tc-3.7.3.9-indicator-url-or-fqdn.json",
    "testcases/indicator/tc-3.7.3.10-indicator-file-hash.json",
];
