//! §3.20 Versioning — creation, modification, and revocation phase tests.

pub mod consumer_creation;
pub mod consumer_modification;
pub mod consumer_revocation;
pub mod description;
pub mod producer_creation;
pub mod producer_modification;
pub mod producer_revocation;

pub const FIXTURE_CREATE_INDICATOR: &str =
    "testcases/versioning/tc-3.20.3.1-creation-of-indicator.json";
pub const FIXTURE_CREATE_SIGHTING: &str =
    "testcases/versioning/tc-3.20.3.2-creation-of-sighting.json";
pub const FIXTURE_MOD_INDICATOR: &str =
    "testcases/versioning/tc-3.20.7.1-modification-of-indicator.json";
pub const FIXTURE_MOD_SIGHTING: &str =
    "testcases/versioning/tc-3.20.7.2-modification-of-sighting.json";
pub const FIXTURE_REV_INDICATOR: &str =
    "testcases/versioning/tc-3.20.11.1-revocation-of-indicator.json";
pub const FIXTURE_REV_SIGHTING: &str =
    "testcases/versioning/tc-3.20.11.2-revocation-of-sighting.json";

pub(crate) const CREATION_FIXTURES: &[&str] =
    &[FIXTURE_CREATE_INDICATOR, FIXTURE_CREATE_SIGHTING];
pub(crate) const MODIFICATION_FIXTURES: &[&str] =
    &[FIXTURE_MOD_INDICATOR, FIXTURE_MOD_SIGHTING];
pub(crate) const REVOCATION_FIXTURES: &[&str] =
    &[FIXTURE_REV_INDICATOR, FIXTURE_REV_SIGHTING];
