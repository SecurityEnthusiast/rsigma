//! Client-side preflight permission checks.

/// Controls whether the client checks `can_read` / `can_write` before requests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PreflightPolicy {
    /// Check collection permissions before read/write operations (default).
    #[default]
    Enabled,
    /// Send all requests; rely on server-side 401/403/404 handling (interop mode).
    Disabled,
}

/// Whether to poll `Status` after POST until completion (TAXII section 5.5 SHOULD).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PostSubmitPolicy {
    /// Poll until `complete` or `failed` (default).
    #[default]
    PollUntilComplete,
    /// Return the initial `Status` response without polling.
    ReturnInitial,
}

/// Whether to verify API Root `versions` and collection `media_types` before use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapabilityPolicy {
    /// Enforce TAXII 2.1 + STIX 2.1 support (default).
    #[default]
    Enforce,
    /// Skip capability checks (interop mode).
    Disabled,
}
