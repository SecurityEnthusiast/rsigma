//! Custom API-key header authentication.

use secrecy::{ExposeSecret, SecretString};

use super::{AuthError, TaxiiAuthProvider, insert_header};
use reqwest::header::HeaderMap;

/// Sends a shared secret in a named request header.
pub struct ApiKeyHeader {
    header_name: String,
    value: SecretString,
}

impl std::fmt::Debug for ApiKeyHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyHeader")
            .field("header_name", &self.header_name)
            .finish_non_exhaustive()
    }
}

impl ApiKeyHeader {
    /// Create an API-key header provider.
    pub fn new(header_name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into(),
            value: SecretString::from(value.into()),
        }
    }
}

impl TaxiiAuthProvider for ApiKeyHeader {
    fn inject_credentials(&self, headers: &mut HeaderMap) -> Result<(), AuthError> {
        insert_header(headers, &self.header_name, self.value.expose_secret())
    }
}
