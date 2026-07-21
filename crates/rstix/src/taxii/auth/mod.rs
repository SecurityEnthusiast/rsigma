//! TAXII authentication providers.

mod api_key;
mod basic;
mod bearer;

pub use api_key::ApiKeyHeader;
pub use basic::BasicAuth;
pub use bearer::BearerAuth;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};

/// Authentication injection errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Header name or value is invalid.
    #[error("invalid auth header: {0}")]
    InvalidHeader(String),
}

/// Injects credentials into outbound TAXII requests.
pub trait TaxiiAuthProvider: Send + Sync {
    /// Add authentication headers to `headers`.
    fn inject_credentials(&self, headers: &mut HeaderMap) -> Result<(), AuthError>;
}

pub(crate) fn insert_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), AuthError> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| AuthError::InvalidHeader(err.to_string()))?;
    let value =
        HeaderValue::from_str(value).map_err(|err| AuthError::InvalidHeader(err.to_string()))?;
    headers.insert(name, value);
    Ok(())
}

pub(crate) fn set_authorization(headers: &mut HeaderMap, value: &str) -> Result<(), AuthError> {
    let parsed =
        HeaderValue::from_str(value).map_err(|err| AuthError::InvalidHeader(err.to_string()))?;
    headers.insert(AUTHORIZATION, parsed);
    Ok(())
}
