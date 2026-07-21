//! Bearer token authentication.

use secrecy::{ExposeSecret, SecretString};

use super::{AuthError, TaxiiAuthProvider, set_authorization};
use reqwest::header::HeaderMap;

/// OAuth-style bearer token authentication.
pub struct BearerAuth {
    token: SecretString,
}

impl std::fmt::Debug for BearerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerAuth").finish_non_exhaustive()
    }
}

impl BearerAuth {
    /// Create a bearer auth provider from `token`.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: SecretString::from(token.into()),
        }
    }
}

impl TaxiiAuthProvider for BearerAuth {
    fn inject_credentials(&self, headers: &mut HeaderMap) -> Result<(), AuthError> {
        set_authorization(headers, &format!("Bearer {}", self.token.expose_secret()))
    }
}
