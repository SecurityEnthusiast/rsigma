//! HTTP Basic authentication.

use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};

use super::{AuthError, TaxiiAuthProvider, set_authorization};
use reqwest::header::HeaderMap;

/// RFC 7617 HTTP Basic authentication.
pub struct BasicAuth {
    username: String,
    password: SecretString,
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuth")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl BasicAuth {
    /// Create a basic auth provider.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: SecretString::from(password.into()),
        }
    }
}

impl TaxiiAuthProvider for BasicAuth {
    fn inject_credentials(&self, headers: &mut HeaderMap) -> Result<(), AuthError> {
        let raw = format!("{}:{}", self.username, self.password.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        set_authorization(headers, &format!("Basic {encoded}"))
    }
}
