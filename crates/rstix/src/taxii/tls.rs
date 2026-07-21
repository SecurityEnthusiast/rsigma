//! Client TLS identity (mTLS) configuration.

use reqwest::Identity;
#[cfg(not(feature = "taxii-native-tls"))]
use secrecy::SecretString;
#[cfg(feature = "taxii-native-tls")]
use secrecy::{ExposeSecret, SecretString};

use super::TaxiiError;

/// Client certificate for mutual TLS (spec section 8.3.1).
#[derive(Clone)]
pub struct ClientCertificate {
    identity: Identity,
}

impl ClientCertificate {
    /// Load a PKCS#12 identity.
    ///
    /// Requires the [`taxii-native-tls`](crate) feature (native TLS backend).
    #[cfg(feature = "taxii-native-tls")]
    pub fn from_pkcs12_der(
        der: impl Into<Vec<u8>>,
        password: impl Into<SecretString>,
    ) -> Result<Self, TaxiiError> {
        let password = password.into();
        Identity::from_pkcs12_der(&der.into(), password.expose_secret())
            .map(|identity| Self { identity })
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))
    }

    /// Load a PKCS#12 identity.
    #[cfg(not(feature = "taxii-native-tls"))]
    pub fn from_pkcs12_der(
        _der: impl Into<Vec<u8>>,
        _password: impl Into<SecretString>,
    ) -> Result<Self, TaxiiError> {
        Err(TaxiiError::InvalidClientCertificate(
            "PKCS#12 client certificates require the `taxii-native-tls` feature; use `from_pem` with the default rustls backend".into(),
        ))
    }

    /// Load a PEM certificate + private key pair (concatenated for rustls).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TaxiiError> {
        let mut buf = Vec::with_capacity(cert_pem.len() + key_pem.len());
        buf.extend_from_slice(cert_pem);
        buf.extend_from_slice(key_pem);
        Identity::from_pem(&buf)
            .map(|identity| Self { identity })
            .map_err(|err| TaxiiError::InvalidClientCertificate(err.to_string()))
    }

    pub(crate) fn identity(&self) -> Identity {
        self.identity.clone()
    }
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate").finish_non_exhaustive()
    }
}
