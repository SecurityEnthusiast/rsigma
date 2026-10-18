//! Listen address for the daemon API server: a TCP `host:port` or, on Unix, a
//! `unix:///path/to.sock` domain socket.
//!
//! A Unix socket is gated by filesystem permissions rather than TLS, so it is
//! treated as a local trust boundary: TLS is rejected on a `unix://` address
//! and neither the plaintext-bind nor the unauthenticated-bind refusal applies.

use std::fmt;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;

/// Where the daemon API server listens.
#[derive(Clone, Debug)]
pub(crate) enum ListenAddr {
    /// A TCP socket address.
    Tcp(SocketAddr),
    /// A Unix domain socket path (Unix only).
    #[cfg(unix)]
    Unix(PathBuf),
}

impl ListenAddr {
    /// Parse `--api-addr`: a `unix://` URI becomes [`ListenAddr::Unix`],
    /// anything else is parsed as a TCP `SocketAddr`.
    pub(crate) fn parse(spec: &str) -> Result<Self, String> {
        if let Some(path) = spec.strip_prefix("unix://") {
            #[cfg(unix)]
            {
                if path.is_empty() {
                    return Err("unix:// socket path is empty".to_string());
                }
                return Ok(ListenAddr::Unix(PathBuf::from(path)));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(
                    "unix:// API addresses are only supported on Unix platforms".to_string()
                );
            }
        }
        spec.parse::<SocketAddr>()
            .map(ListenAddr::Tcp)
            .map_err(|e| format!("expected host:port or unix://path: {e}"))
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenAddr::Tcp(addr) => write!(f, "{addr}"),
            #[cfg(unix)]
            ListenAddr::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

/// Decide whether the API may serve plaintext on `addr`.
///
/// Loopback addresses (`127.0.0.0/8`, `::1`) are always allowed for local
/// development. Any other bind requires an explicit `--allow-plaintext`
/// opt-in so a careless `--api-addr 0.0.0.0:9090` never silently ships
/// detection events over cleartext.
pub(crate) fn enforce_plaintext_policy(
    addr: SocketAddr,
    allow_plaintext: bool,
) -> Result<(), String> {
    if addr.ip().is_loopback() || allow_plaintext {
        return Ok(());
    }
    let enable_tls = if cfg!(feature = "daemon-tls") {
        "pass --tls-cert/--tls-key to enable TLS"
    } else {
        "this build has no TLS support (rebuild with the `daemon-tls` feature)"
    };
    Err(format!(
        "refusing to bind plaintext on non-loopback address {addr}; {enable_tls}, \
         or pass --allow-plaintext to opt out (e.g. when terminating TLS at a \
         sidecar reverse proxy)"
    ))
}

/// Decide whether the API may serve unauthenticated requests on `addr`.
///
/// `authenticated` is true when bearer tokens are configured or the listener
/// requires client certificates. Loopback addresses are always allowed. Any
/// other bind without authentication requires an explicit
/// `--allow-unauthenticated` opt-in, because the API can reload rules, mutate
/// silences and dispositions, and read correlation state.
pub(crate) fn enforce_auth_policy(
    addr: SocketAddr,
    authenticated: bool,
    allow_unauthenticated: bool,
) -> Result<(), String> {
    if authenticated || addr.ip().is_loopback() || allow_unauthenticated {
        return Ok(());
    }
    let client_certs = if cfg!(feature = "daemon-tls") {
        ", require client certificates with --tls-client-ca"
    } else {
        ""
    };
    Err(format!(
        "refusing to serve the API without authentication on non-loopback address \
         {addr}; configure bearer tokens (daemon.api.auth or --api-token-env){client_certs}, \
         or pass --allow-unauthenticated to opt out (e.g. when an authenticating \
         proxy fronts the daemon)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_addr() {
        let addr = ListenAddr::parse("127.0.0.1:9090").unwrap();
        assert!(matches!(addr, ListenAddr::Tcp(_)));
        assert_eq!(addr.to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn rejects_garbage() {
        assert!(ListenAddr::parse("not-an-addr").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parses_unix_path() {
        let addr = ListenAddr::parse("unix:///run/rsigma/api.sock").unwrap();
        assert!(matches!(addr, ListenAddr::Unix(_)));
        assert_eq!(addr.to_string(), "unix:///run/rsigma/api.sock");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_empty_unix_path() {
        assert!(ListenAddr::parse("unix://").is_err());
    }

    #[test]
    fn loopback_bypasses_plaintext_check() {
        assert!(enforce_plaintext_policy("127.0.0.1:0".parse().unwrap(), false).is_ok());
        assert!(enforce_plaintext_policy("[::1]:0".parse().unwrap(), false).is_ok());
    }

    #[test]
    fn public_plaintext_bind_requires_explicit_opt_in() {
        let addr: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        let err = enforce_plaintext_policy(addr, false).unwrap_err();
        assert!(err.contains("refusing to bind plaintext"));
        assert!(err.contains("--allow-plaintext"));
        assert!(enforce_plaintext_policy(addr, true).is_ok());
    }

    #[test]
    fn loopback_bypasses_auth_check() {
        assert!(enforce_auth_policy("127.0.0.1:0".parse().unwrap(), false, false).is_ok());
        assert!(enforce_auth_policy("[::1]:0".parse().unwrap(), false, false).is_ok());
    }

    #[test]
    fn public_unauthenticated_bind_requires_explicit_opt_in() {
        for addr in ["0.0.0.0:9090", "[::]:9090", "10.0.0.5:9090"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let err = enforce_auth_policy(addr, false, false).unwrap_err();
            assert!(err.contains("without authentication"), "{err}");
            assert!(err.contains("--allow-unauthenticated"), "{err}");
            assert!(enforce_auth_policy(addr, false, true).is_ok());
            assert!(enforce_auth_policy(addr, true, false).is_ok());
        }
    }
}
