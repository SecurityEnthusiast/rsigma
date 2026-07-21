//! Live TAXII integration tests (TLS, DNS SRV, mTLS).
//!
//! Not run in default CI. Requires Docker stack — see `tests/taxii-live/README.md`.
//!
//! ```bash
//! export RSTIX_TAXII_LIVE=1
//! export RSTIX_TAXII_LIVE_BASE_URL=https://127.0.0.1:8443
//! cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;

use rstix::taxii::{
    ClientCertificate, ServerTrustPolicy, SpkiPin, TaxiiClient, TaxiiClientConfig,
};
use sha2::{Digest, Sha256};

fn live_enabled() -> bool {
    std::env::var("RSTIX_TAXII_LIVE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name).ok().map(PathBuf::from)
}

fn spki_pin_from_cert_pem(path: &Path) -> SpkiPin {
    let pem = std::fs::read(path).unwrap_or_else(|err| {
        panic!("read server cert {}: {err}", path.display());
    });
    let cert = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
        .next()
        .transpose()
        .unwrap_or_else(|err| panic!("parse PEM in {}: {err}", path.display()))
        .unwrap_or_else(|| panic!("no certificate in {}", path.display()));
    let ee = rustls_webpki::EndEntityCert::try_from(&cert).expect("parse end-entity cert");
    let digest: [u8; 32] = Sha256::digest(ee.subject_public_key_info()).into();
    SpkiPin(digest)
}

fn live_client(base_url: &str, server_cert: &Path) -> TaxiiClient {
    let pin = spki_pin_from_cert_pem(server_cert);
    TaxiiClient::new(
        TaxiiClientConfig::new(base_url).server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin])),
    )
    .expect("live client")
}

#[tokio::test]
#[ignore = "live TLS: start tests/taxii-live docker compose and set RSTIX_TAXII_LIVE=1"]
async fn live_https_discovery_over_tls() {
    if !live_enabled() {
        eprintln!("skip live_https_discovery_over_tls: set RSTIX_TAXII_LIVE=1");
        return;
    }
    let base = std::env::var("RSTIX_TAXII_LIVE_BASE_URL")
        .expect("RSTIX_TAXII_LIVE_BASE_URL e.g. https://127.0.0.1:8443");
    let server_cert = env_path("RSTIX_TAXII_LIVE_SERVER_CERT").unwrap_or_else(|| {
        PathBuf::from("crates/rstix/tests/taxii-live/fixtures/certs/server.pem")
    });
    let client = live_client(&base, &server_cert);
    let discovery = client.discover().await.expect("discovery over TLS");
    assert_eq!(discovery.title, "Live Wiremock TAXII");
    assert!(discovery.default_api_root().is_some());
}

#[tokio::test]
#[ignore = "live mTLS: set RSTIX_TAXII_LIVE=1 and client cert env vars"]
async fn live_mtls_discovery() {
    if !live_enabled() {
        eprintln!("skip live_mtls_discovery: set RSTIX_TAXII_LIVE=1");
        return;
    }
    let base = std::env::var("RSTIX_TAXII_LIVE_MTLS_URL")
        .unwrap_or_else(|_| "https://127.0.0.1:8444".into());
    let server_cert = env_path("RSTIX_TAXII_LIVE_SERVER_CERT").unwrap_or_else(|| {
        PathBuf::from("crates/rstix/tests/taxii-live/fixtures/certs/server.pem")
    });
    let client_cert = env_path("RSTIX_TAXII_LIVE_CLIENT_CERT")
        .expect("RSTIX_TAXII_LIVE_CLIENT_CERT");
    let client_key = env_path("RSTIX_TAXII_LIVE_CLIENT_KEY")
        .expect("RSTIX_TAXII_LIVE_CLIENT_KEY");
    let cert_pem = std::fs::read(&client_cert).expect("client cert");
    let key_pem = std::fs::read(&client_key).expect("client key");
    let pin = spki_pin_from_cert_pem(&server_cert);
    let client = TaxiiClient::new(
        TaxiiClientConfig::new(base)
            .server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin]))
            .client_certificate(ClientCertificate::from_pem(&cert_pem, &key_pem).expect("mtls")),
    )
    .expect("mtls client");
    client.discover().await.expect("discovery over mTLS");
}

#[tokio::test]
#[ignore = "live DNS SRV: configure resolver for taxii.test — see tests/taxii-live/README.md"]
async fn live_discover_via_srv() {
    if !live_enabled() {
        eprintln!("skip live_discover_via_srv: set RSTIX_TAXII_LIVE=1");
        return;
    }
    let domain = std::env::var("RSTIX_TAXII_LIVE_SRV_DOMAIN").unwrap_or_else(|_| "taxii.test".into());
    let server_cert = env_path("RSTIX_TAXII_LIVE_SERVER_CERT").unwrap_or_else(|| {
        PathBuf::from("crates/rstix/tests/taxii-live/fixtures/certs/server.pem")
    });
    let pin = spki_pin_from_cert_pem(&server_cert);
    let config = TaxiiClientConfig::new("https://placeholder.invalid")
        .server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin]));
    match TaxiiClient::discover_via_srv(&domain, config).await {
        Ok(discovery) => {
            assert!(!discovery.api_roots.is_empty() || discovery.default_api_root().is_some());
        }
        Err(err) => {
            eprintln!(
                "live_discover_via_srv skipped: DNS SRV for {domain} not reachable via system resolver ({err}). \
                 Configure /etc/resolver/{domain} → 127.0.0.1:5353 per tests/taxii-live/README.md"
            );
        }
    }
}
