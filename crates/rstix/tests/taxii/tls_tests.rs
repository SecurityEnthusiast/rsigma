//! TLS / trust-policy tests (not exercisable over wiremock HTTP).

use rstix::taxii::{ServerTrustPolicy, SpkiPin, TlsaCache, build_rustls_config};

#[test]
fn build_rustls_config_succeeds_for_all_policies() {
    build_rustls_config(&ServerTrustPolicy::SystemRoots, &TlsaCache::default())
        .expect("system roots");
    let pin = SpkiPin::from_hex(&"ab".repeat(32)).expect("pin");
    build_rustls_config(
        &ServerTrustPolicy::PinnedSpki(vec![pin.clone()]),
        &TlsaCache::default(),
    )
    .expect("pinned spki");
    build_rustls_config(
        &ServerTrustPolicy::PinnedSpkiOnly(vec![pin]),
        &TlsaCache::default(),
    )
    .expect("pin only");
    build_rustls_config(&ServerTrustPolicy::Dane, &TlsaCache::default()).expect("dane");
}

#[test]
fn spki_pin_parses_valid_hex() {
    SpkiPin::from_hex(&"ab".repeat(32)).expect("pin");
}

#[test]
fn client_certificate_from_pem_rejects_garbage() {
    let err = rstix::taxii::ClientCertificate::from_pem(b"not-a-cert", b"not-a-key")
        .expect_err("invalid pem");
    assert!(matches!(
        err,
        rstix::taxii::TaxiiError::InvalidClientCertificate { .. }
    ));
}
