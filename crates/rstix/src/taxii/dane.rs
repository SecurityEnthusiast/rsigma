//! TLSA record matching for DANE (RFC 6698, spec section 8.5.2).

use rustls_pki_types::CertificateDer;
use rustls_webpki::EndEntityCert;
use sha2::{Digest, Sha256};

/// Parsed TLSA association data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsaRecord {
    /// Certificate usage field.
    pub cert_usage: u8,
    /// Selector field.
    pub selector: u8,
    /// Matching type field.
    pub matching: u8,
    /// Certificate association data.
    pub cert_data: Vec<u8>,
}

impl TlsaRecord {
    /// Returns true when the end-entity certificate matches this TLSA record.
    pub fn matches_certificate(&self, end_entity: &CertificateDer<'_>) -> bool {
        let data = match self.selector {
            0 => end_entity.as_ref().to_vec(),
            1 => match spki_bytes(end_entity) {
                Some(spki) => spki,
                None => return false,
            },
            _ => return false,
        };
        let digest = match self.matching {
            0 => data,
            1 => Sha256::digest(&data).to_vec(),
            _ => return false,
        };
        digest == self.cert_data
    }

    /// Usages accepted for TLS client authentication (RFC 7671).
    pub fn acceptable_for_tls_client(&self) -> bool {
        matches!(self.cert_usage, 0..=3)
    }
}

fn spki_bytes(end_entity: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let ee = EndEntityCert::try_from(end_entity).ok()?;
    Some(ee.subject_public_key_info().to_vec())
}

/// Compute SHA-256 hash of the end-entity SPKI (for certificate pinning).
pub fn spki_sha256(end_entity: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let spki = spki_bytes(end_entity)?;
    Some(Sha256::digest(&spki).into())
}

/// Verify `end_entity` against DNSSEC-validated TLSA records.
pub fn verify_dane(end_entity: &CertificateDer<'_>, records: &[TlsaRecord]) -> bool {
    records
        .iter()
        .filter(|r| r.acceptable_for_tls_client())
        .any(|r| r.matches_certificate(end_entity))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_cert_association_matches() {
        let cert = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        let record = TlsaRecord {
            cert_usage: 3,
            selector: 0,
            matching: 0,
            cert_data: cert.as_ref().to_vec(),
        };
        assert!(record.matches_certificate(&cert));
    }
}
