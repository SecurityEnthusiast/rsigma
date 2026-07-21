//! TAXII 2.1 media type constants (spec section 1.6.8).

/// Required `Accept` value for TAXII 2.1 requests.
pub const TAXII_ACCEPT: &str = "application/taxii+json;version=2.1";

/// Manifest endpoint `Accept` (spec section 5.3).
pub const MANIFEST_ACCEPT: &str =
    "application/taxii+json;version=2.1,application/stix+json;version=2.1";

/// Required `Content-Type` for TAXII 2.1 POST bodies.
pub const TAXII_CONTENT_TYPE: &str = "application/taxii+json;version=2.1";

/// Returns true when `content_type` is a TAXII 2.1 JSON media type.
pub fn is_taxii_content_type(content_type: &str) -> bool {
    let primary = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    if primary != "application/taxii+json" {
        return false;
    }
    for part in content_type.split(';').skip(1) {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("version=") {
            return value == "2.1";
        }
    }
    // Spec allows responses without version parameter when server omits it.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_accept_includes_stix_json() {
        assert!(MANIFEST_ACCEPT.contains(TAXII_ACCEPT));
        assert!(MANIFEST_ACCEPT.contains("application/stix+json;version=2.1"));
    }
}
