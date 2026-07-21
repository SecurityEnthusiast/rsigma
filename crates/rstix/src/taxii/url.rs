//! TAXII URL helpers (trailing slash, discovery path, relative API roots).

use url::Url;

use super::TaxiiError;

/// Fixed discovery path (TAXII spec section 4.1).
pub const DISCOVERY_PATH: &str = "/taxii2/";

/// HTTPS enforcement policy (spec section 8.5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpsPolicy {
    /// Reject non-HTTPS URLs (default).
    #[default]
    Required,
    /// Allow `http://` (testing/interop only).
    Allowed,
}

/// Reject non-HTTPS URLs when `policy` is [`HttpsPolicy::Required`].
pub fn ensure_https(url: &Url, policy: HttpsPolicy) -> Result<(), TaxiiError> {
    if policy == HttpsPolicy::Required && url.scheme() != "https" {
        return Err(TaxiiError::InsecureUrl(url.to_string()));
    }
    Ok(())
}

/// Build the discovery URL for `base`.
pub fn discovery_url(base: &Url, policy: HttpsPolicy) -> Result<Url, TaxiiError> {
    join_with_trailing_slash(base, DISCOVERY_PATH, policy)
}

/// Ensure `url` ends with `/`.
pub fn ensure_trailing_slash(url: &mut Url) {
    let path = url.path().to_owned();
    if !path.ends_with('/') {
        url.set_path(&format!("{path}/"));
    }
}

/// Join `base` with a relative or absolute `reference` (API Root resolution).
pub fn resolve_against(
    base: &Url,
    reference: &str,
    policy: HttpsPolicy,
) -> Result<Url, TaxiiError> {
    if reference.starts_with("http://") || reference.starts_with("https://") {
        let mut url =
            Url::parse(reference).map_err(|err| TaxiiError::InvalidUrl(err.to_string()))?;
        ensure_trailing_slash(&mut url);
        ensure_https(&url, policy)?;
        return Ok(url);
    }
    if reference.starts_with("//") || reference.starts_with("../") {
        return Err(TaxiiError::InvalidUrl(format!(
            "invalid API root reference: {reference}"
        )));
    }
    if reference.contains('?') {
        return Err(TaxiiError::InvalidUrl(format!(
            "API root URL must not contain query component: {reference}"
        )));
    }
    join_with_trailing_slash(base, reference, policy)
}

/// Join `api_root` with a collection-relative path segment.
pub fn join_api_root(
    api_root: &str,
    segment: &str,
    policy: HttpsPolicy,
) -> Result<Url, TaxiiError> {
    let mut base = Url::parse(api_root).map_err(|err| TaxiiError::InvalidUrl(err.to_string()))?;
    ensure_trailing_slash(&mut base);
    ensure_https(&base, policy)?;
    let segment = segment.trim_start_matches('/');
    let path = base.path().trim_end_matches('/').to_owned();
    base.set_path(&format!("{path}/{segment}"));
    ensure_trailing_slash(&mut base);
    Ok(base)
}

fn join_with_trailing_slash(
    base: &Url,
    path: &str,
    policy: HttpsPolicy,
) -> Result<Url, TaxiiError> {
    let mut url = base.clone();
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    url.set_path(&path);
    ensure_trailing_slash(&mut url);
    ensure_https(&url, policy)?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_path_is_fixed() {
        let base = Url::parse("https://example.com").unwrap();
        let url = discovery_url(&base, HttpsPolicy::Required).unwrap();
        assert_eq!(url.as_str(), "https://example.com/taxii2/");
    }

    #[test]
    fn resolves_relative_api_root() {
        let base = Url::parse("https://example.com/taxii2/").unwrap();
        let url = resolve_against(&base, "/api1/", HttpsPolicy::Required).unwrap();
        assert_eq!(url.as_str(), "https://example.com/api1/");
    }

    #[test]
    fn rejects_http_when_required() {
        let base = Url::parse("http://example.com").unwrap();
        assert!(discovery_url(&base, HttpsPolicy::Required).is_err());
        assert!(discovery_url(&base, HttpsPolicy::Allowed).is_ok());
    }
}
