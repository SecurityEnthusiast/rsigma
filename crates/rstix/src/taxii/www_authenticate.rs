//! `WWW-Authenticate` challenge parsing (RFC 7235, spec section 1.6.9).

/// Parsed HTTP authentication challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthChallenge {
    /// Scheme name (e.g. `Basic`, `Bearer`).
    pub scheme: String,
    /// Remaining challenge parameters (e.g. `realm="TAXII"`).
    pub params: String,
}

/// Parse a `WWW-Authenticate` header value into challenges.
pub fn parse_www_authenticate(value: &str) -> Vec<AuthChallenge> {
    let mut challenges = Vec::new();
    for part in split_challenges(value) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((scheme, params)) = part.split_once(' ') else {
            challenges.push(AuthChallenge {
                scheme: part.to_owned(),
                params: String::new(),
            });
            continue;
        };
        challenges.push(AuthChallenge {
            scheme: scheme.to_owned(),
            params: params.trim().to_owned(),
        });
    }
    challenges
}

fn split_challenges(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in value.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_challenge() {
        let challenges = parse_www_authenticate(r#"Basic realm="TAXII Server""#);
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].scheme, "Basic");
        assert!(challenges[0].params.contains("realm=\"TAXII Server\""));
    }
}
