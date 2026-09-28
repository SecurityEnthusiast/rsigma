//! Shared MITRE ATT&CK corpus path resolution for env-gated integration tests.

/// Pinned MITRE ATT&CK Enterprise STIX bundle filename (attack-stix-data release).
pub const ATTCK_CORPUS_DEFAULT_FILE: &str = "enterprise-attack-19.2.json";

const DEFAULT_CORPUS_REL: &str = "tests/fixtures/corpus";

/// Resolve the ATT&CK bundle path for optional corpus tests.
///
/// - `RSTIX_ATTCK_BUNDLE` **set** → must exist or resolution fails (caller should panic).
/// - `RSTIX_ATTCK_BUNDLE` **unset** → use `tests/fixtures/corpus/{ATTCK_CORPUS_DEFAULT_FILE}` when
///   present; otherwise skip (`Ok(None)`).
pub fn resolve_attck_bundle_path() -> Result<Option<std::path::PathBuf>, std::path::PathBuf> {
    if let Ok(env_path) = std::env::var("RSTIX_ATTCK_BUNDLE") {
        let path = std::path::PathBuf::from(env_path);
        return if path.is_file() {
            Ok(Some(path))
        } else {
            Err(path)
        };
    }

    let default =
        std::path::PathBuf::from(format!("{DEFAULT_CORPUS_REL}/{ATTCK_CORPUS_DEFAULT_FILE}"));
    Ok(default.is_file().then_some(default))
}
