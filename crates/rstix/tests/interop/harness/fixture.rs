//! Interop fixture loader with mandatory provenance sidecars.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Root of `tests/fixtures/interop/`.
pub fn interop_fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interop")
}

/// Loaded interop fixture: wire JSON plus provenance metadata.
#[derive(Debug)]
pub struct InteropFixture {
    pub relative_path: String,
    pub json: String,
    pub provenance: ProvenanceSidecar,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvenanceSidecar {
    pub fixture: String,
    pub source_doc: String,
    pub source_pages: String,
    pub source_section: String,
    #[serde(default)]
    pub repair: Vec<ProvenanceRepair>,
    #[serde(default)]
    pub divergence_recorded: Vec<DivergenceRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvenanceRepair {
    pub authority: String,
    pub class: String,
    pub description: String,
    #[serde(default)]
    pub spec_basis: Option<String>,
    #[serde(default)]
    pub corroborated_by: Option<String>,
    #[serde(default)]
    pub invents_data: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DivergenceRecord {
    pub site: String,
    pub defect: u32,
    pub description: String,
}

/// Load a fixture relative to `tests/fixtures/interop/`.
pub fn load_fixture(relative_path: &str) -> InteropFixture {
    let json_path = interop_fixtures_root().join(relative_path);
    let sidecar_path = sidecar_path_for(&json_path);

    assert!(
        sidecar_path.exists(),
        "missing provenance sidecar for {} (expected {})",
        json_path.display(),
        sidecar_path.display()
    );

    let json = fs::read_to_string(&json_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", json_path.display()));
    let sidecar_text = fs::read_to_string(&sidecar_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", sidecar_path.display()));
    let provenance: ProvenanceSidecar = toml::from_str(&sidecar_text)
        .unwrap_or_else(|e| panic!("parse {}: {e}", sidecar_path.display()));
    validate_provenance_sidecar(&json_path, &provenance);

    let fixture = InteropFixture {
        relative_path: relative_path.to_owned(),
        json,
        provenance,
    };
    run_load_time_scans(&fixture);
    fixture
}

/// Refuse fixtures without provenance sidecars.
pub fn assert_rejects_missing_provenance() {
    let json_path = interop_fixtures_root().join("testcases/harness/missing-sidecar.json");
    let sidecar_path = sidecar_path_for(&json_path);
    assert!(json_path.exists());
    assert!(!sidecar_path.exists());
    let result = std::panic::catch_unwind(|| {
        load_fixture("testcases/harness/missing-sidecar.json");
    });
    assert!(
        result.is_err(),
        "expected panic for missing provenance sidecar"
    );
}

fn sidecar_path_for(json_path: &Path) -> PathBuf {
    json_path.with_extension("provenance.toml")
}

fn validate_provenance_sidecar(json_path: &Path, provenance: &ProvenanceSidecar) {
    let file_name = json_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    assert_eq!(
        provenance.fixture, file_name,
        "provenance fixture name must match JSON file name"
    );
    assert!(!provenance.source_doc.is_empty());
    assert!(!provenance.source_pages.is_empty());
    assert!(!provenance.source_section.is_empty());

    for repair in &provenance.repair {
        assert!(!repair.authority.is_empty());
        assert!(!repair.class.is_empty());
        assert!(!repair.description.is_empty());
        let _ = (
            &repair.spec_basis,
            &repair.corroborated_by,
            repair.invents_data,
        );
    }
}

/// Three load-time scans: well-formedness, RFC 3339 timestamps, STIX id shape.
///
/// Recorded divergences (`divergence_recorded` in the sidecar) are logged, not rejected.
fn run_load_time_scans(fixture: &InteropFixture) {
    let value: serde_json::Value = serde_json::from_str(&fixture.json).unwrap_or_else(|e| {
        panic!(
            "{}: JSON well-formedness scan failed: {e}",
            fixture.relative_path
        )
    });

    scan_rfc3339_timestamps(&value, fixture);
    scan_stix_identifiers(&value, fixture);
    reconcile_divergence_records(fixture);
}

fn scan_rfc3339_timestamps(value: &serde_json::Value, fixture: &InteropFixture) {
    scan_value_for_keys(
        value,
        &[
            "created",
            "modified",
            "published",
            "first_seen",
            "last_seen",
        ],
        |path, raw| {
            if let Some(s) = raw.as_str()
                && !is_rfc3339_millis(s)
                && !is_recorded_divergence(fixture, path)
            {
                panic!(
                    "{}: RFC 3339 scan failed at {path}: {s:?}",
                    fixture.relative_path
                );
            }
        },
    );
}

fn scan_stix_identifiers(value: &serde_json::Value, fixture: &InteropFixture) {
    scan_value_for_keys(
        value,
        &["id", "created_by_ref", "source_ref", "target_ref"],
        |path, raw| {
            if let Some(s) = raw.as_str()
                && !looks_like_stix_id(s)
                && !is_recorded_divergence(fixture, path)
            {
                panic!(
                    "{}: identifier-shape scan failed at {path}: {s:?}",
                    fixture.relative_path
                );
            }
        },
    );
}

fn reconcile_divergence_records(fixture: &InteropFixture) {
    for record in &fixture.provenance.divergence_recorded {
        assert!(
            !record.site.is_empty() && record.defect > 0 && !record.description.is_empty(),
            "{}: invalid divergence_recorded entry",
            fixture.relative_path
        );
    }
}

fn is_recorded_divergence(fixture: &InteropFixture, site: &str) -> bool {
    fixture
        .provenance
        .divergence_recorded
        .iter()
        .any(|d| d.site == site)
}

fn scan_value_for_keys<F>(value: &serde_json::Value, keys: &[&str], mut f: F)
where
    F: FnMut(&str, &serde_json::Value),
{
    fn walk<F>(prefix: &str, value: &serde_json::Value, keys: &[&str], f: &mut F)
    where
        F: FnMut(&str, &serde_json::Value),
    {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    if keys.contains(&key.as_str()) {
                        f(&path, child);
                    }
                    walk(&path, child, keys, f);
                }
            }
            serde_json::Value::Array(items) => {
                for (idx, child) in items.iter().enumerate() {
                    let path = format!("{prefix}[{idx}]");
                    walk(&path, child, keys, f);
                }
            }
            _ => {}
        }
    }
    walk("", value, keys, &mut f);
}

fn is_rfc3339_millis(value: &str) -> bool {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).is_ok()
}

fn looks_like_stix_id(value: &str) -> bool {
    let Some((ty, uuid)) = value.split_once("--") else {
        return false;
    };
    !ty.is_empty()
        && !uuid.is_empty()
        && ty
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && uuid.len() == 36
        && uuid.chars().filter(|c| *c == '-').count() == 4
}

/// Helper assertions for `harness = false` runner.
pub fn run_helper_self_tests() {
    assert!(is_rfc3339_millis("2020-01-20T12:34:56.000Z"));
    assert!(looks_like_stix_id(
        "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    ));
}
