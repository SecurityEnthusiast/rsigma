//! Parse and validate `fixtures/interop/manifest.toml`.

use std::collections::{BTreeMap, HashSet};
use std::fs;

use super::fixture::interop_fixtures_root;

/// How a manifest row participates in certification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Disposition {
    #[default]
    Tested,
    /// Harness-only smoke check; runs in the suite but does not count as OASIS verification.
    HarnessSmoke,
    ReportOnly,
    ApiSurface,
    Blocked,
}

impl Disposition {
    /// Stable label for traceability exports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::HarnessSmoke => "HARNESS_SMOKE",
            Self::ReportOnly => "REPORT_ONLY",
            Self::ApiSurface => "API_SURFACE",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// One row in the interop traceability matrix.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct RequirementRow {
    pub req_id: String,
    pub use_case: Option<String>,
    pub section: Option<String>,
    pub doc_page: Option<u32>,
    pub role: Option<String>,
    pub level: String,
    pub gating: bool,
    pub test_id: Option<String>,
    pub fixture: Option<String>,
    pub checklist_row: Option<String>,
    pub checklist_role: Option<String>,
    pub verification: Option<String>,
    #[serde(default)]
    pub disposition: Disposition,
    pub blocked_by: Option<u32>,
}

impl RequirementRow {
    pub fn use_case_label(&self) -> &str {
        self.use_case.as_deref().unwrap_or("framework")
    }

    pub fn verification_label(&self) -> &str {
        self.verification.as_deref().unwrap_or("")
    }
}

#[derive(Debug, serde::Deserialize)]
struct ManifestFile {
    requirement: Vec<RequirementRow>,
}

/// Loaded interop manifest.
#[derive(Debug)]
pub struct Manifest {
    pub requirements: Vec<RequirementRow>,
}

impl Manifest {
    pub fn load_from_disk() -> Self {
        let path = interop_fixtures_root().join("manifest.toml");
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Self {
        let parsed: ManifestFile =
            toml::from_str(text).unwrap_or_else(|e| panic!("parse manifest.toml: {e}"));
        let manifest = Self {
            requirements: parsed.requirement,
        };
        manifest.validate();
        manifest
    }

    fn validate(&self) {
        let mut seen = HashSet::new();
        for row in &self.requirements {
            assert!(
                seen.insert(row.req_id.clone()),
                "duplicate req_id: {}",
                row.req_id
            );
            if matches!(
                row.disposition,
                Disposition::Tested | Disposition::HarnessSmoke
            ) {
                assert!(
                    row.test_id.is_some(),
                    "{}: {} disposition requires test_id",
                    row.req_id,
                    row.disposition.as_str()
                );
            }
            if row.disposition == Disposition::Blocked {
                assert!(
                    row.blocked_by.is_some(),
                    "{}: BLOCKED disposition requires blocked_by",
                    row.req_id
                );
            }
            if let Some(fixture) = &row.fixture {
                let path = interop_fixtures_root().join(fixture);
                if matches!(
                    row.disposition,
                    Disposition::Tested | Disposition::HarnessSmoke
                ) {
                    assert!(
                        path.exists(),
                        "{}: fixture missing: {}",
                        row.req_id,
                        path.display()
                    );
                }
            }
        }
        self.assert_p02_select_specify_numbering();
    }

    /// Normalization guard: `REQ-<section>-P-02` is the select/specify row in the manifest.
    fn assert_p02_select_specify_numbering(&self) {
        for row in &self.requirements {
            if row.req_id.ends_with("-P-02") && row.section.is_some() {
                let section = row.section.as_deref().unwrap_or("");
                if section.starts_with("3.") && section != "3.1" && section != "3.3" {
                    assert!(
                        row.req_id.contains("-P-02"),
                        "{}: consolidated sections use P-02 for select/specify",
                        row.req_id
                    );
                }
            }
        }
    }

    pub fn in_scope_rows(&self) -> impl Iterator<Item = &RequirementRow> {
        self.requirements.iter().filter(|row| {
            row.gating || row.disposition == Disposition::ReportOnly || row.checklist_row.is_some()
        })
    }

    pub fn testable_requirements(&self) -> impl Iterator<Item = &RequirementRow> {
        self.requirements
            .iter()
            .filter(|row| row.disposition == Disposition::Tested)
    }

    pub fn registered_test_ids(&self) -> impl Iterator<Item = &RequirementRow> {
        self.requirements.iter().filter(|row| {
            matches!(
                row.disposition,
                Disposition::Tested | Disposition::HarnessSmoke
            )
        })
    }

    pub fn checklist_rows_consumer(&self) -> Vec<&RequirementRow> {
        self.checklist_rows_for_role("consumer")
    }

    pub fn checklist_rows_producer(&self) -> Vec<&RequirementRow> {
        self.checklist_rows_for_role("producer")
    }

    fn checklist_rows_for_role(&self, role: &str) -> Vec<&RequirementRow> {
        let mut rows: Vec<_> = self
            .requirements
            .iter()
            .filter(|row| {
                row.checklist_row.is_some() && row.checklist_role.as_deref() == Some(role)
            })
            .collect();
        rows.sort_by(|a, b| a.checklist_row.cmp(&b.checklist_row));
        rows
    }
}

pub fn load_manifest() -> Manifest {
    Manifest::load_from_disk()
}

/// Manifest parses and validates.
pub fn assert_manifest_valid() {
    let _ = load_manifest();
}

/// Every §4.2 checklist row appears at most once per role.
pub fn assert_checklist_rows_unique() {
    let manifest = load_manifest();
    let mut seen: BTreeMap<(String, String), String> = BTreeMap::new();
    for row in &manifest.requirements {
        if let (Some(checklist_row), Some(role)) = (&row.checklist_row, &row.checklist_role) {
            let key = (role.clone(), checklist_row.clone());
            if let Some(existing) = seen.insert(key, row.req_id.clone()) {
                panic!(
                    "duplicate checklist row {checklist_row} for role {role}: {existing} vs {}",
                    row.req_id
                );
            }
        }
    }
}
