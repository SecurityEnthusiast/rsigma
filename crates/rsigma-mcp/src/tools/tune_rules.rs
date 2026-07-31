//! The `tune_rules` tool: propose a verified Sigma filter from FP/TP events.

use std::path::{Path, PathBuf};

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_eval::{
    TuneConfig, apply_pipelines, parse_pipeline, resolve_builtin_pipeline, tune_rule,
};
use rsigma_parser::{SigmaCollection, parse_sigma_yaml};
use serde_json::{Value, json};

use crate::input::resolve_confined_path;

use super::RsigmaMcp;
use super::shared::{invalid, json_result, to_value};

/// Input for `tune_rules`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TuneRulesInput {
    /// Inline Sigma YAML. Mutually exclusive with `path`.
    #[serde(default)]
    pub yaml: Option<String>,
    /// Sigma file or directory path. Confined to `--rules-dir` when configured.
    #[serde(default)]
    pub path: Option<String>,
    /// Target rule id, falling back to an exact title.
    #[serde(default)]
    pub rule: Option<String>,
    /// Events confirmed as false positives.
    pub false_positives: Vec<Value>,
    /// Known true-positive events that the filter must preserve.
    pub true_positives: Vec<Value>,
    /// Processing pipelines as builtin names or confined file paths.
    #[serde(default)]
    pub pipelines: Vec<String>,
    /// Maximum fields in one selection.
    #[serde(default)]
    pub max_fields: Option<usize>,
    /// Minimum fields required in every emitted selection.
    #[serde(default)]
    pub min_fields: Option<usize>,
    /// Maximum exact values in one OR list.
    #[serde(default)]
    pub max_value_cardinality: Option<usize>,
    /// Minimum FP events required for every emitted selection.
    #[serde(default)]
    pub min_cluster_support: Option<usize>,
    /// Maximum selections in the emitted filter.
    #[serde(default)]
    pub max_clusters: Option<usize>,
    /// Permit verified partial FP coverage.
    #[serde(default)]
    pub allow_partial: bool,
    /// Caller-supplied filter id. Omit to leave the YAML id unset.
    #[serde(default)]
    pub filter_id: Option<String>,
    /// Filter author metadata.
    #[serde(default)]
    pub author: Option<String>,
}

#[tool_router(router = tune_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Propose a verified Sigma filter rule from FP and TP event arrays.
    #[tool(
        description = "Propose a spec-native Sigma filter rule from false-positive and true-positive JSON event arrays. Rules come from inline `yaml` or a `path` confined to `--rules-dir`; select the target with `rule` when needed. Optional `pipelines` transform the target before tuning. The result includes filter YAML, field rationale, clusters, coverage, and closed before/after verification. No proposal may suppress a true positive."
    )]
    async fn tune_rules(
        &self,
        Parameters(input): Parameters<TuneRulesInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_tune_rules(input)?))
    }

    pub(crate) fn run_tune_rules(&self, input: TuneRulesInput) -> Result<Value, McpError> {
        let collection =
            match self.load_tune_collection(input.yaml.as_deref(), input.path.as_deref()) {
                Ok(collection) => collection,
                Err(TuneLoadError::Request(error)) => return Err(error),
                Err(TuneLoadError::Content(error)) => {
                    return Ok(json!({ "ok": false, "error": error }));
                }
            };
        let mut rule = select_rule(&collection, input.rule.as_deref())?.clone();
        let pipelines = match self.load_tune_pipelines(&input.pipelines) {
            Ok(pipelines) => pipelines,
            Err(TuneLoadError::Request(error)) => return Err(error),
            Err(TuneLoadError::Content(error)) => {
                return Ok(json!({ "ok": false, "error": error }));
            }
        };
        if !pipelines.is_empty()
            && let Err(error) = apply_pipelines(&pipelines, &mut rule)
        {
            return Ok(json!({
                "ok": false,
                "error": format!("pipeline application error: {error}")
            }));
        }

        let mut config = TuneConfig::default();
        if let Some(value) = input.max_fields {
            config.max_fields = value;
        }
        if let Some(value) = input.min_fields {
            config.min_fields = value;
        }
        if let Some(value) = input.max_value_cardinality {
            config.max_value_cardinality = value;
        }
        if let Some(value) = input.min_cluster_support {
            config.min_cluster_support = value;
        }
        if let Some(value) = input.max_clusters {
            config.max_clusters = value;
        }
        config.allow_partial = input.allow_partial;
        config.filter_id = input.filter_id;
        if let Some(author) = input.author {
            config.author = author;
        }

        match tune_rule(
            &rule,
            &input.false_positives,
            &input.true_positives,
            &config,
        ) {
            Ok(report) => Ok(json!({ "ok": true, "report": to_value(&report) })),
            Err(error) => Ok(json!({ "ok": false, "error": error.to_string() })),
        }
    }

    fn load_tune_collection(
        &self,
        yaml: Option<&str>,
        path: Option<&str>,
    ) -> Result<SigmaCollection, TuneLoadError> {
        let collection = match (yaml, path) {
            (Some(_), Some(_)) => {
                return Err(TuneLoadError::Request(invalid(
                    "provide either `yaml` or `path`, not both",
                )));
            }
            (None, None) => {
                return Err(TuneLoadError::Request(invalid(
                    "one of `yaml` or `path` is required",
                )));
            }
            (Some(yaml), None) => parse_sigma_yaml(yaml)
                .map_err(|error| TuneLoadError::Content(format!("rule parse error: {error}")))?,
            (None, Some(path)) => {
                let path =
                    resolve_confined_path(path, self.root()).map_err(TuneLoadError::Request)?;
                if path.is_dir() {
                    load_rule_directory(&path)?
                } else {
                    let yaml = std::fs::read_to_string(&path).map_err(|error| {
                        TuneLoadError::Request(invalid(format!(
                            "cannot read '{}': {error}",
                            path.display()
                        )))
                    })?;
                    parse_sigma_yaml(&yaml).map_err(|error| {
                        TuneLoadError::Content(format!(
                            "rule parse error in '{}': {error}",
                            path.display()
                        ))
                    })?
                }
            }
        };
        if collection.has_errors() {
            return Err(TuneLoadError::Content(format!(
                "rule collection contains parse errors: {:?}",
                collection.errors
            )));
        }
        Ok(collection)
    }

    fn load_tune_pipelines(
        &self,
        specs: &[String],
    ) -> Result<Vec<rsigma_eval::Pipeline>, TuneLoadError> {
        let mut pipelines = Vec::with_capacity(specs.len());
        for spec in specs {
            if let Some(result) = resolve_builtin_pipeline(spec) {
                pipelines.push(result.map_err(|error| {
                    TuneLoadError::Content(format!("builtin pipeline '{spec}': {error}"))
                })?);
            } else {
                let path =
                    resolve_confined_path(spec, self.root()).map_err(TuneLoadError::Request)?;
                let yaml = std::fs::read_to_string(&path).map_err(|error| {
                    TuneLoadError::Request(invalid(format!(
                        "cannot read pipeline '{}': {error}",
                        path.display()
                    )))
                })?;
                pipelines.push(parse_pipeline(&yaml).map_err(|error| {
                    TuneLoadError::Content(format!(
                        "pipeline parse error in '{}': {error}",
                        path.display()
                    ))
                })?);
            }
        }
        pipelines.sort_by_key(|pipeline| pipeline.priority);
        Ok(pipelines)
    }
}

enum TuneLoadError {
    Request(McpError),
    Content(String),
}

fn load_rule_directory(root: &Path) -> Result<SigmaCollection, TuneLoadError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::<PathBuf>::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            TuneLoadError::Request(invalid(format!(
                "cannot read rule directory '{}': {error}",
                directory.display()
            )))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                TuneLoadError::Request(invalid(format!(
                    "cannot read an entry under '{}': {error}",
                    directory.display()
                )))
            })?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                TuneLoadError::Request(invalid(format!(
                    "cannot inspect '{}': {error}",
                    path.display()
                )))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(TuneLoadError::Request(invalid(format!(
                    "rule directory contains a symlink, which is not allowed: '{}'",
                    path.display()
                ))));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && path.extension().is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
                })
            {
                files.push(path);
            }
        }
    }

    files.sort();
    let mut collection = SigmaCollection::new();
    for path in files {
        let yaml = std::fs::read_to_string(&path).map_err(|error| {
            TuneLoadError::Request(invalid(format!(
                "cannot read '{}': {error}",
                path.display()
            )))
        })?;
        let parsed = parse_sigma_yaml(&yaml).map_err(|error| {
            TuneLoadError::Content(format!("rule parse error in '{}': {error}", path.display()))
        })?;
        collection.rules.extend(parsed.rules);
        collection.correlations.extend(parsed.correlations);
        collection.filters.extend(parsed.filters);
        collection.errors.extend(parsed.errors);
    }
    Ok(collection)
}

fn select_rule<'a>(
    collection: &'a SigmaCollection,
    selector: Option<&str>,
) -> Result<&'a rsigma_parser::SigmaRule, McpError> {
    if collection.rules.is_empty() {
        return Err(invalid("no detection rules found"));
    }
    let Some(selector) = selector else {
        return if collection.rules.len() == 1 {
            Ok(&collection.rules[0])
        } else {
            Err(invalid(format!(
                "ruleset contains {} detection rules; set `rule` to an id or exact title",
                collection.rules.len()
            )))
        };
    };
    let matches: Vec<_> = collection
        .rules
        .iter()
        .filter(|rule| rule.id.as_deref() == Some(selector) || rule.title.as_str() == selector)
        .collect();
    match matches.as_slice() {
        [rule] => Ok(*rule),
        [] => Err(invalid(format!("no detection rule matched {selector:?}"))),
        _ => Err(invalid(format!(
            "{} detection rules matched {selector:?}; use a unique rule id",
            matches.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use rsigma_parser::LintConfig;
    use serde_json::json;

    use super::*;
    use crate::tools::{VALID_RULE, handler};

    fn input() -> TuneRulesInput {
        TuneRulesInput {
            yaml: Some(VALID_RULE.to_string()),
            path: None,
            rule: None,
            false_positives: vec![
                json!({"CommandLine": "whoami /all", "User": "svc_backup"}),
                json!({"CommandLine": "whoami /all", "User": "svc_backup"}),
            ],
            true_positives: vec![json!({"CommandLine": "whoami", "User": "attacker"})],
            pipelines: vec![],
            max_fields: None,
            min_fields: None,
            max_value_cardinality: None,
            min_cluster_support: None,
            max_clusters: None,
            allow_partial: false,
            filter_id: Some("3f7b1c2e-9a44-4d1e-8f61-2b0c5d9e7a10".to_string()),
            author: None,
        }
    }

    #[test]
    fn tune_rules_returns_verified_report() {
        let value = handler().run_tune_rules(input()).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["report"]["verification"]["false_positives_after"], 0);
        assert_eq!(value["report"]["verification"]["true_positives_after"], 1);
        assert!(
            value["report"]["filter_yaml"]
                .as_str()
                .unwrap()
                .contains("condition: not selection")
        );
    }

    #[test]
    fn tune_rules_rejects_absolute_path_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), VALID_RULE).unwrap();
        let server = RsigmaMcp::new(
            Some(root.path().to_path_buf()),
            LintConfig::default(),
            false,
        );
        let mut input = input();
        input.yaml = None;
        input.path = Some(outside.path().display().to_string());

        let error = server.run_tune_rules(input).unwrap_err();
        assert!(format!("{error:?}").contains("escapes"));
    }

    #[test]
    fn tune_rules_requires_explicit_target_for_multiple_rules() {
        let mut input = input();
        input.yaml = Some(format!("{VALID_RULE}\n---\n{VALID_RULE}"));

        let error = handler().run_tune_rules(input).unwrap_err();
        assert!(format!("{error:?}").contains("set `rule`"));
    }

    #[test]
    fn tune_rules_returns_structured_rule_content_errors() {
        let mut input = input();
        input.yaml = Some("title: [".to_string());

        let value = handler().run_tune_rules(input).unwrap();
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("parse error"));
    }

    #[test]
    fn tune_rules_returns_structured_pipeline_content_errors() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("bad-pipeline.yml"), "transformations: [").unwrap();
        let server = RsigmaMcp::new(
            Some(root.path().to_path_buf()),
            LintConfig::default(),
            false,
        );
        let mut input = input();
        input.pipelines = vec!["bad-pipeline.yml".to_string()];

        let value = server.run_tune_rules(input).unwrap();
        assert_eq!(value["ok"], false);
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .contains("pipeline parse error")
        );
    }

    #[cfg(unix)]
    #[test]
    fn tune_rules_rejects_nested_directory_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let rules = root.path().join("rules");
        let nested = rules.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(rules.join("rule.yml"), VALID_RULE).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), VALID_RULE).unwrap();
        symlink(outside.path(), nested.join("escape.yml")).unwrap();
        let server = RsigmaMcp::new(
            Some(root.path().to_path_buf()),
            LintConfig::default(),
            false,
        );
        let mut input = input();
        input.yaml = None;
        input.path = Some("rules".to_string());

        let error = server.run_tune_rules(input).unwrap_err();
        assert!(format!("{error:?}").contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn tune_rules_rejects_directory_symlink_cycles() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let rules = root.path().join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("rule.yml"), VALID_RULE).unwrap();
        symlink(&rules, rules.join("cycle")).unwrap();
        let server = RsigmaMcp::new(
            Some(root.path().to_path_buf()),
            LintConfig::default(),
            false,
        );
        let mut input = input();
        input.yaml = None;
        input.path = Some("rules".to_string());

        let error = server.run_tune_rules(input).unwrap_err();
        assert!(format!("{error:?}").contains("symlink"));
    }
}
