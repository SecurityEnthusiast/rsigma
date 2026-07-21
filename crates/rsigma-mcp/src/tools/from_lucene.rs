//! The `from_lucene` tool: convert an Elastic Lucene query into a draft Sigma
//! rule.
//!
//! Parses a Lucene / Elasticsearch `query_string` into the intermediate
//! representation, raises a Sigma rule, and returns it as YAML. A query carries
//! no rule metadata, so the title, id, level, status, and logsource come from
//! parameters; the result is a best-effort skeleton for a human to review.
//! Constructs with no Sigma equivalent (boosting, fuzzy/proximity, non-numeric
//! ranges) come back as `{ "ok": false, "error": ... }`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_convert::{LuceneFrontend, ReverseCtx, reverse_collection};
use rsigma_parser::{Level, Status};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `from_lucene`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FromLuceneInput {
    /// The Lucene / Elasticsearch `query_string` to convert.
    pub query: String,
    /// Rule title (recommended; a query has no title of its own).
    #[serde(default)]
    pub title: Option<String>,
    /// Rule id (UUID).
    #[serde(default)]
    pub id: Option<String>,
    /// Rule level: informational, low, medium, high, or critical.
    #[serde(default)]
    pub level: Option<String>,
    /// Rule status: stable, test, experimental, deprecated, or unsupported.
    #[serde(default)]
    pub status: Option<String>,
    /// Logsource product (e.g. windows).
    #[serde(default)]
    pub logsource_product: Option<String>,
    /// Logsource category (e.g. process_creation).
    #[serde(default)]
    pub logsource_category: Option<String>,
    /// Logsource service (e.g. sysmon).
    #[serde(default)]
    pub logsource_service: Option<String>,
}

#[tool_router(router = from_lucene_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Convert an Elastic Lucene query into a draft Sigma rule.
    #[tool(
        description = "Convert an Elastic Lucene / Elasticsearch query_string into a draft Sigma rule (YAML). Supports field:value with wildcards, quoted phrases, /regex/, [a TO b] ranges, comparison shorthand, field:(a OR b) groups, _exists_, keyword terms, and AND/OR/NOT with grouping. A query carries no metadata, so pass title/id/level/status and logsource_product/category/service; the result is a reviewable skeleton. Boosting, fuzzy/proximity, and non-numeric ranges are reported as errors."
    )]
    async fn from_lucene(
        &self,
        Parameters(input): Parameters<FromLuceneInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_from_lucene(input)?))
    }

    pub(crate) fn run_from_lucene(&self, input: FromLuceneInput) -> Result<Value, McpError> {
        let level = parse_meta::<Level>(input.level.as_deref(), "level")?;
        let status = parse_meta::<Status>(input.status.as_deref(), "status")?;

        let ctx = ReverseCtx {
            title: input.title,
            id: input.id,
            level,
            status,
            product: input.logsource_product,
            category: input.logsource_category,
            service: input.logsource_service,
            strict: false,
        };

        let frontend = LuceneFrontend;
        let mut output = reverse_collection(&frontend, std::slice::from_ref(&input.query), &ctx);
        if let Some((_, err)) = output.errors.first() {
            return Ok(json!({ "ok": false, "dialect": "lucene", "error": err.to_string() }));
        }
        let Some(result) = output.rules.pop() else {
            return Ok(
                json!({ "ok": false, "dialect": "lucene", "error": "no rule was produced" }),
            );
        };
        Ok(json!({
            "ok": true,
            "engine": "rsigma",
            "dialect": "lucene",
            "rule_title": result.rule.title,
            "yaml": result.yaml,
        }))
    }
}

fn parse_meta<T: std::str::FromStr>(
    value: Option<&str>,
    label: &str,
) -> Result<Option<T>, McpError> {
    match value {
        None => Ok(None),
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|_| invalid(format!("invalid {label}: '{v}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::handler;

    fn input(query: &str) -> FromLuceneInput {
        FromLuceneInput {
            query: query.to_string(),
            title: Some("Test".into()),
            id: None,
            level: None,
            status: None,
            logsource_product: Some("windows".into()),
            logsource_category: None,
            logsource_service: None,
        }
    }

    #[test]
    fn converts_a_query_to_sigma_yaml() {
        let v = handler()
            .run_from_lucene(input("Image:*\\\\cmd.exe AND NOT User:SYSTEM"))
            .unwrap();
        assert_eq!(v["ok"], true, "envelope: {v}");
        let yaml = v["yaml"].as_str().unwrap();
        assert!(yaml.contains("Image|endswith:"), "{yaml}");
        assert!(
            yaml.contains("condition: selection and not filter"),
            "{yaml}"
        );
    }

    #[test]
    fn unsupported_construct_reports_error_envelope() {
        let v = handler().run_from_lucene(input("field:value^2")).unwrap();
        assert_eq!(v["ok"], false, "envelope: {v}");
        assert!(v["error"].as_str().unwrap().contains("boost"));
    }

    #[test]
    fn invalid_level_is_an_input_error() {
        let mut i = input("EventID:1");
        i.level = Some("bogus".into());
        let err = handler().run_from_lucene(i).unwrap_err();
        assert!(format!("{err:?}").contains("invalid level"));
    }
}
