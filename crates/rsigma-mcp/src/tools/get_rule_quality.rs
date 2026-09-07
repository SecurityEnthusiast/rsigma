//! The `get_rule_quality` tool: wrap `GET /api/v1/dispositions`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

/// Input for `get_rule_quality`.
#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct GetRuleQualityInput {
    /// Keep only this rule's quality row (client-side filter).
    #[serde(default)]
    pub rule_id: Option<String>,
}

#[tool_router(router = get_rule_quality_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Fetch the per-rule false-positive-ratio view from the daemon.
    #[tool(
        description = "Fetch the per-rule quality view from the configured rsigma daemon (GET /api/v1/dispositions). Passes through window_seconds, numerator, and min_sample. Optional rule_id filters client-side. A 503 content error means dispositions are disabled on the daemon."
    )]
    async fn get_rule_quality(
        &self,
        Parameters(input): Parameters<GetRuleQualityInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_get_rule_quality(input).await))
    }

    pub(crate) async fn run_get_rule_quality(&self, input: GetRuleQualityInput) -> Value {
        let mut value = self.daemon_get("/api/v1/dispositions").await;
        if value.get("ok") != Some(&json!(true)) {
            return value;
        }
        if let Some(rule_id) = input.rule_id.as_deref()
            && let Some(rules) = value.get_mut("rules").and_then(Value::as_array_mut)
        {
            rules.retain(|row| row.get("rule_id").and_then(Value::as_str) == Some(rule_id));
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::Json;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;

    async fn view() -> Json<Value> {
        Json(json!({
            "window_seconds": 86400,
            "numerator": "fp_only",
            "min_sample": 5,
            "rules": [
                { "rule_id": "r1", "true_positives": 2, "false_positives": 1, "benign_true_positives": 0, "total": 3, "fp_ratio": 0.33 },
                { "rule_id": "r2", "true_positives": 0, "false_positives": 4, "benign_true_positives": 0, "total": 4, "fp_ratio": 1.0 }
            ]
        }))
    }

    async fn disabled() -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "dispositions disabled",
                "hint": "restart the daemon with --enable-dispositions (or daemon.dispositions.enabled: true)"
            })),
        )
            .into_response()
    }

    #[test]
    fn lists_quality_and_filters_by_rule() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/dispositions", get(view))).await;
            let handler = operate_handler(&url, false);
            let all = handler
                .run_get_rule_quality(GetRuleQualityInput::default())
                .await;
            assert_eq!(all["ok"], true);
            assert_eq!(all["rules"].as_array().unwrap().len(), 2);
            insta::assert_json_snapshot!("get_rule_quality", all);

            let one = handler
                .run_get_rule_quality(GetRuleQualityInput {
                    rule_id: Some("r2".into()),
                })
                .await;
            assert_eq!(one["rules"].as_array().unwrap().len(), 1);
            assert_eq!(one["rules"][0]["rule_id"], "r2");
        });
    }

    #[test]
    fn disabled_dispositions_are_content_error() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/dispositions", get(disabled))).await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_get_rule_quality(GetRuleQualityInput::default())
                .await;
            assert_eq!(value["ok"], false);
            assert_eq!(value["status"], 503);
            assert!(
                value["hint"]
                    .as_str()
                    .unwrap()
                    .contains("--enable-dispositions")
            );
        });
    }
}
