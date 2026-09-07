//! The `list_risk_entities` tool: wrap `GET /api/v1/risk`.

use rmcp::{ErrorData as McpError, model::CallToolResult, tool, tool_router};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::json_result;

#[tool_router(router = list_risk_entities_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List open risk entities from the daemon.
    #[tool(
        description = "List open risk entities from the configured rsigma daemon (GET /api/v1/risk). Empty when no risk accumulator is configured; the response then includes a note so that is not mistaken for a clean estate."
    )]
    async fn list_risk_entities(&self) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_list_risk_entities().await))
    }

    pub(crate) async fn run_list_risk_entities(&self) -> Value {
        let mut value = self.daemon_get("/api/v1/risk").await;
        if value.get("ok") == Some(&json!(true))
            && value
                .get("entities")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            value["note"] = json!(
                "no open risk entities; if this is unexpected, enable a risk accumulator on the daemon"
            );
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
    use axum::routing::get;

    async fn empty() -> Json<Value> {
        Json(json!({ "entities": [], "count": 0 }))
    }

    #[test]
    fn empty_view_explains_capability() {
        block_on(async {
            let url = spawn_stub(axum::Router::new().route("/api/v1/risk", get(empty))).await;
            let handler = operate_handler(&url, false);
            let value = handler.run_list_risk_entities().await;
            assert_eq!(value["ok"], true);
            assert_eq!(value["count"], 0);
            assert!(value["note"].as_str().unwrap().contains("risk accumulator"));
        });
    }
}
