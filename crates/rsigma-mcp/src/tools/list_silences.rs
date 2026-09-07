//! The `list_silences` tool: wrap `GET /api/v1/silences`.

use rmcp::{ErrorData as McpError, model::CallToolResult, tool, tool_router};
use serde_json::Value;

use super::RsigmaMcp;
use super::shared::json_result;

#[tool_router(router = list_silences_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List operator silences from the daemon.
    #[tool(
        description = "List operator silences from the configured rsigma daemon (GET /api/v1/silences). Each entry includes origin (static/api) and derived state (pending/active/expired)."
    )]
    async fn list_silences(&self) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_list_silences().await))
    }

    pub(crate) async fn run_list_silences(&self) -> Value {
        self.daemon_get("/api/v1/silences").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::Json;
    use axum::routing::get;
    use serde_json::json;

    async fn canned() -> Json<Value> {
        Json(json!({
            "silences": [{
                "id": "sil-1",
                "origin": "api",
                "state": "active",
                "created_by": "rsigma-mcp"
            }],
            "count": 1
        }))
    }

    #[test]
    fn lists_silences() {
        block_on(async {
            let url = spawn_stub(axum::Router::new().route("/api/v1/silences", get(canned))).await;
            let handler = operate_handler(&url, false);
            let value = handler.run_list_silences().await;
            assert_eq!(value["ok"], true);
            assert_eq!(value["silences"][0]["id"], "sil-1");
        });
    }
}
