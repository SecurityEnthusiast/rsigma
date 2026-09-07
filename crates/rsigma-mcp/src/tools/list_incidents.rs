//! The `list_incidents` tool: wrap `GET /api/v1/incidents`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `list_incidents`.
#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ListIncidentsInput {
    /// Keep incidents whose `max_level` is at least this Sigma level.
    #[serde(default)]
    pub min_level: Option<String>,
    /// Maximum number of incidents to return after filtering.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[tool_router(router = list_incidents_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// List open incidents from the daemon.
    #[tool(
        description = "List open incidents from the configured rsigma daemon (GET /api/v1/incidents). Optional min_level (informational/low/medium/high/critical) and limit trim the list client-side. Returns the incidents array plus count."
    )]
    async fn list_incidents(
        &self,
        Parameters(input): Parameters<ListIncidentsInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_list_incidents(input).await?))
    }

    pub(crate) async fn run_list_incidents(
        &self,
        input: ListIncidentsInput,
    ) -> Result<Value, McpError> {
        let min_rank = match input.min_level.as_deref() {
            None => None,
            Some(level) => Some(level_rank(level).ok_or_else(|| {
                invalid(format!(
                    "invalid min_level '{level}'; expected informational, low, medium, high, or critical"
                ))
            })?),
        };
        let mut value = self.daemon_get("/api/v1/incidents").await;
        if value.get("ok") != Some(&json!(true)) {
            return Ok(value);
        }
        filter_incidents(&mut value, min_rank, input.limit);
        Ok(value)
    }
}

fn level_rank(level: &str) -> Option<u8> {
    match level.to_ascii_lowercase().as_str() {
        "informational" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

fn filter_incidents(value: &mut Value, min_rank: Option<u8>, limit: Option<usize>) {
    let Some(incidents) = value.get_mut("incidents").and_then(Value::as_array_mut) else {
        return;
    };
    if let Some(min) = min_rank {
        incidents.retain(|incident| {
            incident
                .get("max_level")
                .and_then(Value::as_str)
                .and_then(level_rank)
                .is_some_and(|rank| rank >= min)
        });
    }
    if let Some(limit) = limit {
        incidents.truncate(limit);
    }
    let count = incidents.len();
    value["count"] = json!(count);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::Json;
    use axum::routing::get;

    async fn canned() -> Json<Value> {
        Json(json!({
            "incidents": [
                { "incident_id": "low-1", "max_level": "low", "state": "open" },
                { "incident_id": "high-1", "max_level": "high", "state": "open" },
                { "incident_id": "crit-1", "max_level": "critical", "state": "open" }
            ],
            "count": 3
        }))
    }

    #[test]
    fn lists_all_incidents() {
        block_on(async {
            let url = spawn_stub(axum::Router::new().route("/api/v1/incidents", get(canned))).await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_list_incidents(ListIncidentsInput::default())
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["count"], 3);
            insta::with_settings!({sort_maps => true}, {
                insta::assert_json_snapshot!("list_incidents", value);
            });
        });
    }

    #[test]
    fn min_level_and_limit_trim_client_side() {
        block_on(async {
            let url = spawn_stub(axum::Router::new().route("/api/v1/incidents", get(canned))).await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_list_incidents(ListIncidentsInput {
                    min_level: Some("high".into()),
                    limit: Some(1),
                })
                .await
                .unwrap();
            assert_eq!(value["count"], 1);
            assert_eq!(value["incidents"][0]["incident_id"], "high-1");
        });
    }

    #[test]
    fn rejects_unknown_min_level() {
        let handler = operate_handler("http://127.0.0.1:9090", false);
        let err = block_on(handler.run_list_incidents(ListIncidentsInput {
            min_level: Some("urgent".into()),
            limit: None,
        }))
        .unwrap_err();
        assert!(format!("{err:?}").contains("min_level"));
    }
}
