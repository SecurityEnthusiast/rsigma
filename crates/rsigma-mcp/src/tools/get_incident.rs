//! The `get_incident` tool: wrap `GET /api/v1/incidents/{id}`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::Value;

use super::RsigmaMcp;
use super::shared::{invalid, json_result};

/// Input for `get_incident`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetIncidentInput {
    /// Open incident id.
    pub id: String,
}

#[tool_router(router = get_incident_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Fetch one open incident from the daemon.
    #[tool(
        description = "Fetch one open incident from the configured rsigma daemon (GET /api/v1/incidents/{id}). Unknown ids return a 404 content error; a daemon without grouping returns 503."
    )]
    async fn get_incident(
        &self,
        Parameters(input): Parameters<GetIncidentInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_get_incident(input).await?))
    }

    pub(crate) async fn run_get_incident(
        &self,
        input: GetIncidentInput,
    ) -> Result<Value, McpError> {
        let id = validate_incident_id(&input.id)?;
        Ok(self.daemon_get(&format!("/api/v1/incidents/{id}")).await)
    }
}

pub(crate) fn validate_incident_id(id: &str) -> Result<&str, McpError> {
    if id.is_empty() {
        return Err(invalid("`id` must not be empty"));
    }
    if id.contains('/') {
        return Err(invalid("`id` must not contain '/'"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::Json;
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use serde_json::json;

    async fn one(Path(id): Path<String>) -> Response {
        if id == "inc-1" {
            Json(json!({
                "incident_id": "inc-1",
                "state": "open",
                "max_level": "high"
            }))
            .into_response()
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "no such open incident",
                    "hint": "the id is unknown, or the incident has already resolved and been evicted",
                    "incident_id": id
                })),
            )
                .into_response()
        }
    }

    #[test]
    fn fetches_one_incident() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/incidents/{id}", get(one))).await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_get_incident(GetIncidentInput { id: "inc-1".into() })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["incident_id"], "inc-1");
            insta::assert_json_snapshot!("get_incident", value);
        });
    }

    #[test]
    fn unknown_id_is_404_content_error() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/incidents/{id}", get(one))).await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_get_incident(GetIncidentInput {
                    id: "missing".into(),
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], false);
            assert_eq!(value["status"], 404);
            assert_eq!(value["error"], "no such open incident");
        });
    }

    #[test]
    fn empty_id_is_input_error() {
        let handler = operate_handler("http://127.0.0.1:9090", false);
        let err =
            block_on(handler.run_get_incident(GetIncidentInput { id: String::new() })).unwrap_err();
        assert!(format!("{err:?}").contains("empty"));
    }
}
