//! The `get_incident_bundle` tool: wrap `GET /api/v1/incidents/{id}/bundle`.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use serde_json::Value;

use super::RsigmaMcp;
use super::get_incident::validate_incident_id;
use super::shared::{invalid, json_result};

/// Input for `get_incident_bundle`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetIncidentBundleInput {
    /// Open incident id.
    pub id: String,
    /// `json` (default) or `markdown`.
    #[serde(default)]
    pub format: Option<String>,
}

#[tool_router(router = get_incident_bundle_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Fetch the evidence bundle for one open incident.
    #[tool(
        description = "Fetch the evidence bundle for one open incident from the configured rsigma daemon (GET /api/v1/incidents/{id}/bundle). Joins the incident to its rules' documentation and overlapping risk entities. format is json (default) or markdown."
    )]
    async fn get_incident_bundle(
        &self,
        Parameters(input): Parameters<GetIncidentBundleInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_get_incident_bundle(input).await?))
    }

    pub(crate) async fn run_get_incident_bundle(
        &self,
        input: GetIncidentBundleInput,
    ) -> Result<Value, McpError> {
        let id = validate_incident_id(&input.id)?;
        let path = match input.format.as_deref() {
            None | Some("json") => format!("/api/v1/incidents/{id}/bundle"),
            Some("markdown") => format!("/api/v1/incidents/{id}/bundle?format=markdown"),
            Some(other) => {
                return Err(invalid(format!(
                    "unknown bundle format '{other}'; expected json or markdown"
                )));
            }
        };
        Ok(self.daemon_get(&path).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::spawn_stub;
    use crate::tools::{block_on, operate_handler};
    use axum::extract::{Path, Query};
    use axum::http::header::CONTENT_TYPE;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct BundleQuery {
        format: Option<String>,
    }

    async fn bundle(Path(id): Path<String>, Query(query): Query<BundleQuery>) -> Response {
        match query.format.as_deref() {
            None | Some("json") => {
                axum::Json(json!({ "incident_id": id, "rules": [], "risk": [] })).into_response()
            }
            Some("markdown") => (
                [(CONTENT_TYPE, "text/markdown")],
                format!("# Incident {id}\n"),
            )
                .into_response(),
            Some(other) => (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "error": format!("unknown bundle format `{other}`"),
                    "hint": "supported formats are `json` and `markdown`"
                })),
            )
                .into_response(),
        }
    }

    #[test]
    fn fetches_json_bundle() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/incidents/{id}/bundle", get(bundle)))
                    .await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_get_incident_bundle(GetIncidentBundleInput {
                    id: "inc-1".into(),
                    format: None,
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["incident_id"], "inc-1");
            insta::with_settings!({sort_maps => true}, {
                insta::assert_json_snapshot!("get_incident_bundle", value);
            });
        });
    }

    #[test]
    fn fetches_markdown_bundle() {
        block_on(async {
            let url =
                spawn_stub(axum::Router::new().route("/api/v1/incidents/{id}/bundle", get(bundle)))
                    .await;
            let handler = operate_handler(&url, false);
            let value = handler
                .run_get_incident_bundle(GetIncidentBundleInput {
                    id: "inc-1".into(),
                    format: Some("markdown".into()),
                })
                .await
                .unwrap();
            assert_eq!(value["ok"], true);
            assert_eq!(value["text"], "# Incident inc-1\n");
        });
    }

    #[test]
    fn rejects_unknown_format() {
        let handler = operate_handler("http://127.0.0.1:9090", false);
        let err = block_on(handler.run_get_incident_bundle(GetIncidentBundleInput {
            id: "inc-1".into(),
            format: Some("pdf".into()),
        }))
        .unwrap_err();
        assert!(format!("{err:?}").contains("markdown"));
    }
}
