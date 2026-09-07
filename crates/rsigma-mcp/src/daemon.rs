//! HTTP client for a running rsigma daemon's control-plane API.
//!
//! The operate-cycle MCP tools are thin wrappers over this client. It is
//! deliberately small: one `reqwest` client, a 10s timeout, JSON in and out,
//! no retries. Transport failures and non-2xx responses become tool content
//! errors so the agent decides whether to retry.
//!
//! The Unix-socket listener is unsupported: `reqwest` has no UDS transport.
//! Point the client at the daemon's TCP loopback address instead.

use std::time::Duration;

use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};

/// Default per-request timeout for daemon calls.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Install a process-default rustls crypto provider.
///
/// Under `--all-features` both aws-lc-rs and ring sit in the graph, so rustls
/// has no unambiguous default and the first HTTPS (or extra-CA) client build
/// would otherwise fail with "no process-level CryptoProvider available".
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// How the MCP handler reaches a running daemon.
#[derive(Debug, Clone)]
pub struct DaemonConnect {
    /// Base URL of the daemon API (`http://127.0.0.1:9090`).
    pub url: String,
    /// Extra root CA (PEM) for a self-signed TLS listener.
    pub ca_pem: Option<Vec<u8>>,
    /// Optional bearer token for daemons running API authentication.
    pub token: Option<String>,
}

/// Failure building or calling the daemon client.
#[derive(Debug)]
pub enum DaemonError {
    /// The URL was empty, used a scheme other than `http`/`https`, or failed
    /// to parse.
    Url(String),
    /// The extra root CA could not be parsed as PEM.
    Certificate(String),
    /// The `reqwest` client could not be built.
    Build(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(msg) => write!(f, "{msg}"),
            Self::Certificate(msg) => write!(f, "invalid daemon CA: {msg}"),
            Self::Build(msg) => write!(f, "failed to build daemon HTTP client: {msg}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// HTTP client pointed at one daemon API.
///
/// ```
/// # fn main() -> Result<(), rsigma_mcp::DaemonError> {
/// let client = rsigma_mcp::DaemonClient::connect(&rsigma_mcp::DaemonConnect {
///     url: "http://127.0.0.1:9090".into(),
///     ca_pem: None,
///     token: None,
/// })?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct DaemonClient {
    client: Client,
    base: String,
    token: Option<String>,
}

impl DaemonClient {
    /// Build a client from [`DaemonConnect`].
    ///
    /// Rejects an empty URL, a non-`http`/`https` scheme (including `unix://`),
    /// and a CA PEM that `reqwest` cannot parse.
    pub fn connect(connect: &DaemonConnect) -> Result<Self, DaemonError> {
        let url = connect.url.trim();
        if url.is_empty() {
            return Err(DaemonError::Url("daemon URL must not be empty".into()));
        }
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| DaemonError::Url(format!("invalid daemon URL '{url}': {e}")))?;
        match parsed.scheme() {
            "http" | "https" => {}
            "unix" => {
                return Err(DaemonError::Url(
                    "Unix-socket daemon URLs are unsupported; use the daemon's TCP loopback address"
                        .into(),
                ));
            }
            other => {
                return Err(DaemonError::Url(format!(
                    "daemon URL must be http or https, got '{other}'"
                )));
            }
        }

        ensure_crypto_provider();
        let mut builder = Client::builder().timeout(DEFAULT_TIMEOUT).use_rustls_tls();
        if let Some(pem) = connect.ca_pem.as_deref() {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| DaemonError::Certificate(e.to_string()))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|e| DaemonError::Build(e.to_string()))?;

        Ok(Self {
            client,
            base: url.trim_end_matches('/').to_string(),
            token: connect.token.clone(),
        })
    }

    /// The configured base URL (trailing slash stripped).
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// `GET` `path` (must start with `/`).
    pub async fn get(&self, path: &str) -> Value {
        self.request(Method::GET, path, None).await
    }

    /// `POST` `path` with a JSON body.
    pub async fn post(&self, path: &str, body: &Value) -> Value {
        self.request(Method::POST, path, Some(body)).await
    }

    async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Value {
        let url = format!("{}{path}", self.base);
        let mut req = self.client.request(method.clone(), &url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        match req.send().await {
            Ok(response) => encode_response(method, path, response).await,
            Err(e) => transport_error(&self.base, e),
        }
    }
}

/// Shape a successful or failed HTTP response as a tool content value.
async fn encode_response(method: Method, path: &str, response: reqwest::Response) -> Value {
    let status = response.status();
    let text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return json!({
                "ok": false,
                "status": status.as_u16(),
                "error": format!("failed to read daemon response: {e}"),
                "hint": "retry the call; the daemon closed the body early",
            });
        }
    };

    if status.is_success() {
        return success_body(&text);
    }

    let parsed = serde_json::from_str::<Value>(&text).ok();
    let error = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(Value::as_str)
        .unwrap_or(status.canonical_reason().unwrap_or("request failed"))
        .to_string();
    let hint = parsed
        .as_ref()
        .and_then(|v| v.get("hint"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| failure_hint(status, &method, path));

    let mut out = json!({
        "ok": false,
        "status": status.as_u16(),
        "error": error,
        "hint": hint,
    });
    if let Some(Value::Object(extra)) = parsed
        && let Some(obj) = out.as_object_mut()
    {
        for (key, value) in extra {
            obj.entry(key).or_insert(value);
        }
    }
    out
}

fn success_body(text: &str) -> Value {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(mut map)) => {
            map.insert("ok".into(), json!(true));
            Value::Object(map)
        }
        Ok(other) => json!({ "ok": true, "data": other }),
        Err(_) => json!({ "ok": true, "text": text }),
    }
}

fn transport_error(base: &str, err: reqwest::Error) -> Value {
    json!({
        "ok": false,
        "status": Value::Null,
        "error": err.without_url().to_string(),
        "hint": format!("is the daemon listening at {base}?"),
    })
}

fn failure_hint(status: StatusCode, method: &Method, path: &str) -> String {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            format!(
                "pass --daemon-token (or RSIGMA_MCP_DAEMON_TOKEN); this route requires {}",
                required_permission(method, path)
            )
        }
        _ => format!("the daemon returned HTTP {}", status.as_u16()),
    }
}

fn required_permission(method: &Method, path: &str) -> &'static str {
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        (&Method::GET, "/api/v1/incidents") => "incidents:read",
        (&Method::GET, p) if incident_detail_path(p) => "incidents:read",
        (&Method::GET, p) if incident_bundle_path(p) => "incident-bundles:read",
        (&Method::GET, "/api/v1/risk") => "risk:read",
        (&Method::GET, "/api/v1/silences") => "silences:read",
        (&Method::POST, "/api/v1/silences") => "silences:write",
        (&Method::GET, "/api/v1/dispositions") => "dispositions:read",
        (&Method::POST, "/api/v1/dispositions") => {
            "dispositions:write (and capture:write when capture is enabled)"
        }
        _ => "the permission required by this route",
    }
}

fn incident_detail_path(path: &str) -> bool {
    path.strip_prefix("/api/v1/incidents/")
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}

fn incident_bundle_path(path: &str) -> bool {
    path.strip_prefix("/api/v1/incidents/")
        .is_some_and(|rest| rest.ends_with("/bundle"))
}

/// Bind `router` on an ephemeral loopback port and return its base URL.
///
/// Shared by the per-tool unit tests so they can exercise the client against a
/// canned daemon without standing up `rsigma engine daemon`.
#[cfg(test)]
pub(crate) async fn spawn_stub(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub daemon");
    let addr = listener.local_addr().expect("stub local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

#[cfg(test)]
pub(crate) fn connect_for_test(url: &str) -> DaemonClient {
    DaemonClient::connect(&DaemonConnect {
        url: url.into(),
        ca_pem: None,
        token: None,
    })
    .expect("test client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::header::AUTHORIZATION;
    use axum::routing::{get, post};
    use axum::{Json, extract::Request};

    async fn canned_incidents() -> Json<Value> {
        Json(json!({
            "incidents": [{ "incident_id": "inc-1", "max_level": "high" }],
            "count": 1
        }))
    }

    async fn echo_auth(request: Request) -> Json<Value> {
        let token = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        Json(json!({ "authorization": token }))
    }

    async fn dispositions_off() -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "dispositions disabled",
                "hint": "restart the daemon with --enable-dispositions"
            })),
        )
            .into_response()
    }

    async fn unauthorized() -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response()
    }

    #[test]
    fn rejects_empty_and_unix_urls() {
        let err = DaemonClient::connect(&DaemonConnect {
            url: String::new(),
            ca_pem: None,
            token: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("must not be empty"));

        let err = DaemonClient::connect(&DaemonConnect {
            url: "unix:///tmp/rsigma.sock".into(),
            ca_pem: None,
            token: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("Unix-socket"));
    }

    #[test]
    fn get_success_adds_ok() {
        crate::tools::block_on(async {
            let url =
                spawn_stub(Router::new().route("/api/v1/incidents", get(canned_incidents))).await;
            let client = connect_for_test(&url);
            let value = client.get("/api/v1/incidents").await;
            assert_eq!(value["ok"], true);
            assert_eq!(value["count"], 1);
            assert_eq!(value["incidents"][0]["incident_id"], "inc-1");
        });
    }

    #[test]
    fn get_sends_bearer_token() {
        crate::tools::block_on(async {
            let url = spawn_stub(Router::new().route("/api/v1/incidents", get(echo_auth))).await;
            let client = DaemonClient::connect(&DaemonConnect {
                url,
                ca_pem: None,
                token: Some("s3cret".into()),
            })
            .unwrap();
            let value = client.get("/api/v1/incidents").await;
            assert_eq!(value["ok"], true);
            assert_eq!(value["authorization"], "Bearer s3cret");
        });
    }

    #[test]
    fn non_2xx_becomes_content_error() {
        crate::tools::block_on(async {
            let url =
                spawn_stub(Router::new().route("/api/v1/dispositions", get(dispositions_off)))
                    .await;
            let client = connect_for_test(&url);
            let value = client.get("/api/v1/dispositions").await;
            assert_eq!(value["ok"], false);
            assert_eq!(value["status"], 503);
            assert_eq!(value["error"], "dispositions disabled");
            assert!(
                value["hint"]
                    .as_str()
                    .unwrap()
                    .contains("--enable-dispositions")
            );
        });
    }

    #[test]
    fn unauthorized_hint_names_token_and_permission() {
        crate::tools::block_on(async {
            let url = spawn_stub(Router::new().route("/api/v1/incidents", get(unauthorized))).await;
            let client = connect_for_test(&url);
            let value = client.get("/api/v1/incidents").await;
            assert_eq!(value["ok"], false);
            assert_eq!(value["status"], 401);
            let hint = value["hint"].as_str().unwrap();
            assert!(hint.contains("--daemon-token"));
            assert!(hint.contains("incidents:read"));
        });
    }

    #[test]
    fn post_sends_json_body() {
        crate::tools::block_on(async {
            async fn echo(Json(body): Json<Value>) -> Json<Value> {
                Json(body)
            }
            let url = spawn_stub(Router::new().route("/api/v1/silences", post(echo))).await;
            let client = connect_for_test(&url);
            let value = client
                .post("/api/v1/silences", &json!({ "id": "sil-1" }))
                .await;
            assert_eq!(value["ok"], true);
            assert_eq!(value["id"], "sil-1");
        });
    }

    #[test]
    fn unreachable_daemon_is_content_error() {
        crate::tools::block_on(async {
            let client = connect_for_test("http://127.0.0.1:1");
            let value = client.get("/api/v1/incidents").await;
            assert_eq!(value["ok"], false);
            assert!(value["status"].is_null());
            assert!(
                value["hint"]
                    .as_str()
                    .unwrap()
                    .contains("http://127.0.0.1:1")
            );
        });
    }

    #[test]
    fn permission_table_covers_operate_routes() {
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/incidents/abc"),
            "incidents:read"
        );
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/incidents/abc/bundle"),
            "incident-bundles:read"
        );
        assert_eq!(
            required_permission(&Method::POST, "/api/v1/dispositions"),
            "dispositions:write (and capture:write when capture is enabled)"
        );
    }
}
