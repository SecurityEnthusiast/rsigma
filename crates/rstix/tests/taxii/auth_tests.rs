use rstix::taxii::{ApiKeyHeader, BasicAuth, BearerAuth};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer};

use super::support::{taxii_json, wiremock_config};

#[test]
fn bearer_auth_debug_redacts_token() {
    let auth = BearerAuth::new("super-secret");
    let debug = format!("{auth:?}");
    assert!(!debug.contains("super-secret"));
    assert!(debug.contains("BearerAuth"));
}

#[test]
fn basic_auth_debug_redacts_password() {
    let auth = BasicAuth::new("alice", "hunter2");
    let debug = format!("{auth:?}");
    assert!(!debug.contains("hunter2"));
    assert!(debug.contains("alice"));
}

#[test]
fn api_key_auth_debug_redacts_value() {
    let auth = ApiKeyHeader::new("X-Api-Key", "key-material");
    let debug = format!("{auth:?}");
    assert!(!debug.contains("key-material"));
}

#[tokio::test]
async fn bearer_auth_injects_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "title": "Server", "api_roots": [] }),
        ))
        .mount(&server)
        .await;

    let client = rstix::taxii::TaxiiClient::new(
        wiremock_config(&server).auth(BearerAuth::new("test-token")),
    )
    .expect("client");
    client.discover().await.expect("discover");
}
