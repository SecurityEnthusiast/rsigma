use rstix::taxii::{BearerAuth, TaxiiClient, TaxiiClientConfig};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer};

use super::support::{taxii_json, wiremock_client};

#[tokio::test]
async fn builds_client_with_bearer_auth() {
    let client = TaxiiClient::new(
        TaxiiClientConfig::new("https://taxii.example.com").auth(BearerAuth::new("secret-token")),
    )
    .expect("client builds");
    let _ = client;
}

#[tokio::test]
async fn requests_include_accept_and_user_agent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(header("accept", "application/taxii+json;version=2.1"))
        .and(header(
            "user-agent",
            format!("rstix/{}", env!("CARGO_PKG_VERSION")).as_str(),
        ))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Test Server",
                "api_roots": [format!("{}/api1/", server.uri())]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let discovery = client.discover().await.expect("discover");
    assert_eq!(discovery.title, "Test Server");
}
