use rstix::taxii::{HttpsPolicy, TaxiiError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use super::support::{taxii_json, wiremock_client};

#[tokio::test]
async fn parses_discovery_and_resolves_api_roots() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Server",
                "api_roots": ["/api1/"]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let discovery = client.discover().await.expect("discovery");
    let roots = discovery
        .resolved_api_roots(
            &url::Url::parse(&format!("{}/taxii2/", server.uri())).unwrap(),
            HttpsPolicy::Allowed,
        )
        .expect("resolve");
    assert_eq!(roots[0].path(), "/api1/");
}

#[tokio::test]
async fn maps_http_404_to_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            404,
            serde_json::json!({
                "title": "missing",
                "description": "not here"
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client.discover().await.expect_err("404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}
