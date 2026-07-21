use std::time::Duration;

use rstix::taxii::{RetryPolicy, TaxiiClient, TaxiiError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use super::support::{taxii_json, wiremock_config};

#[tokio::test]
async fn retries_503_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            503,
            serde_json::json!({ "title": "unavailable" }),
        ))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "title": "Server", "api_roots": [] }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(wiremock_config(&server).retry_policy(RetryPolicy {
        max_attempts: 2,
        initial_delay: Duration::from_millis(10),
        ..RetryPolicy::default()
    }))
    .expect("client");
    client.discover().await.expect("discover after retry");
}

#[tokio::test]
async fn does_not_retry_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            404,
            serde_json::json!({ "title": "missing", "description": "gone" }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(wiremock_config(&server).retry_policy(RetryPolicy {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        ..RetryPolicy::default()
    }))
    .expect("client");
    let err = client.discover().await.expect_err("404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}
