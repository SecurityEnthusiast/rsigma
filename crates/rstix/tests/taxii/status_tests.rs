use std::time::Duration;

use rstix::taxii::{StatusState, TaxiiClient};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use super::support::{api_root_url, taxii_json, wiremock_config};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn poll_status_until_complete() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}status/job-1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "job-1",
                "status": "pending",
                "request_timestamp": "2024-01-01T00:00:00.000000Z",
                "total_count": 1,
                "success_count": 0,
                "failure_count": 0,
                "pending_count": 1,
                "x_custom": "preserved"
            }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}status/job-1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "job-1",
                "status": "complete",
                "request_timestamp": "2024-01-01T00:00:00.000000Z",
                "total_count": 1,
                "success_count": 1,
                "failure_count": 0,
                "pending_count": 0,
                "x_custom": "preserved"
            }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(
        wiremock_config(&server)
            .status_poll_interval(Duration::from_millis(10))
            .status_max_polls(5),
    )
    .expect("client");
    let status = client.poll_status(&api, "job-1").await.expect("poll");
    assert_eq!(status.status, StatusState::Complete);
    assert_eq!(
        status.request_timestamp.unwrap().to_rfc3339(),
        "2024-01-01T00:00:00.000000Z"
    );
    assert_eq!(
        status.custom.get("x_custom").and_then(|v| v.as_str()),
        Some("preserved")
    );
}
