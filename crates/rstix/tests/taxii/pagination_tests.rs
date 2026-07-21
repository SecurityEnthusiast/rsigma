use futures::StreamExt;
use rstix::taxii::TaxiiFilter;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::support::{
    TAXII_MEDIA_TYPE, api_root_url, minimal_indicator, taxii_json, wiremock_client_no_preflight,
};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn cursor_pagination_returns_all_objects() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("limit", "1"))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "cursor-2",
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("next", "cursor-2"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [{
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--11111111-1111-1111-1111-111111111111",
                    "created": "2016-04-06T20:03:48.000Z",
                    "modified": "2016-04-06T20:03:48.000Z",
                    "indicator_types": ["malicious-activity"],
                    "pattern": "[ipv4-addr:value = '192.0.2.1']",
                    "pattern_type": "stix",
                    "valid_from": "2016-01-01T00:00:00Z"
                }]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new().limit(1));
    let mut ids = Vec::new();
    while let Some(result) = stream.next().await {
        ids.push(result.unwrap().id().to_string());
    }
    assert_eq!(ids.len(), 2);
}

#[tokio::test]
async fn header_fallback_pagination_returns_all_objects() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param_is_missing("added_after"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    serde_json::json!({
                        "more": true,
                        "objects": [minimal_indicator()]
                    })
                    .to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("x-taxii-date-added-last", "2016-04-06T20:03:48.000000Z"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("added_after", "2016-04-06T20:03:48.000000Z"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [{
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--22222222-2222-2222-2222-222222222222",
                    "created": "2016-04-06T20:03:48.000Z",
                    "modified": "2016-04-06T20:03:48.000Z",
                    "indicator_types": ["malicious-activity"],
                    "pattern": "[ipv4-addr:value = '192.0.2.2']",
                    "pattern_type": "stix",
                    "valid_from": "2016-01-01T00:00:00Z"
                }]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new());
    let count = stream.by_ref().count().await;
    assert_eq!(count, 2);
}

#[tokio::test]
async fn stops_when_more_true_but_follow_on_page_empty() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param_is_missing("added_after"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    serde_json::json!({ "more": true, "objects": [minimal_indicator()] })
                        .to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("x-taxii-date-added-last", "2016-04-06T20:03:48.000000Z"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("added_after", "2016-04-06T20:03:48.000000Z"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "more": true, "objects": [] }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new());
    let count = stream.by_ref().count().await;
    assert_eq!(count, 1);
}
