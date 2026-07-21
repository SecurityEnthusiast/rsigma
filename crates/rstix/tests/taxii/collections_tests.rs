use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use super::support::{api_root_url, taxii_json, wiremock_client};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn parses_collections_with_alias_and_omitted_empty_list() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "collections": [{
                    "id": "col1",
                    "title": "Indicators",
                    "alias": "indicators",
                    "can_read": true,
                    "can_write": false,
                    "media_types": ["application/stix+json;version=2.1"]
                }]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let collections = client.collections(&api).await.expect("collections");
    assert_eq!(collections.len(), 1);
    assert_eq!(collections[0].alias.as_deref(), Some("indicators"));
    assert!(!collections[0].can_write);
}

#[tokio::test]
async fn empty_collections_omits_key() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/")))
        .respond_with(taxii_json(200, serde_json::json!({})))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let collections = client.collections(&api).await.expect("collections");
    assert!(collections.is_empty());
}
