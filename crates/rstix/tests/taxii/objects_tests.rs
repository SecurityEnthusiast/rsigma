use rstix::core::StixId;
use rstix::taxii::{TaxiiEnvelope, TaxiiError, VersionFilter};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer};

use super::support::{
    TAXII_MEDIA_TYPE, api_root_url, minimal_stix_object, readable_collection, taxii_json,
    wiremock_client,
};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn post_uses_taxii_envelope_not_bundle() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(200, readable_collection()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(API_ROOT))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Root",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 1048576
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(header("content-type", TAXII_MEDIA_TYPE))
        .and(body_string_contains("\"objects\""))
        .respond_with(taxii_json(
            202,
            serde_json::json!({
                "id": "status--1",
                "status": "complete",
                "total_count": 1,
                "success_count": 1,
                "failure_count": 0,
                "pending_count": 0
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let indicator = minimal_stix_object();
    let status = client
        .add_objects(&api, "col1", &TaxiiEnvelope::new(vec![indicator]))
        .await
        .expect("add");
    assert_eq!(status.id, "status--1");
}

#[tokio::test]
async fn rejects_oversized_post_before_http() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(200, readable_collection()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(API_ROOT))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Root",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 10
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let indicator = minimal_stix_object();
    let err = client
        .add_objects(&api, "col1", &TaxiiEnvelope::new(vec![indicator]))
        .await
        .expect_err("too large");
    assert!(matches!(err, TaxiiError::RequestBodyTooLarge { .. }));
}

#[tokio::test]
async fn delete_encodes_version_filter() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);
    let object_id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "col1",
                "title": "Writable",
                "can_read": true,
                "can_write": true,
                "media_types": ["application/stix+json;version=2.1"]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!(
            "{API_ROOT}collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/"
        )))
        .and(query_param("match[version]", "first"))
        .respond_with(taxii_json(200, serde_json::json!({})))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    client
        .delete_object(&api, "col1", &object_id, Some(VersionFilter::First))
        .await
        .expect("delete");
}
