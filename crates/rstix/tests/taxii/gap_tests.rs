use std::time::Duration;

use futures::StreamExt;
use rstix::core::StixId;
use rstix::taxii::{
    ObjectByIdFilter, TaxiiClient, TaxiiClientConfig, TaxiiError, TaxiiFilter, VersionFilter,
    VersionsQueryFilter,
};
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::support::{
    TAXII_MEDIA_TYPE, api_root_url, minimal_indicator, readable_collection, taxii_json,
    wiremock_client, wiremock_client_no_preflight, wiremock_config,
};

const API_ROOT: &str = "/api1/";

#[test]
fn rejects_http_base_url_without_opt_in() {
    match TaxiiClient::new(TaxiiClientConfig::new("http://taxii.example.com")) {
        Err(err) => assert!(matches!(err, TaxiiError::InsecureUrl { .. })),
        Ok(_) => panic!("expected insecure URL error"),
    }
}

#[tokio::test]
async fn maps_415_to_unsupported_media_type() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            415,
            serde_json::json!({ "title": "wrong type", "description": "bad accept" }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client.discover().await.expect_err("415");
    assert!(matches!(err, TaxiiError::UnsupportedMediaType { .. }));
}

#[tokio::test]
async fn server_error_includes_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_raw(
                    serde_json::json!({ "title": "busy" }).to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("retry-after", "2"),
        )
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client.discover().await.expect_err("503");
    match err {
        TaxiiError::ServerError { retry_after, .. } => {
            assert_eq!(retry_after, Some(Duration::from_secs(2)));
        }
        other => panic!("expected ServerError, got {other:?}"),
    }
}

#[tokio::test]
async fn get_object_returns_paged_envelope_with_headers() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);
    let object_id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(200, readable_collection()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    serde_json::json!({
                        "more": false,
                        "objects": [minimal_indicator()]
                    })
                    .to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("x-taxii-date-added-first", "2016-04-06T20:03:48.000000Z")
                .insert_header("x-taxii-date-added-last", "2016-04-06T20:03:48.000000Z"),
        )
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let page = client
        .get_object(&api, "col1", &object_id, ObjectByIdFilter::new())
        .await
        .expect("get object");
    assert_eq!(page.value.objects.len(), 1);
    assert!(page.headers.date_added_first.is_some());
    assert!(page.headers.date_added_last.is_some());
}

#[tokio::test]
async fn manifest_stream_paginates() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(200, readable_collection()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/manifest/")))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "m2",
                "objects": [{
                    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "date_added": "2016-04-06T20:03:48.000Z",
                    "version": "2016-04-06T20:03:48.000Z"
                }]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/manifest/")))
        .and(query_param("next", "m2"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [{
                    "id": "indicator--11111111-1111-1111-1111-111111111111",
                    "date_added": "2016-04-06T20:03:48.000Z",
                    "version": "2016-04-06T20:03:48.000Z"
                }]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.manifest_stream(&api, "col1", TaxiiFilter::new());
    let count = stream.by_ref().count().await;
    assert_eq!(count, 2);
}

#[tokio::test]
async fn manifest_request_accepts_stix_media_type() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(200, readable_collection()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/manifest/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "more": false, "objects": [] }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    client
        .manifest(&api, "col1", TaxiiFilter::new())
        .await
        .expect("manifest");
}

#[tokio::test]
async fn versions_stream_paginates() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);
    let object_id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();

    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/versions/"
        )))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "v2",
                "versions": ["2016-04-06T20:03:48.000Z"]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/versions/"
        )))
        .and(query_param("next", "v2"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "versions": ["2017-04-06T20:03:48.000Z"]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream =
        client.object_versions_stream(&api, "col1", object_id, VersionsQueryFilter::new());
    let versions: Vec<_> = stream.by_ref().collect().await;
    assert_eq!(versions.len(), 2);
    assert!(versions.into_iter().all(|v| v.is_ok()));
}

#[tokio::test]
async fn delete_requires_read_and_write() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);
    let object_id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "col1",
                "title": "Write-only",
                "can_read": false,
                "can_write": true,
                "media_types": ["application/stix+json;version=2.1"]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client
        .delete_object(&api, "col1", &object_id, VersionFilter::First)
        .await
        .expect_err("delete blocked");
    assert!(matches!(err, TaxiiError::DeleteNotPermitted));
}

#[test]
fn rejects_zero_limit_filter() {
    let err = TaxiiFilter::new()
        .limit(0)
        .to_query_pairs()
        .expect_err("zero limit");
    assert!(matches!(err, TaxiiError::InvalidFilter { .. }));
}

#[tokio::test]
async fn rejects_unsupported_api_root_version() {
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
                "versions": ["application/taxii+json;version=2.0"],
                "max_content_length": 1048576
            }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(
        wiremock_config(&server).capability(rstix::taxii::CapabilityPolicy::Enforce),
    )
    .expect("client");
    let err = client
        .objects(&api, "col1", TaxiiFilter::new())
        .await
        .expect_err("unsupported api root");
    assert!(matches!(err, TaxiiError::UnsupportedApiRoot { .. }));
}

#[tokio::test]
async fn unauthorized_includes_www_authenticate_challenges() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_raw(
                    serde_json::json!({ "title": "auth" }).to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("www-authenticate", r#"Basic realm="TAXII""#),
        )
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client.discover().await.expect_err("401");
    match err {
        TaxiiError::Unauthorized { challenges, .. } => {
            assert_eq!(challenges.len(), 1);
            assert_eq!(challenges[0].scheme, "Basic");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}
