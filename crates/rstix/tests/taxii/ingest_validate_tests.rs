//! Validate-on-ingest tests (`taxii-store` + `validate` features).

use rstix::core::StixId;
use rstix::store::{MemoryStore, StixStore};
use rstix::taxii::{IngestOptions, TaxiiFilter, ingest_collection_with_bundle_id};
use wiremock::Mock;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};

use super::ingest_support::{
    api_root_url, minimal_indicator, taxii_json, wiremock_client_no_preflight,
};

const API_ROOT: &str = "/api1/";

/// Parses on the wire; fails `producer_strict` with `STIX-E0012` (short timestamp).
fn invalid_identity_short_timestamp() -> serde_json::Value {
    serde_json::json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--11111111-1111-4111-8111-111111111111",
        "created": "2020-01-01T00:00:00Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "x",
        "identity_class": "organization"
    })
}

fn invalid_cve_vulnerability() -> serde_json::Value {
    serde_json::json!({
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "name": "Bad CVE ref",
        "external_references": [{
            "source_name": "cve",
            "external_id": "2016-1234"
        }]
    })
}

#[tokio::test]
async fn ingest_rejects_must_invalid_object_under_producer_strict() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [invalid_identity_short_timestamp()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new(),
        StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
        IngestOptions::producer_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 0);
    assert_eq!(report.validation.objects_rejected, 1);
    assert!(!report.validation.is_valid());
    assert!(
        store
            .get(&StixId::parse("identity--11111111-1111-4111-8111-111111111111").unwrap())
            .expect("get")
            .is_none(),
        "invalid object must not be imported"
    );
}

#[tokio::test]
async fn ingest_valid_page_passes_producer_strict() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new(),
        StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
        IngestOptions::producer_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 1);
    assert!(report.validation.is_valid());
    assert_eq!(report.validation.objects_rejected, 0);
}

#[tokio::test]
async fn ingest_validator_preserves_forward_refs_across_pages() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);
    let indicator_id = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f";

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("limit", "1"))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "cursor-2",
                "objects": [{
                    "type": "report",
                    "spec_version": "2.1",
                    "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
                    "created": "2015-12-21T19:59:11.000Z",
                    "modified": "2015-12-21T19:59:11.000Z",
                    "name": "Forward ref report",
                    "published": "2016-01-20T17:00:00.000Z",
                    "report_types": ["threat-report"],
                    "object_refs": [indicator_id]
                }]
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
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new().limit(1),
        StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
        IngestOptions::producer_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 2);
    assert!(report.validation.is_valid());
    assert!(
        report.import.unresolved_references.is_empty(),
        "forward ref to indicator on page 2 must resolve after full ingest: {:?}",
        report.import.unresolved_references
    );
}

#[tokio::test]
async fn ingest_allow_invalid_objects_still_imports_and_records_failures() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [invalid_identity_short_timestamp()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new(),
        StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
        IngestOptions::producer_strict().allow_invalid_objects(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 1);
    assert_eq!(report.validation.objects_rejected, 0);
    assert_eq!(report.validation.failures.len(), 1);
    assert!(
        store
            .get(&StixId::parse("identity--11111111-1111-4111-8111-111111111111").unwrap())
            .expect("get")
            .is_some(),
        "allow_invalid_objects must still import"
    );
}

#[tokio::test]
async fn ingest_mixed_page_rejects_only_invalid_neighbors() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [invalid_identity_short_timestamp(), minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new(),
        StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
        IngestOptions::producer_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 1);
    assert_eq!(report.validation.objects_rejected, 1);
    assert_eq!(report.validation.failures.len(), 1);
    assert!(
        store
            .get(&StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap())
            .expect("get")
            .is_some(),
        "valid neighbor on the same page must be imported"
    );
}

#[tokio::test]
async fn ingest_interop_strict_rejects_should_level_cve_prefix() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [invalid_cve_vulnerability()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new(),
        StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
        IngestOptions::interop_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 0);
    assert_eq!(report.validation.objects_rejected, 1);
    assert!(
        store
            .get(&StixId::parse("vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").unwrap())
            .expect("get")
            .is_none()
    );
}
