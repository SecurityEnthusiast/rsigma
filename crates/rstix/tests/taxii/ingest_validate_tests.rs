//! Validate-on-ingest tests (`taxii-store` + `validate` features).

use rstix::core::StixId;
use rstix::store::{MemoryStore, StixStore};
use rstix::taxii::{IngestOptions, TaxiiFilter, ingest_collection_with_bundle_id};
use wiremock::Mock;
use wiremock::matchers::{method, path};

use super::ingest_support::{
    api_root_url, minimal_indicator, taxii_json, wiremock_client_no_preflight,
};

const API_ROOT: &str = "/api1/";

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
async fn ingest_rejects_invalid_page_under_interop_strict() {
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
    assert_eq!(report.validation.pages_rejected, 1);
    assert_eq!(report.validation.rejected_object_count, 1);
    assert!(!report.validation.is_valid());
    assert!(
        store
            .get(&StixId::parse("vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").unwrap())
            .expect("get")
            .is_none(),
        "invalid object must not be imported"
    );
}

#[tokio::test]
async fn ingest_valid_page_passes_interop_strict() {
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
        IngestOptions::interop_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, 1);
    assert!(report.validation.is_valid());
    assert_eq!(report.validation.pages_rejected, 0);
}
