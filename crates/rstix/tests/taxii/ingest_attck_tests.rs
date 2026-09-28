//! ATT&CK-scale paginated TAXII ingest (`taxii-store` + `validate` features).

use std::fs::File;
use std::io::BufReader;

use rstix::QueryableContainer;
use rstix::core::StixId;
use rstix::store::{MemoryStore, StixStore};
use rstix::taxii::{IngestOptions, TaxiiFilter, ingest_collection_with_bundle_id};

use super::ingest_support::{
    ATTCK_CORPUS_DEFAULT_FILE, ATTCK_INGEST_PAGE_SIZE, SYNTHETIC_FORWARD_REF_RELATIONSHIP_ID,
    api_root_url, mount_paginated_taxii_objects, resolve_attck_bundle_path,
    synthetic_forward_ref_relationship, synthetic_identity_objects, wiremock_client_attck,
};

const API_ROOT: &str = "/api1/";
const SYNTHETIC_OBJECT_COUNT: usize = 5_000;
const INGEST_BUNDLE_ID: &str = "bundle--00000000-0000-0000-0000-000000000099";

fn load_attck_wire_objects(path: &std::path::Path) -> Vec<serde_json::Value> {
    let file = File::open(path).expect("open ATT&CK bundle");
    let bundle: serde_json::Value =
        serde_json::from_reader(BufReader::new(file)).expect("parse ATT&CK bundle json");
    bundle
        .get("objects")
        .and_then(|value| value.as_array())
        .expect("bundle.objects array")
        .clone()
}

#[tokio::test]
async fn ingest_attck_scale_synthetic_paginated() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);
    let last_identity_index = SYNTHETIC_OBJECT_COUNT - 1;
    let mut objects = synthetic_identity_objects(SYNTHETIC_OBJECT_COUNT);
    // Page 1: relationship whose target sits on the last page (interop_strict would reject).
    objects.insert(
        0,
        synthetic_forward_ref_relationship(0, last_identity_index),
    );
    let expected_count = objects.len();
    mount_paginated_taxii_objects(&server, API_ROOT, "col1", &objects, ATTCK_INGEST_PAGE_SIZE)
        .await;

    let client = wiremock_client_attck(&server);
    let store = MemoryStore::new();
    let bundle_id = StixId::parse(INGEST_BUNDLE_ID).unwrap();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new().limit(ATTCK_INGEST_PAGE_SIZE),
        bundle_id.clone(),
        IngestOptions::producer_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, expected_count);
    assert_eq!(report.validation.objects_validated, expected_count);
    assert_eq!(report.validation.objects_rejected, 0);
    assert!(report.validation.is_valid());
    assert!(
        report.import.unresolved_references.is_empty(),
        "forward ref to identity on last page must resolve after full ingest: {:?}",
        report.import.unresolved_references
    );
    assert!(
        store
            .get(&StixId::parse(SYNTHETIC_FORWARD_REF_RELATIONSHIP_ID).unwrap())
            .expect("get relationship")
            .is_some(),
        "relationship with forward target_ref must be imported under producer_strict"
    );

    let exported = store.export_bundle(bundle_id).expect("export");
    assert_eq!(exported.object_count(), expected_count);
}

#[tokio::test]
async fn ingest_attck_corpus_paginated_when_present() {
    let path = match resolve_attck_bundle_path() {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!(
                "skip ingest_attck_corpus_paginated_when_present: set RSTIX_ATTCK_BUNDLE \
                 (e.g. {ATTCK_CORPUS_DEFAULT_FILE}) or place bundle at \
                 tests/fixtures/corpus/{ATTCK_CORPUS_DEFAULT_FILE}"
            );
            return;
        }
        Err(missing) => {
            panic!(
                "RSTIX_ATTCK_BUNDLE is set but not a readable file: {}",
                missing.display()
            );
        }
    };

    let wire_objects = load_attck_wire_objects(&path);
    let expected_count = wire_objects.len();
    assert!(
        expected_count > 1_000,
        "ATT&CK corpus should contain thousands of objects, got {expected_count}"
    );

    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);
    mount_paginated_taxii_objects(
        &server,
        API_ROOT,
        "col1",
        &wire_objects,
        ATTCK_INGEST_PAGE_SIZE,
    )
    .await;

    let client = wiremock_client_attck(&server);
    let store = MemoryStore::new();
    let bundle_id = StixId::parse(INGEST_BUNDLE_ID).unwrap();
    let report = ingest_collection_with_bundle_id(
        &client,
        &store,
        &api,
        "col1",
        TaxiiFilter::new().limit(ATTCK_INGEST_PAGE_SIZE),
        bundle_id.clone(),
        IngestOptions::producer_strict(),
    )
    .await
    .expect("ingest");

    assert_eq!(report.import.objects_added, expected_count);
    assert_eq!(report.validation.objects_validated, expected_count);
    assert_eq!(report.validation.objects_rejected, 0);
    assert!(report.validation.is_valid());
    assert!(
        report.import.unresolved_references.is_empty(),
        "ATT&CK corpus outbound refs must resolve within the bundle: {:?}",
        report.import.unresolved_references
    );

    let exported = store.export_bundle(bundle_id).expect("export");
    assert_eq!(exported.object_count(), expected_count);
}
