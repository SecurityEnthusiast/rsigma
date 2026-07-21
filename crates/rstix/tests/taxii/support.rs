//! Shared wiremock helpers for TAXII integration tests.

use rstix::model::StixObject;
use rstix::taxii::{
    CapabilityPolicy, PostSubmitPolicy, PreflightPolicy, TaxiiClient, TaxiiClientConfig,
};
use wiremock::{MockServer, ResponseTemplate};

pub const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

/// Wiremock client config with HTTP allowed (required for local mock servers).
pub fn wiremock_config(server: &MockServer) -> TaxiiClientConfig {
    TaxiiClientConfig::new(server.uri())
        .allow_insecure_http(true)
        .post_submit(PostSubmitPolicy::ReturnInitial)
        .capability(CapabilityPolicy::Disabled)
}

/// Build a [`TaxiiClient`] against a wiremock server.
pub fn wiremock_client(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(wiremock_config(server)).expect("client")
}

/// Wiremock client with collection preflight disabled.
pub fn wiremock_client_no_preflight(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(wiremock_config(server).preflight(PreflightPolicy::Disabled)).expect("client")
}

/// Build a wiremock response with TAXII 2.1 `Content-Type`.
pub fn taxii_json(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_string(), TAXII_MEDIA_TYPE)
}

/// Full API Root URL for mock server tests.
pub fn api_root_url(server: &MockServer) -> String {
    format!("{}/api1/", server.uri().trim_end_matches('/'))
}

/// Readable collection fixture used by object/manifest tests.
pub fn readable_collection() -> serde_json::Value {
    serde_json::json!({
        "id": "col1",
        "title": "Test Collection",
        "can_read": true,
        "can_write": true,
        "media_types": ["application/stix+json;version=2.1"]
    })
}

/// Minimal indicator object for envelope payloads.
pub fn minimal_indicator() -> serde_json::Value {
    serde_json::json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "indicator_types": ["malicious-activity"],
        "name": "Poison Ivy Malware",
        "description": "This file is part of Poison Ivy",
        "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
        "pattern_type": "stix",
        "valid_from": "2016-01-01T00:00:00Z"
    })
}

/// Parse the minimal indicator fixture as a [`StixObject`].
pub fn minimal_stix_object() -> StixObject {
    let bundle_json = serde_json::json!({
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000000",
        "objects": [minimal_indicator()]
    });
    rstix::parse_bundle(&bundle_json.to_string())
        .expect("indicator fixture")
        .objects()[0]
        .clone()
}
