//! Bundle reference-closure checking with TLP marking exemption.

use std::collections::HashSet;

use rstix::model::Bundle;
use rstix::model::meta::{
    TLP1_AMBER_ID, TLP1_GREEN_ID, TLP1_RED_ID, TLP1_WHITE_ID, TLP2_AMBER_ID, TLP2_AMBER_STRICT_ID,
    TLP2_CLEAR_ID, TLP2_GREEN_ID, TLP2_RED_ID,
};

/// Reference property names walked for bundle closure (§2.3.3).
const REF_KEYS: &[&str] = &[
    "created_by_ref",
    "source_ref",
    "target_ref",
    "object_marking_refs",
    "granular_marking_refs",
    "object_refs",
    "sighting_of_ref",
    "observed_data_refs",
    "where_sighted_refs",
    "belongs_to_ref",
    "sample_refs",
    "analysis_sco_refs",
    "host_vm_ref",
    "operating_system_ref",
    "installed_software_refs",
    "account_ref",
    "parent_directory_ref",
    "contains_refs",
    "image_ref",
    "parent_process_ref",
    "opened_connection_refs",
    "creator_user_ref",
    "process_ref",
    "child_refs",
    "src_ref",
    "dst_ref",
    "src_payload_ref",
    "dst_payload_ref",
    "encapsulates_refs",
    "encapsulated_by_ref",
    "from_ref",
    "sender_ref",
    "to_refs",
    "cc_refs",
    "bcc_refs",
    "raw_email_ref",
    "body_raw_ref",
    "content_ref",
    "object_ref",
];

/// Predefined TLP marking ids exempt from bundle inclusion (§2.3.4 / REQ-2.3-X-04).
pub fn tlp_exempt_ids() -> HashSet<&'static str> {
    HashSet::from([
        TLP1_WHITE_ID,
        TLP1_GREEN_ID,
        TLP1_AMBER_ID,
        TLP1_RED_ID,
        TLP2_CLEAR_ID,
        TLP2_GREEN_ID,
        TLP2_AMBER_ID,
        TLP2_AMBER_STRICT_ID,
        TLP2_RED_ID,
    ])
}

/// Collect every STIX id referenced by objects in a parsed bundle.
pub fn collect_referenced_ids(bundle: &Bundle) -> HashSet<String> {
    let mut refs = HashSet::new();
    for object in bundle.objects().iter() {
        if let Ok(value) = serde_json::to_value(object) {
            collect_refs_from_value(&value, &mut refs);
        }
    }
    refs
}

fn collect_refs_from_value(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if REF_KEYS.contains(&key.as_str()) {
                    push_ref_value(child, out);
                }
                collect_refs_from_value(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_refs_from_value(child, out);
            }
        }
        _ => {}
    }
}

fn push_ref_value(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::String(s) => {
            out.insert(s.clone());
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let serde_json::Value::String(s) = item {
                    out.insert(s.clone());
                }
            }
        }
        _ => {}
    }
}

/// Return referenced ids missing from the bundle (excluding TLP exemptions).
#[expect(dead_code, reason = "retained for parsed-bundle closure helpers")]
pub fn missing_closure_ids(bundle: &Bundle) -> Vec<String> {
    let present: HashSet<String> = bundle
        .objects()
        .iter()
        .map(|o| o.id().as_str().to_owned())
        .collect();
    let referenced = collect_referenced_ids(bundle);
    let exempt = tlp_exempt_ids();

    referenced
        .into_iter()
        .filter(|id| !present.contains(id) && !exempt.contains(id.as_str()))
        .collect()
}

/// Return referenced ids missing from wire JSON (excluding TLP exemptions).
pub fn missing_closure_ids_from_json(json: &str) -> Vec<String> {
    let value: serde_json::Value =
        serde_json::from_str(json).expect("parse bundle JSON for closure check");
    let objects = value
        .get("objects")
        .and_then(serde_json::Value::as_array)
        .expect("bundle must contain objects array");

    let present: HashSet<String> = objects
        .iter()
        .filter_map(|obj| obj.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect();

    let mut referenced = HashSet::new();
    for object in objects {
        collect_refs_from_value(object, &mut referenced);
    }

    let exempt = tlp_exempt_ids();
    referenced
        .into_iter()
        .filter(|id| !present.contains(id) && !exempt.contains(id.as_str()))
        .collect()
}

/// Assert interop reference closure on wire JSON (TLP predefined markings exempt per §2.3.4).
pub fn assert_bundle_reference_closed(json: &str) {
    let missing = missing_closure_ids_from_json(json);
    assert!(
        missing.is_empty(),
        "bundle not reference-closed; missing ids: {missing:?}"
    );
}
