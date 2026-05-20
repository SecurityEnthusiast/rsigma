//! Golden NDJSON snapshot tests for the unified `EvaluationResult` wire shape.
//!
//! These tests pin the exact byte-for-byte serialization of one detection
//! result and one correlation result. They guarantee:
//!
//! 1. Both kinds serialize to a single flat top-level JSON object (no
//!    `result_kind` discriminator was added by the unification refactor).
//! 2. Detection lines carry `matched_fields` / `matched_selections` and no
//!    `correlation_type` field; correlation lines carry `correlation_type`
//!    and no `matched_fields` field. Downstream NDJSON consumers
//!    disambiguate by these fields.
//! 3. Field ordering and `skip_serializing_if` behavior match what every
//!    existing sink (file, stdout, NATS) has always emitted.
//!
//! If a future refactor changes the wire shape, these tests fail loudly.
//! Updating them is intentional, never automatic.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};

fn header(title: &str) -> RuleHeader {
    RuleHeader {
        rule_title: title.to_string(),
        rule_id: Some(format!("{title}-id")),
        level: Some(Level::High),
        tags: vec![
            "attack.execution".to_string(),
            "attack.t1059.001".to_string(),
        ],
        custom_attributes: Arc::new(HashMap::new()),
        enrichments: None,
    }
}

#[test]
fn detection_golden_ndjson_line() {
    let result = EvaluationResult {
        header: header("Suspicious PowerShell Encoded Command"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection_image".to_string(), "selection_args".to_string()],
            matched_fields: vec![
                FieldMatch {
                    field: "Image".to_string(),
                    value: serde_json::json!("C:\\Windows\\System32\\powershell.exe"),
                },
                FieldMatch {
                    field: "CommandLine".to_string(),
                    value: serde_json::json!("powershell -nop -w hidden -enc JAB..."),
                },
            ],
            event: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"Suspicious PowerShell Encoded Command","rule_id":"Suspicious PowerShell Encoded Command-id","level":"high","tags":["attack.execution","attack.t1059.001"],"matched_selections":["selection_image","selection_args"],"matched_fields":[{"field":"Image","value":"C:\\Windows\\System32\\powershell.exe"},{"field":"CommandLine","value":"powershell -nop -w hidden -enc JAB..."}]}"#;
    assert_eq!(
        actual, expected,
        "Detection NDJSON wire shape drift detected. If this change is intentional, update the golden string in this test and document it in the CHANGELOG."
    );

    // Downstream-disambiguation contract: a detection line carries
    // matched_fields and does NOT carry correlation_type.
    let parsed: serde_json::Value = serde_json::from_str(&actual).unwrap();
    assert!(parsed.get("matched_fields").is_some());
    assert!(parsed.get("correlation_type").is_none());
}

#[test]
fn correlation_golden_ndjson_line() {
    let result = EvaluationResult {
        header: header("SSH brute force from single source"),
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![
                ("SourceIP".to_string(), "203.0.113.4".to_string()),
                ("User".to_string(), "root".to_string()),
            ],
            aggregated_value: 73.0,
            timespan_secs: 300,
            events: None,
            event_refs: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"SSH brute force from single source","rule_id":"SSH brute force from single source-id","level":"high","tags":["attack.execution","attack.t1059.001"],"correlation_type":"event_count","group_key":[["SourceIP","203.0.113.4"],["User","root"]],"aggregated_value":73.0,"timespan_secs":300}"#;
    assert_eq!(
        actual, expected,
        "Correlation NDJSON wire shape drift detected. If this change is intentional, update the golden string in this test and document it in the CHANGELOG."
    );

    // Downstream-disambiguation contract: a correlation line carries
    // correlation_type and does NOT carry matched_fields.
    let parsed: serde_json::Value = serde_json::from_str(&actual).unwrap();
    assert!(parsed.get("correlation_type").is_some());
    assert!(parsed.get("matched_fields").is_none());
}

/// `enrichments` is `None` by default and must be skipped from serialization,
/// matching the contract for fields added by post-evaluation middleware (#34).
#[test]
fn enrichments_none_is_skipped() {
    let result = EvaluationResult {
        header: header("Detection With No Enrichments"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![],
            event: None,
        }),
    };
    let json = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("enrichments").is_none(),
        "enrichments key must be omitted when None"
    );
}

/// When enrichment middleware populates the map, the field is emitted at the
/// top level (flattened from `RuleHeader`).
#[test]
fn enrichments_some_serializes_at_top_level() {
    let mut enrichments = serde_json::Map::new();
    enrichments.insert(
        "asset_info".to_string(),
        serde_json::json!({"hostname": "dc01", "owner": "IT-Ops"}),
    );
    enrichments.insert(
        "runbook_url".to_string(),
        serde_json::json!("https://wiki.internal/runbooks/abc123"),
    );

    let mut h = header("Detection With Enrichments");
    h.enrichments = Some(enrichments);
    let result = EvaluationResult {
        header: h,
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![],
            event: None,
        }),
    };
    let json = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let enr = parsed.get("enrichments").expect("enrichments at top level");
    assert_eq!(enr["asset_info"]["hostname"], "dc01");
    assert_eq!(
        enr["runbook_url"].as_str(),
        Some("https://wiki.internal/runbooks/abc123")
    );
}
