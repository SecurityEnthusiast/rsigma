//! Phase 0 bench gate for the EvaluationResult unification refactor.
//!
//! Compares three serialize variants of the post-evaluation result types
//! against four representative input shapes:
//!
//! - **V1**: byte-for-byte copies of today's flat `MatchResult` and
//!   `CorrelationResult`. Baseline.
//! - **V2**: proposed `EvaluationResult` with `RuleHeader` + untagged
//!   `ResultBody`, both `#[serde(flatten)]`-ed via derive.
//! - **V3**: same field set as V2 but with a hand-written `Serialize` impl
//!   that walks `header` fields then dispatches to `body`. No flatten
//!   machinery.
//!
//! All three variants serialize to byte-identical JSON; a `#[test]` at the
//! bottom asserts this so a regression in the prototype types is caught
//! before the bench numbers are trusted.
//!
//! Decision matrix (V2 throughput relative to V1):
//!
//! - V2 within 15%: ship V2 (derive). Plan Phase 1 proceeds with the
//!   derived `Serialize`.
//! - V2 in the 15-40% band: ship V3 (hand-written). Plan Phase 1 absorbs
//!   the hand-written impl as a required deliverable.
//! - V2 worse than 40% and V3 not within 10% of V1: fall back to Option A
//!   (keep two structs, extract a shared `RuleHeader` flattened into both)
//!   documented in the plan file.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::OnceLock;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_parser::{CorrelationType, Level};
use serde::Serialize;
use serde::ser::SerializeMap;

// ===========================================================================
// V1: baseline copies of today's MatchResult and CorrelationResult.
//
// Kept in lock-step with the upstream types in:
// - crates/rsigma-eval/src/result.rs
// - crates/rsigma-eval/src/correlation_engine/types.rs
//
// `EventRef` is mirrored locally instead of imported so the bench is
// self-contained and does not pin a specific accessor visibility.
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
struct EventRefV1 {
    timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FieldMatchV1 {
    field: String,
    value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct MatchResultV1 {
    rule_title: String,
    rule_id: Option<String>,
    level: Option<Level>,
    tags: Vec<String>,
    matched_selections: Vec<String>,
    matched_fields: Vec<FieldMatchV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize)]
struct CorrelationResultV1 {
    rule_title: String,
    rule_id: Option<String>,
    level: Option<Level>,
    tags: Vec<String>,
    correlation_type: CorrelationType,
    group_key: Vec<(String, String)>,
    aggregated_value: f64,
    timespan_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_refs: Option<Vec<EventRefV1>>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

// ===========================================================================
// V2: EvaluationResult with #[serde(flatten)] + untagged ResultBody enum.
// Derived Serialize all the way through.
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
struct RuleHeaderV2 {
    rule_title: String,
    rule_id: Option<String>,
    level: Option<Level>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    custom_attributes: Arc<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrichments: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize)]
struct DetectionBodyV2 {
    matched_selections: Vec<String>,
    matched_fields: Vec<FieldMatchV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct CorrelationBodyV2 {
    correlation_type: CorrelationType,
    group_key: Vec<(String, String)>,
    aggregated_value: f64,
    timespan_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_refs: Option<Vec<EventRefV1>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum ResultBodyV2 {
    Detection(DetectionBodyV2),
    Correlation(CorrelationBodyV2),
}

#[derive(Debug, Clone, Serialize)]
struct EvaluationResultV2 {
    #[serde(flatten)]
    header: RuleHeaderV2,
    #[serde(flatten)]
    body: ResultBodyV2,
}

// ===========================================================================
// V3: same shape as V2 but hand-written Serialize that emits a single
// flat map without going through `#[serde(flatten)]`. Same wire shape.
//
// Field ordering matches V1 / V2: header fields first, then body. The
// `skip_serializing_if` rules from V1 are honored manually here.
// ===========================================================================

#[derive(Debug, Clone)]
struct EvaluationResultV3 {
    header: RuleHeaderV3,
    body: ResultBodyV3,
}

#[derive(Debug, Clone)]
struct RuleHeaderV3 {
    rule_title: String,
    rule_id: Option<String>,
    level: Option<Level>,
    tags: Vec<String>,
    custom_attributes: Arc<HashMap<String, serde_json::Value>>,
    enrichments: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone)]
enum ResultBodyV3 {
    Detection(DetectionBodyV3),
    Correlation(CorrelationBodyV3),
}

#[derive(Debug, Clone)]
struct DetectionBodyV3 {
    matched_selections: Vec<String>,
    matched_fields: Vec<FieldMatchV1>,
    event: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct CorrelationBodyV3 {
    correlation_type: CorrelationType,
    group_key: Vec<(String, String)>,
    aggregated_value: f64,
    timespan_secs: u64,
    events: Option<Vec<serde_json::Value>>,
    event_refs: Option<Vec<EventRefV1>>,
}

impl Serialize for EvaluationResultV3 {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // Count present fields up-front so the serializer can pre-size the
        // map. Header fields: rule_title, level, tags always; rule_id always
        // (None serializes as null in V1 because the type is Option but no
        // skip_serializing_if was set); custom_attributes and enrichments
        // honor skip_serializing_if. Then 3 or 6 body fields depending on
        // variant, with event / events / event_refs skipped when None.
        let mut field_count = 4; // rule_title, rule_id, level, tags
        if !self.header.custom_attributes.is_empty() {
            field_count += 1;
        }
        if self.header.enrichments.is_some() {
            field_count += 1;
        }
        match &self.body {
            ResultBodyV3::Detection(d) => {
                field_count += 2; // matched_selections, matched_fields
                if d.event.is_some() {
                    field_count += 1;
                }
            }
            ResultBodyV3::Correlation(c) => {
                field_count += 4; // correlation_type, group_key, aggregated_value, timespan_secs
                if c.events.is_some() {
                    field_count += 1;
                }
                if c.event_refs.is_some() {
                    field_count += 1;
                }
            }
        }

        let mut map = ser.serialize_map(Some(field_count))?;
        map.serialize_entry("rule_title", &self.header.rule_title)?;
        map.serialize_entry("rule_id", &self.header.rule_id)?;
        map.serialize_entry("level", &self.header.level)?;
        map.serialize_entry("tags", &self.header.tags)?;

        match &self.body {
            ResultBodyV3::Detection(d) => {
                map.serialize_entry("matched_selections", &d.matched_selections)?;
                map.serialize_entry("matched_fields", &d.matched_fields)?;
                if let Some(event) = &d.event {
                    map.serialize_entry("event", event)?;
                }
            }
            ResultBodyV3::Correlation(c) => {
                map.serialize_entry("correlation_type", &c.correlation_type)?;
                map.serialize_entry("group_key", &c.group_key)?;
                map.serialize_entry("aggregated_value", &c.aggregated_value)?;
                map.serialize_entry("timespan_secs", &c.timespan_secs)?;
                if let Some(events) = &c.events {
                    map.serialize_entry("events", events)?;
                }
                if let Some(event_refs) = &c.event_refs {
                    map.serialize_entry("event_refs", event_refs)?;
                }
            }
        }

        if !self.header.custom_attributes.is_empty() {
            map.serialize_entry("custom_attributes", &*self.header.custom_attributes)?;
        }
        if let Some(enrichments) = &self.header.enrichments {
            map.serialize_entry("enrichments", enrichments)?;
        }

        map.end()
    }
}

// ===========================================================================
// Sample inputs (small + realistic, detection + correlation).
// Built once and reused across iterations via `OnceLock`.
// ===========================================================================

#[derive(Debug, Clone, Copy)]
enum Sample {
    SmallDetection,
    RealisticDetection,
    SmallCorrelation,
    RealisticCorrelation,
}

impl Sample {
    fn label(self) -> &'static str {
        match self {
            Sample::SmallDetection => "small_det",
            Sample::RealisticDetection => "realistic_det",
            Sample::SmallCorrelation => "small_corr",
            Sample::RealisticCorrelation => "realistic_corr",
        }
    }
}

fn empty_attrs() -> Arc<HashMap<String, serde_json::Value>> {
    Arc::new(HashMap::new())
}

fn small_detection_v1() -> MatchResultV1 {
    MatchResultV1 {
        rule_title: "Detect Whoami".to_string(),
        rule_id: Some("rule-001".to_string()),
        level: Some(Level::Medium),
        tags: vec!["attack.t1033".to_string()],
        matched_selections: vec!["selection".to_string()],
        matched_fields: vec![],
        event: None,
        custom_attributes: empty_attrs(),
    }
}

fn realistic_detection_v1() -> MatchResultV1 {
    MatchResultV1 {
        rule_title: "Suspicious PowerShell Encoded Command".to_string(),
        rule_id: Some("rule-9f3c2a-pwsh-enc".to_string()),
        level: Some(Level::High),
        tags: vec![
            "attack.execution".to_string(),
            "attack.t1059.001".to_string(),
            "attack.defense_evasion".to_string(),
        ],
        matched_selections: vec!["selection_image".to_string(), "selection_args".to_string()],
        matched_fields: vec![
            FieldMatchV1 {
                field: "Image".to_string(),
                value: serde_json::json!("C:\\Windows\\System32\\powershell.exe"),
            },
            FieldMatchV1 {
                field: "CommandLine".to_string(),
                value: serde_json::json!(
                    "powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0A"
                ),
            },
            FieldMatchV1 {
                field: "ParentImage".to_string(),
                value: serde_json::json!("C:\\Windows\\System32\\cmd.exe"),
            },
            FieldMatchV1 {
                field: "User".to_string(),
                value: serde_json::json!("CONTOSO\\jdoe"),
            },
            FieldMatchV1 {
                field: "HostName".to_string(),
                value: serde_json::json!("WS-FINANCE-04"),
            },
        ],
        event: None,
        custom_attributes: empty_attrs(),
    }
}

fn small_correlation_v1() -> CorrelationResultV1 {
    CorrelationResultV1 {
        rule_title: "Failed Login Burst".to_string(),
        rule_id: Some("corr-001".to_string()),
        level: Some(Level::High),
        tags: vec!["attack.t1110".to_string()],
        correlation_type: CorrelationType::EventCount,
        group_key: vec![("SourceIP".to_string(), "203.0.113.4".to_string())],
        aggregated_value: 73.0,
        timespan_secs: 300,
        events: None,
        event_refs: None,
        custom_attributes: empty_attrs(),
    }
}

fn realistic_correlation_v1() -> CorrelationResultV1 {
    let mut events: Vec<serde_json::Value> = Vec::with_capacity(10);
    for i in 0..10 {
        events.push(serde_json::json!({
            "@timestamp": format!("2026-05-20T19:00:{:02}Z", i),
            "EventType": "ssh_login",
            "Result": "failure",
            "SourceIP": "203.0.113.4",
            "SourcePort": 50000 + i,
            "User": "root",
            "Host": "edge-bastion-01",
            "AuthMethod": "password",
        }));
    }
    CorrelationResultV1 {
        rule_title: "SSH brute force from single source".to_string(),
        rule_id: Some("corr-ssh-brute-cdf09a".to_string()),
        level: Some(Level::High),
        tags: vec![
            "attack.t1110".to_string(),
            "attack.credential_access".to_string(),
        ],
        correlation_type: CorrelationType::EventCount,
        group_key: vec![
            ("SourceIP".to_string(), "203.0.113.4".to_string()),
            ("DestinationHost".to_string(), "edge-bastion-01".to_string()),
            ("User".to_string(), "root".to_string()),
        ],
        aggregated_value: 73.0,
        timespan_secs: 300,
        events: Some(events),
        event_refs: None,
        custom_attributes: empty_attrs(),
    }
}

// ---- V1 to V2 / V3 projections (identical fields, just re-laid-out). ----

fn det_v2_from(v1: &MatchResultV1) -> EvaluationResultV2 {
    EvaluationResultV2 {
        header: RuleHeaderV2 {
            rule_title: v1.rule_title.clone(),
            rule_id: v1.rule_id.clone(),
            level: v1.level,
            tags: v1.tags.clone(),
            custom_attributes: v1.custom_attributes.clone(),
            enrichments: None,
        },
        body: ResultBodyV2::Detection(DetectionBodyV2 {
            matched_selections: v1.matched_selections.clone(),
            matched_fields: v1.matched_fields.clone(),
            event: v1.event.clone(),
        }),
    }
}

fn corr_v2_from(v1: &CorrelationResultV1) -> EvaluationResultV2 {
    EvaluationResultV2 {
        header: RuleHeaderV2 {
            rule_title: v1.rule_title.clone(),
            rule_id: v1.rule_id.clone(),
            level: v1.level,
            tags: v1.tags.clone(),
            custom_attributes: v1.custom_attributes.clone(),
            enrichments: None,
        },
        body: ResultBodyV2::Correlation(CorrelationBodyV2 {
            correlation_type: v1.correlation_type,
            group_key: v1.group_key.clone(),
            aggregated_value: v1.aggregated_value,
            timespan_secs: v1.timespan_secs,
            events: v1.events.clone(),
            event_refs: v1.event_refs.clone(),
        }),
    }
}

fn det_v3_from(v1: &MatchResultV1) -> EvaluationResultV3 {
    EvaluationResultV3 {
        header: RuleHeaderV3 {
            rule_title: v1.rule_title.clone(),
            rule_id: v1.rule_id.clone(),
            level: v1.level,
            tags: v1.tags.clone(),
            custom_attributes: v1.custom_attributes.clone(),
            enrichments: None,
        },
        body: ResultBodyV3::Detection(DetectionBodyV3 {
            matched_selections: v1.matched_selections.clone(),
            matched_fields: v1.matched_fields.clone(),
            event: v1.event.clone(),
        }),
    }
}

fn corr_v3_from(v1: &CorrelationResultV1) -> EvaluationResultV3 {
    EvaluationResultV3 {
        header: RuleHeaderV3 {
            rule_title: v1.rule_title.clone(),
            rule_id: v1.rule_id.clone(),
            level: v1.level,
            tags: v1.tags.clone(),
            custom_attributes: v1.custom_attributes.clone(),
            enrichments: None,
        },
        body: ResultBodyV3::Correlation(CorrelationBodyV3 {
            correlation_type: v1.correlation_type,
            group_key: v1.group_key.clone(),
            aggregated_value: v1.aggregated_value,
            timespan_secs: v1.timespan_secs,
            events: v1.events.clone(),
            event_refs: v1.event_refs.clone(),
        }),
    }
}

// ---- One slot per (variant, sample) so each iteration is allocation-free. ----

#[derive(Debug, Clone)]
enum V1Sample {
    Detection(MatchResultV1),
    Correlation(CorrelationResultV1),
}

#[derive(Debug, Clone)]
struct SampleSet {
    v1: V1Sample,
    v2: EvaluationResultV2,
    v3: EvaluationResultV3,
}

fn sample_set(sample: Sample) -> &'static SampleSet {
    macro_rules! cell {
        () => {{
            static CELL: OnceLock<SampleSet> = OnceLock::new();
            &CELL
        }};
    }
    let cell = match sample {
        Sample::SmallDetection => cell!(),
        Sample::RealisticDetection => cell!(),
        Sample::SmallCorrelation => cell!(),
        Sample::RealisticCorrelation => cell!(),
    };
    cell.get_or_init(|| match sample {
        Sample::SmallDetection => {
            let v1 = small_detection_v1();
            SampleSet {
                v2: det_v2_from(&v1),
                v3: det_v3_from(&v1),
                v1: V1Sample::Detection(v1),
            }
        }
        Sample::RealisticDetection => {
            let v1 = realistic_detection_v1();
            SampleSet {
                v2: det_v2_from(&v1),
                v3: det_v3_from(&v1),
                v1: V1Sample::Detection(v1),
            }
        }
        Sample::SmallCorrelation => {
            let v1 = small_correlation_v1();
            SampleSet {
                v2: corr_v2_from(&v1),
                v3: corr_v3_from(&v1),
                v1: V1Sample::Correlation(v1),
            }
        }
        Sample::RealisticCorrelation => {
            let v1 = realistic_correlation_v1();
            SampleSet {
                v2: corr_v2_from(&v1),
                v3: corr_v3_from(&v1),
                v1: V1Sample::Correlation(v1),
            }
        }
    })
}

fn serialize_v1(v: &V1Sample) -> String {
    match v {
        V1Sample::Detection(d) => serde_json::to_string(d).unwrap(),
        V1Sample::Correlation(c) => serde_json::to_string(c).unwrap(),
    }
}

// ===========================================================================
// Criterion bench: V1 vs V2 vs V3 across four sample shapes
// ===========================================================================

fn bench_result_serialize(c: &mut Criterion) {
    // Equivalence preflight: assert that V1, V2, and V3 produce byte-identical
    // JSON for every sample before any timing data is trusted. Criterion's
    // harness swallows the inline `#[test]` functions in benches, so the
    // check is wired here where it runs unconditionally with the bench.
    for sample in [
        Sample::SmallDetection,
        Sample::RealisticDetection,
        Sample::SmallCorrelation,
        Sample::RealisticCorrelation,
    ] {
        let set = sample_set(sample);
        let v1 = serialize_v1(&set.v1);
        let v2 = serde_json::to_string(&set.v2).unwrap();
        let v3 = serde_json::to_string(&set.v3).unwrap();
        assert_eq!(
            v1,
            v2,
            "V1 vs V2 wire-shape mismatch on sample {}\nv1: {v1}\nv2: {v2}",
            sample.label()
        );
        assert_eq!(
            v1,
            v3,
            "V1 vs V3 wire-shape mismatch on sample {}\nv1: {v1}\nv3: {v3}",
            sample.label()
        );
    }

    let mut group = c.benchmark_group("result_serialize");
    // Per-iteration cost is in the sub-microsecond range; collect plenty
    // of samples so the variance is small enough to compare the three
    // variants confidently.
    group.sample_size(200);

    for sample in [
        Sample::SmallDetection,
        Sample::RealisticDetection,
        Sample::SmallCorrelation,
        Sample::RealisticCorrelation,
    ] {
        let set = sample_set(sample);
        let label = sample.label();

        group.bench_with_input(BenchmarkId::new("v1_baseline", label), &set.v1, |b, v| {
            b.iter(|| {
                let s = serialize_v1(black_box(v));
                black_box(s);
            });
        });

        group.bench_with_input(
            BenchmarkId::new("v2_flatten_derive", label),
            &set.v2,
            |b, v| {
                b.iter(|| {
                    let s = serde_json::to_string(black_box(v)).unwrap();
                    black_box(s);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("v3_hand_written", label),
            &set.v3,
            |b, v| {
                b.iter(|| {
                    let s = serde_json::to_string(black_box(v)).unwrap();
                    black_box(s);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_result_serialize);
criterion_main!(benches);
