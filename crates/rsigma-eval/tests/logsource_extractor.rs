use std::borrow::Cow;
use std::collections::BTreeSet;

use rsigma_eval::event::{Event, EventValue};
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, Engine, EvaluationResult, ExtractLogSource, JsonEvent,
    MatchDetailLevel, ProcessResultExt, RoutingConfig, RoutingPlan, SchemaClassifier, SchemaRouter,
};
use rsigma_parser::{LogSource, parse_sigma_yaml};
use serde_json::{Value, json};

/// An event whose logsource travels as metadata beside the payload. The
/// payload's own `product` field deliberately disagrees, so a test only passes
/// when pruning reads the metadata.
struct TaggedEvent {
    product: Option<&'static str>,
    payload: JsonEvent<'static>,
}

impl TaggedEvent {
    fn new(product: Option<&'static str>, payload: Value) -> Self {
        TaggedEvent {
            product,
            payload: JsonEvent::owned(payload),
        }
    }
}

impl Event for TaggedEvent {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        self.payload.get_field(path)
    }
    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        self.payload.any_string_value(pred)
    }
    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        self.payload.all_string_values()
    }
    fn to_json(&self) -> Value {
        self.payload.to_json()
    }
}

struct MetadataExtractor;

impl ExtractLogSource<TaggedEvent> for MetadataExtractor {
    fn extract(&self, event: &TaggedEvent) -> LogSource {
        LogSource {
            product: event.product.map(str::to_string),
            ..LogSource::default()
        }
    }
}

const RULES: &str = r#"
title: Windows whoami
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Linux whoami
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Any whoami
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#;

fn titles(results: &[EvaluationResult]) -> BTreeSet<String> {
    results
        .iter()
        .map(|r| r.header.rule_title.clone())
        .collect()
}

fn set(titles: &[&str]) -> BTreeSet<String> {
    titles.iter().map(|t| t.to_string()).collect()
}

fn engine() -> Engine<MetadataExtractor> {
    let mut engine = Engine::with_logsource_extractor(MetadataExtractor);
    engine
        .add_collection(&parse_sigma_yaml(RULES).unwrap())
        .unwrap();
    engine
}

#[test]
fn engine_prunes_by_metadata_not_payload() {
    let engine = engine();
    let event = TaggedEvent::new(
        Some("windows"),
        json!({"CommandLine": "whoami", "product": "linux"}),
    );

    assert_eq!(
        titles(&engine.evaluate(&event)),
        set(&["Windows whoami", "Any whoami"])
    );
    assert_eq!(engine.logsource_pruned_total(), 1);
}

#[test]
fn engine_fails_open_without_metadata() {
    let engine = engine();
    let event = TaggedEvent::new(None, json!({"CommandLine": "whoami", "product": "linux"}));

    assert_eq!(engine.evaluate(&event).len(), 3);
    assert_eq!(engine.logsource_pruned_total(), 0);
    assert_eq!(engine.logsource_absent_total(), 1);
}

#[test]
fn engine_batch_uses_custom_extractor() {
    let engine = engine();
    let windows = TaggedEvent::new(Some("windows"), json!({"CommandLine": "whoami"}));
    let linux = TaggedEvent::new(Some("linux"), json!({"CommandLine": "whoami"}));

    let results = engine.evaluate_batch(&[&windows, &linux]);

    assert_eq!(titles(&results[0]), set(&["Windows whoami", "Any whoami"]));
    assert_eq!(titles(&results[1]), set(&["Linux whoami", "Any whoami"]));
}

#[test]
fn disabling_custom_extractor_stops_pruning() {
    let mut engine = engine();
    engine.set_logsource_extractor(None);
    let event = TaggedEvent::new(Some("windows"), json!({"CommandLine": "whoami"}));

    assert_eq!(engine.evaluate(&event).len(), 3);
}

/// Two detection rules without an `id` share a title, so their results can
/// only be told apart by the compiled rule identity. Evaluating through the
/// correlation engine's own extractor keeps that identity, which detections
/// precomputed with `evaluate_pruned` and fed to `process_with_detections`
/// lose.
#[test]
fn correlation_engine_keeps_rule_identity_with_custom_extractor() {
    let yaml = r#"
title: Whoami
name: windows_whoami
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Whoami
name: linux_whoami
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Windows whoami by host
correlation:
    type: event_count
    rules: [windows_whoami]
    group-by: [Host]
    timespan: 10s
    generate: true
    condition:
        gte: 1
"#;
    let mut engine = CorrelationEngine::with_logsource_extractor(
        CorrelationConfig::default(),
        MetadataExtractor,
    );
    engine
        .add_collection(&parse_sigma_yaml(yaml).unwrap())
        .unwrap();

    let event = TaggedEvent::new(
        Some("windows"),
        json!({"CommandLine": "whoami", "Host": "h1", "product": "linux"}),
    );
    let results = engine.process_event_at(&event, 1000);

    assert_eq!(results.detection_count(), 1);
    assert_eq!(results.correlation_count(), 1);
    assert_eq!(engine.logsource_pruned_total(), 1);
}

#[test]
fn correlation_batch_uses_custom_extractor() {
    let mut engine = CorrelationEngine::with_logsource_extractor(
        CorrelationConfig::default(),
        MetadataExtractor,
    );
    engine
        .add_collection(&parse_sigma_yaml(RULES).unwrap())
        .unwrap();
    let windows = TaggedEvent::new(Some("windows"), json!({"CommandLine": "whoami"}));
    let linux = TaggedEvent::new(Some("linux"), json!({"CommandLine": "whoami"}));

    let results = engine.process_batch(&[&windows, &linux]);

    assert_eq!(titles(&results[0]), set(&["Windows whoami", "Any whoami"]));
    assert_eq!(titles(&results[1]), set(&["Linux whoami", "Any whoami"]));
}

fn router() -> SchemaRouter<MetadataExtractor> {
    SchemaRouter::build_with_logsource_extractor(
        &parse_sigma_yaml(RULES).unwrap(),
        SchemaClassifier::builtin(),
        RoutingPlan::from_config(&RoutingConfig::default()),
        vec![vec![]],
        CorrelationConfig::default(),
        false,
        MatchDetailLevel::Off,
        MetadataExtractor,
        false,
    )
    .unwrap()
}

#[test]
fn router_prunes_by_metadata() {
    let mut router = router();
    let event = TaggedEvent::new(
        Some("windows"),
        json!({"CommandLine": "whoami", "product": "linux"}),
    );

    let routed = router.route(&event);

    assert_eq!(
        titles(&routed.results),
        set(&["Windows whoami", "Any whoami"])
    );
    assert_eq!(router.logsource_pruned_total(), 1);
}

/// When the custom extractor leaves a dimension unset, the recognized schema's
/// implied logsource fills it: a Sysmon-shaped event implies `product: windows`.
#[test]
fn router_fills_unset_dimensions_from_schema() {
    let mut router = router();
    let event = TaggedEvent::new(
        None,
        json!({
            "EventID": 1,
            "ProcessGuid": "{abc}",
            "Image": "C:/Windows/System32/cmd.exe",
            "CommandLine": "cmd /c whoami"
        }),
    );

    let routed = router.route(&event);

    assert_eq!(routed.schema.as_deref(), Some("sysmon"));
    assert_eq!(
        titles(&routed.results),
        set(&["Windows whoami", "Any whoami"])
    );
}

#[test]
fn router_batch_uses_custom_extractor() {
    let router = router();
    let windows = TaggedEvent::new(Some("windows"), json!({"CommandLine": "whoami"}));
    let linux = TaggedEvent::new(Some("linux"), json!({"CommandLine": "whoami"}));

    let results = router.detect_batch(&[&windows, &linux]);

    assert_eq!(titles(&results[0]), set(&["Windows whoami", "Any whoami"]));
    assert_eq!(titles(&results[1]), set(&["Linux whoami", "Any whoami"]));
}
