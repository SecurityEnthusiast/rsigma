//! Post-engine alert-processing layer.
//!
//! An optional stage in the daemon sink path, between post-evaluation
//! enrichment and the sinks, modeled on the Alertmanager processing pipeline.
//! It currently runs two stages: fingerprint deduplication (`active ->
//! resolved` lifecycle) and incident grouping (`group_by` equality or an
//! opt-in `entity_graph` union-find). It is the home for the silencing and
//! inhibition stages as they land.
//!
//! The layer is strictly post-engine: it consumes [`EvaluationResult`]s and
//! emits [`EvaluationResult`]s plus [`IncidentResult`]s, so the evaluation hot
//! path is untouched. The immutable, validated config ([`AlertPipeline`]) is
//! built from a YAML file and swapped atomically on hot-reload; the mutable
//! [`DedupStore`] and [`IncidentStore`] are owned by the sink task (the
//! incident store behind an `RwLock` so the admin API can read open incidents).

mod config;
mod dedup;
mod grouping;
mod selector;

pub use config::{
    AlertPipelineConfigError, AlertPipelineFile, CapsFile, DedupFile, GroupFile, GroupModeLabel,
    IncludeLabel, ScopeConfig, build_alert_pipeline, load_alert_pipeline_file,
    parse_alert_pipeline_config,
};
pub use dedup::DedupStore;
pub use grouping::{GroupMode, IncidentRef, IncidentResult, IncidentStore, IncludeMode};
pub use selector::{Selector, SelectorParseError};

use rsigma_eval::{EvaluationResult, ProcessResult};
use serde_json::Value;

use crate::{MetricsHook, Scope};

use dedup::DedupConfig;
use grouping::{GroupConfig, OvermergeGuard};

/// Output of [`AlertPipeline::tick`]: dedup summary records (re-emit /
/// resolved) and incident emissions.
#[derive(Debug, Default)]
pub struct TickOutput {
    /// Dedup `repeat` / `resolved` records, dispatched like normal results.
    pub results: ProcessResult,
    /// Incident emissions, dispatched via the incident path.
    pub incidents: Vec<IncidentResult>,
}

/// A validated, runnable alert-processing pipeline.
///
/// Immutable after construction and cheap to clone behind an `Arc`, so it can
/// be swapped atomically on hot-reload while the sink task keeps a live
/// snapshot for the duration of a batch.
#[derive(Debug)]
pub struct AlertPipeline {
    scope: Scope,
    strip_event: bool,
    dedup: Option<DedupConfig>,
    group: Option<GroupConfig>,
}

impl AlertPipeline {
    /// Construct from validated parts. Prefer [`build_alert_pipeline`].
    pub(crate) fn new(
        scope: Scope,
        strip_event: bool,
        dedup: Option<DedupConfig>,
        group: Option<GroupConfig>,
    ) -> Self {
        AlertPipeline {
            scope,
            strip_event,
            dedup,
            group,
        }
    }

    /// True when the pipeline does nothing, so the sink task can skip it.
    pub fn is_noop(&self) -> bool {
        self.dedup.is_none() && self.group.is_none() && !self.strip_event
    }

    /// The configured incident include mode, if grouping is enabled.
    pub fn incident_include(&self) -> Option<IncludeMode> {
        self.group.as_ref().map(|g| g.include)
    }

    /// The configured incident NATS subject override, if any.
    pub fn incident_nats_subject(&self) -> Option<&str> {
        self.group.as_ref().and_then(|g| g.nats_subject.as_deref())
    }

    /// Process the results produced from one input event: dedup folds
    /// duplicates into `dedup_store`, grouping assigns survivors to incidents
    /// in `incident_store` and annotates them with `incident_id`. Out-of-scope
    /// results pass through untouched.
    pub fn process(
        &self,
        results: ProcessResult,
        dedup_store: &mut DedupStore,
        incident_store: &mut IncidentStore,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> ProcessResult {
        if self.is_noop() {
            return results;
        }
        let start = std::time::Instant::now();
        let mut kept = Vec::with_capacity(results.len());

        for mut result in results {
            if !self.scope.matches(&result) {
                kept.push(result);
                continue;
            }

            // Dedup: fold duplicates into the active alert.
            if let Some(cfg) = self.dedup.as_ref() {
                let fingerprint = dedup::fingerprint(&cfg.fingerprint, &result);
                if dedup_store.contains(&fingerprint) {
                    dedup_store.fold(&fingerprint, now);
                    metrics.on_alert_pipeline_result("folded");
                    continue;
                }
                let fields = dedup::resolve_fields(&cfg.fingerprint, &result);
                let sample = dedup::sample_of(&result);
                dedup_store.insert(fingerprint, now, sample, fields);
                metrics.on_alert_pipeline_result("emitted");
            }

            // Grouping: assign the survivor to an incident, reading entity /
            // group-by selectors off the result while the event is still
            // present, then annotate it with the incident id.
            if let Some(gcfg) = self.group.as_ref()
                && let Some(id) = incident_store.assign(gcfg, &result, now, |guard| {
                    metrics.on_alert_pipeline_overmerge(guard_label(guard));
                })
            {
                if self.strip_event {
                    strip_event_payloads(&mut result);
                }
                annotate_incident(&mut result, id);
                kept.push(result);
                continue;
            }

            if self.strip_event {
                strip_event_payloads(&mut result);
            }
            kept.push(result);
        }

        if self.dedup.is_some() {
            metrics.set_alert_pipeline_store_entries(dedup_store.len() as i64);
        }
        if self.group.is_some() {
            metrics.set_incidents_open(incident_store.len() as i64);
        }
        metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        kept
    }

    /// Advance time: emit due dedup `repeat` / `resolved` records and incident
    /// emissions (`group_wait` / `group_interval` / `repeat` / `resolved`).
    pub fn tick(
        &self,
        dedup_store: &mut DedupStore,
        incident_store: &mut IncidentStore,
        now: i64,
        metrics: &dyn MetricsHook,
    ) -> TickOutput {
        let start = std::time::Instant::now();
        let mut out = TickOutput::default();

        if let Some(cfg) = self.dedup.as_ref() {
            for record in dedup_store.tick(cfg, now) {
                metrics.on_alert_pipeline_result(record.state);
                metrics.on_alert_pipeline_summary_emitted();
                if record.state == "resolved" {
                    metrics.on_alert_pipeline_eviction();
                }
                out.results.push(record.result);
            }
            metrics.set_alert_pipeline_store_entries(dedup_store.len() as i64);
        }

        if let Some(gcfg) = self.group.as_ref() {
            for emission in incident_store.tick(gcfg, now) {
                metrics.on_incident_emitted(emission.trigger);
                out.incidents.push(emission.result);
            }
            metrics.set_incidents_open(incident_store.len() as i64);
        }

        if !out.results.is_empty() || !out.incidents.is_empty() {
            metrics.observe_alert_pipeline_duration(start.elapsed().as_secs_f64());
        }
        out
    }
}

/// Inject the reserved `incident_id` key into a result's enrichments. The layer
/// wins on a collision with a user enricher.
fn annotate_incident(result: &mut EvaluationResult, id: String) {
    let map = result
        .header
        .enrichments
        .get_or_insert_with(serde_json::Map::new);
    if map.contains_key("incident_id") {
        tracing::warn!("alert pipeline: overwriting a user-set `incident_id` enrichment key");
    }
    map.insert("incident_id".to_string(), Value::String(id));
}

/// Metric label for an entity-graph guard hit.
fn guard_label(guard: OvermergeGuard) -> &'static str {
    match guard {
        OvermergeGuard::StopValue => "stop_value",
        OvermergeGuard::CardinalityCeiling => "cardinality_ceiling",
    }
}

/// Remove raw event payloads from a result. Used for the long-lived dedup
/// sample and, when `strip_event` is set, for pass-through results, so the
/// layer can fingerprint and group on `event.*` without emitting full events.
pub(crate) fn strip_event_payloads(result: &mut EvaluationResult) {
    if let Some(detection) = result.as_detection_mut() {
        detection.event = None;
    }
    if let Some(correlation) = result.as_correlation_mut() {
        correlation.events = None;
        correlation.event_refs = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopMetrics;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn pipeline(yaml: &str) -> AlertPipeline {
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        build_alert_pipeline(file).unwrap()
    }

    fn detection(ip: &str, level: Level) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Brute force".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: Some(serde_json::json!({"raw": "event"})),
            }),
        }
    }

    fn run(
        p: &AlertPipeline,
        ip: &str,
        level: Level,
        dedup: &mut DedupStore,
        incidents: &mut IncidentStore,
        now: i64,
    ) -> ProcessResult {
        p.process(
            vec![detection(ip, level)],
            dedup,
            incidents,
            now,
            &NoopMetrics,
        )
    }

    #[test]
    fn dedup_emits_first_fire_and_folds_duplicates() {
        let p = pipeline("dedup:\n  fingerprint: [match.SourceIp]\n  resolve_timeout: 1h\n");
        let mut dedup = DedupStore::default();
        let mut inc = IncidentStore::default();

        let first = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 0);
        assert_eq!(first.len(), 1);
        let dup = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 5);
        assert!(dup.is_empty());
    }

    #[test]
    fn out_of_scope_results_bypass_the_layer() {
        let p = pipeline("scope:\n  levels: [critical]\ndedup:\n  fingerprint: [match.SourceIp]\n");
        let mut dedup = DedupStore::default();
        let mut inc = IncidentStore::default();
        let a = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 0);
        let b = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 1);
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(dedup.is_empty());
    }

    #[test]
    fn grouping_annotates_incident_id_and_opens_on_group_wait() {
        let p =
            pipeline("group:\n  by: [match.SourceIp]\n  group_wait: 30s\n  resolve_timeout: 1h\n");
        let mut dedup = DedupStore::default();
        let mut inc = IncidentStore::default();
        let kept = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 0);
        assert_eq!(kept.len(), 1);
        let id = kept[0].header.enrichments.as_ref().unwrap()["incident_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!id.is_empty());

        // No incident emission before group_wait; one open emission after.
        assert!(
            p.tick(&mut dedup, &mut inc, 10, &NoopMetrics)
                .incidents
                .is_empty()
        );
        let out = p.tick(&mut dedup, &mut inc, 40, &NoopMetrics);
        assert_eq!(out.incidents.len(), 1);
        assert_eq!(out.incidents[0].incident_id, id);
        assert_eq!(out.incidents[0].trigger, "group_wait");
    }

    #[test]
    fn dedup_then_group_compose() {
        let p = pipeline(
            "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\ngroup:\n  by: [match.SourceIp]\n  group_wait: 0s\n",
        );
        let mut dedup = DedupStore::default();
        let mut inc = IncidentStore::default();
        // First fire: deduped (passes) and grouped.
        let a = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 0);
        assert_eq!(a.len(), 1);
        assert!(
            a[0].header
                .enrichments
                .as_ref()
                .unwrap()
                .contains_key("incident_id")
        );
        // Duplicate: folded by dedup, never reaches grouping.
        let b = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 1);
        assert!(b.is_empty());
        assert_eq!(inc.len(), 1, "the duplicate did not open a second incident");
    }

    #[test]
    fn strip_event_drops_payload_after_grouping() {
        let p = pipeline("strip_event: true\ngroup:\n  by: [event.raw]\n  group_wait: 0s\n");
        let mut dedup = DedupStore::default();
        let mut inc = IncidentStore::default();
        let kept = run(&p, "10.0.0.1", Level::High, &mut dedup, &mut inc, 0);
        assert_eq!(kept.len(), 1);
        // Event stripped from the delivered result, but grouping still keyed
        // on event.raw (one incident opened).
        assert!(kept[0].as_detection().unwrap().event.is_none());
        assert_eq!(inc.len(), 1);
    }
}
