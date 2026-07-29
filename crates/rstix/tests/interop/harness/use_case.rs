//! Interop use-case object rules stricter than STIX §4.x (§3.x Producer Persona Support).

use rstix::core::StixId;
use rstix::model::Bundle;
use rstix::model::sdo::{
    AttackPattern, Campaign, CourseOfAction, Grouping, Indicator, Infrastructure, IntrusionSet,
    Location, Malware, MalwareAnalysis, Note, ObservedData, Opinion, Report, ThreatActor, Tool,
    Vulnerability,
};
use rstix::model::sro::Sighting;
use serde_json::Value;

fn require_non_empty_string(object: &Value, key: &str, label: &str) -> Result<(), String> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(format!("{label} missing interop-mandatory `{key}`")),
    }
}

fn require_non_empty_array(object: &Value, key: &str, label: &str) -> Result<(), String> {
    match object.get(key).and_then(Value::as_array) {
        Some(items) if !items.is_empty() => Ok(()),
        _ => Err(format!("{label} missing interop-mandatory `{key}`")),
    }
}

fn require_present(object: &Value, key: &str, label: &str) -> Result<(), String> {
    if object.get(key).is_some() {
        Ok(())
    } else {
        Err(format!("{label} missing interop-mandatory `{key}`"))
    }
}

/// Interop-mandatory attack-pattern fields beyond STIX §4.1 optional properties (§3.1).
pub fn validate_attack_pattern_interop(ap: &AttackPattern) -> Result<(), String> {
    if ap.common.external_references.is_empty() {
        return Err("attack-pattern missing interop-mandatory external_references".into());
    }
    if ap.kill_chain_phases.is_empty() {
        return Err("attack-pattern missing interop-mandatory kill_chain_phases".into());
    }
    Ok(())
}

fn validate_wire_use_case_object(object: &Value) -> Result<(), String> {
    let object_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "use-case object missing type".to_owned())?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(object_type);
    let label = format!("{object_type} `{id}`");

    require_non_empty_string(object, "created_by_ref", &label)?;

    match object_type {
        "attack-pattern" => {
            require_non_empty_string(object, "name", &label)?;
            require_non_empty_array(object, "external_references", &label)?;
            require_non_empty_array(object, "kill_chain_phases", &label)?;
        }
        "indicator" => {
            require_non_empty_string(object, "name", &label)?;
            require_non_empty_string(object, "pattern", &label)?;
            require_non_empty_string(object, "pattern_type", &label)?;
            require_non_empty_array(object, "indicator_types", &label)?;
            require_present(object, "valid_from", &label)?;
        }
        "sighting" => {
            require_present(object, "sighting_of_ref", &label)?;
            require_present(object, "count", &label)?;
            require_present(object, "first_seen", &label)?;
            require_present(object, "last_seen", &label)?;
        }
        "observed-data" => {
            require_present(object, "first_observed", &label)?;
            require_present(object, "last_observed", &label)?;
            require_present(object, "number_observed", &label)?;
            require_non_empty_array(object, "object_refs", &label)?;
        }
        "grouping" => {
            require_non_empty_string(object, "context", &label)?;
            require_non_empty_array(object, "object_refs", &label)?;
        }
        "opinion" => {
            require_non_empty_string(object, "opinion", &label)?;
            require_non_empty_array(object, "object_refs", &label)?;
        }
        "note" => {
            require_non_empty_string(object, "content", &label)?;
            require_non_empty_array(object, "object_refs", &label)?;
        }
        "report" => {
            require_non_empty_string(object, "name", &label)?;
            require_present(object, "published", &label)?;
            require_non_empty_array(object, "object_refs", &label)?;
            require_non_empty_array(object, "report_types", &label)?;
        }
        "malware-analysis" => {
            require_non_empty_string(object, "product", &label)?;
            require_non_empty_string(object, "version", &label)?;
            require_present(object, "submitted", &label)?;
            require_present(object, "analysis_started", &label)?;
            require_present(object, "analysis_ended", &label)?;
            require_non_empty_string(object, "result", &label)?;
        }
        "campaign" | "course-of-action" => {
            require_non_empty_string(object, "name", &label)?;
        }
        "malware" => {
            require_non_empty_string(object, "name", &label)?;
            require_present(object, "is_family", &label)?;
            require_non_empty_array(object, "malware_types", &label)?;
        }
        "intrusion-set" | "threat-actor" | "tool" | "infrastructure" | "vulnerability" => {
            require_non_empty_string(object, "name", &label)?;
        }
        "location" => {
            require_non_empty_string(object, "region", &label)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_typed_use_case_object(
    bundle: &Bundle,
    id: &StixId,
    object_type: &str,
) -> Result<(), String> {
    match object_type {
        "attack-pattern" => {
            let ap = bundle
                .get_typed::<AttackPattern>(id)
                .ok_or_else(|| format!("typed attack-pattern {}", id.as_str()))?;
            validate_attack_pattern_interop(ap)
        }
        "indicator" => {
            let indicator = bundle
                .get_typed::<Indicator>(id)
                .ok_or_else(|| format!("typed indicator {}", id.as_str()))?;
            if indicator.name.is_none() {
                return Err(format!("indicator {} missing name", id.as_str()));
            }
            Ok(())
        }
        "sighting" => {
            let sighting = bundle
                .get_typed::<Sighting>(id)
                .ok_or_else(|| format!("typed sighting {}", id.as_str()))?;
            if sighting.sighting_of_ref.as_str().is_empty() {
                return Err(format!("sighting {} missing sighting_of_ref", id.as_str()));
            }
            Ok(())
        }
        "campaign" => bundle
            .get_typed::<Campaign>(id)
            .ok_or_else(|| format!("typed campaign {}", id.as_str()))
            .map(|_| ()),
        "course-of-action" => bundle
            .get_typed::<CourseOfAction>(id)
            .ok_or_else(|| format!("typed course-of-action {}", id.as_str()))
            .map(|_| ()),
        "grouping" => bundle
            .get_typed::<Grouping>(id)
            .ok_or_else(|| format!("typed grouping {}", id.as_str()))
            .map(|_| ()),
        "infrastructure" => bundle
            .get_typed::<Infrastructure>(id)
            .ok_or_else(|| format!("typed infrastructure {}", id.as_str()))
            .map(|_| ()),
        "intrusion-set" => bundle
            .get_typed::<IntrusionSet>(id)
            .ok_or_else(|| format!("typed intrusion-set {}", id.as_str()))
            .map(|_| ()),
        "location" => bundle
            .get_typed::<Location>(id)
            .ok_or_else(|| format!("typed location {}", id.as_str()))
            .map(|_| ()),
        "malware" => bundle
            .get_typed::<Malware>(id)
            .ok_or_else(|| format!("typed malware {}", id.as_str()))
            .map(|_| ()),
        "malware-analysis" => bundle
            .get_typed::<MalwareAnalysis>(id)
            .ok_or_else(|| format!("typed malware-analysis {}", id.as_str()))
            .map(|_| ()),
        "note" => bundle
            .get_typed::<Note>(id)
            .ok_or_else(|| format!("typed note {}", id.as_str()))
            .map(|_| ()),
        "observed-data" => bundle
            .get_typed::<ObservedData>(id)
            .ok_or_else(|| format!("typed observed-data {}", id.as_str()))
            .map(|_| ()),
        "opinion" => bundle
            .get_typed::<Opinion>(id)
            .ok_or_else(|| format!("typed opinion {}", id.as_str()))
            .map(|_| ()),
        "report" => bundle
            .get_typed::<Report>(id)
            .ok_or_else(|| format!("typed report {}", id.as_str()))
            .map(|_| ()),
        "threat-actor" => bundle
            .get_typed::<ThreatActor>(id)
            .ok_or_else(|| format!("typed threat-actor {}", id.as_str()))
            .map(|_| ()),
        "tool" => bundle
            .get_typed::<Tool>(id)
            .ok_or_else(|| format!("typed tool {}", id.as_str()))
            .map(|_| ()),
        "vulnerability" => bundle
            .get_typed::<Vulnerability>(id)
            .ok_or_else(|| format!("typed vulnerability {}", id.as_str()))
            .map(|_| ()),
        other => Err(format!("unsupported use-case object type `{other}`")),
    }
}

/// Apply interop use-case rules only to listed object ids (two-tier validation spine).
pub fn validate_use_case_objects(
    bundle: &Bundle,
    use_case_object_ids: &[String],
    wire_objects: &[Value],
) -> Result<(), String> {
    for object_id in use_case_object_ids {
        let id = StixId::parse(object_id)
            .map_err(|err| format!("invalid use-case object id {object_id}: {err}"))?;
        let wire = wire_objects
            .iter()
            .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id))
            .ok_or_else(|| format!("wire object missing for use-case id {object_id}"))?;
        let object_type = wire
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("wire object {object_id} missing type"))?;

        validate_wire_use_case_object(wire)?;
        validate_typed_use_case_object(bundle, &id, object_type)?;
    }
    Ok(())
}
