//! Interop use-case object rules stricter than STIX §4.x (§3.1 attack-pattern instance).

use rstix::core::StixId;
use rstix::model::Bundle;
use rstix::model::sdo::AttackPattern;

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

/// Apply interop use-case rules only to listed object ids (two-tier validation spine).
pub fn validate_use_case_objects(
    bundle: &Bundle,
    use_case_object_ids: &[String],
) -> Result<(), String> {
    for object_id in use_case_object_ids {
        let id = StixId::parse(object_id)
            .map_err(|err| format!("invalid use-case object id {object_id}: {err}"))?;
        if let Some(ap) = bundle.get_typed::<AttackPattern>(&id) {
            validate_attack_pattern_interop(ap)?;
        }
    }
    Ok(())
}
