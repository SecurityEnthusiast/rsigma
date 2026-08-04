//! Wire-level summaries of normative interop fixtures for suite-wide §2.3 checks.

use serde_json::Value;

const META_TYPES: &[&str] = &["identity", "relationship", "marking-definition"];

const SCO_TYPES: &[&str] = &[
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
];

/// Summary of object types and ids in a normative testcase bundle.
#[derive(Debug, Clone)]
pub struct FixtureWireSummary {
    pub identity_ids: Vec<String>,
    pub primary_sdo_count: usize,
    pub relationship_count: usize,
    pub sighting_count: usize,
    pub sco_objects: Vec<ScoMember>,
}

#[derive(Debug, Clone)]
pub struct ScoMember {
    pub id: String,
    pub object_type: String,
}

/// Parse bundle wire JSON into object array.
pub fn parse_fixture_objects(json: &str) -> Result<Vec<Value>, String> {
    let root: Value = serde_json::from_str(json).map_err(|err| format!("invalid JSON: {err}"))?;
    root.get("objects")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "bundle must contain objects array".to_owned())
}

/// Parse bundle wire JSON into a lightweight catalog entry.
pub fn summarize_fixture_wire(json: &str) -> Result<FixtureWireSummary, String> {
    let objects = parse_fixture_objects(json)?;

    let mut identity_ids = Vec::new();
    let mut primary_sdo_count = 0usize;
    let mut relationship_count = 0usize;
    let mut sighting_count = 0usize;
    let mut sco_objects = Vec::new();

    for object in &objects {
        let Some(object_type) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        match object_type {
            "attack-pattern" => {
                primary_sdo_count += 1;
            }
            "identity" => {
                if let Some(id) = object.get("id").and_then(Value::as_str) {
                    identity_ids.push(id.to_owned());
                }
            }
            "relationship" => relationship_count += 1,
            "sighting" => {
                sighting_count += 1;
                primary_sdo_count += 1;
            }
            ty if META_TYPES.contains(&ty) => {}
            ty if SCO_TYPES.contains(&ty) => {
                if let Some(id) = object.get("id").and_then(Value::as_str) {
                    sco_objects.push(ScoMember {
                        id: id.to_owned(),
                        object_type: ty.to_owned(),
                    });
                }
            }
            _ => primary_sdo_count += 1,
        }
    }

    Ok(FixtureWireSummary {
        identity_ids,
        primary_sdo_count,
        relationship_count,
        sighting_count,
        sco_objects,
    })
}

/// Use-case object types for a normative fixture, inferred from its directory.
pub fn use_case_types_for_fixture(relative: &str) -> &'static [&'static str] {
    let section = relative
        .strip_prefix("testcases/")
        .and_then(|path| path.split('/').next());
    match section {
        Some("attack-pattern") => &["attack-pattern"],
        Some("campaign") => &["campaign"],
        Some("course-of-action") => &["course-of-action"],
        Some("confidence") => &["indicator"],
        Some("data-markings") => &["indicator"],
        Some("grouping") => &["grouping"],
        Some("indicator") => &["indicator"],
        Some("infrastructure") => &["infrastructure"],
        Some("intrusion-set") => &["intrusion-set"],
        Some("location") => &["location"],
        Some("malware") => &["malware"],
        Some("malware-analysis") => &["malware-analysis"],
        Some("note") => &["note"],
        Some("observed-data") => &["observed-data"],
        Some("opinion") => &["opinion"],
        Some("report") => &["report"],
        Some("sighting") => &["sighting"],
        Some("threat-actor") => &["threat-actor"],
        Some("tool") => &["tool"],
        Some("versioning") => {
            // Indicator vs sighting phase fixtures share a directory; pick by filename.
            if relative.contains("sighting") {
                &["sighting"]
            } else {
                &["indicator"]
            }
        }
        Some("vulnerability") => &["vulnerability"],
        _ => &[],
    }
}

/// Object ids that receive interop use-case rules (referenced bundle members stay spec-only).
pub fn use_case_object_ids(relative: &str, objects: &[Value]) -> Vec<String> {
    let types = use_case_types_for_fixture(relative);
    objects
        .iter()
        .filter_map(|object| {
            let object_type = object.get("type")?.as_str()?;
            if !types.contains(&object_type) {
                return None;
            }
            Some(object.get("id")?.as_str()?.to_owned())
        })
        .collect()
}

/// Object ids of a given STIX type present in a fixture bundle.
pub fn object_ids_of_type(objects: &[Value], object_type: &str) -> Vec<String> {
    objects
        .iter()
        .filter(|object| object.get("type").and_then(Value::as_str) == Some(object_type))
        .filter_map(|object| object.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// Use-case object ids for two-tier interop validation, derived from fixture path.
pub fn use_case_object_ids_for_fixture(relative: &str, json: &str) -> Result<Vec<String>, String> {
    let objects = parse_fixture_objects(json)?;
    Ok(use_case_object_ids(relative, &objects))
}

/// Whether a fixture is expected to carry explicit SRO content (relationship or sighting).
pub fn fixture_expects_sro(relative: &str, summary: &FixtureWireSummary) -> bool {
    if summary.relationship_count > 0 || summary.sighting_count > 0 {
        return true;
    }
    relative.contains("targets-")
        || relative.contains("attributed-to-")
        || relative.contains("hosting-")
        || relative.starts_with("testcases/sighting/")
        || relative.starts_with("testcases/versioning/tc-3.20.3.2")
        || relative.starts_with("testcases/versioning/tc-3.20.7.2")
        || relative.starts_with("testcases/versioning/tc-3.20.11.2")
}

/// Whether §2.3.4 self-referential `created_by_ref` is required for identities in this fixture.
pub fn identity_self_ref_required(relative: &str) -> bool {
    !(relative.starts_with("testcases/sighting/")
        || relative.starts_with("testcases/opinion/")
        || relative.starts_with("testcases/data-markings/")
        || relative.starts_with("testcases/versioning/"))
}
