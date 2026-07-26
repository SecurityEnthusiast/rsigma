use super::Pipeline;
use super::parsing::parse_pipeline;
use crate::error::Result;

const ECS_WINDOWS_YAML: &str = include_str!("../../pipelines/ecs_windows.yml");
const FIBRATUS_WINDOWS_YAML: &str = include_str!("../../pipelines/fibratus_windows.yml");
const SYSMON_YAML: &str = include_str!("../../pipelines/sysmon.yml");

/// Builtin pipeline entries: (name, yaml_content).
const BUILTIN_PIPELINES: &[(&str, &str)] = &[
    ("ecs_windows", ECS_WINDOWS_YAML),
    ("fibratus_windows", FIBRATUS_WINDOWS_YAML),
    ("sysmon", SYSMON_YAML),
];

/// Resolve a pipeline name to a parsed `Pipeline`.
///
/// Returns `Some(pipeline)` if the name matches a builtin pipeline,
/// `None` if the name is not a known builtin (caller should try as a file path).
pub fn resolve_builtin(name: &str) -> Option<Result<Pipeline>> {
    BUILTIN_PIPELINES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, yaml)| parse_pipeline(yaml))
}

/// Return the list of available builtin pipeline names.
pub fn builtin_names() -> &'static [&'static str] {
    &["ecs_windows", "fibratus_windows", "sysmon"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecs_windows_parses_successfully() {
        let pipeline = resolve_builtin("ecs_windows").unwrap().unwrap();
        assert_eq!(pipeline.name, "ecs_windows");
        assert_eq!(pipeline.priority, 20);
        assert!(!pipeline.transformations.is_empty());
    }

    #[test]
    fn sysmon_parses_successfully() {
        let pipeline = resolve_builtin("sysmon").unwrap().unwrap();
        assert_eq!(pipeline.name, "sysmon");
        assert_eq!(pipeline.priority, 10);
        assert!(!pipeline.transformations.is_empty());
    }

    #[test]
    fn fibratus_windows_parses_successfully() {
        let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
        assert_eq!(pipeline.name, "fibratus_windows");
        assert_eq!(pipeline.priority, 20);
        assert!(!pipeline.transformations.is_empty());
    }

    #[test]
    fn unknown_name_returns_none() {
        assert!(resolve_builtin("nonexistent").is_none());
    }

    #[test]
    fn builtin_names_lists_all() {
        let names = builtin_names();
        assert!(names.contains(&"ecs_windows"));
        assert!(names.contains(&"fibratus_windows"));
        assert!(names.contains(&"sysmon"));
    }

    fn sysmon_eventid_route(category: &str) -> Option<Vec<i64>> {
        use crate::pipeline::Transformation;
        use rsigma_parser::SigmaValue;

        let pipeline = resolve_builtin("sysmon").unwrap().unwrap();
        for item in &pipeline.transformations {
            if let Transformation::AddCondition { conditions, .. } = &item.transformation {
                if let Some(evts) = conditions.get("EventID") {
                    if let Some(rule_cond) = item.rule_conditions.first() {
                        if let crate::pipeline::RuleCondition::Logsource {
                            category: Some(cat),
                            ..
                        } = &rule_cond.condition
                        {
                            if cat == category {
                                return Some(
                                    evts.iter()
                                        .filter_map(|v| match v {
                                            SigmaValue::Integer(n) => Some(*n),
                                            _ => None,
                                        })
                                        .collect(),
                                );
                            }
                        }
                    }
                }
            }
        }
        None
    }

    #[test]
    fn sysmon_builtin_routes_new_categories() {
        assert_eq!(sysmon_eventid_route("sysmon_status").unwrap(), vec![4, 16]);
        assert_eq!(
            sysmon_eventid_route("registry_event").unwrap(),
            vec![12, 13, 14]
        );
        assert_eq!(sysmon_eventid_route("wmi_event").unwrap(), vec![19, 20, 21]);
        assert_eq!(
            sysmon_eventid_route("file_block_shredding").unwrap(),
            vec![28]
        );
        assert_eq!(sysmon_eventid_route("pipe_created").unwrap(), vec![17, 18]);
        assert_eq!(sysmon_eventid_route("sysmon_error").unwrap(), vec![255]);
    }

    #[test]
    fn sysmon_builtin_eventid_order() {
        use crate::pipeline::Transformation;
        use rsigma_parser::SigmaValue;

        let pipeline = resolve_builtin("sysmon").unwrap().unwrap();
        let add_conditions: Vec<(&str, Vec<i64>)> = pipeline
            .transformations
            .iter()
            .filter_map(|item| {
                if let Transformation::AddCondition { conditions, .. } = &item.transformation {
                    if let Some(evts) = conditions.get("EventID") {
                        let nums: Vec<i64> = evts
                            .iter()
                            .filter_map(|v| match v {
                                SigmaValue::Integer(n) => Some(*n),
                                _ => None,
                            })
                            .collect();
                        if !nums.is_empty() {
                            return Some((item.id.as_deref().unwrap_or(""), nums));
                        }
                    }
                }
                None
            })
            .collect();

        for i in 0..add_conditions.len().saturating_sub(1) {
            let (_, prev_nums) = &add_conditions[i];
            let (_, next_nums) = &add_conditions[i + 1];
            let prev_min = prev_nums.iter().copied().min().unwrap();
            let next_min = next_nums.iter().copied().min().unwrap();
            assert!(
                prev_min <= next_min,
                "sysmon routing: {:?} (min {}) is not before {:?} (min {})",
                prev_nums,
                prev_min,
                next_nums,
                next_min
            );
        }
    }
}
