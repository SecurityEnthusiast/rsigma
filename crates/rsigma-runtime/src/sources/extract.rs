//! Expression-based data extraction for dynamic sources.
//!
//! Supports three extraction languages with dual syntax:
//! - Plain string: always jq (the common case)
//! - Structured object `{ expr, type }`: explicit language selection
//!
//! Supported types: `jq` (default), `jsonpath`, `cel`.

use super::{SourceError, SourceErrorKind};

/// Apply an extract expression to parsed source data.
///
/// The expression is always treated as jq in Phase 2a. JSONPath and CEL
/// support will be added in later sub-phases.
pub fn apply_extract(
    data: &serde_json::Value,
    expr: &str,
) -> Result<serde_json::Value, SourceError> {
    apply_jq(data, expr)
}

/// Apply a jq expression using jaq.
fn apply_jq(data: &serde_json::Value, expr: &str) -> Result<serde_json::Value, SourceError> {
    use jaq_interpret::{Ctx, FilterT, RcIter, Val};

    let mut defs = jaq_interpret::ParseCtx::new(vec![]);
    let (filter, errs) = jaq_parse::parse(expr, jaq_parse::main());

    if !errs.is_empty() || filter.is_none() {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("invalid jq expression: {expr}")),
        });
    }

    let filter = defs.compile(filter.unwrap());
    let inputs = RcIter::new(std::iter::empty());
    let val = Val::from(data.clone());

    let ctx = Ctx::new([], &inputs);
    let results: Vec<Val> = filter
        .run((ctx, val))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Extract(format!("jq execution error: {e}")),
        })?;

    match results.len() {
        0 => Ok(serde_json::Value::Null),
        1 => Ok(val_to_json(&results[0])),
        _ => {
            let arr: Vec<serde_json::Value> = results.iter().map(val_to_json).collect();
            Ok(serde_json::Value::Array(arr))
        }
    }
}

/// Convert a jaq `Val` to a `serde_json::Value`.
fn val_to_json(val: &jaq_interpret::Val) -> serde_json::Value {
    match val {
        jaq_interpret::Val::Null => serde_json::Value::Null,
        jaq_interpret::Val::Bool(b) => serde_json::Value::Bool(*b),
        jaq_interpret::Val::Int(i) => serde_json::json!(i),
        jaq_interpret::Val::Float(f) => serde_json::json!(f),
        jaq_interpret::Val::Num(n) => {
            if let Ok(i) = n.parse::<i64>() {
                serde_json::json!(i)
            } else if let Ok(f) = n.parse::<f64>() {
                serde_json::json!(f)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        jaq_interpret::Val::Str(s) => serde_json::Value::String(s.to_string()),
        jaq_interpret::Val::Arr(arr) => {
            serde_json::Value::Array(arr.iter().map(val_to_json).collect())
        }
        jaq_interpret::Val::Obj(obj) => {
            let map: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .map(|(k, v)| (k.to_string(), val_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}
