//! Row-to-event reshaping.
//!
//! Two modes, keyed off the backend's `json_field` option:
//!
//! - **JSONB mode** is the high-fidelity path: the stored column *is* the
//!   original event, so it is emitted verbatim, merging the timestamp column
//!   under its column name when the event body lacks one. Round-trip
//!   fidelity is exact by construction.
//! - **Flat-column mode** reconstructs the event from the row: each non-NULL
//!   column becomes a JSON key named by the column, with SQL types mapped to
//!   JSON types. NULL columns are dropped rather than emitted as `null`: the
//!   reference schema is a wide single-landing-table where most
//!   category-specific columns are NULL for any given event, and a draft
//!   mined from all-columns-present events would score field presence wrong.
//!
//! Columns of a type the executor cannot decode arrive as
//! [`SqlValue::Unmapped`] and are dropped; the executor warns once per
//! column/type pair (the binary wire protocol has no portable text form for
//! types without a decoder).

use chrono::{DateTime, Utc};

/// A decoded column value, already mapped off the wire type.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Timestamp(DateTime<Utc>),
    Json(serde_json::Value),
    /// A wire type with no decoder (e.g. `tsvector`). Carries the SQL type
    /// name so the executor can warn naming column and type.
    Unmapped {
        type_name: String,
    },
}

/// One column of a decoded row, in column order.
#[derive(Debug)]
pub(crate) struct DecodedColumn {
    pub name: String,
    pub value: SqlValue,
}

/// A decoded row: columns in result order.
pub(crate) type DecodedRow = Vec<DecodedColumn>;

/// Non-fatal reshaping notes, surfaced on stderr by the caller.
#[derive(Debug, PartialEq)]
pub(crate) enum ReshapeNote {
    /// The event body already carried the timestamp key; the body's value
    /// won and the column value was not merged.
    TimestampConflict { column: String },
}

/// Map a decoded value to its JSON form. `None` means "drop the column"
/// (NULL and undecodable values).
fn value_to_json(value: &SqlValue) -> Option<serde_json::Value> {
    match value {
        SqlValue::Null | SqlValue::Unmapped { .. } => None,
        SqlValue::Bool(b) => Some((*b).into()),
        SqlValue::Int(i) => Some((*i).into()),
        // Non-finite floats have no JSON number; render them as text.
        SqlValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(Into::into)
            .or_else(|| Some(f.to_string().into())),
        SqlValue::Text(s) => Some(s.clone().into()),
        SqlValue::Timestamp(ts) => Some(ts.to_rfc3339().into()),
        SqlValue::Json(v) => Some(v.clone()),
    }
}

/// Flat-column mode: reconstruct the event from the row's non-NULL columns.
pub(crate) fn reshape_flat(row: &DecodedRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for col in row {
        if let Some(value) = value_to_json(&col.value) {
            map.insert(col.name.clone(), value);
        }
    }
    serde_json::Value::Object(map)
}

/// JSONB mode: emit the `json_field` column verbatim, merging the timestamp
/// column under its name when the event body lacks it (the body wins on
/// conflict, with a note). A non-object JSONB value is emitted as-is.
pub(crate) fn reshape_jsonb(
    row: &DecodedRow,
    json_field: &str,
    timestamp_field: &str,
) -> Result<(serde_json::Value, Vec<ReshapeNote>), String> {
    let Some(col) = row.iter().find(|c| c.name == json_field) else {
        return Err(format!(
            "the result has no '{json_field}' column; check -O json_field= against the table schema"
        ));
    };
    let SqlValue::Json(event) = &col.value else {
        return Err(format!(
            "column '{json_field}' did not decode as JSONB; check -O json_field= against the table schema"
        ));
    };

    let mut notes = Vec::new();
    let mut event = event.clone();
    if let serde_json::Value::Object(map) = &mut event
        && let Some(ts_col) = row.iter().find(|c| c.name == timestamp_field)
    {
        if map.contains_key(timestamp_field) {
            notes.push(ReshapeNote::TimestampConflict {
                column: timestamp_field.to_string(),
            });
        } else if let Some(value) = value_to_json(&ts_col.value) {
            map.insert(timestamp_field.to_string(), value);
        }
    }
    Ok((event, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, value: SqlValue) -> DecodedColumn {
        DecodedColumn {
            name: name.to_string(),
            value,
        }
    }

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-01T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    // -- type mapping ---------------------------------------------------------

    #[test]
    fn flat_maps_every_type() {
        let row = vec![
            col("time", SqlValue::Timestamp(ts())),
            col("event_id", SqlValue::Int(42)),
            col("severity", SqlValue::Float(2.5)),
            col("category", SqlValue::Text("process".to_string())),
            col("success", SqlValue::Bool(true)),
            col(
                "metadata",
                SqlValue::Json(serde_json::json!({"source": "agent"})),
            ),
        ];
        let event = reshape_flat(&row);
        assert_eq!(
            event,
            serde_json::json!({
                "time": "2026-07-01T10:00:00+00:00",
                "event_id": 42,
                "severity": 2.5,
                "category": "process",
                "success": true,
                "metadata": {"source": "agent"},
            })
        );
    }

    #[test]
    fn flat_drops_null_and_unmapped_columns() {
        let row = vec![
            col("category", SqlValue::Text("auth".to_string())),
            col("dst_ip", SqlValue::Null),
            col(
                "search_vector",
                SqlValue::Unmapped {
                    type_name: "tsvector".to_string(),
                },
            ),
        ];
        let event = reshape_flat(&row);
        assert_eq!(event, serde_json::json!({"category": "auth"}));
    }

    #[test]
    fn flat_renders_non_finite_floats_as_text() {
        let row = vec![col("score", SqlValue::Float(f64::NAN))];
        let event = reshape_flat(&row);
        assert_eq!(event, serde_json::json!({"score": "NaN"}));
    }

    // -- JSONB mode -------------------------------------------------------------

    #[test]
    fn jsonb_emits_verbatim_and_merges_timestamp() {
        let row = vec![
            col("time", SqlValue::Timestamp(ts())),
            col(
                "data",
                SqlValue::Json(serde_json::json!({"Image": "/usr/bin/curl"})),
            ),
        ];
        let (event, notes) = reshape_jsonb(&row, "data", "time").unwrap();
        assert!(notes.is_empty());
        assert_eq!(
            event,
            serde_json::json!({"Image": "/usr/bin/curl", "time": "2026-07-01T10:00:00+00:00"})
        );
    }

    #[test]
    fn jsonb_body_wins_on_timestamp_conflict() {
        let row = vec![
            col("time", SqlValue::Timestamp(ts())),
            col(
                "data",
                SqlValue::Json(serde_json::json!({"time": "1999-01-01T00:00:00Z"})),
            ),
        ];
        let (event, notes) = reshape_jsonb(&row, "data", "time").unwrap();
        assert_eq!(event, serde_json::json!({"time": "1999-01-01T00:00:00Z"}));
        assert_eq!(
            notes,
            vec![ReshapeNote::TimestampConflict {
                column: "time".to_string()
            }]
        );
    }

    #[test]
    fn jsonb_missing_column_is_a_pointed_error() {
        let row = vec![col("time", SqlValue::Timestamp(ts()))];
        let err = reshape_jsonb(&row, "data", "time").unwrap_err();
        assert!(err.contains("no 'data' column"), "{err}");
    }

    #[test]
    fn jsonb_non_json_column_is_a_pointed_error() {
        let row = vec![col("data", SqlValue::Text("not json".to_string()))];
        let err = reshape_jsonb(&row, "data", "time").unwrap_err();
        assert!(err.contains("did not decode as JSONB"), "{err}");
    }

    #[test]
    fn jsonb_non_object_event_is_emitted_as_is() {
        let row = vec![
            col("time", SqlValue::Timestamp(ts())),
            col("data", SqlValue::Json(serde_json::json!(["a", "b"]))),
        ];
        let (event, notes) = reshape_jsonb(&row, "data", "time").unwrap();
        assert!(notes.is_empty());
        assert_eq!(event, serde_json::json!(["a", "b"]));
    }

    // -- golden -----------------------------------------------------------------

    fn golden_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden")
            .join(name)
    }

    /// Rebuild every object with its keys sorted, so a golden stays valid
    /// under both serde_json map orderings (`preserve_order` is
    /// feature-unified on in some workspace builds and off in others).
    fn canonical(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                serde_json::Value::Object(
                    keys.into_iter()
                        .map(|key| (key.clone(), canonical(&map[key])))
                        .collect(),
                )
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(canonical).collect())
            }
            other => other.clone(),
        }
    }

    /// Compare against the committed golden. Set `RSIGMA_UPDATE_GOLDEN=1` to
    /// rewrite after an intentional change.
    fn check_golden(name: &str, actual: &str) {
        let path = golden_path(name);
        if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(actual, expected, "hunt golden drifted for '{name}'");
    }

    /// The exemplar contract `rule draft`/`rule tune`/backtest consume: one
    /// raw JSON event object per line, keyed by the archive's native
    /// (post-pipeline) field names.
    #[test]
    fn golden_flat_ndjson() {
        let rows = vec![
            vec![
                col("time", SqlValue::Timestamp(ts())),
                col("event_id", SqlValue::Int(9001)),
                col("category", SqlValue::Text("process".to_string())),
                col("src_ip", SqlValue::Text("10.0.0.8".to_string())),
                col("dst_ip", SqlValue::Null),
                col("success", SqlValue::Bool(false)),
                col(
                    "search_vector",
                    SqlValue::Unmapped {
                        type_name: "tsvector".to_string(),
                    },
                ),
            ],
            vec![
                col("time", SqlValue::Timestamp(ts())),
                col("event_id", SqlValue::Int(9002)),
                col("category", SqlValue::Text("authentication".to_string())),
                col("metadata", SqlValue::Json(serde_json::json!({"mfa": true}))),
            ],
        ];
        let mut actual = String::new();
        for row in &rows {
            let event = canonical(&reshape_flat(row));
            actual.push_str(&serde_json::to_string(&event).unwrap());
            actual.push('\n');
        }
        check_golden("hunt_events_flat.ndjson", &actual);
    }

    #[test]
    fn golden_jsonb_ndjson() {
        let rows = vec![vec![
            col("time", SqlValue::Timestamp(ts())),
            col(
                "data",
                SqlValue::Json(serde_json::json!({
                    "Image": "/usr/bin/curl",
                    "CommandLine": "curl --insecure https://example.invalid",
                })),
            ),
        ]];
        let mut actual = String::new();
        for row in &rows {
            let (event, notes) = reshape_jsonb(row, "data", "time").unwrap();
            assert!(notes.is_empty());
            actual.push_str(&serde_json::to_string(&canonical(&event)).unwrap());
            actual.push('\n');
        }
        check_golden("hunt_events_jsonb.ndjson", &actual);
    }
}
