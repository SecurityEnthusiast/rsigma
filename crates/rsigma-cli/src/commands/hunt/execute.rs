//! The gated executor: one read-only tokio-postgres connection per
//! invocation, rows streamed (never paged) and reshaped to NDJSON.
//!
//! Read-only is enforced, not promised: the session opens with
//! `SET default_transaction_read_only = on` and a server-side statement
//! timeout before any hunt SQL runs, so even a buggy generated query cannot
//! write and a pathological scan is bounded. TLS uses rustls with the
//! system root store; `sslmode` in the DSN is honored by tokio-postgres
//! (`disable` plaintext, `prefer` TLS with plaintext fallback, `require`
//! TLS-only).

use std::collections::HashSet;
use std::io::Write;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::NaiveDateTime;
use tokio_postgres::Row;
use tokio_postgres::types::Type;
use tokio_stream::StreamExt;

use super::query::HuntPlan;
use super::reshape::{
    DecodedColumn, DecodedRow, ReshapeNote, SqlValue, reshape_flat, reshape_jsonb,
};
use crate::exit_code;
use crate::output::{OutputCtx, OutputFormat};

/// Entry point for `--emit events`. Builds a current-thread runtime and runs
/// the hunt to completion; exits the process on any failure.
pub(crate) fn run(
    dsn: &str,
    plan: &HuntPlan,
    timeout: Duration,
    output: Option<&std::path::Path>,
    ctx: &OutputCtx,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("failed to start the async runtime: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        });
    runtime.block_on(run_async(dsn, plan, timeout, output, ctx));
}

async fn run_async(
    dsn: &str,
    plan: &HuntPlan,
    timeout: Duration,
    output: Option<&std::path::Path>,
    ctx: &OutputCtx,
) {
    let config: tokio_postgres::Config = dsn.parse().unwrap_or_else(|e| {
        eprintln!("invalid hunt DSN: {e}");
        process::exit(exit_code::CONFIG_ERROR);
    });
    let redacted = redacted_dsn(&config);

    let tls = rustls_connector();
    let (client, connection) = config.connect(tls).await.unwrap_or_else(|e| {
        eprintln!("could not connect to {redacted}: {}", pg_error(&e));
        process::exit(exit_code::CONFIG_ERROR);
    });
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection to the archive failed mid-hunt: {e}");
        }
    });

    // Enforce the read-only, time-boxed session before any hunt SQL runs.
    // The timeout is an integer millisecond literal, never interpolated text.
    let setup = format!(
        "SET default_transaction_read_only = on; SET statement_timeout = {}",
        timeout.as_millis()
    );
    client.batch_execute(&setup).await.unwrap_or_else(|e| {
        eprintln!(
            "could not establish the read-only session on {redacted}: {}",
            pg_error(&e)
        );
        process::exit(exit_code::CONFIG_ERROR);
    });

    if ctx.explicit_format && ctx.format != OutputFormat::Ndjson {
        ctx.warn_ignored("hunt run", "hunt events are always NDJSON");
    }

    let mut sink = open_sink(output);
    let started = Instant::now();
    let mut total_rows = 0usize;
    let mut any_truncated = false;
    let mut warned_types: HashSet<(String, String)> = HashSet::new();
    let mut noted_conflict = false;

    for query in &plan.queries {
        let rows = client
            .query_raw(&query.sql, Vec::<String>::new())
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "hunt query for rule '{}' failed on {redacted}: {}",
                    query.rule_title,
                    pg_error(&e)
                );
                process::exit(exit_code::CONFIG_ERROR);
            });
        tokio::pin!(rows);

        let mut rule_rows = 0usize;
        while let Some(row) = rows.next().await {
            let row = row.unwrap_or_else(|e| {
                eprintln!(
                    "hunt stream for rule '{}' failed: {}",
                    query.rule_title,
                    pg_error(&e)
                );
                process::exit(exit_code::CONFIG_ERROR);
            });
            let decoded = decode_row(&row);
            warn_unmapped_once(&decoded, &mut warned_types);
            let event = match reshape_row(&decoded, plan, &mut noted_conflict) {
                Ok(event) => event,
                Err(msg) => {
                    eprintln!(
                        "cannot reshape a row for rule '{}': {msg}",
                        query.rule_title
                    );
                    process::exit(exit_code::CONFIG_ERROR);
                }
            };
            write_event(&mut sink, &event);
            rule_rows += 1;
        }

        let truncated = plan.limit != 0 && rule_rows == plan.limit;
        any_truncated |= truncated;
        total_rows += rule_rows;
        if ctx.show_progress() {
            eprintln!(
                "rule '{}': {rule_rows} row(s){}",
                query.rule_title,
                if truncated {
                    format!(", reached --limit {} (output may be truncated)", plan.limit)
                } else {
                    String::new()
                }
            );
        }
    }

    if ctx.show_stats() {
        eprintln!(
            "hunted {total_rows} row(s) from {} rule(s) in {:.2?} against {redacted}{}",
            plan.queries.len(),
            started.elapsed(),
            if any_truncated { " (truncated)" } else { "" },
        );
    }
}

/// Render a tokio-postgres error with the server's message when present:
/// the bare `Display` of a database error is just "db error", while the
/// wrapped `DbError` carries the SQLSTATE detail ("ERROR: cannot execute
/// DELETE in a read-only transaction").
fn pg_error(e: &tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|db| db.to_string())
        .unwrap_or_else(|| e.to_string())
}

/// Decode one wire row into the reshaper's column list.
fn decode_row(row: &Row) -> DecodedRow {
    row.columns()
        .iter()
        .enumerate()
        .map(|(i, c)| DecodedColumn {
            name: c.name().to_string(),
            value: decode_value(row, i, c.type_()),
        })
        .collect()
}

/// Typed decode with a NULL-first read. A decode failure on a *known* type
/// (e.g. a timestamp outside chrono's range) degrades to `Unmapped` so the
/// warning names the column and type instead of aborting the hunt.
fn decode<T>(row: &Row, idx: usize, ty: &Type, map: impl FnOnce(T) -> SqlValue) -> SqlValue
where
    T: for<'a> tokio_postgres::types::FromSql<'a>,
{
    match row.try_get::<usize, Option<T>>(idx) {
        Ok(Some(v)) => map(v),
        Ok(None) => SqlValue::Null,
        Err(_) => SqlValue::Unmapped {
            type_name: ty.name().to_string(),
        },
    }
}

fn decode_value(row: &Row, idx: usize, ty: &Type) -> SqlValue {
    match *ty {
        Type::BOOL => decode(row, idx, ty, SqlValue::Bool),
        Type::INT2 => decode(row, idx, ty, |v: i16| SqlValue::Int(i64::from(v))),
        Type::INT4 => decode(row, idx, ty, |v: i32| SqlValue::Int(i64::from(v))),
        Type::INT8 => decode(row, idx, ty, SqlValue::Int),
        Type::FLOAT4 => decode(row, idx, ty, |v: f32| SqlValue::Float(f64::from(v))),
        Type::FLOAT8 => decode(row, idx, ty, SqlValue::Float),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            decode(row, idx, ty, SqlValue::Text)
        }
        Type::TIMESTAMPTZ => decode(row, idx, ty, SqlValue::Timestamp),
        // A bare TIMESTAMP carries no zone; read it as UTC.
        Type::TIMESTAMP => decode(row, idx, ty, |v: NaiveDateTime| {
            SqlValue::Timestamp(v.and_utc())
        }),
        Type::JSON | Type::JSONB => decode(row, idx, ty, SqlValue::Json),
        Type::UUID => decode(row, idx, ty, |v: uuid::Uuid| SqlValue::Text(v.to_string())),
        Type::INET => decode(row, idx, ty, |v: std::net::IpAddr| {
            SqlValue::Text(v.to_string())
        }),
        _ => SqlValue::Unmapped {
            type_name: ty.name().to_string(),
        },
    }
}

/// Warn once per (column, type) pair about columns dropped as undecodable.
fn warn_unmapped_once(row: &DecodedRow, warned: &mut HashSet<(String, String)>) {
    for col in row {
        if let SqlValue::Unmapped { type_name } = &col.value
            && warned.insert((col.name.clone(), type_name.clone()))
        {
            eprintln!(
                "warning: column '{}' has unmapped type '{}'; the column is skipped",
                col.name, type_name
            );
        }
    }
}

fn reshape_row(
    row: &DecodedRow,
    plan: &HuntPlan,
    noted_conflict: &mut bool,
) -> Result<serde_json::Value, String> {
    match &plan.json_field {
        Some(json_field) => {
            let (event, notes) = reshape_jsonb(row, json_field, &plan.timestamp_field)?;
            for note in notes {
                match note {
                    ReshapeNote::TimestampConflict { column } if !*noted_conflict => {
                        *noted_conflict = true;
                        eprintln!(
                            "note: event bodies already carry '{column}'; the body's value wins \
                             over the timestamp column"
                        );
                    }
                    _ => {}
                }
            }
            Ok(event)
        }
        None => Ok(reshape_flat(row)),
    }
}

/// rustls with the system root store and the workspace's aws-lc-rs provider.
/// `sslmode` handling lives in tokio-postgres, so one connector covers
/// disable/prefer/require.
fn rustls_connector() -> tokio_postgres_rustls::MakeRustlsConnect {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        eprintln!(
            "warning: no usable system root certificates ({ignored} ignored); \
             TLS verification will fail unless the server uses a publicly trusted chain"
        );
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| {
            eprintln!("failed to configure TLS: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        })
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_postgres_rustls::MakeRustlsConnect::new(config)
}

/// Render the connection target for logs and errors without ever including
/// the password: rebuilt from the parsed config's non-secret fields.
fn redacted_dsn(config: &tokio_postgres::Config) -> String {
    let user = config.get_user().unwrap_or("postgres");
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(name)) => name.clone(),
        Some(tokio_postgres::config::Host::Unix(path)) => path.display().to_string(),
        None => "localhost".to_string(),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let db = config.get_dbname().unwrap_or(user);
    format!("postgres://{user}@{host}:{port}/{db}")
}

fn open_sink(output: Option<&std::path::Path>) -> Box<dyn Write> {
    match output {
        Some(path) => {
            let file = std::fs::File::create(path).unwrap_or_else(|e| {
                eprintln!("Error writing to {}: {e}", path.display());
                process::exit(exit_code::CONFIG_ERROR);
            });
            Box::new(file)
        }
        None => Box::new(std::io::stdout().lock()),
    }
}

/// One raw JSON event object per line; nothing else ever lands on stdout.
fn write_event(sink: &mut dyn Write, event: &serde_json::Value) {
    let mut write = || -> std::io::Result<()> {
        serde_json::to_writer(&mut *sink, event)?;
        sink.write_all(b"\n")
    };
    if let Err(e) = write() {
        eprintln!("failed to write hunt output: {e}");
        process::exit(exit_code::CONFIG_ERROR);
    }
}
