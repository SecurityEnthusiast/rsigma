//! The `hunt` command group: execute converted detection rules against a
//! PostgreSQL/TimescaleDB archive and stream the matching rows back as
//! exemplar-shaped NDJSON events consumable by `rule draft`, `rule tune`,
//! `rule test`, and `rule backtest`.
//!
//! rsigma is a read-only client of stores it already generates queries for;
//! it does not store or search logs itself. Query construction (`query`) is
//! always compiled so `--emit sql` works in every build; row reshaping and
//! execution ship with the `hunt-postgres` feature, since their only
//! consumer is the gated database client.

pub(crate) mod query;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand, ValueEnum};

use crate::exit_code;
use crate::output::OutputCtx;
use query::{DEFAULT_LIMIT, HuntQueryError, HuntWindow};

/// What `hunt run` produces.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum EmitMode {
    /// Stream matching rows as exemplar-shaped NDJSON events.
    #[default]
    Events,
    /// Print the wrapped SQL and exit without connecting.
    Sql,
}

#[derive(Args, Debug)]
pub(crate) struct HuntRunArgs {
    /// Sigma rule file(s) or director(ies) to hunt with. Repeatable.
    #[arg(short = 'r', long = "rules", value_name = "PATH", num_args = 1.., required = true)]
    pub rules: Vec<PathBuf>,

    /// Hunt target. Only `postgres` is executable; every other target stays
    /// convert-only.
    #[arg(short, long)]
    pub target: String,

    /// PostgreSQL connection string. May also come from the
    /// RSIGMA_HUNT_DSN environment variable. Required for `--emit events`.
    #[arg(long, env = "RSIGMA_HUNT_DSN", hide_env_values = true)]
    pub dsn: Option<String>,

    /// Processing pipeline(s) (repeatable). Accepts builtin names
    /// (ecs_windows, sysmon) or YAML file paths.
    #[arg(short = 'p', long = "pipeline")]
    pub pipeline: Vec<PathBuf>,

    /// Backend options as key=value pairs (repeatable): table, schema,
    /// json_field, timestamp_field, ...
    #[arg(short = 'O', long = "option")]
    pub backend_options: Vec<String>,

    /// Window start: an RFC 3339 instant or a duration relative to now
    /// (e.g. 30m, 12h, 7d).
    #[arg(long)]
    pub since: Option<String>,

    /// Window end (exclusive): an RFC 3339 instant or a duration relative to
    /// now.
    #[arg(long)]
    pub until: Option<String>,

    /// Maximum rows per rule (0 = unbounded). Hitting the limit is reported
    /// on stderr so a truncated hunt is never mistaken for a complete one.
    #[arg(long, default_value_t = DEFAULT_LIMIT)]
    pub limit: usize,

    /// Server-side statement timeout for the hunt session.
    #[arg(long, default_value = "60s")]
    pub timeout: String,

    /// What to produce: `events` (NDJSON, the default) or `sql` (print the
    /// wrapped queries without connecting; works in every build).
    #[arg(long, value_enum, default_value = "events")]
    pub emit: EmitMode,

    /// Output file (default: stdout).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum HuntCommands {
    /// Convert detection rules and hunt matching rows in a PostgreSQL archive
    Run(HuntRunArgs),
}

pub(crate) fn dispatch_hunt(cmd: HuntCommands, ctx: OutputCtx) {
    match cmd {
        HuntCommands::Run(args) => cmd_hunt_run(args, &ctx),
    }
}

/// Map a query-build failure to its house exit code: bad flags and options
/// are config errors; rule-side failures are rule errors.
fn query_error_exit_code(err: &HuntQueryError) -> i32 {
    match err {
        HuntQueryError::InvalidIdentifier { .. }
        | HuntQueryError::EmptyWindow { .. }
        | HuntQueryError::InvalidTimeBound { .. } => exit_code::CONFIG_ERROR,
        HuntQueryError::CorrelationRejected { .. }
        | HuntQueryError::Conversion(_)
        | HuntQueryError::RuleFailures(_)
        | HuntQueryError::NonSelectOutput { .. } => exit_code::RULE_ERROR,
    }
}

fn cmd_hunt_run(args: HuntRunArgs, ctx: &OutputCtx) {
    if !matches!(args.target.as_str(), "postgres" | "postgresql" | "pg") {
        eprintln!(
            "hunt run supports --target postgres only; '{}' is convert-only. \
             Convert with `rsigma backend convert -t {}` and run the query in the \
             target's own tooling.",
            args.target, args.target
        );
        process::exit(exit_code::CONFIG_ERROR);
    }

    let now = chrono::Utc::now();
    let parse_bound = |value: &str| {
        query::parse_time_bound(value, now).unwrap_or_else(|e| {
            eprintln!("{}", e.message());
            process::exit(exit_code::CONFIG_ERROR);
        })
    };
    let window = HuntWindow {
        since: args.since.as_deref().map(&parse_bound),
        until: args.until.as_deref().map(&parse_bound),
    };

    let options: HashMap<String, String> = args
        .backend_options
        .iter()
        .filter_map(|opt| {
            opt.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    let plan = query::build_hunt_plan(&args.rules, &args.pipeline, &options, &window, args.limit)
        .unwrap_or_else(|e| {
            let code = query_error_exit_code(&e);
            eprintln!("{}", e.message());
            process::exit(code);
        });

    match args.emit {
        EmitMode::Sql => emit_sql(&plan, args.output.as_deref()),
        EmitMode::Events => run_events(args, plan, ctx),
    }
}

/// `--emit sql`: print each wrapped query, attributed by comment headers so
/// the output stays loadable in psql, and exit without connecting. The
/// effective window/JSONB options are printed once at the top: they are the
/// settings a reviewer needs to eyeball the predicates.
fn emit_sql(plan: &query::HuntPlan, output: Option<&std::path::Path>) {
    let mut rendered = format!("-- timestamp_field: {}\n", plan.timestamp_field);
    if let Some(json_field) = &plan.json_field {
        rendered.push_str(&format!("-- json_field: {json_field}\n"));
    }
    for (i, q) in plan.queries.iter().enumerate() {
        if i > 0 {
            rendered.push('\n');
        }
        let id = q
            .rule_id
            .as_deref()
            .map(|id| format!(" (id: {id})"))
            .unwrap_or_default();
        rendered.push_str(&format!("-- rule: {}{}\n{};\n", q.rule_title, id, q.sql));
    }
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &rendered) {
                eprintln!("Error writing to {}: {e}", path.display());
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
        None => print!("{rendered}"),
    }
}

/// `--emit events` without the executor compiled in: fail with a pointed
/// message. The executor ships with the `hunt-postgres` feature.
fn run_events(args: HuntRunArgs, plan: query::HuntPlan, _ctx: &OutputCtx) {
    // Parsed for fail-fast validation even on the disabled path, so flag
    // errors look identical in every build.
    let _timeout = humantime::parse_duration(&args.timeout).unwrap_or_else(|_| {
        eprintln!(
            "invalid --timeout '{}': expected a duration like 30s, 5m",
            args.timeout
        );
        process::exit(exit_code::CONFIG_ERROR);
    });
    let _ = &plan;
    eprintln!(
        "this binary was built without the 'hunt-postgres' feature; rebuild with \
         --features hunt-postgres or use a released binary. \
         (--emit sql works in every build.)"
    );
    process::exit(exit_code::CONFIG_ERROR);
}
