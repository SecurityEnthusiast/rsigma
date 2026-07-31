//! `rsigma rule tune`: propose a verified Sigma filter from FP/TP exemplars.

use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::{TuneConfig, TuneReport, apply_pipelines, tune_rule};

use super::draft::{EmitMode, read_events};
use crate::output::{OutputCtx, OutputFormat, render_json};

/// Arguments for `rsigma rule tune`.
#[derive(Args, Debug)]
pub(crate) struct TuneArgs {
    /// Path to a Sigma rule file or directory.
    #[arg(short, long)]
    pub rules: PathBuf,

    /// Target rule id, falling back to an exact title.
    /// Required when the ruleset contains more than one detection rule.
    #[arg(long, value_name = "ID|TITLE")]
    pub rule: Option<String>,

    /// False-positive events as inline JSON or @path to NDJSON/EVTX.
    /// Reads NDJSON from stdin when omitted.
    #[arg(long, value_name = "JSON|@PATH")]
    pub fp: Option<String>,

    /// True-positive events as inline JSON or @path to NDJSON/EVTX.
    #[arg(long, value_name = "JSON|@PATH")]
    pub tp: String,

    /// Processing pipeline(s) applied before tuning and verification.
    #[arg(short = 'p', long = "pipeline", value_name = "PATH|NAME")]
    pub pipelines: Vec<PathBuf>,

    /// Maximum fields in one filter selection.
    #[arg(long, default_value_t = 4)]
    pub max_fields: usize,

    /// Maximum exact values emitted as one OR list.
    #[arg(long, default_value_t = 8)]
    pub max_value_cardinality: usize,

    /// Minimum events required in a derived FP cluster.
    #[arg(long, default_value_t = 2)]
    pub min_cluster_support: usize,

    /// Maximum selections emitted in one filter rule.
    #[arg(long, default_value_t = 5)]
    pub max_clusters: usize,

    /// Emit verified clean clusters even if some FPs remain uncovered.
    #[arg(long)]
    pub allow_partial: bool,

    /// What to print: filter YAML (default) or the rationale report.
    #[arg(long, value_enum, default_value_t = EmitMode::Yaml)]
    pub emit: EmitMode,
}

pub(crate) fn cmd_tune(args: TuneArgs, ctx: OutputCtx) {
    let false_positives = read_corpus(args.fp.as_deref(), "false-positive");
    let true_positives = read_corpus(Some(args.tp.as_str()), "true-positive");

    let collection = crate::load_collection(&args.rules);
    let mut rule = match select_rule(&collection.rules, args.rule.as_deref()) {
        Ok(rule) => rule.clone(),
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    let pipelines = crate::load_pipelines(&args.pipelines);
    if !pipelines.is_empty()
        && let Err(error) = apply_pipelines(&pipelines, &mut rule)
    {
        eprintln!("error applying pipeline to {:?}: {error}", rule.title);
        process::exit(crate::exit_code::RULE_ERROR);
    }

    let config = TuneConfig {
        max_fields: args.max_fields,
        max_value_cardinality: args.max_value_cardinality,
        min_cluster_support: args.min_cluster_support,
        max_clusters: args.max_clusters,
        allow_partial: args.allow_partial,
        filter_id: Some(uuid::Uuid::new_v4().to_string()),
        ..TuneConfig::default()
    };
    let report = match tune_rule(
        &rule,
        &false_positives.events,
        &true_positives.events,
        &config,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error tuning rule: {error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    match args.emit {
        EmitMode::Yaml => {
            if ctx.explicit_format {
                ctx.warn_unsupported("rule tune", "Sigma YAML");
            }
            print!("{}", report.filter_yaml);
            if ctx.show_stats() {
                print_summary_stderr(&report);
            }
        }
        EmitMode::Report => render_report(&report, &ctx),
    }
}

fn read_corpus(spec: Option<&str>, label: &str) -> super::draft::Corpus {
    let corpus = match read_events(spec, label) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("{error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };
    if corpus.parse_errors > 0 {
        eprintln!(
            "warning: {} {label} line(s) failed to parse as JSON and were skipped",
            corpus.parse_errors
        );
    }
    corpus
}

fn select_rule<'a>(
    rules: &'a [rsigma_parser::SigmaRule],
    selector: Option<&str>,
) -> Result<&'a rsigma_parser::SigmaRule, String> {
    if rules.is_empty() {
        return Err("no detection rules found".to_string());
    }
    let Some(selector) = selector else {
        return if rules.len() == 1 {
            Ok(&rules[0])
        } else {
            Err(format!(
                "ruleset contains {} detection rules; pass --rule <id-or-title>",
                rules.len()
            ))
        };
    };

    let matches: Vec<_> = rules
        .iter()
        .filter(|rule| rule.id.as_deref() == Some(selector) || rule.title.as_str() == selector)
        .collect();
    match matches.as_slice() {
        [rule] => Ok(*rule),
        [] => Err(format!("no detection rule matched {selector:?}")),
        _ => Err(format!(
            "{} detection rules matched {selector:?}; use a unique rule id",
            matches.len()
        )),
    }
}

fn render_report(report: &TuneReport, ctx: &OutputCtx) {
    match ctx.format {
        OutputFormat::Json => render_json(report, true),
        OutputFormat::Ndjson => render_json(report, false),
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            if !matches!(ctx.format, OutputFormat::Table) {
                ctx.warn_unsupported("rule tune --emit report", "human report");
            }
            println!(
                "Suppressed {}/{} false positives; protected {}/{} true positives",
                report.verification.false_positives_before
                    - report.verification.false_positives_after,
                report.verification.false_positives_before,
                report.verification.true_positives_after,
                report.verification.true_positives_before
            );
            println!();
            println!("FIELD\tSCORE\tSTABILITY\tTP HITS\tDISPOSITION\tVALUES");
            for field in &report.fields {
                println!(
                    "{}\t{:.3}\t{}\t{}\t{:?}\t{}",
                    field.field,
                    field.score,
                    field.stability,
                    field.true_positive_hits,
                    field.disposition,
                    field.values.join(", ")
                );
            }
            println!();
            println!("# Filter rule");
            print!("{}", report.filter_yaml);
        }
    }
}

fn print_summary_stderr(report: &TuneReport) {
    eprintln!(
        "suppressed {}/{} false positives; protected {}/{} true positives",
        report.verification.false_positives_before - report.verification.false_positives_after,
        report.verification.false_positives_before,
        report.verification.true_positives_after,
        report.verification.true_positives_before
    );
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_rules(yaml: &str) -> Vec<rsigma_parser::SigmaRule> {
        rsigma_parser::parse_sigma_yaml(yaml).unwrap().rules
    }

    #[test]
    fn selector_requires_explicit_target_for_multiple_rules() {
        let rules = parsed_rules(
            r#"
title: One
id: one
logsource:
    category: test
detection:
    selection:
        value: one
    condition: selection
---
title: Two
id: two
logsource:
    category: test
detection:
    selection:
        value: two
    condition: selection
"#,
        );
        assert!(select_rule(&rules, None).is_err());
        assert_eq!(select_rule(&rules, Some("two")).unwrap().title, "Two");
    }
}
