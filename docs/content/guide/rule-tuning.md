# Rule Tuning

`rsigma rule tune` turns analyst-confirmed false positives into a reviewable Sigma filter rule while protecting a required set of known true positives. The command proposes a separate filter artifact; it never rewrites the detection rule and never merges a change.

## Workflow

```bash
# Collect events that fired the same target rule and classify them.
rsigma rule tune -r rules/ --rule <RULE_ID> --fp @false-positives.ndjson --tp @true-positives.ndjson > tuning-filter.yml

# Review the rationale and machine-readable verification.
rsigma rule tune -r rules/ --rule <RULE_ID> --fp @false-positives.ndjson --tp @true-positives.ndjson --expectations expectations.yml --emit report --output-format json

# Confirm the artifact after any manual edits.
rsigma rule lint tuning-filter.yml
rsigma rule backtest -r rules-with-filter/ --corpus regression-events/
```

The true-positive set is mandatory. A suppression proposal without a do-not-break corpus can reduce noise by silently deleting useful coverage, so the command treats an empty TP set as an error.

## Closed verification

Tuning runs the target through the real evaluator twice:

1. The target rule is compiled without a filter. Every supplied FP and TP must fire, otherwise the command returns the non-firing exemplar indexes as a labeling error.
2. The target and proposed filter are added to one `SigmaCollection`. `Engine::add_collection` applies the filter exactly as production loading does. Every TP must still fire and every covered FP must stop firing.

This catches polarity errors, Sigma wildcard escaping, modifier semantics, pipeline field mappings, filter targeting, and logsource compatibility through the production code path rather than a second approximation.

When `--expectations` is supplied, report mode also lists the target's existing backtest bounds and appends a paste-ready fragment for the FP and TP corpus filenames. The fragment pins the post-filter FP count and requires at least the verified TP count, so the tuning change can carry its own regression evidence into CI.

## Why the condition is negated

The Sigma filter parser stores the condition under the `filter:` section, and RSigma ANDs that condition into the target rule exactly as written. There is no implicit negation. A filter intended to suppress `selection` must therefore emit:

```yaml
filter:
    rules:
        - <RULE_ID>
    selection:
        User: svc_backup
    condition: not selection
```

Writing `condition: selection` would invert the intent and narrow the target so it fired only on the benign pattern.

## Contrastive field selection

The profiler shares rule drafting's typed values, volatility detection, pattern inference, wildcard escaping, and YAML writer. It ranks fields that are stable across FPs and rare across TPs. Any candidate or conjunction that suppresses a TP is rejected.

Exact value sets may contain up to eight values by default because benign service-account or host allowlists commonly exceed the drafting default of four. String values above that limit may still become a readable prefix, suffix, or token form. Regex synthesis is intentionally excluded.

## Disjoint benign patterns

When one conjunction cannot separate the entire FP set, tuning may partition it into supported clusters and emit multiple selections:

```yaml
filter:
    rules:
        - <RULE_ID>
    selection:
        User: svc_backup
        Image|startswith: 'C:\Program Files\Veeam\'
    selection_2:
        User: svc_acronis
        Image|startswith: 'D:\Tools\Acronis\'
    condition: not (selection or selection_2)
```

Each cluster must contain at least two FP exemplars by default, which prevents a unique event from being memorized as a tuning pattern. One filter contains at most five clusters by default so the proposal remains reviewable. `--allow-partial` may emit the verified clusters and identify uncovered FP indexes, but no option permits suppressing a TP.

## Pipelines and logsource

Pass the same `-p/--pipeline` values used by evaluation or deployment. The target rule is transformed before tuning, so emitted field names and the copied logsource match the compiled detection. Copying the target's post-pipeline logsource keeps the filter lint-clean and guarantees `filter_logsource_contains` cannot skip it.

## Human review boundary

Treat the output as a proposed code change with regression evidence. Review whether an attacker could deliberately satisfy the benign pattern, prefer stable identity/context pairs over broad paths or networks, document the operational reason for the exception, and rerun the report against an expanded TP corpus before merging.

## See also

- [`rule tune` reference](../cli/rule/tune.md) for flags and exit codes.
- [Drafting Rules from Logs](rule-drafting.md) for creating new detection rules from positive exemplars.
- [Triage Feedback Loop](triage-feedback.md) for the analyst dispositions that identify noisy rules.
- [Detection Scorecard](detection-scorecard.md) for per-rule tune recommendations.
