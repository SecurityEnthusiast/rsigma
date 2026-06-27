# Rule Hygiene

Detection programs accumulate rules faster than they retire them. The 2026 detection-engineering maturity guidance makes retirement a first-class discipline: every detection needs an owner, a last-fired date, and a deletion bar, and without a forcing function the rule catalog grows until the team drowns in unowned, untuned, never-firing rules. `rsigma rule hygiene` is that forcing function. It assembles the signals rsigma already produces into one report of retirement and clean-up candidates, then lets CI gate on them.

This guide covers which input feeds which signal, how to read the report, and how to wire `--fail-on` into CI.

## What it flags

The report carries seven signals in one pass:

- **silent**: a rule with no matches over the metrics window, or one whose last-fired is older than the silence threshold. A rule that has not fired in a year is a deletion candidate.
- **noisy**: a fire-count outlier. A rule that fires far more than its peers is either too broad or firing only on false positives.
- **untagged**: a rule with no `attack.*` ATT&CK tag. This is the same untagged set [`rule coverage`](../cli/rule/coverage.md) reports, rolled into the hygiene verdict rather than recomputed.
- **no-owner**: a rule with no owner, so no one is accountable for tuning or retiring it.
- **incomplete-ads**: a `stable` detection rule missing required [ADS](detection-strategy.md) sections, so it ships to production without a documented strategy.
- **broken-fields**: a rule whose referenced fields are never seen in the data, so it cannot fire no matter what.
- **deprecated**: a rule already marked `deprecated`/`unsupported`, or one whose `modified` date is older than the staleness threshold.

## Which input feeds which signal

| You have | Pass | You unlock |
|----------|------|------------|
| Just the rules | `--rules <PATH>` | untagged, no-owner, incomplete-ads, deprecated |
| A Prometheus scrape or endpoint | `--metrics <FILE\|URL>` | silent, noisy |
| A field-observability snapshot | `--fields <FILE>` | broken-fields |

The static signals need only `--rules`, so the cheapest useful run is one that flags untagged, unowned, undocumented, and deprecated rules with no infrastructure at all. Layering in `--metrics` and `--fields` adds the data-driven signals.

### Production fire volume

`--metrics` reads the two per-rule counter families (`rsigma_detection_matches_by_rule_total` and `rsigma_correlation_matches_by_rule_total`, joined by `rule_title`). Point it at a saved `/metrics` scrape or a live endpoint:

```bash
rsigma rule hygiene --rules ./rules --metrics http://localhost:9090/metrics
```

A point-in-time scrape establishes silence by absence: a rule whose counter has never registered has never fired in that process. For a true last-fired timestamp, point `--metrics` at a Prometheus query-API base and pass `--metrics-window`:

```bash
rsigma rule hygiene --rules ./rules \
    --metrics http://prometheus:9090 --metrics-window 90d \
    --silent-threshold 90d
```

### Broken field coverage

`--fields` consumes a [field-observability](observability.md) snapshot: the daemon's `/api/v1/fields` payload, or the report from `rsigma engine eval --observe-fields`. Its `missing` set is the rule-referenced fields that no event ever carried. Hygiene rolls that up per rule: a rule whose every referenced field is unseen is flagged `broken-fields`. Generate the snapshot from the same rule set so the field names line up.

## Reading the report

On a TTY the default `table` view prints a per-signal summary and the flagged rules:

```text
Rules: 200 (180 detection, 20 correlation) | Flagged: 37 | Sources: rules + metrics + fields
  12 silent  3 noisy  6 untagged  9 no-owner  4 incomplete-ads  1 broken-fields  2 deprecated
```

For machine consumption, `--output-format json` emits the full document (a `summary`, a `rules[]` array of flagged verdicts, and a per-signal list for each signal), and `ndjson`/`csv`/`tsv` emit one row per flagged rule. `--report <FILE>` always writes the full JSON document regardless of the chosen output format, so a CI job can both print a table and archive the JSON.

## Gating CI

`--fail-on` is repeatable and exits `1` when a selected condition matches at least one rule. Gate on the conditions your program treats as blocking:

```bash
# Fail the build if any rule has been silent past the threshold or has no owner.
rsigma rule hygiene --rules ./rules --metrics metrics.txt \
    --silent-threshold 365d \
    --fail-on silent --fail-on no-owner
```

Use `--fail-on any` to fail on any finding, or set the policy in the config file under `hygiene.fail_on`. The exit codes follow the [house convention](../reference/exit-codes.md): `0` clean (or report-only), `1` a selected condition matched, `2` the rules could not load, `3` a bad flag or an unreadable metrics/fields input.

## Relationship to the scorecard

Hygiene is the static, coverage-structural half of the retirement story: it surfaces candidates from owner, tag, status, silence, noise, and field-coverage signals, and stops at flagging them. The [Detection Scorecard](detection-scorecard.md) is the quantitative keep/tune/retire verdict that fuses a backtest and coverage report (and optionally the same Prometheus volume) into a precision-driven decision. Run hygiene for the cheap, no-backtest sweep; run the scorecard when you have the backtest and coverage reports and want the graded verdict.

## See also

- [`rule hygiene` reference](../cli/rule/hygiene.md) for the full flag and exit-code tables.
- [Detection Scorecard](detection-scorecard.md) for the quantitative verdict.
- [Observability](observability.md) for generating the field-observability snapshot.
- [CI/CD](ci-cd.md) for wiring hygiene into a pipeline alongside lint, validate, and backtest.
