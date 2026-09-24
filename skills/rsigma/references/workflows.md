# Workflows

Command names and the convert split are in [SKILL.md](../SKILL.md). This page is the loop. Flag tables are on [rsigma.io](https://rsigma.io/), not here.

Author Sigma YAML with the sigma-rules skill. Use the steps below to check and run it.

## Write, lint, evaluate, convert

Prefer the MCP tool when `rsigma mcp serve` is connected. Otherwise use the CLI.

1. **Draft.** Hand-authored YAML (sigma-rules), `rule draft` from exemplar events, or `reverse_convert` / `rule reverse` from a Lucene query. Call `parse_rule` (or `rule parse`) and stop if the structure is invalid.
2. **Lint.** `lint_rules` or `rule lint`. Each finding has a rule id and a `fixable` flag. Apply a known-safe fix with `fix_rules` or `rule lint --fix`. Rewrite the rest by hand. Do not treat a count of checks as stable. The catalogue is the [linting guide](https://rsigma.io/guide/linting-rules/).
3. **Evaluate.** `evaluate_events` or `engine eval` against a few positive and negative events. `match_detail` of `summary` or `full` explains why an event matched. When the events live on the rule as `rsigma.exemplars`, `test_exemplars` or `rule test` is the closed runner.
4. **Tune.** For a noisy rule, `tune_rules` or `rule tune` with classified false positives and a true-positive set that must still fire. Review the returned filter before writing it.
5. **Validate.** `validate_rules` or `rule validate` on the set, with pipelines when the rules depend on them.
6. **Convert.** `convert_rules` or `backend convert` to the deployment target. Native targets run in-process. Other targets need sigma-cli, and on MCP they also need `--allow-sigma-cli`.

Guide: [MCP server](https://rsigma.io/guide/mcp-server/).

## Eval versus daemon

`engine eval` reads a fixed input and exits. Use it to test a rule.

`engine daemon` stays up, reloads rules, and exposes health and metrics. Use it when events are a stream (stdin, HTTP, NATS, OTLP). It needs the `daemon` feature. Release binaries include it.

Guide: [Evaluating rules](https://rsigma.io/guide/evaluating-rules/), [Streaming detection](https://rsigma.io/guide/streaming-detection/).

## Draft versus a rule you already know

`rule draft` proposes a detection from exemplar events, optionally contrasted with a baseline. `rule draft --groups` proposes a temporal correlation from grouped, timed exemplars. Use draft when the user has events and wants a rule inferred from them.

When the user describes the behavior in words, write the YAML with sigma-rules. Then run the loop above. Do not ask draft to invent a rule from a sentence.

Guide: [Rule drafting](https://rsigma.io/guide/rule-drafting/).

## Convert

```bash
rsigma backend targets
rsigma backend convert -t postgres rules/
rsigma backend convert -t splunk rules/
```

`backend targets` is the list of compiled-in backends. `postgres`, `lynxdb`, `fibratus`, and `test` are native. Any other installed sigma-cli target is delegated. If delegation fails, the error is that `sigma` is missing, not that the target name is wrong.

Reference: [backend convert](https://rsigma.io/cli/backend/convert/).
