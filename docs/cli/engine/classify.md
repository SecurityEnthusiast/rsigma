# `rsigma engine classify`

Report which schema each event matches, recognized from the event's content.

## Synopsis

```text
rsigma engine classify [OPTIONS]
```

## Description

Reads events and prints, per event, the schema RSigma recognizes it as (or `unknown`), plus a per-schema summary. Recognition is content-based: it keys off marker fields and values, not the wire format, so it tells ECS, flat Sysmon, rendered Windows Event Log, CEF, and OCSF apart even when they all arrive as JSON.

This is a diagnostic for understanding a mixed dataset and for tuning schema signatures before wiring them into a pipeline. It does not load rules or evaluate detections. For the live equivalent on a running daemon, see the `GET /api/v1/schemas` endpoint and the `--observe-schemas` flag on [`engine daemon`](daemon.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --event <EVENT>` | stdin | A single event as a JSON string, or `@path` to read NDJSON from a file. Without this flag, reads NDJSON from stdin. |
| `--schema-config <PATH>` | unset | YAML file of user-defined schema signatures, merged over the built-ins. |

The global [`--output-format`](../../reference/output.md) flag selects `json`, `ndjson`, `table`, `csv`, or `tsv`.

## Built-in schemas

| Schema | Recognized by |
|--------|---------------|
| `ecs` | `ecs.version` present |
| `ocsf` | `class_uid` and `metadata.version` present |
| `windows_eventlog` | `Event.System.EventID` or `Event.System.Provider` present (rendered EVTX) |
| `sysmon` | the Sysmon channel/provider, or flat `EventID` + `ProcessGuid` + `Image`/`CommandLine` |
| `cef` | `deviceVendor`, `deviceProduct`, and `signatureId` present |
| `generic_json` | any structured event matching no specific schema |

An event that matches no signature (for example a field-less object or non-JSON line) is reported as `unknown`, which is the signal for an unsupported schema.

## User signatures

`--schema-config` loads additional signatures. Each is a name, an optional `specificity` (higher wins on overlap; default 50), and a `match` list of conditions that must all hold:

```yaml
schemas:
  - name: my_vendor
    specificity: 70
    match:
      - field_present: vendor.product
      - equals:
          field: event_type
          value: alert
      - any_of: [user.name, user.id]
      - matches:
          field: message
          value: "^CEF:\\d"
      - field_absent: ecs.version
```

## Examples

Classify a single event:

```bash
rsigma engine classify -e '{"ecs.version":"8.11.0","process":{"command_line":"whoami"}}'
```

Classify an NDJSON stream and see the per-schema table:

```bash
cat events.ndjson | rsigma engine classify --output-format table
```

Tune custom signatures against a sample:

```bash
rsigma engine classify -e @sample.ndjson --schema-config schemas.yml --output-format json
```

## Output

The structured report carries a `summary` (`total_events`, `classified`, `unknown`, `parse_errors`, and `by_schema` counts) and an `events` array with the `index`, `schema`, and `specificity` of each event. In `table`, `csv`, and `tsv` formats the per-event rows go to stdout and the summary line to stderr.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Bad input (invalid inline JSON, unreadable file) |
| `3` | Bad schema config |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.
