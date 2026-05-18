# `rsigma backend formats`

List the output formats supported by one backend.

## Synopsis

```text
rsigma backend formats [OPTIONS] <TARGET>
```

## Description

Prints every `-f <FORMAT>` value [`backend convert`](convert.md) accepts for the given backend. Each entry has a short description.

## Flags

| Flag | Description |
|------|-------------|
| `<TARGET>` | Backend name (e.g. `postgres`, `lynxdb`, `test`). Use [`backend targets`](targets.md) for the list. |

## Examples

### PostgreSQL formats

```bash
rsigma backend formats postgres
```

```text
Available formats for 'postgres':
  default               - Plain PostgreSQL SQL
  view                  - CREATE OR REPLACE VIEW for each rule
  timescaledb           - TimescaleDB-optimized queries with time_bucket()
  continuous_aggregate  - CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)
  sliding_window        - Correlation queries using window functions for per-row sliding detection
```

### LynxDB formats

```bash
rsigma backend formats lynxdb
```

```text
Available formats for 'lynxdb':
  default  - Full SPL2 with `FROM <index> | search ...`
  minimal  - Just the search expression, for use as a REST API `q=` parameter
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Backend listed. |
| `3` | Unknown backend name. |

## See also

- [`backend convert`](convert.md) for using a format.
- [`backend targets`](targets.md) for the list of backends.
- [Rule Conversion](../../guide/rule-conversion.md) for when to pick each format.
