# `rsigma backend convert`

Convert Sigma rules into backend-native queries (SQL, SPL, …).

## Synopsis

```text
rsigma backend convert [OPTIONS] --target <TARGET> [RULES]...
```

## Description

Reads one or more rule files (or a directory) and emits backend-native query strings, one per rule. Output goes to stdout by default; use `-o` to write to a file. Use [`backend targets`](targets.md) to list available backends and [`backend formats`](formats.md) to list the output formats supported by a specific backend.

For narrative coverage, including the PostgreSQL and LynxDB workflows, see [Rule Conversion](../../guide/rule-conversion.md).

## Flags

### Required

| Flag | Description |
|------|-------------|
| `-t, --target <TARGET>` | Backend to convert to. Run [`backend targets`](targets.md) for the live list. Today: `postgres` (aliases `postgresql`, `pg`), `lynxdb`, `test`. |
| `[RULES]...` | Path(s) to Sigma rule file(s) or a directory. |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format <FORMAT>` | `default` | Backend-specific output format. Run [`backend formats <TARGET>`](formats.md) for the list. PostgreSQL examples: `default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`. |
| `-o, --output <PATH>` | stdout | Write to a file instead of stdout. |

### Pipeline

| Flag | Description |
|------|-------------|
| `-p, --pipeline <PIPELINE>` | Processing pipeline(s) (repeatable). Builtin names (`ecs_windows`, `sysmon`) or YAML file paths. |
| `--without-pipeline` | Skip the pipeline-requirement check that some backends enforce. Use when you know the rules already match your target schema. |

### Backend options and error handling

| Flag | Description |
|------|-------------|
| `-O, --option <KEY=VALUE>` | Backend-specific option. Repeatable. PostgreSQL examples: `-O table=okta_events`, `-O json_field=data`, `-O timestamp_field=time`, `-O case_sensitive_re=true`. See [PostgreSQL backend reference](../../reference/backends/postgres.md) for the full list. |
| `-s, --skip-unsupported` | Skip rules that the backend cannot represent instead of failing the run with exit `2`. The skipped rules are reported on stderr. |

## Examples

### PostgreSQL default

```bash
rsigma backend convert -t postgres rules/
```

```sql
SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

### PostgreSQL view per rule

```bash
rsigma backend convert -t postgres -f view -p ecs_windows rules/
```

```sql
CREATE OR REPLACE VIEW sigma_8b1d8c97_5b3a_4d77_9b48_7c5f7c8b1a2a AS
    SELECT * FROM security_events WHERE "process.command_line" ILIKE '%whoami%'
```

### JSONB mode against an Okta-style schema

```bash
rsigma backend convert -t postgres \
    -O table=okta_events \
    -O json_field=data \
    -O timestamp_field=time \
    rules/
```

```sql
SELECT * FROM okta_events
WHERE data->>'eventType' = 'group.user_membership.add'
  AND data->'actor'->>'alternateId' ILIKE '%@partner.example.com'
```

### LynxDB SPL2

```bash
rsigma backend convert -t lynxdb rules/
```

### Sliding-window correlation (skip the base detection rules)

```bash
rsigma backend convert -t postgres -f sliding_window --skip-unsupported rules/
```

Base detection rules return `unknown output format: sliding_window` and are skipped; only the correlation rule converts.

### Convert a whole tree to a file

```bash
rsigma backend convert rules/ -t postgres -f view \
    -p pipelines/ocsf_postgres.yml \
    --skip-unsupported \
    -o /var/lib/rsigma/sql/views.sql
psql -f /var/lib/rsigma/sql/views.sql
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Conversion succeeded. |
| `2` | One or more rules failed to convert (unless `--skip-unsupported`), or rules path empty. |
| `3` | Unknown `--target`, unknown `--format`, unwritable `--output`, or other CLI configuration error. |

## See also

- [Rule Conversion](../../guide/rule-conversion.md) for the full workflow.
- [`backend targets`](targets.md) and [`backend formats`](formats.md) for the discovery commands.
- [PostgreSQL backend reference](../../reference/backends/postgres.md), [LynxDB backend reference](../../reference/backends/lynxdb.md).
- [`rule fields`](../rule/fields.md) for auditing which fields each rule references before conversion.
