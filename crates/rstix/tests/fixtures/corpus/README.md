# MITRE ATT&CK STIX corpus (local, optional)

Large ATT&CK bundles are **not committed** to the repository. Env-gated integration tests look for:

| Location | Used when |
|----------|-----------|
| `RSTIX_ATTCK_BUNDLE` | Explicit path to a bundle file (**must exist** — test fails if missing) |
| `tests/fixtures/corpus/enterprise-attack-19.2.json` | Default when the env var is unset (**skip** if missing) |

## Pinned release

**`enterprise-attack-19.2.json`** — MITRE ATT&CK Enterprise STIX 2.1 (~51 MiB).

Download:

```bash
curl -fsSL -o enterprise-attack-19.2.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json
```

Place the file in this directory, or set `RSTIX_ATTCK_BUNDLE` to any path (for example a copy under `plan/`).

## Tests that use it

- `integration::attck_corpus_roundtrip_when_present` (`serde`)
- `taxii_store::ingest_attck_corpus_paginated_when_present` (`taxii-store` + `validate`)

Both skip cleanly when the file is absent.
