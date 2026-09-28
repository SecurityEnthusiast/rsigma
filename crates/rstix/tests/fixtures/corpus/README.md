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

Place the file in this directory, or set `RSTIX_ATTCK_BUNDLE` to any readable path.

The download URL uses the `master` branch path; the **versioned filename** (`enterprise-attack-19.2.json`) is the pin.

## Tests that use it

- `integration::attck_corpus_roundtrip_when_present` (`serde`)
- `taxii_store::ingest_attck_corpus_paginated_when_present` (`taxii-store` + `validate`)

Skip vs fail (see table above):

- **`RSTIX_ATTCK_BUNDLE` unset** and the default file under this directory is missing → **skip**
- **`RSTIX_ATTCK_BUNDLE` set** to a path that is not a readable file → **fail** (panic)
