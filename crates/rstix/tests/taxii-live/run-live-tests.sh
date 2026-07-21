#!/usr/bin/env bash
# Generate certs and start the Docker stack for live TAXII tests.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

"$ROOT/generate-certs.sh"
docker compose -f "$ROOT/docker-compose.yml" up -d --wait

echo "Stack ready. From repo root run:"
echo "  cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture"
