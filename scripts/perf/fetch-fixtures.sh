#!/usr/bin/env bash
# Materialize the performance baseline workload reproducibly:
#   - SigmaHQ rules at the same pinned SHA the CI corpus job uses
#   - deterministic NDJSON event lanes (scripts/perf/gen_events.py)
#
# Usage:
#   scripts/perf/fetch-fixtures.sh [DEST_DIR] [EVENTS_PER_LANE]
#
# DEST_DIR defaults to target/perf-fixtures. EVENTS_PER_LANE defaults to 10000.
#
# Optional environment:
#   SIGMA_CORPUS_SHA          override the pinned SigmaHQ commit
#   RSIGMA_PERF_RAW_OVERRIDE  path to an externally supplied raw-Windows lane
#                             (copied over events/raw_windows.ndjson, e.g. an
#                             unmodified vendor reproduction kept out of git)
set -euo pipefail

# Keep in sync with SIGMA_CORPUS_SHA in .github/workflows/ci.yml.
SIGMA_CORPUS_SHA="${SIGMA_CORPUS_SHA:-994da16651194500b607a3007186c29779e1f961}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
dest="${1:-${repo_root}/target/perf-fixtures}"
count="${2:-10000}"

mkdir -p "${dest}"

sigma_dir="${dest}/sigma"
if [ -d "${sigma_dir}/.git" ] && [ "$(git -C "${sigma_dir}" rev-parse HEAD)" = "${SIGMA_CORPUS_SHA}" ]; then
    echo "SigmaHQ corpus already at ${SIGMA_CORPUS_SHA}" >&2
else
    rm -rf "${sigma_dir}"
    mkdir -p "${sigma_dir}"
    git -C "${sigma_dir}" init -q
    git -C "${sigma_dir}" remote add origin https://github.com/SigmaHQ/sigma.git
    git -C "${sigma_dir}" fetch -q --depth 1 origin "${SIGMA_CORPUS_SHA}"
    git -C "${sigma_dir}" checkout -q FETCH_HEAD
    echo "Checked out SigmaHQ/sigma at ${SIGMA_CORPUS_SHA}" >&2
fi

events_dir="${dest}/events"
python3 "${script_dir}/gen_events.py" --out-dir "${events_dir}" --count "${count}"

correlation_rules="${dest}/correlation-rules"
rm -rf "${correlation_rules}"
mkdir -p "${correlation_rules}"
cp "${script_dir}/fixtures/correlation.yml" "${correlation_rules}/correlation.yml"

if [ -n "${RSIGMA_PERF_RAW_OVERRIDE:-}" ]; then
    cp "${RSIGMA_PERF_RAW_OVERRIDE}" "${events_dir}/raw_windows.ndjson"
    echo "raw_windows lane overridden from ${RSIGMA_PERF_RAW_OVERRIDE}" >&2
fi

rule_count="$(find "${sigma_dir}/rules" -name '*.yml' | wc -l | tr -d ' ')"
echo "Fixtures ready: ${dest} (${rule_count} rule files, lanes in ${events_dir})" >&2
