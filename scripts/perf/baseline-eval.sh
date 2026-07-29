#!/usr/bin/env bash
# Run the offline `engine eval` throughput matrix over the perf fixture lanes
# and print one TSV row per run (lane, flags, events, matches, load seconds,
# eval seconds, events/sec).
#
# Usage:
#   scripts/perf/baseline-eval.sh [FIXTURES_DIR] [LANES...]
#
# FIXTURES_DIR defaults to target/perf-fixtures (see fetch-fixtures.sh).
# LANES defaults to "raw_windows structured_windows". The binary is expected
# at target/release/rsigma, built with --all-features.
#
# Environment:
#   REPEAT    times to concatenate each lane (default 10). Loading the pinned
#             SigmaHQ corpus costs ~0.3 s, which swamps a single 10k-event pass,
#             so the lane is repeated to push the eval share of wall time up.
#   RUNS      measured evaluation runs per lane and variant (default 3); the
#             reported evaluation time is their median.
#   RSIGMA    override the binary under test (default target/release/rsigma),
#             so a pre-change build can be measured with the same harness.
#   SAMPLES_FILE  optional TSV path for every raw measured run.
#
# Reported events/sec is net of rule load: the harness times a load-only run
# (empty stdin) and subtracts it, because load is a fixed startup cost and
# leaving it in the per-event figure makes a faster evaluator look slower than
# it is. Both the load and eval columns are printed so the split stays visible.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixtures="${1:-${repo_root}/target/perf-fixtures}"
shift || true
lanes=("${@:-raw_windows structured_windows}")
if [ "${#lanes[@]}" -eq 1 ]; then
    # Allow a single space-separated argument.
    read -r -a lanes <<<"${lanes[0]}"
fi

bin="${RSIGMA:-${repo_root}/target/release/rsigma}"
rules="${fixtures}/sigma/rules"
repeat="${REPEAT:-10}"
runs="${RUNS:-3}"
[ -x "${bin}" ] || { echo "build first: cargo build --release --all-features --bin rsigma" >&2; exit 1; }
[ -d "${rules}" ] || { echo "fixtures missing: run scripts/perf/fetch-fixtures.sh" >&2; exit 1; }

variants=(
    "baseline|"
    "logsource|--logsource-routing"
    "ac|--cross-rule-ac"
    "logsource+ac|--logsource-routing --cross-rule-ac"
)

now() { python3 -c 'import time; print(time.time())'; }

if [ -n "${SAMPLES_FILE:-}" ]; then
    printf 'lane\tvariant\trun\tevents\tmatches\tload_s\teval_s\teps\n' >"${SAMPLES_FILE}"
fi

# Median of three load-only runs, one warm-up discarded.
"${bin}" engine eval -r "${rules}" --quiet --output-format ndjson </dev/null >/dev/null
load_samples=()
for _ in 1 2 3; do
    start="$(now)"
    "${bin}" engine eval -r "${rules}" --quiet --output-format ndjson </dev/null >/dev/null
    end="$(now)"
    load_samples+=("$(python3 -c "print(${end}-${start})")")
done
load="$(printf '%s\n' "${load_samples[@]}" | sort -g | sed -n 2p)"

echo -e "lane\tvariant\tevents\tmatches\tload_s\teval_s\teps\teps_ci_low\teps_ci_high"
for lane in "${lanes[@]}"; do
    events_file="${fixtures}/events/${lane}.ndjson"
    [ -f "${events_file}" ] || { echo "missing lane ${events_file}" >&2; continue; }
    stream="${TMPDIR:-/tmp}/rsigma-perf-${lane}.ndjson"
    : >"${stream}"
    for _ in $(seq 1 "${repeat}"); do cat "${events_file}" >>"${stream}"; done
    n_events="$(wc -l <"${stream}" | tr -d ' ')"
    for spec in "${variants[@]}"; do
        name="${spec%%|*}"
        flags="${spec#*|}"
        samples=()
        for run in $(seq 1 "${runs}"); do
            start="$(now)"
            # shellcheck disable=SC2086
            matches="$("${bin}" engine eval \
                -r "${rules}" ${flags} --quiet --output-format ndjson \
                <"${stream}" | wc -l | tr -d ' ')"
            end="$(now)"
            elapsed="$(python3 -c "print(max(${end}-${start}-${load}, 1e-9))")"
            samples+=("${matches}:${elapsed}")
            if [ -n "${SAMPLES_FILE:-}" ]; then
                python3 - "${lane}" "${name}" "${run}" "${n_events}" "${matches}" "${load}" "${elapsed}" >>"${SAMPLES_FILE}" <<'PY'
import sys
lane, name, run, events, matches, load, elapsed = sys.argv[1:]
print(f"{lane}\t{name}\t{run}\t{events}\t{matches}\t{float(load):.6f}\t{float(elapsed):.6f}\t{int(events) / float(elapsed):.0f}")
PY
            fi
        done
        python3 - "${lane}" "${name}" "${n_events}" "${load}" "${samples[@]}" <<'PY'
import random
import statistics
import sys
lane, name, n_events, load = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
samples = [(int(sample.split(":", 1)[0]), float(sample.split(":", 1)[1])) for sample in sys.argv[5:]]
matches = {sample[0] for sample in samples}
if len(matches) != 1:
    raise SystemExit(f"match count changed across runs: {sorted(matches)}")
times = [sample[1] for sample in samples]
evaluated = statistics.median(times)
rng = random.Random(0)
bootstrap = sorted(statistics.median(rng.choices(times, k=len(times))) for _ in range(10000))
low_time = bootstrap[int(len(bootstrap) * 0.025)]
high_time = bootstrap[int(len(bootstrap) * 0.975)]
print(
    f"{lane}\t{name}\t{n_events}\t{matches.pop()}\t{load:.2f}\t{evaluated:.2f}\t"
    f"{n_events / evaluated:.0f}\t{n_events / high_time:.0f}\t{n_events / low_time:.0f}"
)
PY
    done
    rm -f "${stream}"
done
