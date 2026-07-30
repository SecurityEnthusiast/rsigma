#!/usr/bin/env bash
# Compare daemon HTTP throughput between two container images end-to-end.
#
# baseline-daemon.sh drives a native build, so cost that the released artifact
# adds on top of the source -- the target libc and its allocator among it --
# never reaches a measurement. This races two images over the same fixtures,
# driving both with daemon-load.js from the official k6 image, so Docker, git
# and python3 are the only host requirements.
#
# Usage:
#   scripts/perf/image-compare.sh [FIXTURES_DIR] [LANE] [EXTRA_DAEMON_FLAGS...]
#
# To compare a change against its merge base, build that revision first:
#   git archive <base-sha> | docker build -t rsigma:base -
#   BASELINE=rsigma:base scripts/perf/image-compare.sh
#
# Environment: BASELINE (a published release), CANDIDATE (skips the working-tree
#              build), REPEAT (3, median reported), DAEMON_CPUS and LOAD_CPUS
#              (cpusets, unpinned by default), BATCH (500), VUS (4),
#              DURATION (30s), BATCH_SIZE (512), K6_IMAGE.
#
# Pin DAEMON_CPUS and LOAD_CPUS to disjoint cores. k6 is not cheap, and when it
# shares cores with the daemon the result describes how the two split the
# machine rather than how fast the daemon is. Throughput is each daemon's own
# rsigma_events_processed_total delta, reported next to the cores it used.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
fixtures="${1:-${repo_root}/target/perf-fixtures}"
lane="${2:-raw_windows}"
shift 2 2>/dev/null || shift $# || true

baseline="${BASELINE:-ghcr.io/timescale/rsigma:0.20.0}"
k6_image="${K6_IMAGE:-grafana/k6:2.1.0@sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669}"
duration="${DURATION:-30s}"
batch_size="${BATCH_SIZE:-512}"
repeat="${REPEAT:-3}"
network=rsigma-perf-compare
container=rsigma-perf-daemon
addr=127.0.0.1:19090
metrics="http://${addr}/metrics"

daemon_cpus=()
[ -n "${DAEMON_CPUS:-}" ] && daemon_cpus=(--cpuset-cpus "${DAEMON_CPUS}")
load_cpus=()
[ -n "${LOAD_CPUS:-}" ] && load_cpus=(--cpuset-cpus "${LOAD_CPUS}")

[ -d "${fixtures}/sigma/rules" ] || "${script_dir}/fetch-fixtures.sh" "${fixtures}"
fixtures="$(cd "${fixtures}" && pwd)"
lane_file="${fixtures}/events/${lane}.ndjson"
[ -f "${lane_file}" ] || { echo "missing lane ${lane_file}" >&2; exit 1; }

candidate="${CANDIDATE:-}"
if [ -z "${candidate}" ]; then
    echo "building the working tree" >&2
    docker build -q -t rsigma:perf-candidate "${repo_root}" >/dev/null
    candidate=rsigma:perf-candidate
fi

# Only reach for the registry when the tag is not already local, so a baseline
# built from the merge base works the same way a published tag does.
for image in "${baseline}" "${k6_image}"; do
    docker image inspect "${image}" >/dev/null 2>&1 || docker pull -q "${image}" >/dev/null
done
docker network create "${network}" >/dev/null 2>&1 || true

trap 'docker rm -f "${container}" >/dev/null 2>&1 || true; \
      docker network rm "${network}" >/dev/null 2>&1 || true' EXIT

metric() {
    curl -sf "${metrics}" \
        | awk -v k="$1" '$1 == k {print $2; found = 1} END {if (!found) print 0}'
}

now() { python3 -c 'import time; print(time.time())'; }

# Echoes "eps cores" for one load run against the daemon already running.
run_load() {
    local before start cpu_log sampler prev=-1 now_count end
    before="$(metric rsigma_events_processed_total)"
    start="$(now)"

    cpu_log="$(mktemp)"
    ( while :; do
          docker stats --no-stream --format '{{.CPUPerc}}' "${container}" 2>/dev/null | tr -d '%'
          sleep 1
      done >"${cpu_log}" ) &
    sampler=$!

    docker run --rm --network "${network}" "${load_cpus[@]+"${load_cpus[@]}"}" \
        -e LANE=/lane.ndjson -e "URL=http://${container}:9090/api/v1/events" \
        -e "BATCH=${BATCH:-500}" -e "VUS=${VUS:-4}" -e "DURATION=${duration}" \
        -v "${lane_file}:/lane.ndjson:ro" \
        -v "${script_dir}/daemon-load.js:/load.js:ro" \
        "${k6_image}" run --quiet /load.js >/dev/null 2>&1

    # Drain before the final read, and measure over wall time rather than the k6
    # duration: events still queued when k6 exits are processed after it, and
    # charging them to the load window reports a rate never sustained.
    for _ in $(seq 1 60); do
        now_count="$(metric rsigma_events_processed_total)"
        [ "${now_count}" = "${prev}" ] && break
        prev="${now_count}"
        sleep 1
    done
    end="$(now)"
    kill "${sampler}" 2>/dev/null || true
    wait "${sampler}" 2>/dev/null || true

    python3 - "${before}" "${prev}" "${start}" "${end}" "${cpu_log}" <<'PY'
import sys

before, after, start, end, cpu_log = sys.argv[1:6]
secs = max(float(end) - float(start), 1e-9)
samples = [float(line) for line in open(cpu_log) if line.strip()]
cores = (sum(samples) / len(samples) / 100) if samples else 0.0
print(f"{(int(after) - int(before)) / secs:.0f} {cores:.1f}")
PY
    rm -f "${cpu_log}"
}

# Echoes "eps cores" for one image, from the median of REPEAT runs.
measure() {
    local image="$1"
    shift
    docker rm -f "${container}" >/dev/null 2>&1 || true

    docker run -d --name "${container}" --network "${network}" \
        "${daemon_cpus[@]+"${daemon_cpus[@]}"}" \
        -p "${addr}:9090" -v "${fixtures}/sigma/rules:/rules:ro" \
        "${image}" engine daemon -r /rules --input http \
        --api-addr 0.0.0.0:9090 --allow-plaintext \
        --batch-size "${batch_size}" --output "file:///dev/null" "$@" >/dev/null

    local ready=""
    for _ in $(seq 1 240); do
        curl -sf "http://${addr}/readyz" 2>/dev/null | grep -q rules_loaded && { ready=yes; break; }
        sleep 0.5
    done
    [ -n "${ready}" ] || {
        docker logs "${container}" >&2
        echo "daemon did not become ready" >&2
        exit 1
    }

    local runs=()
    for i in $(seq 1 "${repeat}"); do
        echo "  ${image}: run ${i}/${repeat}" >&2
        runs+=("$(run_load)")
    done

    python3 - "${runs[@]}" <<'PY'
import sys

pairs = sorted((float(r.split()[0]), float(r.split()[1])) for r in sys.argv[1:])
eps, cores = pairs[len(pairs) // 2]
print(f"{eps:.0f} {cores:.1f}")
PY
}

read -r base_eps base_cores <<<"$(measure "${baseline}" "$@")"
read -r cand_eps cand_cores <<<"$(measure "${candidate}" "$@")"

printf '\nlane=%s batch-size=%s vus=%s duration=%s repeat=%s pinning=%s flags=%s\n' \
    "${lane}" "${batch_size}" "${VUS:-4}" "${duration}" "${repeat}" \
    "${DAEMON_CPUS:-none}/${LOAD_CPUS:-none}" "${*:-none}"

# Formatted in python rather than printf: these are floats with a dot decimal
# separator, which printf(1) rejects under a comma-decimal locale.
python3 - "${baseline}" "${base_eps}" "${base_cores}" \
         "${candidate}" "${cand_eps}" "${cand_cores}" <<'PY'
import sys

rows = [tuple(sys.argv[1:4]), tuple(sys.argv[4:7])]
print(f"{'image':<40} {'events/s':>10} {'cores':>7} {'eps/core':>10}")
for image, eps, cores in rows:
    per_core = float(eps) / float(cores) if float(cores) > 0 else 0.0
    print(f"{image:<40} {float(eps):>10.0f} {float(cores):>7.1f} {per_core:>10.0f}")
base, cand = float(rows[0][1]), float(rows[1][1])
print(f"\nratio {cand / base:.2f}x" if base > 0 else "\nratio n/a")
PY
