#!/usr/bin/env bash
# Run baseline-daemon.sh across the vendor-shape lanes and the flag variants
# that matter after witness indexing: bare default, default with full event
# output, logsource routing with and without full event output, and routing
# plus the cross-rule AC pass. A separate handcrafted lane keeps correlation
# measurable because the pinned SigmaHQ tree contains no correlation rules.
#
# Usage: scripts/perf/daemon-matrix.sh [FIXTURES_DIR]
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="${1:-$(cd "${script_dir}/../.." && pwd)/target/perf-fixtures}"

for lane in raw_windows structured_windows match_heavy cisco_syslog sysmon_file_event; do
    for variant in default default_include_event logsource logsource_include_event logsource_ac; do
        case "${variant}" in
            default) flags=() ;;
            default_include_event) flags=(--include-event) ;;
            logsource) flags=(--logsource-routing) ;;
            logsource_include_event) flags=(--logsource-routing --include-event) ;;
            logsource_ac) flags=(--logsource-routing --cross-rule-ac) ;;
        esac
        printf 'variant=%s ' "${variant}"
        "${script_dir}/baseline-daemon.sh" "${fixtures}" "${lane}" "${flags[@]+"${flags[@]}"}"
    done
done

printf 'variant=correlation '
RULES="${fixtures}/correlation-rules" \
    "${script_dir}/baseline-daemon.sh" "${fixtures}" correlation \
    --no-detections --action reset
