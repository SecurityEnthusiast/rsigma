#!/usr/bin/env python3
"""Gate on rstix STIX 2.1 interop self-certification report artifacts.

Used by CI (and locally after ``cargo test -p rstix --test interop``) to ensure
``target/interop-report/`` was produced by this run and that every ``TESTED``
manifest row recorded ``Pass``. That report package is the operational
SXP/SXC self-certification evidence against Interoperability CSD01.

Environment:

- ``INTEROP_RUN_START`` — required UTC RFC 3339 timestamp taken before the
  interop suite ran. ``summary.json`` ``generated_at`` must be >= this value
  so a stale report from a previous run cannot satisfy the gate.

Exits 0 on success, 1 on failure. Stdlib only.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


REPORT_DIR = Path("target/interop-report")
REQUIRED_ARTIFACTS = (
    "summary.json",
    "traceability.csv",
    "sxc-table-55.md",
    "sxp-table-56.md",
    "risks.md",
)


def parse_rfc3339(value: str) -> datetime:
    # Accept trailing Z from both the harness and `date -u +%Y-%m-%dT%H:%M:%SZ`.
    normalized = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fail(message: str) -> None:
    print(f"interop-report-gate: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    start_raw = os.environ.get("INTEROP_RUN_START")
    if not start_raw:
        fail("INTEROP_RUN_START is required (UTC RFC 3339 from before the suite ran)")

    try:
        run_start = parse_rfc3339(start_raw)
    except ValueError as err:
        fail(f"INTEROP_RUN_START is not RFC 3339: {start_raw!r} ({err})")

    if not REPORT_DIR.is_dir():
        fail(f"missing report directory {REPORT_DIR}")

    for name in REQUIRED_ARTIFACTS:
        path = REPORT_DIR / name
        if not path.is_file():
            fail(f"missing required artifact {path}")

    summary_path = REPORT_DIR / "summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read {summary_path}: {err}")

    generated_raw = summary.get("generated_at")
    if not isinstance(generated_raw, str) or not generated_raw:
        fail("summary.json missing string field generated_at")

    try:
        generated_at = parse_rfc3339(generated_raw)
    except ValueError as err:
        fail(f"summary.json generated_at is not RFC 3339: {generated_raw!r} ({err})")

    if generated_at < run_start:
        fail(
            "summary.json is stale: "
            f"generated_at={generated_raw} < INTEROP_RUN_START={start_raw}"
        )

    by = summary.get("manifest_rows_by_disposition")
    if not isinstance(by, dict):
        fail("summary.json missing manifest_rows_by_disposition object")

    tested = by.get("tested")
    harness_smoke = by.get("harness_smoke", 0)
    tested_passed = summary.get("tested_rows_passed")
    smoke_executed = summary.get("harness_smoke_executed")
    blocked = summary.get("blocked_rows")
    report_only = summary.get("report_only_rows")
    features = summary.get("features_enabled")

    if tested_passed != tested:
        fail(f"TESTED rows not fully passed: tested_rows_passed={tested_passed} tested={tested}")
    if smoke_executed != harness_smoke:
        fail(
            "HARNESS_SMOKE mismatch: "
            f"harness_smoke_executed={smoke_executed} harness_smoke={harness_smoke}"
        )
    if blocked != by.get("blocked"):
        fail(
            "blocked_rows mismatch: "
            f"blocked_rows={blocked} disposition.blocked={by.get('blocked')}"
        )
    if report_only != by.get("report_only"):
        fail(
            "report_only_rows mismatch: "
            f"report_only_rows={report_only} disposition.report_only={by.get('report_only')}"
        )
    if not isinstance(features, dict) or not all(
        features.get(name) is True for name in ("validate", "marking", "graph")
    ):
        fail(f"features_enabled must be validate/marking/graph all true, got {features!r}")

    print(
        "interop-report-gate ok: "
        f"generated_at={generated_raw} "
        f"tested_passed={tested_passed} "
        f"harness_smoke={smoke_executed} "
        f"report_only={report_only} "
        f"blocked={blocked}"
    )


if __name__ == "__main__":
    main()
