#!/usr/bin/env python3
"""Generate ``gate-expectations.json`` from ``manifest.toml``.

Run from the repository root when the interop manifest changes:

    python3 scripts/generate-interop-gate-expectations.py

The committed JSON is checked by the interop harness (Layer 2) and
``scripts/interop-report-gate.py`` (Layer 3). Semantics mirror
``crates/rstix/tests/interop/harness/gate_expectations.rs``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    print("generate-interop-gate-expectations: Python 3.11+ required (tomllib)", file=sys.stderr)
    sys.exit(1)


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "crates/rstix/tests/fixtures/interop/manifest.toml"
OUTPUT = REPO_ROOT / "crates/rstix/tests/fixtures/interop/gate-expectations.json"
TRACEABILITY_HEADER = "req_id,test_id,fixture,role,level,doc_page,disposition,outcome"
CHECKLIST_ROW_COUNT = 23


def checklist_result_for_export(row: dict[str, object]) -> str:
    disposition = row.get("disposition", "TESTED")
    if disposition == "BLOCKED":
        return "BLOCKED (unrepairable published test data)"
    if disposition == "REPORT_ONLY":
        return "Pending (checklist report only)"
    if disposition == "HARNESS_SMOKE":
        return "Harness smoke (not normative verification)"
    return "Pass"


def expected_csv_outcome(disposition: str) -> str:
    return {
        "TESTED": "Pass",
        "HARNESS_SMOKE": "HARNESS_SMOKE",
        "BLOCKED": "BLOCKED",
        "REPORT_ONLY": "REPORT_ONLY",
        "API_SURFACE": "API_SURFACE",
    }[disposition]


def use_case_label(row: dict[str, object]) -> str:
    use_case = row.get("use_case")
    return use_case if isinstance(use_case, str) and use_case else "framework"


def verification_label(row: dict[str, object]) -> str:
    verification = row.get("verification")
    return verification if isinstance(verification, str) else ""


def checklist_expectations(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "req_id": row["req_id"],
            "use_case": use_case_label(row),
            "section": row.get("section") or "",
            "verification": verification_label(row),
            "disposition": row.get("disposition", "TESTED"),
            "expected_result": checklist_result_for_export(row),
        }
        for row in rows
    ]


def checklist_rows_for_role(rows: list[dict[str, object]], role: str) -> list[dict[str, object]]:
    filtered = [
        row
        for row in rows
        if row.get("checklist_row") and row.get("checklist_role") == role
    ]
    filtered.sort(key=lambda row: row["checklist_row"])
    return filtered


def disposition_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    counts = {
        "tested": 0,
        "harness_smoke": 0,
        "report_only": 0,
        "blocked": 0,
        "api_surface": 0,
    }
    mapping = {
        "TESTED": "tested",
        "HARNESS_SMOKE": "harness_smoke",
        "REPORT_ONLY": "report_only",
        "BLOCKED": "blocked",
        "API_SURFACE": "api_surface",
    }
    for row in rows:
        key = mapping[row.get("disposition", "TESTED")]
        counts[key] += 1
    return counts


def main() -> None:
    if not MANIFEST.is_file():
        print(f"generate-interop-gate-expectations: missing {MANIFEST}", file=sys.stderr)
        sys.exit(1)

    rows: list[dict[str, object]] = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))[
        "requirement"
    ]
    table_55 = checklist_expectations(checklist_rows_for_role(rows, "consumer"))
    table_56 = checklist_expectations(checklist_rows_for_role(rows, "producer"))

    if len(table_55) != CHECKLIST_ROW_COUNT or len(table_56) != CHECKLIST_ROW_COUNT:
        print(
            "generate-interop-gate-expectations: expected "
            f"{CHECKLIST_ROW_COUNT} checklist rows per role, got "
            f"consumer={len(table_55)} producer={len(table_56)}",
            file=sys.stderr,
        )
        sys.exit(1)

    expectations = {
        "manifest_rows_total": len(rows),
        "manifest_rows_by_disposition": disposition_counts(rows),
        "traceability_header": TRACEABILITY_HEADER,
        "checklist_row_count": CHECKLIST_ROW_COUNT,
        "table_55": table_55,
        "table_56": table_56,
        "traceability_rows": [
            {
                "req_id": row["req_id"],
                "disposition": row.get("disposition", "TESTED"),
                "expected_outcome": expected_csv_outcome(row.get("disposition", "TESTED")),
            }
            for row in rows
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(expectations, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
