#!/usr/bin/env python3
"""Compare two baseline-eval TSV files and reject coarse regressions."""

import argparse
import csv
import os
import sys
from pathlib import Path


def read_rows(path):
    with Path(path).open(encoding="utf-8", newline="") as handle:
        rows = {}
        for row in csv.DictReader(handle, delimiter="\t"):
            key = (row["lane"], row["variant"])
            rows[key] = {
                "events": int(row["events"]),
                "matches": int(row["matches"]),
                "eps": float(row["eps"]),
            }
        return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("head")
    parser.add_argument(
        "--minimum-ratio",
        type=float,
        default=0.5,
        help="minimum head/base EPS ratio (default: 0.5)",
    )
    args = parser.parse_args()

    base = read_rows(args.base)
    head = read_rows(args.head)
    if not base:
        raise SystemExit(f"no baseline rows in {args.base}")
    if base.keys() != head.keys():
        missing = sorted(base.keys() - head.keys())
        extra = sorted(head.keys() - base.keys())
        raise SystemExit(f"row mismatch: missing={missing}, extra={extra}")

    failures = []
    lines = [
        "## Performance regression check",
        "",
        "| Lane | Variant | Base EPS | Head EPS | Ratio |",
        "|---|---|---:|---:|---:|",
    ]
    for key in sorted(base):
        before, after = base[key], head[key]
        if before["events"] != after["events"]:
            failures.append(f"{key}: event count changed")
        if before["matches"] != after["matches"]:
            failures.append(
                f"{key}: match count changed {before['matches']} -> {after['matches']}"
            )
        ratio = after["eps"] / before["eps"]
        lines.append(
            f"| {key[0]} | {key[1]} | {before['eps']:.0f} | "
            f"{after['eps']:.0f} | {ratio:.2f}x |"
        )
        if ratio < args.minimum_ratio:
            failures.append(
                f"{key}: {ratio:.2f}x is below the {args.minimum_ratio:.2f}x floor"
            )

    report = "\n".join(lines) + "\n"
    print(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(report)

    if failures:
        print("\n".join(f"error: {failure}" for failure in failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
