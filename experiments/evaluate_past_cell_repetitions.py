#!/usr/bin/env python3
"""Aggregate real-Tor attempts to decrypt a past cell with post-cell state."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def wilson(k: int, n: int) -> list[float]:
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--run", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    rows = []
    for run in args.run:
        result = json.loads((run / "replay-result.json").read_text())
        success = (
            result.get("expected_unrecognized") is True
            and result.get("recognized_hop") == -1
            and result.get("payload_match") is False
        )
        rows.append({"run": run.name, "past_cell_rejected": success})
    successes = sum(r["past_cell_rejected"] for r in rows)
    report = {
        "schema": "tor-cgo-past-cell-repetition/0.1",
        "post_cell_state_failed_to_decrypt_past_cell": successes,
        "independent_process_runs": len(rows),
        "wilson_95": wilson(successes, len(rows)),
        "runs": rows,
        "interpretation": "This tests the immediately preceding forward cell, not all possible historical evidence conditions.",
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
