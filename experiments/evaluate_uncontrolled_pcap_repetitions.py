#!/usr/bin/env python3
"""Aggregate independent uncontrolled-timing replay cases."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def wilson(k: int, n: int) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for run in args.run:
        result = json.loads((run / "uncontrolled-pcap-evaluation.json").read_text())
        rows.append({
            "run": run.name,
            "status": result["status"],
            "success": result["success"],
            "path_length": result["path_length"],
            "recognized_hop": result["recognized_hop"],
            "tls_write_sequence_at_core": result["tls_write_sequence_at_core"],
            "authenticated_tls_records": result["authenticated_tls_records"],
            "offline_candidate_count": result["offline_candidate_count"],
            "evidence_stages": result["evidence_stages"],
        })
    accepted = sum(row["success"] for row in rows)
    safe_stops = sum(row["status"].startswith("safe_stop") for row in rows)
    invalid = len(rows) - accepted - safe_stops
    report = {
        "schema": "tor-cgo-uncontrolled-pcap-core-repetitions/0.1",
        "independent_process_runs": len(rows),
        "authenticated_recoveries": accepted,
        "safe_stops": safe_stops,
        "invalid_evidence_chains": invalid,
        "acceptable_outcomes": accepted + safe_stops,
        "acceptable_outcome_wilson_95": wilson(accepted + safe_stops, len(rows)),
        "authenticated_recovery_wilson_95": wilson(accepted, len(rows)),
        "path_lengths_tested": sorted({row["path_length"] for row in rows}),
        "recognized_hops_observed": sorted({
            row["recognized_hop"] for row in rows if row["recognized_hop"] is not None
        }),
        "tls_write_sequences_observed": sorted({
            row["tls_write_sequence_at_core"] for row in rows
            if row["tls_write_sequence_at_core"] is not None
        }),
        "stage_success_counts": {
            stage: sum(row["evidence_stages"][stage] for row in rows)
            for stage in ("E1", "E2", "E3", "E4", "E5")
        },
        "runs": rows,
        "independence": "Every row starts a fresh Tor process and fresh Chutney network.",
        "timing": (
            "Traffic is not paused and no dynamic cell hook chooses the snapshot boundary; "
            "gcore necessarily stops the process while copying its memory."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
