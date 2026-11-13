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
    parser.add_argument(
        "--evaluation-name", default="uncontrolled-pcap-evaluation.json"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for run in args.run:
        result = json.loads((run / args.evaluation_name).read_text())
        rows.append({
            "run": run.name,
            "status": result["status"],
            "cgo_authentication_succeeded": result[
                "cgo_authentication_succeeded"
            ],
            "marker_bearing_relay_body_recovered": result[
                "marker_bearing_relay_body_recovered"
            ],
            "path_length": result["path_length"],
            "recognized_hop": result["recognized_hop"],
            "tls_write_sequence_at_core": result["tls_write_sequence_at_core"],
            "authenticated_tls_records": result["authenticated_tls_records"],
            "offline_candidate_count": result["offline_candidate_count"],
            "relay_body_length": result["relay_body_length"],
            "relay_body_sha256": result["relay_body_sha256"],
            "relay_command_code": result.get("relay_command_code"),
            "relay_command_name": result.get("relay_command_name"),
            "replay_build": result.get("replay_build"),
            "verification_results": result["verification_results"],
        })
    recovered = sum(
        row["status"] == "recovered_marker_bearing_relay_body" for row in rows
    )
    marker_absent = sum(
        row["status"] == "authenticated_marker_absent_relay_body" for row in rows
    )
    no_unique = sum(
        row["status"] == "no_unique_authenticated_candidate" for row in rows
    )
    invalid = sum(
        row["status"] == "verification_prerequisite_failed" for row in rows
    )
    classified = recovered + marker_absent + no_unique + invalid
    if classified != len(rows):
        unknown = sorted({
            row["status"] for row in rows
            if row["status"] not in {
                "recovered_marker_bearing_relay_body",
                "authenticated_marker_absent_relay_body",
                "no_unique_authenticated_candidate",
                "verification_prerequisite_failed",
            }
        })
        raise SystemExit(f"unknown result status: {unknown}")
    report = {
        "schema": "tor-cgo-uncontrolled-pcap-core-repetitions/0.4",
        "independent_process_runs": len(rows),
        "cgo_authenticated_relay_bodies": sum(
            row["cgo_authentication_succeeded"] for row in rows
        ),
        "marker_bearing_relay_bodies": recovered,
        "authenticated_marker_absent_relay_bodies": marker_absent,
        "relay_command_counts": {
            name: sum(row["relay_command_name"] == name for row in rows)
            for name in sorted({
                row["relay_command_name"] for row in rows
                if row["relay_command_name"] is not None
            })
        },
        "no_unique_authenticated_candidates": no_unique,
        "verification_prerequisite_failures": invalid,
        "cgo_authentication_wilson_95": wilson(
            sum(row["cgo_authentication_succeeded"] for row in rows), len(rows)
        ),
        "marker_bearing_relay_body_wilson_95": wilson(recovered, len(rows)),
        "path_lengths_tested": sorted({row["path_length"] for row in rows}),
        "recognized_hops_observed": sorted({
            row["recognized_hop"] for row in rows if row["recognized_hop"] is not None
        }),
        "tls_write_sequences_observed": sorted({
            row["tls_write_sequence_at_core"] for row in rows
            if row["tls_write_sequence_at_core"] is not None
        }),
        "verification_success_counts": {
            name: sum(row["verification_results"][name] for row in rows)
            for name in rows[0]["verification_results"]
        },
        "runs": rows,
        "independence": "Every row starts a fresh Tor process and fresh Chutney network.",
        "timing": (
            "Traffic is not paused. The snapshot starts after a predetermined fixed delay "
            "without observing a relay-cell or TLS-record boundary; gcore necessarily "
            "stops the process while copying its memory."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
