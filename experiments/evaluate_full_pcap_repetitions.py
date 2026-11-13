#!/usr/bin/env python3
"""Aggregate independent full PCAP-to-CGO replay runs."""

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
        result = json.loads((run / "full-pcap-evaluation.json").read_text())
        decrypt = json.loads((run / "tls-pcap-decryption.json").read_text())
        rows.append({
            "run": run.name,
            "success": result["all_checks_pass"],
            "control_circuit_id": result["control_circuit_id"],
            "entry_link_circuit_id": result["entry_link_circuit_id"],
            "tls_write_sequence_at_core": result["tls_write_sequence_at_core"],
            "authenticated_tls_records": decrypt["authenticated_tls_records"],
            "offline_candidate_count": result["offline_candidate_count"],
            "cgo_authenticated_candidate_count": result["cgo_authenticated_candidate_count"],
            "recognized_hop": result["recognized_hop"],
            "payload_bytes_compared": result["payload_bytes_compared"],
            "evidence_stages": result["evidence_stages"],
        })
    successes = sum(row["success"] for row in rows)
    report = {
        "schema": "tor-cgo-full-pcap-core-repetitions/0.3",
        "successful_full_chains": successes,
        "independent_process_runs": len(rows),
        "wilson_95": wilson(successes, len(rows)),
        "runs": rows,
        "stage_success_counts": {
            stage: sum(row["evidence_stages"][stage] for row in rows)
            for stage in ("E1", "E2", "E3", "E4", "E5")
        },
        "chain": [
            "saved PCAP",
            "TLS 1.3 traffic secrets extracted from synchronized client core",
            "authenticated TLS record decryption",
            "all Tor-cell candidates enumerated by entry circuit ID and exact core write sequence",
            "only circuits admitted by the ownership-first E3 manifest enter TLS/CGO secret extraction",
            "CGO state extracted from the same E3 circuit in the same core",
            "exactly one candidate must authenticate under CGO; hop recognition and 493-byte plaintext equality are checked afterward",
        ],
        "limits": [
            "All runs use Tor 0.4.9.16, OpenSSL 3.0.22, Debian arm64, and one host.",
            "The PCAP begins after the TLS handshake; the core supplies the current record sequence.",
            "Dynamic cell capture supplies evaluation truth only to the post-recovery evaluator and is absent from extraction, selection, replay fixtures, and CGO processing.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
