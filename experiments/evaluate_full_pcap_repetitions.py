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
        checks = result["checks"]
        verification_results = result.get("verification_results") or {
            "owner_list_completely_enumerated": checks[
                "owner_list_completely_enumerated"
            ],
            "circuit_owner_path_and_crypto_valid": checks.get(
                "selected_circuit_owner_path_and_crypto_valid",
                checks.get("selected_circuit_reached_E1_E2_E3", False),
            ),
            "secret_extraction_constrained_to_verified_circuit_list": (
                checks.get(
                    "selected_circuit_owner_path_and_crypto_valid",
                    checks.get("selected_circuit_reached_E1_E2_E3", False),
                )
                and checks.get(
                    "secret_extractors_constrained_by_same_verified_circuit_list",
                    checks.get("secret_extractors_constrained_by_same_E3_manifest", False),
                )
            ),
            "tls_record_authenticated_at_core_sequence": (
                checks["tls_record_authenticated"]
                and checks["target_tor_cell_selected_by_core_sequence"]
            ),
            "exactly_one_relay_body_authenticated_by_cgo": checks[
                "exactly_one_candidate_authenticated_by_cgo"
            ],
            "recognized_hop_matches_evaluation_truth": checks[
                "cgo_recognized_expected_hop"
            ],
            "relay_body_493_bytes_matches_evaluation_truth": checks[
                "cgo_plaintext_493_bytes_match"
            ],
        }
        cgo_authentication_succeeded = result.get(
            "cgo_authentication_succeeded",
            checks["exactly_one_candidate_authenticated_by_cgo"],
        )
        evaluation_truth_match = result.get(
            "evaluation_truth_match",
            checks["unique_authenticated_candidate_matches_posthoc_truth"]
            and checks["cgo_recognized_expected_hop"]
            and checks["cgo_plaintext_493_bytes_match"],
        )
        rows.append({
            "run": run.name,
            "success": result["all_checks_pass"],
            "cgo_authentication_succeeded": cgo_authentication_succeeded,
            "evaluation_truth_match": evaluation_truth_match,
            "control_circuit_id": result["control_circuit_id"],
            "entry_link_circuit_id": result["entry_link_circuit_id"],
            "tls_write_sequence_at_core": result["tls_write_sequence_at_core"],
            "authenticated_tls_records": decrypt["authenticated_tls_records"],
            "offline_candidate_count": result["offline_candidate_count"],
            "cgo_authenticated_candidate_count": result["cgo_authenticated_candidate_count"],
            "recognized_hop": result["recognized_hop"],
            "payload_bytes_compared": result["payload_bytes_compared"],
            "verification_results": verification_results,
        })
    successes = sum(row["success"] for row in rows)
    report = {
        "schema": "tor-cgo-full-pcap-core-repetitions/0.4",
        "successful_full_chains": successes,
        "cgo_authenticated_relay_bodies": sum(
            row["cgo_authentication_succeeded"] for row in rows
        ),
        "evaluation_truth_matches": sum(
            row["evaluation_truth_match"] for row in rows
        ),
        "independent_process_runs": len(rows),
        "wilson_95": wilson(successes, len(rows)),
        "runs": rows,
        "verification_success_counts": {
            name: sum(row["verification_results"][name] for row in rows)
            for name in rows[0]["verification_results"]
        },
        "chain": [
            "saved PCAP",
            "TLS 1.3 traffic secrets extracted from synchronized client core",
            "authenticated TLS record decryption",
            "all Tor-cell candidates enumerated by entry circuit ID and exact core write sequence",
            "only circuits with verified ownership, path structure, and initialized CGO contexts enter TLS/CGO secret extraction",
            "CGO state extracted from the same verified circuit in the same core",
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
