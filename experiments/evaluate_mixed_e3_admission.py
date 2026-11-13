#!/usr/bin/env python3
"""Verify that mixed CGO/TOR1 circuits are classified but not admitted to E4."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    scan = json.loads(args.scan.read_text())
    manifest = json.loads(args.manifest.read_text())

    active_e3 = []
    for circuit in scan["circuits"]:
        if circuit.get("lifecycle") != "active":
            continue
        if circuit.get("highest_core_evidence_level") != "E3":
            continue
        kinds = [hop["crypto_kind"] for hop in circuit["hops"]]
        active_e3.append({
            "control_circuit_id": circuit["control_circuit_id"],
            "hop_crypto_kinds": kinds,
            "all_cgo": bool(kinds) and all(kind == "CGO" for kind in kinds),
            "mixed_cgo_tor1": "CGO" in kinds and "TOR1" in kinds,
        })

    expected = {row["control_circuit_id"] for row in active_e3 if row["all_cgo"]}
    admitted = {row["control_circuit_id"] for row in manifest["circuits"]}
    mixed = {row["control_circuit_id"] for row in active_e3 if row["mixed_cgo_tor1"]}
    checks = {
        "owner_list_completely_enumerated": (
            scan["recovery_completeness"] == "owner_list_enumerated"
            and not scan["errors"]
            and manifest["owner_list_completely_enumerated"] is True
        ),
        "manifest_exactly_equals_all_cgo_E3_set": admitted == expected,
        "no_mixed_circuit_admitted": not (mixed & admitted),
        "mixed_circuit_present_as_negative_control": bool(mixed),
    }
    report = {
        "schema": "tor-cgo-mixed-e3-admission/0.1",
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "active_E3_circuits": len(active_e3),
        "all_cgo_E3_circuits": len(expected),
        "mixed_cgo_tor1_E3_circuits": len(mixed),
        "admitted_to_E4_E5_pipeline": len(admitted),
        "mixed_admitted": len(mixed & admitted),
        "mixed_circuit_ids": sorted(mixed),
        "admitted_circuit_ids": sorted(admitted),
        "circuits": active_e3,
        "interpretation": (
            "Mixed circuits remain reportable at E3, but the current CGO-only replay "
            "pipeline fails closed before secret extraction and traffic recovery."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
