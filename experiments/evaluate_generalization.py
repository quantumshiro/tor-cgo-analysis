#!/usr/bin/env python3
"""Aggregate controlled-circuit results across generalization cases."""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, centre - margin), min(1.0, centre + margin)]


def case_result(case_dir: Path) -> dict:
    controlled = json.loads((case_dir / "controlled-circuits.json").read_text())
    scan = json.loads((case_dir / "scan.json").read_text())
    evaluation = json.loads((case_dir / "evaluation.json").read_text())
    metadata = json.loads((case_dir / "metadata.json").read_text())

    wanted = set(controlled["built_circuit_ids"])
    expected_path = controlled["path_identities"]
    observed = {c["control_circuit_id"]: c for c in scan["circuits"]}
    recovered = wanted & set(observed)
    exact_path_ids = {
        circuit_id
        for circuit_id in recovered
        if [h["identity_sha1"] for h in observed[circuit_id]["hops"]] == expected_path
    }
    structurally_valid_ids = {
        circuit_id for circuit_id in recovered if observed[circuit_id]["path_structurally_valid"]
    }
    controlled_hops = [
        hop for circuit_id in recovered for hop in observed[circuit_id]["hops"]
    ]
    crypto_counts: dict[str, int] = {}
    forensic_state_counts: dict[str, int] = {}
    for hop in controlled_hops:
        crypto_counts[hop["crypto_kind"]] = crypto_counts.get(hop["crypto_kind"], 0) + 1
        state = hop.get("forensic_crypto_state", "legacy_unclassified")
        forensic_state_counts[state] = forensic_state_counts.get(state, 0) + 1

    label = case_dir.name
    components = label.split("-")
    return {
        "case": label,
        "architecture": components[0],
        "optimization": components[-1],
        "tor_version": metadata["tor_version"],
        "build_id": metadata["build_id"],
        "core_sha256": metadata["core_sha256"],
        "controlled": {
            "expected_circuits": len(wanted),
            "recovered_circuits": len(recovered),
            "exact_path_circuits": len(exact_path_ids),
            "structurally_valid_circuits": len(structurally_valid_ids),
            "expected_hops": len(wanted) * len(expected_path),
            "observed_hops": len(controlled_hops),
            "crypto_hop_counts": crypto_counts,
            "forensic_crypto_state_counts": forensic_state_counts,
            "missing_ids": sorted(wanted - recovered),
        },
        "ambient": evaluation,
        "scan_errors": scan["errors"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_dirs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    cases = [case_result(path) for path in args.case_dirs]
    circuit_total = sum(c["controlled"]["expected_circuits"] for c in cases)
    circuit_recovered = sum(c["controlled"]["recovered_circuits"] for c in cases)
    circuit_exact = sum(c["controlled"]["exact_path_circuits"] for c in cases)
    hop_total = sum(c["controlled"]["expected_hops"] for c in cases)
    cgo_hops = sum(
        c["controlled"]["forensic_crypto_state_counts"].get("CGO_established", 0)
        for c in cases
    )
    process_successes = sum(
        c["controlled"]["recovered_circuits"] == c["controlled"]["expected_circuits"]
        and c["controlled"]["exact_path_circuits"] == c["controlled"]["expected_circuits"]
        and c["controlled"]["forensic_crypto_state_counts"].get("CGO_established", 0)
        == c["controlled"]["expected_hops"]
        and not c["scan_errors"]
        for c in cases
    )
    grouped: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        grouped[f"{case['architecture']}|{case['tor_version']}|{case['optimization']}"].append(case)
    report = {
        "schema": "tor-cgo-generalization-evaluation/0.1",
        "cases": cases,
        "pooled_controlled": {
            "circuit_recovery": {
                "successes": circuit_recovered,
                "total": circuit_total,
                "wilson_95_ci": wilson(circuit_recovered, circuit_total),
            },
            "exact_path": {
                "successes": circuit_exact,
                "total": circuit_total,
                "wilson_95_ci": wilson(circuit_exact, circuit_total),
            },
            "established_cgo_hop_classification": {
                "successes": cgo_hops,
                "total": hop_total,
                "wilson_95_ci": wilson(cgo_hops, hop_total),
            },
        },
        "independent_process_runs": {
            "complete_successes": process_successes,
            "total": len(cases),
            "wilson_95_ci": wilson(process_successes, len(cases)),
        },
        "condition_repetitions": {
            key: {
                "runs": len(rows),
                "complete_successes": sum(
                    row["controlled"]["recovered_circuits"] == row["controlled"]["expected_circuits"]
                    and row["controlled"]["exact_path_circuits"] == row["controlled"]["expected_circuits"]
                    and row["controlled"]["forensic_crypto_state_counts"].get("CGO_established", 0)
                    == row["controlled"]["expected_hops"]
                    and not row["scan_errors"]
                    for row in rows
                ),
            }
            for key, rows in sorted(grouped.items())
        },
        "independence_caveat": (
            "Pooled Wilson intervals treat circuits/hops as Bernoulli trials, but observations "
            "within one process snapshot are correlated; intervals are descriptive, not a "
            "population-level generalization guarantee."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
