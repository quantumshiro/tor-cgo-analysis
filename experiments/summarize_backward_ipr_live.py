#!/usr/bin/env python3
"""Aggregate independent live CGO backward-IPR boundary trials."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if trials <= 0:
        raise ValueError("trials must be positive")
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = (
        z
        * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return center - radius, center + radius


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dirs", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    for result_dir in args.result_dirs:
        evaluation = json.loads((result_dir / "evaluation.json").read_text())
        rows.append(
            {
                "result_dir": str(result_dir),
                "controlled_circuit_id": evaluation["controlled_circuit_id"],
                "entry_fault_injection_count": evaluation["entry_fault_injection_count"],
                "client_unrecognized_close_count": evaluation[
                    "client_unrecognized_close_count"
                ],
                "controlled_circuit_present_after_attack": evaluation[
                    "controlled_circuit_present_after_attack"
                ],
                "expected_boundary_observed": evaluation[
                    "expected_boundary_observed"
                ],
            }
        )

    trials = len(rows)
    successes = sum(row["expected_boundary_observed"] for row in rows)
    lower, upper = wilson_interval(successes, trials)
    report = {
        "schema": "tor-cgo-backward-ipr-live-statistics/0.1",
        "unit_of_independence": "fresh Chutney network and Tor processes",
        "trials": trials,
        "successes": successes,
        "observed_rate": successes / trials,
        "wilson_95_two_sided": {"lower": lower, "upper": upper},
        "all_trials_single_injection": all(
            row["entry_fault_injection_count"] == 1 for row in rows
        ),
        "all_trials_circuit_absent_after_attack": all(
            not row["controlled_circuit_present_after_attack"] for row in rows
        ),
        "trial_results": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
