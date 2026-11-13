#!/usr/bin/env python3
"""Audit that evaluation truth is absent from the offline recovery path."""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runs = []
    for run in sorted(args.root.glob("rep*"), key=lambda path: int(path.name[3:])):
        cells = json.loads((run / "pcap-extracted-cell.json").read_text())
        manifest = json.loads((run / "replay-candidates.json").read_text())
        replay_results = [json.loads(Path(path).read_text()) for path in glob.glob(
            str(run / "replay-candidates" / "candidate-*.json")
        )]
        evaluation = json.loads((run / "full-pcap-evaluation.json").read_text())
        checks = {
            "cell_enumeration_no_external_selector": cells["external_circuit_selector_used"] is False,
            "fixture_manifest_excludes_truth": manifest["evaluation_truth_included"] is False,
            "fixture_manifest_no_external_selector": manifest["external_circuit_selector_used"] is False,
            "all_replays_exclude_truth": all(
                row["evaluation_truth_used"] is False for row in replay_results
            ),
            "post_recovery_evaluation_passed": evaluation["all_checks_pass"] is True,
        }
        runs.append({
            "run": run.name,
            "checks": checks,
            "all_checks_pass": all(checks.values()),
            "candidate_count": len(replay_results),
        })
    report = {
        "schema": "tor-cgo-evidence-separation-audit/0.1",
        "runs": runs,
        "all_runs_pass": bool(runs) and all(row["all_checks_pass"] for row in runs),
        "boundary": "cell.json is opened only by the post-recovery evaluator; CGO replay results already exist before that comparison",
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["all_runs_pass"]:
        raise SystemExit("evidence-separation audit failed")


if __name__ == "__main__":
    main()
