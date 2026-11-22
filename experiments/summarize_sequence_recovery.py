#!/usr/bin/env python3
"""Summarize CGO sequence results without copying plaintext or secrets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        action="append",
        nargs=3,
        metavar=("LABEL", "METADATA", "RESULT"),
    )
    parser.add_argument(
        "--case-dir",
        action="append",
        type=Path,
        default=[],
        help="directory containing sequence-1000 metadata and result files",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inputs = list(args.case or [])
    for directory in args.case_dir:
        inputs.append((
            directory.name,
            str(directory / "sequence-1000-metadata.json"),
            str(directory / "sequence-1000-result.json"),
        ))
    if not inputs:
        parser.error("at least one --case or --case-dir is required")

    cases = []
    for label, metadata_path, result_path in inputs:
        metadata = load(Path(metadata_path))
        result = load(Path(result_path))
        processed = int(result["processed_cell_count"])
        failure = result["first_failure_index"]
        authenticated = processed if failure is None else int(failure)
        cases.append({
            "label": label,
            "authenticated_anchor_sequence_index": metadata.get(
                "authenticated_anchor_sequence_index"
            ),
            "captured_candidates_skipped_before_anchor": metadata.get(
                "captured_candidates_skipped_before_anchor"
            ),
            "input_cell_count": int(metadata["cell_count"]),
            "processed_cell_count": processed,
            "authenticated_cell_count": authenticated,
            "first_failure_index": failure,
            "all_processed_cells_authenticated": bool(
                result["all_processed_cells_authenticated"]
            ),
            "drop_relative_index": metadata.get("drop_relative_index"),
            "dropped_sequence_index": metadata.get("dropped_sequence_index"),
        })

    report = {
        "schema": "tor-cgo-sequence-recovery-summary/0.1",
        "case_count": len(cases),
        "all_complete_cases_authenticated": all(
            row["all_processed_cells_authenticated"]
            for row in cases if row["drop_relative_index"] is None
        ),
        "all_loss_cases_stopped_at_omission": all(
            row["first_failure_index"] == row["drop_relative_index"]
            for row in cases if row["drop_relative_index"] is not None
        ),
        "cases": cases,
        "plaintext_included": False,
        "raw_secrets_included": False,
        "evaluation_truth_used": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
