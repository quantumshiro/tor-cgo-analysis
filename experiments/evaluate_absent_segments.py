#!/usr/bin/env python3
"""Summarize fail-closed behavior for genuinely absent core PT_LOAD segments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", nargs=2, action="append", metavar=("LABEL", "DIR"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for label, directory in args.case:
        root = Path(directory)
        mutation = json.loads((root / "mutation.json").read_text())
        scan = json.loads((root / "scan.json").read_text())
        rows.append({
            "label": label,
            "removed_program_header_index": mutation["removed_segment"]["program_header_index"],
            "removed_virtual_address": mutation["removed_segment"]["virtual_address"],
            "recovery_completeness": scan["recovery_completeness"],
            "reported_errors": scan["errors"],
            "reported_circuits": len(scan["circuits"]),
            "false_valid_acceptances": sum(
                circuit.get("highest_core_evidence_level") in ("E2", "E3")
                for circuit in scan["circuits"]
            ),
            "failed_closed": (
                scan["recovery_completeness"] == "owner_list_unavailable"
                and len(scan["circuits"]) == 0
                and bool(scan["errors"])
            ),
        })
    report = {
        "schema": "tor-cgo-absent-core-segment-evaluation/0.1",
        "scope": "PT_LOAD containing the selected evidence was changed to PT_NULL, making the range unavailable to the core reader rather than zero-filled",
        "cases": rows,
        "all_failed_closed": all(row["failed_closed"] for row in rows),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
