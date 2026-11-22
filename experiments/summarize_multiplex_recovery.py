#!/usr/bin/env python3
"""Summarize recovery of circuits multiplexed over one TLS connection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--acquisition", type=Path, required=True)
    parser.add_argument("--attachments", type=Path, required=True)
    parser.add_argument("--tls-forward", type=Path, required=True)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--anchor-search", type=Path, required=True)
    parser.add_argument(
        "--sequence",
        action="append",
        nargs=3,
        metavar=("CIRCUIT_ID", "METADATA", "RESULT"),
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    acquisition = load(args.acquisition)
    attachments = load(args.attachments)
    tls = load(args.tls_forward)
    cells = load(args.cells)["cells"]
    anchor = load(args.anchor_search)
    recognized_by_circuit: dict[int, list[dict]] = {}
    # Candidate indexes refer to the ordered cell list.
    for recognized in anchor["recognized"]:
        candidate_index = int(recognized["candidate_index"])
        cell = cells[candidate_index]
        circuit_id = int(cell["control_circuit_id"])
        recognized_by_circuit.setdefault(circuit_id, []).append({
            "candidate_index": candidate_index,
            "sequence_index": int(cell["sequence_index"]),
            "recognized_hop": int(recognized["recognized_hop"]),
        })

    sequences = []
    for circuit_text, metadata_path, result_path in args.sequence:
        circuit_id = int(circuit_text)
        metadata = load(Path(metadata_path))
        result = load(Path(result_path))
        sequences.append({
            "control_circuit_id": circuit_id,
            "authenticated_anchors": recognized_by_circuit.get(circuit_id, []),
            "input_cell_count": int(metadata["cell_count"]),
            "processed_cell_count": int(result["processed_cell_count"]),
            "first_failure_index": result["first_failure_index"],
            "all_processed_cells_authenticated": bool(
                result["all_processed_cells_authenticated"]
            ),
        })

    snapshot_sequences = {
        int(row["snapshot_write_sequence"]) for row in tls["anchors"]
    }
    report = {
        "schema": "tor-cgo-multiplex-recovery/0.1",
        "controlled_circuit_count": acquisition["controlled_circuit_count"],
        "traffic_connection_count": acquisition["traffic_connection_count"],
        "attached_circuit_ids": attachments["circuits_with_attachments"],
        "shared_tls_snapshot_sequence": (
            snapshot_sequences.pop() if len(snapshot_sequences) == 1 else None
        ),
        "tls_authenticated_record_count": max(
            int(row["authenticated_record_count"]) for row in tls["anchors"]
        ),
        "tls_stop_reasons": sorted({row["stop_reason"] for row in tls["anchors"]}),
        "candidate_cell_count": len(cells),
        "circuit_results": sequences,
        "circuits_with_one_authenticated_anchor": sum(
            len(row["authenticated_anchors"]) == 1 for row in sequences
        ),
        "circuits_with_complete_available_sequence": sum(
            row["all_processed_cells_authenticated"] for row in sequences
        ),
        "capture_gap_limited_recovery": any(
            row["stop_reason"] == "tcp_gap_after_authenticated_segment"
            for row in tls["anchors"]
        ),
        "raw_secrets_included": False,
        "plaintext_included": False,
        "evaluation_truth_used_for_candidate_selection": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
