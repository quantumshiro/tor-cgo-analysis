#!/usr/bin/env python3
"""Relate a snapshot's queues and buffers to the first CGO-authenticated cell."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--anchor-manifest", type=Path, required=True)
    parser.add_argument("--anchor-result-dir", type=Path, required=True)
    parser.add_argument("--acquisition", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scan = load(args.scan)
    cells_doc = load(args.cells)
    manifest = load(args.anchor_manifest)
    cells_by_candidate = {
        index: row for index, row in enumerate(cells_doc["cells"])
    }
    recognized = []
    for candidate in manifest["candidates"]:
        if candidate.get("status") != "ready":
            continue
        index = int(candidate["candidate_index"])
        result_path = args.anchor_result_dir / f"candidate-{index:05d}.json"
        result = load(result_path)
        if int(result["recognized_hop"]) >= 0:
            recognized.append({
                **candidate,
                "recognized_hop": int(result["recognized_hop"]),
                "result": str(result_path),
            })

    if len(recognized) == 1:
        anchor = recognized[0]
        control_id = int(anchor["control_circuit_id"])
        sequence_index = int(anchor["sequence_index"])
        classification = (
            "snapshot_state_matches_first_captured_candidate"
            if sequence_index == 0
            else "snapshot_state_matches_after_earlier_captured_candidates"
        )
    else:
        anchor = None
        control_id = None
        sequence_index = None
        classification = (
            "no_cgo_authenticated_candidate" if not recognized
            else "multiple_cgo_authenticated_candidates"
        )

    circuit = None
    if control_id is not None:
        circuit = next(
            (row for row in scan["circuits"]
             if int(row["control_circuit_id"]) == control_id),
            None,
        )
    queue = circuit.get("outbound_cell_queue", {}) if circuit else {}
    buffers = circuit.get("entry_channel_buffers", {}) if circuit else {}
    queued_hashes = {
        row["wire_sha256"]: row for row in queue.get("cells", [])
    }
    earlier_cells = []
    queue_matches = []
    if anchor is not None:
        anchor_id = int(anchor["anchor_id"])
        for candidate_index, cell in cells_by_candidate.items():
            if (
                int(cell["control_circuit_id"]) == control_id
                and int(cell["anchor_id"]) == anchor_id
                and int(cell["sequence_index"]) < sequence_index
            ):
                row = {
                    "candidate_index": candidate_index,
                    "sequence_index": int(cell["sequence_index"]),
                    "wire_sha256": cell["wire_sha256"],
                }
                earlier_cells.append(row)
                if cell["wire_sha256"] in queued_hashes:
                    queue_matches.append({
                        **row,
                        "queue_index": queued_hashes[cell["wire_sha256"]][
                            "queue_index"
                        ],
                    })

    report = {
        "schema": "tor-cgo-snapshot-correspondence/0.1",
        "classification": classification,
        "cgo_authenticated_anchor_count": len(recognized),
        "authenticated_anchor": anchor,
        "captured_target_cells_before_anchor": len(earlier_cells),
        "earlier_captured_cells": earlier_cells,
        "earlier_cells_found_in_snapshot_circuit_queue": len(queue_matches),
        "queue_matches": queue_matches,
        "snapshot_circuit_queue": {
            "declared_cell_count": queue.get("declared_cell_count"),
            "enumerated_cell_count": queue.get("enumerated_cell_count"),
            "enumeration_complete": queue.get("enumeration_complete"),
        },
        "snapshot_entry_connection": {
            "output_buffer_bytes": buffers.get("output_buffer_bytes"),
            "input_buffer_bytes": buffers.get("input_buffer_bytes"),
            "bytes_xmitted": buffers.get("bytes_xmitted"),
            "bytes_xmitted_by_tls": buffers.get("bytes_xmitted_by_tls"),
        },
        "snapshot_circuit_blocked_on_entry_channel": (
            circuit.get("circuit_blocked_on_entry_channel") if circuit else None
        ),
        "interpretation": (
            "A pre-anchor hash match proves that CGO had advanced before the "
            "corresponding Tor cell left the circuit queue. Unmatched pre-anchor "
            "cells may already have moved to the shared TLS output buffer or the "
            "kernel and are not attributed from buffer occupancy alone."
        ),
        "evaluation_truth_used_for_candidate_selection": False,
    }
    if args.acquisition is not None:
        acquisition = load(args.acquisition)
        selected_boundary = bool(
            acquisition.get("snapshot_boundary_selected_from_cell_processing")
        )
        report["posthoc_evaluation"] = {
            "snapshot_mode": acquisition.get("snapshot_mode"),
            "dynamic_cell_hook_used": acquisition.get("dynamic_cell_hook_used"),
            "snapshot_boundary_selected_from_cell_processing": selected_boundary,
            "consistent_with_observation": (
                sequence_index == 1 if selected_boundary else None
            ),
            "expected_boundary": (
                "after CGO state update and before circuit-queue insertion"
                if selected_boundary else None
            ),
            "used_for_candidate_selection": False,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
