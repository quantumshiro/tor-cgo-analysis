#!/usr/bin/env python3
"""Measure what is lost when individual evidence links are omitted."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--tls-forward", type=Path, required=True)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--anchor-search", type=Path, required=True)
    parser.add_argument("--sequence-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scan = load(args.scan)
    tls = load(args.tls_forward)
    cells = load(args.cells)["cells"]
    anchor = load(args.anchor_search)
    sequence = load(args.sequence_result)

    e3_circuits = [
        row for row in scan["circuits"]
        if row.get("evidence", {}).get(
            "E3_all_hops_open_with_instantiated_crypto"
        ) is True
        and row.get("circuit_state") == "open"
        and row.get("lifecycle") == "active"
        and row.get("hops")
        and all(hop.get("crypto_kind") == "CGO" for hop in row["hops"])
    ]
    hop_counts = Counter(len(row["hops"]) for row in e3_circuits)
    target_cells = len(cells)
    target_control_ids = {int(row["control_circuit_id"]) for row in cells}
    target_e3_circuits = [
        row for row in e3_circuits
        if int(row["control_circuit_id"]) in target_control_ids
    ]
    authenticated_records = sum(
        int(row["authenticated_record_count"]) for row in tls["anchors"]
    )
    recognized = anchor.get("recognized", [])
    full_authenticated = int(sequence["processed_cell_count"])
    if not sequence["all_processed_cells_authenticated"]:
        full_authenticated -= 1

    report = {
        "schema": "tor-cgo-method-ablation/0.1",
        "input_counts": {
            "owned_e3_all_cgo_circuits": len(e3_circuits),
            "hop_count_distribution": {
                str(key): value for key, value in sorted(hop_counts.items())
            },
            "tls_authenticated_records_after_snapshot": authenticated_records,
            "target_relay_cell_candidates": target_cells,
            "target_owned_circuits": len(target_e3_circuits),
        },
        "full_method": {
            "cgo_authenticated_anchor_count": len(recognized),
            "statefully_authenticated_cells": full_authenticated,
            "first_failure_index": sequence["first_failure_index"],
        },
        "ablations": [
            {
                "omitted_evidence": "Tor ownership list",
                "remaining_output": "unattributed structures and cryptographic values",
                "lost_conclusion": (
                    "membership in Tor's owned origin-circuit set at acquisition"
                ),
                "quantitative_substitute_available": False,
                "reason": (
                    "the same bytes do not contain an independent ownership label"
                ),
            },
            {
                "omitted_evidence": "entry-oriented cpath head and links",
                "remaining_interpretations_per_three_hop_circuit": 3,
                "lost_conclusion": "which rotation starts at the entry hop",
            },
            {
                "omitted_evidence": "snapshot TLS write-record sequence",
                "remaining_authenticated_record_positions": authenticated_records,
                "lost_conclusion": (
                    "which authenticated TLS position corresponds to acquisition"
                ),
                "note": (
                    "record authentication may still be attempted if sequence "
                    "numbers can be inferred or searched, but it no longer anchors "
                    "the record to the snapshot"
                ),
            },
            {
                "omitted_evidence": "CGO authentication tag",
                "remaining_candidate_hop_outputs": sum(
                    len(row["hops"]) for row in target_e3_circuits
                ) * target_cells,
                "lost_conclusion": (
                    "which candidate and destination hop are cryptographically valid"
                ),
            },
            {
                "omitted_evidence": "CGO state update after the anchor",
                "independently_authenticated_snapshot_anchors": len(recognized),
                "statefully_authenticated_cells_with_full_method": (
                    full_authenticated
                ),
                "lost_conclusion": (
                    "continuous recovery after the first synchronized cell"
                ),
            },
        ],
        "evaluation_truth_used": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
