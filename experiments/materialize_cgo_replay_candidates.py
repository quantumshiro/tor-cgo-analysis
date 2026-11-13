#!/usr/bin/env python3
"""Create one truth-free CGO replay fixture for every offline cell candidate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from build_cgo_replay_fixture import build_fixture


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--states", type=Path, required=True)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    state_doc = json.loads(args.states.read_text())
    cell_doc = json.loads(args.cells.read_text())
    states = {
        row["control_circuit_id"]: row
        for row in state_doc.get("circuits", [state_doc])
    }
    cells = cell_doc.get("cells", [cell_doc])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for cell in cells:
        control_id = cell["tls_record"]["control_circuit_id"]
        state = states.get(control_id)
        if state is None:
            rows.append({
                "candidate_index": cell.get("candidate_index"),
                "control_circuit_id": control_id,
                "status": "no_matching_cgo_state",
            })
            continue
        blob, metadata = build_fixture({
            **state,
            "layout": state_doc.get("layout"),
            "raw_secrets_included": state_doc.get("raw_secrets_included", False),
        }, cell)
        index = int(cell.get("candidate_index", len(rows)))
        fixture = args.output_dir / f"candidate-{index:03d}.bin"
        result = args.output_dir / f"candidate-{index:03d}.json"
        fixture.write_bytes(blob)
        os.chmod(fixture, 0o600)
        rows.append({
            "candidate_index": index,
            "control_circuit_id": control_id,
            "entry_link_circuit_id": state["entry_link_circuit_id"],
            "fixture": str(fixture),
            "result": str(result),
            "fixture_metadata": metadata,
            "status": "ready",
        })
    manifest = {
        "schema": "tor-cgo-replay-candidate-manifest/0.1",
        "evaluation_truth_included": False,
        "external_circuit_selector_used": False,
        "candidates": rows,
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
