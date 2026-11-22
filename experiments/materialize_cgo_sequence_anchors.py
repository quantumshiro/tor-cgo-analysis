#!/usr/bin/env python3
"""Create one single-cell CGO fixture for every TLS-authenticated candidate.

Every fixture starts from the same core-derived CGO state.  A recognized
candidate therefore identifies the first captured cell synchronized with the
snapshot without using a plaintext marker, expected hop, or Control Protocol
circuit identifier.
"""

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
        int(row["control_circuit_id"]): row
        for row in state_doc.get("circuits", [state_doc])
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for candidate_index, cell in enumerate(cell_doc["cells"]):
        control_id = int(cell["control_circuit_id"])
        state = states.get(control_id)
        if state is None:
            rows.append({
                "candidate_index": candidate_index,
                "status": "no_matching_cgo_state",
            })
            continue
        normalized = {
            "wire": {
                "circ_id": int(cell["entry_link_circuit_id"]),
                "command": int(cell["command"]),
                "payload_hex": cell["payload_hex"],
            }
        }
        blob, metadata = build_fixture({
            **state,
            "raw_secrets_included": state_doc.get(
                "raw_secrets_included", state.get("raw_secrets_included", False)
            ),
        }, normalized)
        fixture = args.output_dir / f"candidate-{candidate_index:05d}.bin"
        result = args.output_dir / f"candidate-{candidate_index:05d}.json"
        fixture.write_bytes(blob)
        os.chmod(fixture, 0o600)
        rows.append({
            "candidate_index": candidate_index,
            "anchor_id": int(cell["anchor_id"]),
            "sequence_index": int(cell["sequence_index"]),
            "control_circuit_id": control_id,
            "fixture": str(fixture),
            "result": str(result),
            "fixture_metadata": metadata,
            "status": "ready",
        })
    manifest = {
        "schema": "tor-cgo-sequence-anchor-candidates/0.1",
        "candidate_count": len(rows),
        "selection": "CGO authentication from the snapshot state for each candidate independently",
        "evaluation_truth_included": False,
        "external_circuit_selector_used": False,
        "candidates": rows,
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
