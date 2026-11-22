#!/usr/bin/env python3
"""Map a prior single-cell CGO authentication to a forward cell sequence.

The mapping uses the SHA-256 digest of the encrypted 509-byte payload.  It
does not inspect a plaintext marker, expected hop, or Control Protocol truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prior-cells", type=Path, required=True)
    parser.add_argument("--prior-result-dir", type=Path, required=True)
    parser.add_argument("--sequence-cells", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    prior_cells = json.loads(args.prior_cells.read_text())["cells"]
    authenticated = []
    for result_path in sorted(args.prior_result_dir.glob("candidate-*.json")):
        result = json.loads(result_path.read_text())
        if int(result["recognized_hop"]) < 0:
            continue
        prior_index = int(result_path.stem.split("-")[-1])
        cell = prior_cells[prior_index]
        payload = bytes.fromhex(cell["wire"]["payload_hex"])
        authenticated.append({
            "prior_candidate_index": prior_index,
            "recognized_hop": int(result["recognized_hop"]),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "evaluation_truth_used": bool(result["evaluation_truth_used"]),
        })
    if len(authenticated) != 1:
        raise SystemExit(
            f"expected one prior CGO-authenticated cell; observed {len(authenticated)}"
        )
    prior = authenticated[0]
    if prior["evaluation_truth_used"]:
        raise SystemExit("prior replay result used evaluation truth")

    sequence = json.loads(args.sequence_cells.read_text())["cells"]
    matches = [
        (index, cell) for index, cell in enumerate(sequence)
        if cell["payload_sha256"] == prior["payload_sha256"]
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one encrypted-payload hash match; observed {len(matches)}"
        )
    candidate_index, cell = matches[0]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    result_path = args.output_dir / f"candidate-{candidate_index:05d}.json"
    result = {
        "schema": "tor-cgo-mapped-authenticated-anchor/0.1",
        "recognized_hop": prior["recognized_hop"],
        "payload_sha256": prior["payload_sha256"],
        "prior_candidate_index": prior["prior_candidate_index"],
        "sequence_candidate_index": candidate_index,
        "mapping": "SHA-256 of the encrypted 509-byte Tor cell payload",
        "evaluation_truth_used": False,
    }
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    manifest = {
        "schema": "tor-cgo-sequence-anchor-candidates/0.1",
        "candidate_count": 1,
        "selection": "prior unique CGO authentication mapped by encrypted-payload SHA-256",
        "evaluation_truth_included": False,
        "external_circuit_selector_used": False,
        "candidates": [{
            "candidate_index": candidate_index,
            "anchor_id": int(cell["anchor_id"]),
            "sequence_index": int(cell["sequence_index"]),
            "control_circuit_id": int(cell["control_circuit_id"]),
            "result": str(result_path),
            "status": "ready",
        }],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
