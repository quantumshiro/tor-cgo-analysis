#!/usr/bin/env python3
"""Build a CGO replay fixture from offline evidence only.

The fixture deliberately excludes the evaluation hop and plaintext.  Those
values belong to the separate evaluator and must never be visible to the
replay process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def build_fixture(state: dict, cell: dict) -> tuple[bytes, dict]:
    """Return a truth-free CGR2 blob and non-secret metadata."""
    hops = state["hops"]
    if not (1 <= len(hops) <= 3) or not state["raw_secrets_included"]:
        raise ValueError("fixture requires one to three raw forward states")
    command = cell["wire"]["command"]
    if cell["wire"]["circ_id"] != state["entry_link_circuit_id"]:
        raise ValueError("entry circuit ID mismatch")

    blob = bytearray(b"CGR2" + bytes([len(hops), command, 0, 0]))
    secret_hashes = []
    for hop in hops:
        forward = hop["forward"]
        raw = bytes.fromhex(forward["state_hex"])
        tprime = bytes.fromhex(forward["tprime_hex"])
        if len(raw) != 80 or len(tprime) != 16:
            raise ValueError("invalid state length")
        blob.extend(raw)
        blob.extend(tprime)
        secret_hashes.append({
            "index_from_entry": hop["index_from_entry"],
            "state_sha256": hashlib.sha256(raw).hexdigest(),
            "tprime_sha256": hashlib.sha256(tprime).hexdigest(),
        })
    wire = bytes.fromhex(cell["wire"]["payload_hex"])
    if len(wire) != 509:
        raise ValueError("invalid cell payload length")
    blob.extend(wire)
    metadata = {
        "schema": "tor-cgo-replay-fixture-metadata/0.2",
        "fixture_sha256": hashlib.sha256(blob).hexdigest(),
        "fixture_size": len(blob),
        "control_circuit_id": state["control_circuit_id"],
        "entry_link_circuit_id": state["entry_link_circuit_id"],
        "command": command,
        "hop_count": len(hops),
        "secret_component_hashes": secret_hashes,
        "evaluation_truth_included": False,
        "raw_secrets_omitted_from_metadata": True,
    }
    return bytes(blob), metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--cell", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()

    state = json.loads(args.state.read_text())
    cell = json.loads(args.cell.read_text())
    try:
        blob, metadata = build_fixture(state, cell)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    args.fixture.parent.mkdir(parents=True, exist_ok=True)
    args.fixture.write_bytes(blob)
    os.chmod(args.fixture, 0o600)
    args.metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
