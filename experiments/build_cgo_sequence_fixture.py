#!/usr/bin/env python3
"""Build a CGR3 fixture for stateful replay from a CGO-authenticated anchor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path


def load_unique_anchor(
    manifest: dict, result_dir: Path, control_circuit_id: int | None
) -> dict:
    recognized = []
    for candidate in manifest["candidates"]:
        if candidate.get("status") != "ready":
            continue
        if (
            control_circuit_id is not None
            and int(candidate["control_circuit_id"]) != control_circuit_id
        ):
            continue
        index = int(candidate["candidate_index"])
        result = json.loads(
            (result_dir / f"candidate-{index:05d}.json").read_text()
        )
        if int(result["recognized_hop"]) >= 0:
            recognized.append({**candidate, "recognized_hop": int(result["recognized_hop"])})
    if len(recognized) != 1:
        raise ValueError(
            f"expected one CGO-authenticated anchor; observed {len(recognized)}"
        )
    return recognized[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--states", type=Path, required=True)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--anchor-manifest", type=Path)
    parser.add_argument("--anchor-result-dir", type=Path)
    parser.add_argument("--start-at-first-candidate", action="store_true")
    parser.add_argument("--control-circuit-id", type=int)
    parser.add_argument("--max-cells", type=int, default=1000)
    parser.add_argument("--drop-relative-index", type=int)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    if args.max_cells < 1:
        raise SystemExit("--max-cells must be positive")

    state_doc = json.loads(args.states.read_text())
    cell_doc = json.loads(args.cells.read_text())
    if args.start_at_first_candidate:
        pairs = {
            (int(row["control_circuit_id"]), int(row["anchor_id"]))
            for row in cell_doc["cells"]
        }
        if len(pairs) != 1:
            raise SystemExit(
                "--start-at-first-candidate requires one circuit and TLS anchor"
            )
        control_id, anchor_id = pairs.pop()
        start = 0
        anchor = {"recognized_hop": None}
        anchor_pre_authenticated = False
    else:
        if args.anchor_manifest is None or args.anchor_result_dir is None:
            raise SystemExit(
                "--anchor-manifest and --anchor-result-dir are required unless "
                "starting at the first candidate"
            )
        manifest = json.loads(args.anchor_manifest.read_text())
        try:
            anchor = load_unique_anchor(
                manifest, args.anchor_result_dir, args.control_circuit_id
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        control_id = int(anchor["control_circuit_id"])
        anchor_id = int(anchor["anchor_id"])
        start = int(anchor["sequence_index"])
        anchor_pre_authenticated = True
    if (
        args.control_circuit_id is not None
        and control_id != args.control_circuit_id
    ):
        raise SystemExit("selected anchor does not match --control-circuit-id")
    state = next(
        row for row in state_doc.get("circuits", [state_doc])
        if int(row["control_circuit_id"]) == control_id
    )
    hops = state["hops"]
    if not (1 <= len(hops) <= 3):
        raise SystemExit("fixture requires one to three hops")
    selected = [
        row for row in cell_doc["cells"]
        if int(row["control_circuit_id"]) == control_id
        and int(row["anchor_id"]) == anchor_id
        and int(row["sequence_index"]) >= start
    ]
    selected.sort(key=lambda row: int(row["sequence_index"]))
    selected = selected[:args.max_cells]
    dropped = None
    if args.drop_relative_index is not None:
        if not (0 <= args.drop_relative_index < len(selected)):
            raise SystemExit("--drop-relative-index is outside the selected sequence")
        dropped = selected.pop(args.drop_relative_index)

    blob = bytearray(b"CGR3" + bytes([len(hops), 0, 0, 0]))
    blob.extend(struct.pack("!I", len(selected)))
    secret_hashes = []
    for hop in hops:
        raw = bytes.fromhex(hop["forward"]["state_hex"])
        tprime = bytes.fromhex(hop["forward"]["tprime_hex"])
        if len(raw) != 80 or len(tprime) != 16:
            raise SystemExit("invalid CGO state length")
        blob.extend(raw)
        blob.extend(tprime)
        secret_hashes.append({
            "index_from_entry": hop["index_from_entry"],
            "state_sha256": hashlib.sha256(raw).hexdigest(),
            "tprime_sha256": hashlib.sha256(tprime).hexdigest(),
        })
    cell_hashes = []
    for row in selected:
        payload = bytes.fromhex(row["payload_hex"])
        if len(payload) != 509:
            raise SystemExit("invalid Tor cell payload length")
        blob.extend(bytes([int(row["command"]), 0, 0, 0]))
        blob.extend(payload)
        cell_hashes.append({
            "sequence_index": int(row["sequence_index"]),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        })

    metadata = {
        "schema": "tor-cgo-stateful-replay-fixture/0.1",
        "fixture_sha256": hashlib.sha256(blob).hexdigest(),
        "fixture_size": len(blob),
        "control_circuit_id": control_id,
        "entry_link_circuit_id": state["entry_link_circuit_id"],
        "anchor_id": anchor_id,
        "authenticated_anchor_sequence_index": start,
        "authenticated_anchor_hop": anchor["recognized_hop"],
        "anchor_pre_authenticated": anchor_pre_authenticated,
        "captured_candidates_skipped_before_anchor": start,
        "cell_count": len(selected),
        "drop_relative_index": args.drop_relative_index,
        "dropped_sequence_index": (
            int(dropped["sequence_index"]) if dropped is not None else None
        ),
        "secret_component_hashes": secret_hashes,
        "cell_hashes": cell_hashes,
        "evaluation_truth_included": False,
        "external_circuit_selector_used": False,
    }
    args.fixture.parent.mkdir(parents=True, exist_ok=True)
    args.fixture.write_bytes(blob)
    os.chmod(args.fixture, 0o600)
    args.metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
