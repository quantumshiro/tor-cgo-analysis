#!/usr/bin/env python3
"""Compare archived replay outputs with the official-version replay outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    for old_path in sorted(args.root.glob("pkg-*/replay-candidates/candidate-*.json")):
        run = old_path.parent.parent.name
        new_path = old_path.parent.parent / "replay-candidates-04917" / old_path.name
        old = load(old_path)
        new = load(new_path)
        fields = ("recognized_hop", "recovered_payload_hex", "evaluation_truth_used")
        equal = all(old.get(field) == new.get(field) for field in fields)
        rows.append({
            "run": run,
            "candidate": old_path.stem,
            "equal": equal,
            "recognized_hop": new.get("recognized_hop"),
            "recovered_payload_sha256": hashlib.sha256(
                bytes.fromhex(new.get("recovered_payload_hex", ""))
            ).hexdigest(),
        })

    build = load(args.build)
    report = {
        "schema": "tor-cgo-replay-version-comparison/1.0",
        "archived_replay_base_version": "0.4.9.16",
        "new_replay_version": build["tor_version"],
        "new_binary_sha256": build["binary_sha256"],
        "candidate_outputs_compared": len(rows),
        "semantically_identical_outputs": sum(row["equal"] for row in rows),
        "comparison_fields": list(fields),
        "all_equal": all(row["equal"] for row in rows),
        "rows": rows,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
