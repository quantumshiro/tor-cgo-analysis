#!/usr/bin/env python3
"""Run independent CGO anchor candidates with bounded parallelism."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def run_one(
    candidate: dict,
    fixture_dir: Path,
    result_dir: Path,
    replay_binary: Path,
    test_name: str,
) -> dict:
    index = int(candidate["candidate_index"])
    stem = f"candidate-{index:05d}"
    fixture = fixture_dir / f"{stem}.bin"
    result = result_dir / f"{stem}.json"
    log = result_dir / f"{stem}.log"
    if result.exists():
        row = json.loads(result.read_text())
        return {"candidate_index": index, "status": "existing", **row}

    env = os.environ.copy()
    env["CGO_REPLAY_FIXTURE"] = str(fixture)
    env["CGO_REPLAY_RESULT"] = str(result)
    with log.open("wb") as output:
        completed = subprocess.run(
            [str(replay_binary), test_name],
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if completed.returncode != 0 or not result.exists():
        return {
            "candidate_index": index,
            "status": "failed",
            "returncode": completed.returncode,
            "log": str(log),
        }
    row = json.loads(result.read_text())
    return {"candidate_index": index, "status": "completed", **row}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--replay-binary", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument(
        "--test-name",
        default="crypto/cgo/cgo_external_core_replay",
    )
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    candidates = [
        row for row in manifest["candidates"] if row.get("status") == "ready"
    ]
    args.result_dir.mkdir(parents=True, exist_ok=True)
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
        futures = [
            executor.submit(
                run_one,
                candidate,
                args.fixture_dir,
                args.result_dir,
                args.replay_binary,
                args.test_name,
            )
            for candidate in candidates
        ]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda row: int(row["candidate_index"]))
    recognized = [
        {
            "candidate_index": int(row["candidate_index"]),
            "recognized_hop": int(row["recognized_hop"]),
        }
        for row in results
        if row.get("status") != "failed"
        and int(row.get("recognized_hop", -1)) >= 0
    ]
    summary = {
        "schema": "tor-cgo-anchor-search/0.1",
        "candidate_count": len(candidates),
        "completed_count": sum(
            row.get("status") != "failed" for row in results
        ),
        "failed_count": sum(row.get("status") == "failed" for row in results),
        "recognized_count": len(recognized),
        "recognized": recognized,
        "evaluation_truth_used": False,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
