#!/usr/bin/env python3
"""Exercise fail-closed TLS controls against the offline recovery stage."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
from pathlib import Path


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run_case(
    tool: Path, label: str, state: Path, cgo: Path, pcap: Path, out: Path,
    expected_acceptance: bool,
) -> dict:
    completed = subprocess.run([
        sys.executable, str(tool), "--pcap", str(pcap), "--tls-state", str(state),
        "--cgo-state", str(cgo), "--output", str(out / f"{label}-report.json"),
        "--cell-output", str(out / f"{label}-cells.json"),
    ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    accepted = completed.returncode == 0
    return {
        "label": label,
        "exit_status": completed.returncode,
        "authenticated_or_selected": accepted,
        "diagnostic": completed.stdout.strip(),
        "expected_acceptance": expected_acceptance,
        "meets_expectation": accepted == expected_acceptance,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tls-state", type=Path, required=True)
    parser.add_argument("--other-tls-state", type=Path, required=True)
    parser.add_argument("--cgo-state", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    tool = Path(__file__).with_name("decrypt_tls13_pcap.py")
    original = json.loads(args.tls_state.read_text())

    wrong_secret = copy.deepcopy(original)
    for row in wrong_secret.get("circuits", [wrong_secret]):
        secret = bytearray.fromhex(row["client_traffic_secret"])
        secret[0] ^= 1
        row["client_traffic_secret"] = secret.hex()
    wrong_secret_path = args.output_dir / "wrong-secret-state.json"
    write_json(wrong_secret_path, wrong_secret)

    wrong_sequence = copy.deepcopy(original)
    for row in wrong_sequence.get("circuits", [wrong_sequence]):
        row["write_sequence"] += 1
    wrong_sequence_path = args.output_dir / "wrong-sequence-state.json"
    write_json(wrong_sequence_path, wrong_sequence)

    rows = [
        run_case(tool, "wrong-secret", wrong_secret_path, args.cgo_state, args.pcap, args.output_dir, False),
        run_case(tool, "wrong-sequence", wrong_sequence_path, args.cgo_state, args.pcap, args.output_dir, True),
        run_case(tool, "other-connection", args.other_tls_state, args.cgo_state, args.pcap, args.output_dir, False),
    ]
    report = {
        "schema": "tor-cgo-tls-negative-controls/0.1",
        "cases": rows,
        "all_expectations_met": all(row["meets_expectation"] for row in rows),
        "scope": "deterministic controls for wrong client traffic secret, a later valid write sequence, and a different process connection",
        "interpretation": "AEAD rejects wrong secrets and other connections, but a later record with the correct connection secret remains cryptographically valid; temporal correctness therefore depends on the core sequence and acquisition timeline, not AEAD alone",
    }
    write_json(args.output_dir / "summary.json", report)
    if not report["all_expectations_met"]:
        raise SystemExit("a TLS control differed from its stated expectation")


if __name__ == "__main__":
    main()
