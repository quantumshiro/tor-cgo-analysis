#!/usr/bin/env python3
"""Evaluate a truth-free, uncontrolled-timing core/PCAP replay case.

The marker is checked only after TLS and CGO authentication have selected a
unique candidate.  It is therefore an evaluation oracle, not a selector.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--path-length", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.result_dir

    executable = load(root / "executable-verification.json")
    scan = load(root / "core-scan.json")
    e3 = load(root / "e3-circuit-manifest.json")
    cgo = load(root / "secret-state.json")
    tls = load(root / "tls-secret-state.json")
    decrypt = load(root / "tls-pcap-decryption.json")
    cells = load(root / "pcap-extracted-cell.json")
    manifest = load(root / "replay-candidates.json")

    replay_rows = []
    for candidate in manifest["candidates"]:
        if candidate.get("status") != "ready":
            continue
        index = int(candidate["candidate_index"])
        result = load(root / "replay-candidates" / f"candidate-{index:03d}.json")
        replay_rows.append({
            "candidate_index": index,
            "control_circuit_id": candidate["control_circuit_id"],
            "recognized_hop": int(result["recognized_hop"]),
            "evaluation_truth_used": bool(result["evaluation_truth_used"]),
            "recovered_payload_hex": result.get("recovered_payload_hex", ""),
        })

    recognized = [row for row in replay_rows if row["recognized_hop"] >= 0]
    marker = args.marker.encode()
    marker_matches = []
    for row in recognized:
        recovered = bytes.fromhex(row["recovered_payload_hex"])
        if marker in recovered:
            marker_matches.append(row)

    e3_hash = e3["source_scan_sha256"]
    checks = {
        "candidate_executable_compatible_with_core": executable["verified"] is True,
        "owner_list_completely_enumerated": (
            scan["recovery_completeness"] == "owner_list_enumerated"
            and not scan["errors"]
            and e3["owner_list_completely_enumerated"] is True
        ),
        "secret_extractors_constrained_by_same_E3_manifest": (
            cgo["e3_manifest_enforced"] is True
            and tls["e3_manifest_enforced"] is True
            and cgo["e3_manifest_source_scan_sha256"] == e3_hash
            and tls["e3_manifest_source_scan_sha256"] == e3_hash
        ),
        "tls_record_authenticated_at_core_sequence": (
            decrypt["authenticated_tls_records"] > 0
            and decrypt["target_tor_cells_in_snapshot_sequence"] > 0
        ),
        "no_external_circuit_or_cell_selector": (
            decrypt["external_circuit_selector_used"] is False
            and cells["external_circuit_selector_used"] is False
            and manifest["external_circuit_selector_used"] is False
            and manifest["evaluation_truth_included"] is False
        ),
        "exactly_one_candidate_authenticated_by_cgo": len(recognized) == 1,
        "authenticated_candidate_contains_posthoc_marker": (
            len(recognized) == 1 and len(marker_matches) == 1
        ),
        "recognized_hop_matches_path_length": (
            len(recognized) == 1
            and recognized[0]["recognized_hop"] == args.path_length - 1
        ),
        "replay_fixture_excluded_evaluation_truth": all(
            row["evaluation_truth_used"] is False for row in replay_rows
        ),
    }
    structural = all(checks[name] for name in (
        "candidate_executable_compatible_with_core",
        "owner_list_completely_enumerated",
        "secret_extractors_constrained_by_same_E3_manifest",
        "no_external_circuit_or_cell_selector",
        "replay_fixture_excluded_evaluation_truth",
    ))
    authenticated = (
        structural
        and checks["tls_record_authenticated_at_core_sequence"]
        and checks["exactly_one_candidate_authenticated_by_cgo"]
    )
    success = authenticated and checks["authenticated_candidate_contains_posthoc_marker"]
    status = (
        "recovered_authenticated_marker" if success
        else "safe_stop_no_unique_authenticated_candidate" if structural
        else "invalid_evidence_chain"
    )

    selected = recognized[0] if len(recognized) == 1 else None
    tls_rows = tls.get("circuits", [tls])
    selected_tls = None
    if selected is not None:
        selected_tls = next(
            (row for row in tls_rows
             if row["control_circuit_id"] == selected["control_circuit_id"]),
            None,
        )
    report = {
        "schema": "tor-cgo-uncontrolled-pcap-core-replay/0.1",
        "status": status,
        "success": success,
        "checks": checks,
        "path_length": args.path_length,
        "offline_candidate_count": len(cells["cells"]),
        "cgo_authenticated_candidate_count": len(recognized),
        "marker_match_count_after_authentication": len(marker_matches),
        "recognized_hop": selected["recognized_hop"] if selected else None,
        "control_circuit_id": selected["control_circuit_id"] if selected else None,
        "tls_write_sequence_at_core": selected_tls["write_sequence"] if selected_tls else None,
        "authenticated_tls_records": decrypt["authenticated_tls_records"],
        "evidence_stages": {
            "E1": checks["owner_list_completely_enumerated"],
            "E2": checks["owner_list_completely_enumerated"],
            "E3": structural,
            "E4": structural and checks["tls_record_authenticated_at_core_sequence"],
            "E5": authenticated,
        },
        "evaluation_boundary": (
            "No dynamic cell truth or Control Protocol circuit selector enters recovery; "
            "the controlled marker is tested only after unique CGO authentication."
        ),
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
