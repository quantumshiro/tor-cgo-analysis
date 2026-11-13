#!/usr/bin/env python3
"""Evaluate a truth-free, uncontrolled-timing core/PCAP replay case.

The marker is checked only after TLS and CGO authentication have selected a
unique candidate.  It is therefore an evaluation oracle, not a selector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--path-length", type=int, required=True)
    parser.add_argument(
        "--replay-dir", type=Path, default=Path("replay-candidates")
    )
    parser.add_argument("--replay-build", type=Path)
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
        result = load(root / args.replay_dir / f"candidate-{index:03d}.json")
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
        if len(recovered) != 509:
            raise SystemExit(
                f"candidate {row['candidate_index']} returned {len(recovered)} bytes; "
                "expected one 509-byte relay cell payload"
            )
        relay_body = recovered[16:]
        row["relay_body_length"] = len(relay_body)
        row["relay_body_sha256"] = hashlib.sha256(relay_body).hexdigest()
        row["relay_command_code"] = relay_body[0]
        row["relay_command_name"] = {
            2: "DATA",
            5: "SENDME",
        }.get(relay_body[0], f"UNKNOWN_{relay_body[0]}")
        if marker in relay_body:
            marker_matches.append(row)

    e3_hash = e3["source_scan_sha256"]
    checks = {
        "candidate_executable_compatible_with_core": executable["verified"] is True,
        "owner_list_completely_enumerated": (
            scan["recovery_completeness"] == "owner_list_enumerated"
            and not scan["errors"]
            and e3["owner_list_completely_enumerated"] is True
        ),
        "secret_extractors_constrained_by_same_verified_circuit_list": (
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
    scan_by_control_id = {
        int(circuit["control_circuit_id"]): circuit
        for circuit in scan["circuits"]
    }
    admitted_circuits = [
        scan_by_control_id.get(int(circuit["control_circuit_id"]))
        for circuit in e3["circuits"]
    ]
    checks["all_admitted_circuits_have_valid_owner_and_path_structure"] = (
        bool(admitted_circuits)
        and all(circuit is not None for circuit in admitted_circuits)
        and all(
            circuit["evidence"].get(
                "E2_origin_magic_index_and_entry_path_valid"
            ) is True
            for circuit in admitted_circuits
        )
    )
    checks["all_admitted_circuits_have_initialized_cgo_contexts"] = (
        bool(admitted_circuits)
        and all(circuit is not None for circuit in admitted_circuits)
        and all(
            circuit["evidence"].get(
                "E3_all_hops_open_with_instantiated_crypto"
            ) is True
            for circuit in admitted_circuits
        )
    )
    structural = all(checks[name] for name in (
        "candidate_executable_compatible_with_core",
        "owner_list_completely_enumerated",
        "all_admitted_circuits_have_valid_owner_and_path_structure",
        "all_admitted_circuits_have_initialized_cgo_contexts",
        "secret_extractors_constrained_by_same_verified_circuit_list",
        "no_external_circuit_or_cell_selector",
        "replay_fixture_excluded_evaluation_truth",
    ))
    authenticated = (
        structural
        and checks["tls_record_authenticated_at_core_sequence"]
        and checks["exactly_one_candidate_authenticated_by_cgo"]
    )
    marker_bearing_body_recovered = (
        authenticated and checks["authenticated_candidate_contains_posthoc_marker"]
    )
    status = (
        "recovered_marker_bearing_relay_body" if marker_bearing_body_recovered
        else "authenticated_marker_absent_relay_body" if authenticated
        else "no_unique_authenticated_candidate" if structural
        else "verification_prerequisite_failed"
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
        "schema": "tor-cgo-uncontrolled-pcap-core-replay/0.4",
        "status": status,
        "cgo_authentication_succeeded": authenticated,
        "marker_bearing_relay_body_recovered": marker_bearing_body_recovered,
        "checks": checks,
        "path_length": args.path_length,
        "offline_candidate_count": len(cells["cells"]),
        "cgo_authenticated_candidate_count": len(recognized),
        "marker_match_count_after_authentication": len(marker_matches),
        "recognized_hop": selected["recognized_hop"] if selected else None,
        "relay_body_length": selected.get("relay_body_length") if selected else None,
        "relay_body_sha256": selected.get("relay_body_sha256") if selected else None,
        "relay_command_code": selected.get("relay_command_code") if selected else None,
        "relay_command_name": selected.get("relay_command_name") if selected else None,
        "control_circuit_id": selected["control_circuit_id"] if selected else None,
        "tls_write_sequence_at_core": selected_tls["write_sequence"] if selected_tls else None,
        "authenticated_tls_records": decrypt["authenticated_tls_records"],
        "verification_results": {
            "owner_list_completely_enumerated": checks[
                "owner_list_completely_enumerated"
            ],
            "circuit_owner_and_path_structure_valid": checks[
                "all_admitted_circuits_have_valid_owner_and_path_structure"
            ],
            "cgo_contexts_initialized": checks[
                "all_admitted_circuits_have_initialized_cgo_contexts"
            ],
            "tls_record_authenticated_at_core_sequence": (
                structural and checks["tls_record_authenticated_at_core_sequence"]
            ),
            "exactly_one_relay_body_authenticated_by_cgo": authenticated,
            "marker_bearing_relay_body_recovered_posthoc": (
                marker_bearing_body_recovered
            ),
        },
        "evaluation_boundary": (
            "No dynamic cell truth or Control Protocol circuit selector enters recovery; "
            "the controlled marker is tested only after unique CGO authentication."
        ),
    }
    if args.replay_build:
        build = load(args.replay_build)
        report["replay_build"] = {
            "tor_version": build["tor_version"],
            "binary_sha256": build["binary_sha256"],
            "source_archive_sha256": build["source_archive_sha256"],
            "test_overlay_sha256": build["test_overlay_sha256"],
        }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
