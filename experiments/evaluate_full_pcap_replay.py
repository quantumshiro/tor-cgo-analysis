#!/usr/bin/env python3
"""Evaluate the core -> TLS -> PCAP -> CGO replay evidence chain."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--result-dir", type=Path, required=True)
    p.add_argument("--truth-cell", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    root = args.result_dir
    executable = json.loads((root / "executable-verification.json").read_text())
    scan = json.loads((root / "core-scan.json").read_text())
    e3_manifest = json.loads((root / "e3-circuit-manifest.json").read_text())
    cgo = json.loads((root / "secret-state.json").read_text())
    tls = json.loads((root / "tls-secret-state.json").read_text())
    decrypt = json.loads((root / "tls-pcap-decryption.json").read_text())
    pcap_cells = json.loads((root / "pcap-extracted-cell.json").read_text())
    truth_path = args.truth_cell or (root / "cell.json")
    truth_cell = json.loads(truth_path.read_text())
    manifest = json.loads((root / "replay-candidates.json").read_text())
    truth_matches = [
        cell for cell in pcap_cells["cells"]
        if cell["wire"]["circ_id"] == truth_cell["wire"]["circ_id"]
        and cell["wire"]["command"] == truth_cell["wire"]["command"]
        and cell["wire"]["payload_hex"] == truth_cell["wire"]["payload_hex"]
    ]
    if len(truth_matches) != 1:
        raise SystemExit(f"expected one evaluation-wire match, got {len(truth_matches)}")
    truth_candidate = truth_matches[0]
    candidate_index = truth_candidate["candidate_index"]
    replay = json.loads(
        (root / "replay-candidates" / f"candidate-{candidate_index:03d}.json").read_text()
    )
    replay_results = []
    for candidate in manifest["candidates"]:
        if candidate.get("status") != "ready":
            continue
        index = int(candidate["candidate_index"])
        result = json.loads(
            (root / "replay-candidates" / f"candidate-{index:03d}.json").read_text()
        )
        replay_results.append({
            "candidate_index": index,
            "control_circuit_id": candidate["control_circuit_id"],
            "recognized_hop": result["recognized_hop"],
            "evaluation_truth_used": result["evaluation_truth_used"],
        })
    recognized = [row for row in replay_results if row["recognized_hop"] >= 0]
    selected_id = truth_candidate["tls_record"]["control_circuit_id"]
    tls_rows = tls.get("circuits", [tls])
    selected_tls = next(
        row for row in tls_rows if row["control_circuit_id"] == selected_id
    )
    selected_cgo = next(
        row for row in cgo["circuits"] if row["control_circuit_id"] == selected_id
    )
    selected_e3 = next(
        row for row in e3_manifest["circuits"]
        if row["control_circuit_id"] == selected_id
    )
    selected_scan = next(
        row for row in scan["circuits"] if row["control_circuit_id"] == selected_id
    )
    pcap_payload = truth_candidate["wire"]["payload_hex"]
    truth_payload = truth_cell["wire"]["payload_hex"]
    recovered = bytes.fromhex(replay["recovered_payload_hex"])
    truth_plaintext = bytes.fromhex(truth_cell["plaintext"]["payload_hex"])
    expected_hop = truth_cell["plaintext"]["target_hop_index"]
    e3_hash = e3_manifest["source_scan_sha256"]
    checks = {
        "candidate_executable_compatible_with_core": executable["verified"] is True,
        "owner_list_completely_enumerated": (
            scan["recovery_completeness"] == "owner_list_enumerated"
            and not scan["errors"]
            and e3_manifest["owner_list_completely_enumerated"] is True
        ),
        "selected_circuit_reached_E1_E2_E3": (
            selected_scan["highest_core_evidence_level"] == "E3"
            and all(selected_scan["evidence"].values())
            and selected_e3["owner_index"] == selected_scan["global_origin_list_index"]
            and selected_e3["entry_link_circuit_id"] == selected_scan["entry_link_circuit_id"]
        ),
        "secret_extractors_constrained_by_same_E3_manifest": (
            cgo["e3_manifest_enforced"] is True
            and tls["e3_manifest_enforced"] is True
            and cgo["e3_manifest_source_scan_sha256"] == e3_hash
            and tls["e3_manifest_source_scan_sha256"] == e3_hash
            and selected_cgo["owner_index"] == selected_e3["owner_index"]
            and selected_tls["owner_index"] == selected_e3["owner_index"]
        ),
        "tls13_secret_extracted": selected_tls["tls_version"] == "1.3" and selected_tls["secret_length"] in (32, 48),
        "tls_cipher_suite_read_from_ssl_state": (
            selected_tls["cipher_suite_source"] == "SSL.session->cipher->id"
            and selected_tls["cipher_suite"] in (
                "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"
            )
        ),
        "tls_record_authenticated": decrypt["authenticated_tls_records"] > 0,
        "target_tor_cell_selected_by_core_sequence": decrypt["target_tor_cells_in_snapshot_sequence"] > 0,
        "external_circuit_selector_not_used": (
            decrypt["external_circuit_selector_used"] is False
            and pcap_cells["external_circuit_selector_used"] is False
            and manifest["external_circuit_selector_used"] is False
            and manifest["evaluation_truth_included"] is False
        ),
        "pcap_cell_matches_evaluation_wire_cell": pcap_payload == truth_payload,
        "replay_fixture_excluded_evaluation_truth": replay["evaluation_truth_used"] is False,
        "exactly_one_candidate_authenticated_by_cgo": len(recognized) == 1,
        "unique_authenticated_candidate_matches_posthoc_truth": (
            len(recognized) == 1
            and recognized[0]["candidate_index"] == candidate_index
        ),
        "cgo_recognized_expected_hop": replay["recognized_hop"] == expected_hop,
        "cgo_plaintext_493_bytes_match": recovered[16:] == truth_plaintext[16:],
    }
    report = {
        "schema": "tor-cgo-full-pcap-core-replay/0.3",
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "control_circuit_id": selected_tls["control_circuit_id"],
        "entry_link_circuit_id": selected_tls["entry_link_circuit_id"],
        "tls_write_sequence_at_core": selected_tls["write_sequence"],
        "selected_tls_record": truth_candidate["tls_record"],
        "offline_candidate_count": len(pcap_cells["cells"]),
        "cgo_authenticated_candidate_count": len(recognized),
        "cgo_authenticated_candidates": recognized,
        "evaluation_truth_candidate_index": candidate_index,
        "recognized_hop": replay["recognized_hop"],
        "payload_bytes_compared": 493,
        "evidence_stages": {
            "E1": checks["owner_list_completely_enumerated"],
            "E2": checks["selected_circuit_reached_E1_E2_E3"],
            "E3": (
                checks["selected_circuit_reached_E1_E2_E3"]
                and checks["secret_extractors_constrained_by_same_E3_manifest"]
            ),
            "E4": (
                checks["tls_record_authenticated"]
                and checks["target_tor_cell_selected_by_core_sequence"]
            ),
            "E5": (
                checks["exactly_one_candidate_authenticated_by_cgo"]
                and checks["cgo_recognized_expected_hop"]
                and checks["cgo_plaintext_493_bytes_match"]
            ),
        },
        "evidence_boundary": "evaluation truth is read only by this post-recovery evaluator and is absent from extraction, selection, TLS decryption, fixture, and CGO replay",
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
