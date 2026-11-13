#!/usr/bin/env python3
"""Build the fail-closed E3 circuit manifest consumed by secret extractors.

The manifest is derived only from the ownership-first core scan.  It contains
no Control Protocol truth and no packet-derived selector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"cannot build E3 manifest: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scan_bytes = args.scan.read_bytes()
    scan = json.loads(scan_bytes)
    if scan.get("schema") != "tor-cgo-memory-forensics/0.2":
        fail("unsupported scan schema")
    owner = scan.get("global_origin_circuit_list")
    if not isinstance(owner, dict) or owner.get("bounds_valid") is not True:
        fail("owner-list bounds are not verified")
    if scan.get("recovery_completeness") != "owner_list_enumerated":
        fail("owner list was not completely enumerated")
    if scan.get("errors"):
        fail("core scan contains errors")
    circuits = scan.get("circuits", [])
    if len(circuits) != owner.get("num_used"):
        fail("enumerated circuit count differs from owner-list count")

    eligible = []
    for circuit in circuits:
        evidence = circuit.get("evidence", {})
        hops = circuit.get("hops", [])
        all_cgo = bool(hops) and all(
            hop.get("crypto_kind") == "CGO"
            and hop.get("state") == "open"
            and hop.get("forensic_crypto_state") == "CGO_established"
            and hop.get("crypto_evidence", {}).get("initialized") is True
            for hop in hops
        )
        if not (
            evidence.get("E1_owned_list_completely_enumerated") is True
            and evidence.get("E2_origin_magic_index_and_entry_path_valid") is True
            and evidence.get("E3_all_hops_open_with_instantiated_crypto") is True
            and circuit.get("circuit_state") == "open"
            and circuit.get("lifecycle") == "active"
            and all_cgo
        ):
            continue
        hop_rows = []
        for hop in hops:
            crypto = hop["crypto_evidence"]
            hop_rows.append({
                "index_from_entry": hop["index_from_entry"],
                "address": hop["address"],
                "crypto_kind": hop["crypto_kind"],
                "forward_nonce_sha256": crypto["forward_nonce_sha256"],
                "forward_tprime_sha256": crypto["forward_state_sha256"],
                "backward_nonce_sha256": crypto["backward_nonce_sha256"],
                "backward_tprime_sha256": crypto["backward_state_sha256"],
            })
        identity = {
            "owner_index": circuit["global_origin_list_index"],
            "circuit_address": circuit["address"],
            "control_circuit_id": circuit["control_circuit_id"],
            "entry_link_circuit_id": circuit["entry_link_circuit_id"],
            "entry_link_channel_id": circuit["entry_link_channel_id"],
            "hop_count": len(hop_rows),
            "hops": hop_rows,
        }
        identity["structural_state_fingerprint_sha256"] = canonical_sha256(identity)
        eligible.append(identity)

    if not eligible:
        fail("no active all-CGO circuit reached E3")
    manifest = {
        "schema": "tor-cgo-e3-circuit-manifest/0.1",
        "source": "ownership-first offline core scan",
        "source_scan": str(args.scan),
        "source_scan_sha256": hashlib.sha256(scan_bytes).hexdigest(),
        "external_circuit_selector_used": False,
        "owner_list_count": owner["num_used"],
        "owner_list_completely_enumerated": True,
        "required_evidence_level": "E3",
        "selection": "all active E3 circuits whose every open hop has instantiated CGO state",
        "circuits": eligible,
    }
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    os.chmod(args.output, 0o600)


if __name__ == "__main__":
    main()
