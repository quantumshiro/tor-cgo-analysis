#!/usr/bin/env python3
"""Authenticate a TLS 1.3 record at a snapshot sequence and continue forward.

The snapshot provides the next client write-record sequence number.  The tool
first locates the unique PCAP record that authenticates at that number.  It
then authenticates later records in wire order while incrementing the record
number.  Only after TLS authentication does it enumerate fixed-length Tor
relay cells for every all-CGO circuit recovered from the same core.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes

from decrypt_tls13_pcap import (
    decrypt_record,
    hkdf_expand_label,
    packets,
    tcp_segment,
    tls_records,
)


@dataclass(frozen=True)
class Segment:
    sequence: int
    payload: bytes


@dataclass
class ReassembledStream:
    segments: list[bytes]
    complete: bool
    gaps: list[dict[str, int]]
    conflicting_overlaps: int


def reassemble_with_gaps(path: Path) -> dict[tuple[str, int, str, int], ReassembledStream]:
    """Reassemble each TCP direction and record gaps or conflicting overlaps."""
    by_flow: dict[tuple[str, int, str, int], dict[int, bytes]] = {}
    conflicts: dict[tuple[str, int, str, int], int] = {}
    for frame in packets(path):
        parsed = tcp_segment(frame)
        if parsed is None:
            continue
        flow, sequence, payload = parsed
        if not payload:
            continue
        parts = by_flow.setdefault(flow, {})
        previous = parts.get(sequence)
        if previous is None or len(payload) > len(previous):
            if previous is not None and not payload.startswith(previous):
                conflicts[flow] = conflicts.get(flow, 0) + 1
            parts[sequence] = payload
        elif previous != payload and not previous.startswith(payload):
            conflicts[flow] = conflicts.get(flow, 0) + 1

    result: dict[tuple[str, int, str, int], ReassembledStream] = {}
    for flow, parts in by_flow.items():
        ordered = [Segment(seq, parts[seq]) for seq in sorted(parts)]
        if not ordered:
            continue
        cursor = ordered[0].sequence
        segments: list[bytearray] = [bytearray()]
        gaps: list[dict[str, int]] = []
        for segment in ordered:
            end = segment.sequence + len(segment.payload)
            if end <= cursor:
                continue
            if segment.sequence > cursor:
                gaps.append({"start_sequence": cursor, "end_sequence": segment.sequence})
                cursor = segment.sequence
                segments.append(bytearray())
            overlap = max(0, cursor - segment.sequence)
            segments[-1].extend(segment.payload[overlap:])
            cursor = end
        result[flow] = ReassembledStream(
            segments=[bytes(segment) for segment in segments if segment],
            complete=not gaps and conflicts.get(flow, 0) == 0,
            gaps=gaps,
            conflicting_overlaps=conflicts.get(flow, 0),
        )
    return result


def tls_profile(state: dict) -> tuple[bytes, bytes]:
    secret = bytes.fromhex(state["client_traffic_secret"])
    suite = state["cipher_suite"]
    hash_name = state["hash_algorithm"]
    if suite == "TLS_AES_256_GCM_SHA384" and hash_name == "SHA384" and len(secret) == 48:
        algorithm: hashes.HashAlgorithm = hashes.SHA384()
        key_length = 32
    elif suite == "TLS_AES_128_GCM_SHA256" and hash_name == "SHA256" and len(secret) == 32:
        algorithm = hashes.SHA256()
        key_length = 16
    else:
        raise ValueError(
            f"unsupported TLS profile {suite}/{hash_name}/{len(secret)}"
        )
    return (
        hkdf_expand_label(secret, b"key", key_length, algorithm),
        hkdf_expand_label(secret, b"iv", 12, algorithm),
    )


def authenticate_forward_records(
    stream: bytes,
    key: bytes,
    iv: bytes,
    snapshot_sequence: int,
    limit: int,
) -> list[dict]:
    """Return every unique authenticated suffix beginning at snapshot_sequence."""
    records = list(tls_records(stream))
    suffixes = []
    for anchor_position, (record_index, offset, header, body) in enumerate(records):
        if header[0] != 23 or len(body) < 17:
            continue
        try:
            content, inner_type = decrypt_record(
                key, iv, snapshot_sequence, header, body
            )
        except Exception:
            continue
        authenticated = [{
            "record_index": record_index,
            "stream_offset": offset,
            "sequence": snapshot_sequence,
            "inner_content_type": inner_type,
            "content": content,
        }]
        stop_reason = "record_limit"
        next_sequence = snapshot_sequence + 1
        for later in records[anchor_position + 1:]:
            if len(authenticated) >= limit:
                break
            later_index, later_offset, later_header, later_body = later
            if later_header[0] != 23:
                continue
            try:
                later_content, later_inner_type = decrypt_record(
                    key, iv, next_sequence, later_header, later_body
                )
            except Exception:
                stop_reason = "next_encrypted_record_failed_authentication"
                break
            authenticated.append({
                "record_index": later_index,
                "stream_offset": later_offset,
                "sequence": next_sequence,
                "inner_content_type": later_inner_type,
                "content": later_content,
            })
            next_sequence += 1
        else:
            stop_reason = "end_of_capture"
        suffixes.append({
            "anchor_record_index": record_index,
            "records": authenticated,
            "stop_reason": stop_reason,
        })
    return suffixes


def application_stream(records: list[dict]) -> tuple[bytes, list[dict]]:
    stream = bytearray()
    spans = []
    for row in records:
        if row["inner_content_type"] != 23:
            continue
        start = len(stream)
        stream.extend(row["content"])
        spans.append({
            "start": start,
            "end": len(stream),
            "record_index": row["record_index"],
            "sequence": row["sequence"],
        })
    return bytes(stream), spans


def containing_record(spans: list[dict], offset: int) -> dict | None:
    for span in spans:
        if span["start"] <= offset < span["end"]:
            return span
    return None


def enumerate_target_cells(
    content: bytes,
    spans: list[dict],
    state: dict,
    flow: tuple[str, int, str, int],
) -> list[dict]:
    """Enumerate complete RELAY/RELAY_EARLY cells without using truth data."""
    cells = []
    circuit_id = int(state["entry_link_circuit_id"])
    for command in (3, 9):
        prefix = struct.pack("!IB", circuit_id, command)
        start = 0
        while True:
            position = content.find(prefix, start)
            if position < 0:
                break
            end = position + 514
            if end <= len(content):
                source = containing_record(spans, position)
                last = containing_record(spans, end - 1)
                cells.append({
                    "control_circuit_id": state["control_circuit_id"],
                    "entry_link_circuit_id": circuit_id,
                    "command": command,
                    "payload_hex": content[position + 5:end].hex(),
                    "wire_sha256": hashlib.sha256(content[position:end]).hexdigest(),
                    "payload_sha256": hashlib.sha256(content[position + 5:end]).hexdigest(),
                    "application_stream_offset": position,
                    "starts_in_record_index": source["record_index"] if source else None,
                    "ends_in_record_index": last["record_index"] if last else None,
                    "starts_at_tls_sequence": source["sequence"] if source else None,
                    "flow": list(flow),
                })
            start = position + 1
    cells.sort(key=lambda row: row["application_stream_offset"])
    return cells


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--tls-state", type=Path, required=True)
    parser.add_argument("--cgo-state", type=Path, required=True)
    parser.add_argument("--record-limit", type=int, default=4096)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cell-output", type=Path, required=True)
    args = parser.parse_args()
    if args.record_limit < 1:
        raise SystemExit("--record-limit must be positive")

    tls_doc = json.loads(args.tls_state.read_text())
    cgo_doc = json.loads(args.cgo_state.read_text())
    tls_states = tls_doc.get("circuits", [tls_doc])
    cgo_ids = {
        int(row["control_circuit_id"])
        for row in cgo_doc.get("circuits", [cgo_doc])
    }
    states = [
        row for row in tls_states
        if int(row["control_circuit_id"]) in cgo_ids
    ]
    if not states:
        raise SystemExit("no TLS state belongs to an extracted all-CGO circuit")
    if not tls_doc.get("raw_secrets_included") and not all(
        row.get("raw_secrets_included") for row in states
    ):
        raise SystemExit("raw TLS secrets are required")

    streams = reassemble_with_gaps(args.pcap)
    anchors = []
    cells = []
    for state in states:
        key, iv = tls_profile(state)
        for flow, stream in streams.items():
            for segment_index, segment in enumerate(stream.segments):
                suffixes = authenticate_forward_records(
                    segment,
                    key,
                    iv,
                    int(state["write_sequence"]),
                    args.record_limit,
                )
                for suffix in suffixes:
                    if (
                        suffix["stop_reason"] == "end_of_capture"
                        and segment_index + 1 < len(stream.segments)
                    ):
                        suffix["stop_reason"] = "tcp_gap_after_authenticated_segment"
                    app_data, spans = application_stream(suffix["records"])
                    found = enumerate_target_cells(app_data, spans, state, flow)
                    anchor_id = len(anchors)
                    for index, cell in enumerate(found):
                        cell["anchor_id"] = anchor_id
                        cell["sequence_index"] = index
                    cells.extend(found)
                    anchors.append({
                        "anchor_id": anchor_id,
                        "control_circuit_id": state["control_circuit_id"],
                        "entry_link_circuit_id": state["entry_link_circuit_id"],
                        "flow": list(flow),
                        "tcp_segment_index": segment_index,
                        "snapshot_write_sequence": state["write_sequence"],
                        "anchor_record_index": suffix["anchor_record_index"],
                        "authenticated_record_count": len(suffix["records"]),
                        "last_authenticated_sequence": suffix["records"][-1]["sequence"],
                        "stop_reason": suffix["stop_reason"],
                        "application_bytes": len(app_data),
                        "target_relay_cell_candidates": len(found),
                        "authenticated_records": [{
                            key: value for key, value in row.items() if key != "content"
                        } | {
                            "content_length": len(row["content"]),
                            "content_sha256": hashlib.sha256(row["content"]).hexdigest(),
                        } for row in suffix["records"]],
                    })

    report = {
        "schema": "tor-cgo-tls13-forward-sequence/0.1",
        "pcap_sha256": hashlib.sha256(args.pcap.read_bytes()).hexdigest(),
        "reassembled_tcp_directions": len(streams),
        "complete_tcp_directions": sum(stream.complete for stream in streams.values()),
        "incomplete_tcp_directions": sum(not stream.complete for stream in streams.values()),
        "candidate_all_cgo_circuits": len(states),
        "authenticated_anchor_count": len(anchors),
        "anchors": anchors,
        "selection_rule": (
            "TLS AEAD at the core-derived write sequence, followed by consecutive "
            "record authentication; no Control Protocol circuit selector or plaintext marker"
        ),
        "external_circuit_selector_used": False,
        "evaluation_truth_used": False,
    }
    bundle = {
        "schema": "tor-cgo-forward-cell-sequences/0.1",
        "cells": cells,
        "anchors": [{
            key: value for key, value in row.items()
            if key != "authenticated_records"
        } for row in anchors],
        "external_circuit_selector_used": False,
        "evaluation_truth_used": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.cell_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.cell_output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    if not anchors:
        raise SystemExit("no contiguous TCP segment contained a TLS record authenticating at the snapshot sequence")


if __name__ == "__main__":
    main()
