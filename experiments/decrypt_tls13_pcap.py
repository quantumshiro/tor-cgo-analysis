#!/usr/bin/env python3
"""Decrypt TLS 1.3 records from a PCAP using core-extracted traffic secrets."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import struct
from collections import defaultdict
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def hkdf_expand_label(
    secret: bytes, label: bytes, length: int, algorithm: hashes.HashAlgorithm
) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(
        algorithm=algorithm, length=length, info=info
    ).derive(secret)


def packets(path: Path):
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("unsupported PCAP encoding")
    off = 24
    while off + 16 <= len(data):
        _sec, _usec, captured, _original = struct.unpack_from("<IIII", data, off)
        off += 16
        yield data[off : off + captured]
        off += captured
    if off != len(data):
        raise ValueError("truncated PCAP")


def tcp_segment(frame: bytes):
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[9] != 6:
        return None
    ihl = (ip[0] & 15) * 4
    total = struct.unpack_from("!H", ip, 2)[0]
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    src_port, dst_port, seq = struct.unpack_from("!HHI", tcp, 0)
    doff = (tcp[12] >> 4) * 4
    return (
        str(ipaddress.ip_address(ip[12:16])), src_port,
        str(ipaddress.ip_address(ip[16:20])), dst_port,
    ), seq, tcp[doff:]


def reassemble(path: Path):
    streams = defaultdict(dict)
    for frame in packets(path):
        parsed = tcp_segment(frame)
        if parsed is None:
            continue
        key, seq, payload = parsed
        if payload:
            streams[key].setdefault(seq, payload)
    return {
        key: b"".join(parts[seq] for seq in sorted(parts))
        for key, parts in streams.items()
    }


def tls_records(stream: bytes):
    off = 0
    record_index = 0
    while off + 5 <= len(stream):
        content_type = stream[off]
        version = stream[off + 1 : off + 3]
        length = struct.unpack_from("!H", stream, off + 3)[0]
        if (
            content_type not in (20, 21, 22, 23)
            or version not in (b"\x03\x01", b"\x03\x03")
            or length > 18432
            or off + 5 + length > len(stream)
        ):
            off += 1
            continue
        header = stream[off : off + 5]
        body = stream[off + 5 : off + 5 + length]
        yield record_index, off, header, body
        record_index += 1
        off += 5 + length


def decrypt_record(key: bytes, iv: bytes, sequence: int, header: bytes, body: bytes):
    nonce = bytearray(iv)
    seq = sequence.to_bytes(12, "big")
    for i in range(12):
        nonce[i] ^= seq[i]
    plaintext = AESGCM(key).decrypt(bytes(nonce), body, header)
    end = len(plaintext) - 1
    while end >= 0 and plaintext[end] == 0:
        end -= 1
    if end < 0:
        raise ValueError("empty TLSInnerPlaintext")
    return plaintext[:end], plaintext[end]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", type=Path, required=True)
    p.add_argument("--tls-state", type=Path, required=True)
    p.add_argument("--cgo-state", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cell-output", type=Path, required=True)
    p.add_argument("--decrypted-output", type=Path)
    args = p.parse_args()

    state_doc = json.loads(args.tls_state.read_text())
    states = state_doc.get("circuits", [state_doc])
    if not state_doc.get("raw_secrets_included") and not all(
        state.get("raw_secrets_included") for state in states
    ):
        raise SystemExit("raw TLS secrets are required")
    if args.cgo_state:
        cgo_doc = json.loads(args.cgo_state.read_text())
        cgo_ids = {
            row["control_circuit_id"] for row in cgo_doc.get("circuits", [cgo_doc])
        }
        states = [row for row in states if row["control_circuit_id"] in cgo_ids]
    if not states:
        raise SystemExit("no TLS state belongs to an extracted all-CGO circuit")
    streams = reassemble(args.pcap)
    decrypted = []
    candidates = []
    for state in states:
        secret = bytes.fromhex(state["client_traffic_secret"])
        hash_name = state["hash_algorithm"]
        cipher_suite = state["cipher_suite"]
        if cipher_suite == "TLS_AES_256_GCM_SHA384" and hash_name == "SHA384" and len(secret) == 48:
            algorithm = hashes.SHA384()
            key_length = 32
        elif cipher_suite == "TLS_AES_128_GCM_SHA256" and hash_name == "SHA256" and len(secret) == 32:
            algorithm = hashes.SHA256()
            key_length = 16
        else:
            raise SystemExit(
                "unsupported or inconsistent TLS cipher profile: "
                f"{cipher_suite}/{hash_name}/{len(secret)}"
            )
        key = hkdf_expand_label(secret, b"key", key_length, algorithm)
        iv = hkdf_expand_label(secret, b"iv", 12, algorithm)
        sequence = state["write_sequence"]
        target_circid = state["entry_link_circuit_id"]
        for flow, stream in streams.items():
            for record_index, offset, header, body in tls_records(stream):
                if header[0] != 23 or len(body) < 17:
                    continue
                try:
                    content, inner_type = decrypt_record(
                        key, iv, sequence, header, body
                    )
                except Exception:
                    continue
                row = {
                    "flow": list(flow),
                    "record_index": record_index,
                    "stream_offset": offset,
                    "traffic_secret": "client",
                    "sequence": sequence,
                    "inner_content_type": inner_type,
                    "content_length": len(content),
                    "content_sha256": __import__("hashlib").sha256(content).hexdigest(),
                    "control_circuit_id": state["control_circuit_id"],
                    "entry_link_circuit_id": target_circid,
                    "cipher_suite": cipher_suite,
                    "cipher_suite_source": state["cipher_suite_source"],
                }
                decrypted.append((row, content))
                if inner_type == 23:
                    for command in (3, 9):
                        prefix = struct.pack("!IB", target_circid, command)
                        start = 0
                        while True:
                            pos = content.find(prefix, start)
                            if pos < 0:
                                break
                            if pos + 514 <= len(content):
                                candidates.append((row, command, content[pos + 5 : pos + 514], pos))
                            start = pos + 1

    if not decrypted:
        raise SystemExit("no TLS 1.3 record authenticated at a core write sequence")
    if not candidates:
        raise SystemExit("authenticated records contain no matching all-CGO circuit cell")
    # Return every distinct candidate instead of using an external circuit ID
    # to guess which multiplexed circuit is the evaluation target.
    unique = {}
    for record, command, payload, cell_offset in candidates:
        identity = (
            record["control_circuit_id"], record["record_index"], cell_offset,
            __import__("hashlib").sha256(payload).hexdigest(),
        )
        unique.setdefault(identity, (record, command, payload, cell_offset))
    cells = []
    for candidate_index, (record, command, payload, cell_offset) in enumerate(
        sorted(unique.values(), key=lambda item: (
            item[0]["control_circuit_id"], item[0]["record_index"], item[3]
        ))
    ):
        cells.append({
            "candidate_index": candidate_index,
            "source": "offline_pcap_tls13_decryption",
            "wire": {
                "circ_id": record["entry_link_circuit_id"],
                "command": command,
                "payload_hex": payload.hex(),
            },
            "tls_record": record,
            "cell_offset_in_tls_content": cell_offset,
        })
    cell_bundle = {
        "schema": "tor-cgo-cells-extracted-from-tls-pcap/0.2",
        "selection": "all all-CGO circuit cells in TLS-authenticated client records at exact core write sequences",
        "external_circuit_selector_used": False,
        "cells": cells,
    }
    args.cell_output.write_text(
        json.dumps(cell_bundle, indent=2, sort_keys=True) + "\n"
    )
    report = {
        "schema": "tor-cgo-tls13-pcap-decryption/0.1",
        "reassembled_tcp_directions": len(streams),
        "authenticated_tls_records": len(decrypted),
        "target_tor_cells_overall": len(cells),
        "target_tor_cells_in_snapshot_sequence": len(cells),
        "candidate_control_circuit_ids": sorted({
            cell["tls_record"]["control_circuit_id"] for cell in cells
        }),
        "selection_rule": "all all-CGO circuit cells in TLS-authenticated client records at exact core write sequences",
        "external_circuit_selector_used": False,
        "raw_decrypted_content_emitted": args.decrypted_output is not None,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.decrypted_output:
        with args.decrypted_output.open("wb") as out:
            for row, content in decrypted:
                encoded = json.dumps(row, sort_keys=True).encode()
                out.write(struct.pack("!II", len(encoded), len(content)))
                out.write(encoded)
                out.write(content)
        os.chmod(args.decrypted_output, 0o600)


if __name__ == "__main__":
    main()
