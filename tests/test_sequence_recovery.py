from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

from decrypt_tls13_sequence import (  # noqa: E402
    application_stream,
    authenticate_forward_records,
    enumerate_target_cells,
)


def tls_record(key: bytes, iv: bytes, sequence: int, content: bytes) -> bytes:
    plaintext = content + b"\x17"
    header = b"\x17\x03\x03" + struct.pack("!H", len(plaintext) + 16)
    nonce = bytearray(iv)
    encoded = sequence.to_bytes(12, "big")
    for index in range(12):
        nonce[index] ^= encoded[index]
    return header + AESGCM(key).encrypt(bytes(nonce), plaintext, header)


class TLSSequenceTests(unittest.TestCase):
    def test_authentication_starts_at_snapshot_sequence_and_continues(self):
        key = bytes(range(16))
        iv = bytes(range(12))
        stream = b"".join([
            tls_record(key, iv, 4, b"before"),
            tls_record(key, iv, 5, b"first"),
            tls_record(key, iv, 6, b"second"),
        ])
        suffixes = authenticate_forward_records(stream, key, iv, 5, 20)
        self.assertEqual(len(suffixes), 1)
        self.assertEqual(
            [row["sequence"] for row in suffixes[0]["records"]], [5, 6]
        )
        self.assertEqual(
            [row["content"] for row in suffixes[0]["records"]],
            [b"first", b"second"],
        )
        self.assertEqual(suffixes[0]["stop_reason"], "end_of_capture")

    def test_authentication_stops_at_first_missing_record(self):
        key = bytes(range(16))
        iv = bytes(range(12))
        stream = b"".join([
            tls_record(key, iv, 5, b"first"),
            tls_record(key, iv, 7, b"third-with-second-missing"),
        ])
        suffixes = authenticate_forward_records(stream, key, iv, 5, 20)
        self.assertEqual(len(suffixes), 1)
        self.assertEqual(len(suffixes[0]["records"]), 1)
        self.assertEqual(
            suffixes[0]["stop_reason"],
            "next_encrypted_record_failed_authentication",
        )

    def test_tor_cell_can_span_two_authenticated_tls_records(self):
        circuit_id = 0x12345678
        wire = struct.pack("!IB", circuit_id, 3) + bytes(range(253)) * 2 + b"abc"
        self.assertEqual(len(wire), 514)
        records = [
            {
                "record_index": 8,
                "sequence": 21,
                "inner_content_type": 23,
                "content": wire[:100],
            },
            {
                "record_index": 9,
                "sequence": 22,
                "inner_content_type": 23,
                "content": wire[100:],
            },
        ]
        content, spans = application_stream(records)
        cells = enumerate_target_cells(
            content,
            spans,
            {
                "control_circuit_id": 44,
                "entry_link_circuit_id": circuit_id,
            },
            ("127.0.0.1", 1, "127.0.0.1", 2),
        )
        self.assertEqual(len(cells), 1)
        self.assertEqual(cells[0]["starts_in_record_index"], 8)
        self.assertEqual(cells[0]["ends_in_record_index"], 9)
        self.assertEqual(bytes.fromhex(cells[0]["payload_hex"]), wire[5:])


if __name__ == "__main__":
    unittest.main()
