#!/usr/bin/env python3
"""Capture a selected loopback TCP port into a minimal classic PCAP file."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import time
from pathlib import Path


def tcp_ports(frame: bytes) -> tuple[int, int] | None:
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 4:
        return None
    return struct.unpack("!HH", ip[ihl : ihl + 4])


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--stop-file", type=Path, required=True)
    p.add_argument("--ready-file", type=Path, required=True)
    p.add_argument("--metadata", type=Path, required=True)
    args = p.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind(("lo", 0))
    sock.settimeout(0.1)
    packets = bytes_captured = 0
    started = time.time_ns()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        args.ready_file.write_text("ready\n")
        while not args.stop_file.exists():
            try:
                frame = sock.recv(262144)
            except TimeoutError:
                continue
            ports = tcp_ports(frame)
            if ports is None or args.port not in ports:
                continue
            now = time.time_ns()
            sec, usec = divmod(now, 1_000_000_000)
            out.write(struct.pack("<IIII", sec, usec // 1000, len(frame), len(frame)))
            out.write(frame)
            packets += 1
            bytes_captured += len(frame)
    sock.close()
    args.metadata.write_text(json.dumps({
        "schema": "tor-cgo-loopback-pcap-capture/0.1",
        "port": args.port,
        "packets": packets,
        "bytes_captured": bytes_captured,
        "started_unix_ns": started,
        "finished_unix_ns": time.time_ns(),
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
