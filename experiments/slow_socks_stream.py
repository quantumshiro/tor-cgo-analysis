#!/usr/bin/env python3
"""Run a controlled, pausable SOCKS4 stream against a local echo server."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
from pathlib import Path


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def echo_server(listener: socket.socket, errors: list[str]) -> None:
    try:
        conn, _ = listener.accept()
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
    except Exception as exc:
        errors.append(str(exc))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socks-port", type=int, required=True)
    parser.add_argument("--echo-port", type=int, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--pause-request", type=Path, required=True)
    parser.add_argument("--paused-file", type=Path, required=True)
    parser.add_argument("--resume-file", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ip")
    parser.add_argument("--payload-prefix", default="")
    args = parser.parse_args()

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.echo_port))
    listener.listen(1)
    errors: list[str] = []
    thread = threading.Thread(target=echo_server, args=(listener, errors), daemon=True)
    thread.start()
    sent = received = iterations = 0
    started_ns = time.time_ns()

    try:
        sock = socket.socket()
        if args.source_ip:
            sock.bind((args.source_ip, 0))
        sock.settimeout(10)
        sock.connect(("127.0.0.1", args.socks_port))
        with sock:
            request = b"\x04\x01" + struct.pack("!H", args.echo_port)
            request += socket.inet_aton("127.0.0.1") + b"cgo-lab\0"
            sock.sendall(request)
            reply = recv_exact(sock, 8)
            if reply[1] != 90:
                raise RuntimeError(f"SOCKS4 rejected request: {reply.hex()}")
            sock.settimeout(10)
            args.ready_file.write_text("ready\n")
            while not args.stop_file.exists():
                if args.pause_request.exists() and not args.resume_file.exists():
                    args.paused_file.write_text("paused\n")
                    while not args.resume_file.exists() and not args.stop_file.exists():
                        time.sleep(0.01)
                    if args.stop_file.exists():
                        break
                prefix = args.payload_prefix.encode("utf-8")
                if len(prefix) > 4096:
                    raise RuntimeError("payload prefix exceeds 4096 bytes")
                payload = prefix + bytes(
                    (iterations + i * 17) & 0xFF
                    for i in range(4096 - len(prefix))
                )
                sock.sendall(payload)
                sent += len(payload)
                echoed = recv_exact(sock, len(payload))
                received += len(echoed)
                if echoed != payload:
                    raise RuntimeError("echo mismatch")
                iterations += 1
                time.sleep(0.01)
    finally:
        listener.close()

    result = {
        "schema": "tor-cgo-controlled-slow-stream/0.1",
        "started_unix_ns": started_ns,
        "finished_unix_ns": time.time_ns(),
        "bytes_sent": sent,
        "bytes_received": received,
        "iterations": iterations,
        "server_errors": errors,
        "source_ip": args.source_ip,
        "payload_prefix": args.payload_prefix,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
