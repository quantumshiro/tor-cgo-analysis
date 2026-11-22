#!/usr/bin/env python3
"""Generate controlled full-duplex SOCKS4 traffic without per-chunk waiting."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
from pathlib import Path


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)


def echo_connection(conn: socket.socket, errors: list[str]) -> None:
    try:
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
    except Exception as exc:
        errors.append(str(exc))


def echo_server(
    listener: socket.socket,
    connection_count: int,
    errors: list[str],
) -> None:
    workers = []
    try:
        for _ in range(connection_count):
            conn, _ = listener.accept()
            worker = threading.Thread(
                target=echo_connection, args=(conn, errors), daemon=True
            )
            worker.start()
            workers.append(worker)
        for worker in workers:
            worker.join()
    except Exception as exc:
        errors.append(str(exc))


def receive_echoes(
    sock: socket.socket,
    stop: threading.Event,
    counters: dict[str, int],
    errors: list[str],
) -> None:
    try:
        while not stop.is_set():
            data = sock.recv(65536)
            if not data:
                return
            counters["bytes_received"] += len(data)
    except Exception as exc:
        errors.append(str(exc))


def send_stream(
    sock: socket.socket,
    connection_index: int,
    prefix: bytes,
    stop_file: Path,
    counters: dict[str, int],
    counter_lock: threading.Lock,
    errors: list[str],
    iteration_delay: float,
) -> None:
    receiver_stop = threading.Event()
    receiver = threading.Thread(
        target=receive_echoes,
        args=(sock, receiver_stop, counters, errors),
        daemon=True,
    )
    receiver.start()
    try:
        iteration = 0
        while not stop_file.exists():
            payload = prefix + bytes(
                (connection_index * 29 + iteration + offset * 17) & 0xFF
                for offset in range(16384 - len(prefix))
            )
            sock.sendall(payload)
            with counter_lock:
                counters["bytes_sent"] += len(payload)
                counters["iterations"] += 1
            iteration += 1
            if iteration_delay:
                time.sleep(iteration_delay)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        deadline = time.monotonic() + 2
        while (
            counters["bytes_received"] < counters["bytes_sent"]
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
    except Exception as exc:
        errors.append(str(exc))
    finally:
        receiver_stop.set()
        receiver.join(timeout=1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socks-port", type=int, required=True)
    parser.add_argument("--echo-port", type=int, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--payload-prefix", default="")
    parser.add_argument("--source-ip")
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--iteration-delay", type=float, default=0.0)
    args = parser.parse_args()
    if args.connections < 1:
        raise SystemExit("--connections must be positive")
    if args.iteration_delay < 0:
        raise SystemExit("--iteration-delay must be nonnegative")

    prefix = args.payload_prefix.encode()
    if len(prefix) > 16384:
        raise SystemExit("payload prefix exceeds 16384 bytes")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.echo_port))
    listener.listen(args.connections)
    errors: list[str] = []
    server = threading.Thread(
        target=echo_server,
        args=(listener, args.connections, errors),
        daemon=True,
    )
    server.start()
    counters = {"bytes_sent": 0, "bytes_received": 0, "iterations": 0}
    counter_lock = threading.Lock()
    started_ns = time.time_ns()

    try:
        sockets = []
        for _ in range(args.connections):
            sock = socket.socket()
            if args.source_ip:
                sock.bind((args.source_ip, 0))
            sock.settimeout(30)
            sock.connect(("127.0.0.1", args.socks_port))
            request = b"\x04\x01" + struct.pack("!H", args.echo_port)
            request += socket.inet_aton("127.0.0.1") + b"cgo-lab\0"
            sock.sendall(request)
            reply = recv_exact(sock, 8)
            if reply[1] != 90:
                raise RuntimeError(f"SOCKS4 rejected request: {reply.hex()}")
            sock.settimeout(None)
            sockets.append(sock)
        workers = [
            threading.Thread(
                target=send_stream,
                args=(
                    sock,
                    index,
                    prefix,
                    args.stop_file,
                    counters,
                    counter_lock,
                    errors,
                    args.iteration_delay,
                ),
                daemon=True,
            )
            for index, sock in enumerate(sockets)
        ]
        for worker in workers:
            worker.start()
        args.ready_file.write_text("ready\n")
        for worker in workers:
            worker.join()
        for sock in sockets:
            sock.close()
    finally:
        listener.close()

    result = {
        "schema": "tor-cgo-controlled-flood-stream/0.1",
        "started_unix_ns": started_ns,
        "finished_unix_ns": time.time_ns(),
        **counters,
        "server_errors": errors,
        "source_ip": args.source_ip,
        "payload_prefix": args.payload_prefix,
        "per_chunk_echo_wait": False,
        "connection_count": args.connections,
        "iteration_delay_seconds": args.iteration_delay,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
