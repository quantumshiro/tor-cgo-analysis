#!/usr/bin/env python3
"""Attach new SOCKS streams round-robin to controlled Tor circuits."""

from __future__ import annotations

import argparse
from collections import deque
import json
import select
import socket
import time
from pathlib import Path

from build_controlled_circuits import command


def attach_on_event_connection(
    stream, stream_id: int, circuit_id: int
) -> tuple[list[str], list[str]]:
    """Attach on the controller connection that owns unattached streams.

    Tor associates an unattached stream with the controller connection which
    requested STREAM events.  A second authenticated connection gets
    ``555 Connection is not managed by controller``.  While waiting for the
    ATTACHSTREAM reply, retain asynchronous 650 events separately so that a
    650 line is not mistaken for the command's final status line.
    """
    stream.write(f"ATTACHSTREAM {stream_id} {circuit_id}\r\n".encode("ascii"))
    reply: list[str] = []
    asynchronous: list[str] = []
    while True:
        raw = stream.readline()
        if not raw:
            raise RuntimeError("control connection closed during ATTACHSTREAM")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("650 "):
            asynchronous.append(line)
            continue
        reply.append(line)
        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
            break
    if not reply or not reply[-1].startswith("250 "):
        raise RuntimeError("control command failed: " + " | ".join(reply))
    return reply, asynchronous


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-port", type=int, required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--circuits", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    circuit_ids = json.loads(args.circuits.read_text())["built_circuit_ids"]
    attachments = []
    rejected_events = []
    pending_events: deque[str] = deque()

    with socket.create_connection(("127.0.0.1", args.control_port), timeout=10) as event_sock:
        event_stream = event_sock.makefile("rwb", buffering=0)
        auth = "AUTHENTICATE " + args.cookie.read_bytes().hex()
        command(event_stream, auth)
        command(event_stream, "SETCONF __LeaveStreamsUnattached=1")
        # EXTENDCIRCUIT purpose=controller keeps Tor from selecting these
        # circuits on its own while ground truth is prepared.  They must be
        # promoted before carrying SOCKS payloads; ATTACHSTREAM can otherwise
        # return OK while the application remains in its SOCKS handshake.
        for circuit_id in circuit_ids:
            command(
                event_stream,
                f"SETCIRCUITPURPOSE {circuit_id} purpose=general",
            )
        command(event_stream, "SETEVENTS STREAM")
        args.ready_file.write_text("ready\n")
        next_index = 0
        try:
            while not args.stop_file.exists():
                if pending_events:
                    line = pending_events.popleft()
                else:
                    readable, _, _ = select.select([event_sock], [], [], 0.2)
                    if not readable:
                        continue
                    raw = event_stream.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                fields = line.split()
                if len(fields) < 4 or fields[0] != "650" or fields[1] != "STREAM":
                    continue
                if fields[3] not in {"NEW", "NEWRESOLVE"}:
                    continue
                # Tor also reports internal directory streams as NEW.  Those
                # deliberately bypass LeaveStreamsUnattached and therefore
                # cannot be attached by a controller.
                if "PURPOSE=USER" not in fields:
                    rejected_events.append({
                        "event": line,
                        "reason": "non_user_stream",
                        "unix_ns": time.time_ns(),
                    })
                    continue
                stream_id = int(fields[2])
                circuit_id = circuit_ids[next_index % len(circuit_ids)]
                next_index += 1
                try:
                    reply, asynchronous = attach_on_event_connection(
                        event_stream, stream_id, circuit_id
                    )
                    pending_events.extend(asynchronous)
                except RuntimeError as exc:
                    rejected_events.append({
                        "stream_id": stream_id,
                        "circuit_id": circuit_id,
                        "event": line,
                        "reason": str(exc),
                        "unix_ns": time.time_ns(),
                    })
                    continue
                attachments.append({
                    "stream_id": stream_id,
                    "circuit_id": circuit_id,
                    "event": line,
                    "reply": reply,
                    "unix_ns": time.time_ns(),
                })
        finally:
            try:
                command(event_stream, "RESETCONF __LeaveStreamsUnattached")
            except Exception:
                pass

    result = {
        "schema": "tor-cgo-stream-attachments/0.1",
        "controlled_circuit_ids": circuit_ids,
        "attachments": attachments,
        "attachment_count": len(attachments),
        "circuits_with_attachments": sorted({row["circuit_id"] for row in attachments}),
        "rejected_events": rejected_events,
        "rejected_event_count": len(rejected_events),
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
