#!/usr/bin/env python3
"""Build persistent controller-purpose circuits over one explicit path."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path


def read_reply(stream) -> list[str]:
    lines: list[str] = []
    while True:
        raw = stream.readline()
        if not raw:
            raise RuntimeError("control connection closed")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
            # GETINFO circuit-status data lines begin with a numeric circuit
            # identifier.  Once IDs reach three digits, e.g. ``100 BUILT``,
            # they resemble a protocol status line but 100 is not a valid
            # final Control Protocol reply code.
            code = int(line[:3])
            if 200 <= code <= 599:
                return lines


def command(stream, text: str) -> list[str]:
    stream.write((text + "\r\n").encode("ascii"))
    reply = read_reply(stream)
    if not reply[-1].startswith("250 "):
        raise RuntimeError("control command failed: " + " | ".join(reply))
    return reply


def circuit_status(stream) -> dict[int, str]:
    result: dict[int, str] = {}
    for line in command(stream, "GETINFO circuit-status"):
        if not line or not line[0].isdigit():
            continue
        fields = line.split()
        if (
            len(fields) >= 2
            and fields[0].isdigit()
            and fields[1] in {"LAUNCHED", "BUILT", "FAILED", "CLOSED", "EXTENDED"}
        ):
            result[int(fields[0])] = fields[1]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-port", type=int, required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--path", required=True, help="comma-separated relay fingerprints")
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument("--timeout-s", type=float, default=30.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    fingerprints = [item.lstrip("$").upper() for item in args.path.split(",")]
    path_argument = ",".join("$" + item for item in fingerprints)
    created: list[int] = []
    with socket.create_connection(("127.0.0.1", args.control_port), timeout=10) as sock:
        stream = sock.makefile("rwb", buffering=0)
        command(stream, "AUTHENTICATE " + args.cookie.read_bytes().hex())
        for _ in range(args.count):
            reply = command(
                stream,
                "EXTENDCIRCUIT 0 " + path_argument + " purpose=controller",
            )
            created.append(int(reply[-1].split()[-1]))

        deadline = time.monotonic() + args.timeout_s
        final_status: dict[int, str] = {}
        while time.monotonic() < deadline:
            final_status = circuit_status(stream)
            if all(final_status.get(circuit_id) == "BUILT" for circuit_id in created):
                break
            time.sleep(0.1)
        command(stream, "QUIT")

    built = [circuit_id for circuit_id in created if final_status.get(circuit_id) == "BUILT"]
    result = {
        "schema": "tor-cgo-controlled-circuits/0.1",
        "created_unix_s": time.time(),
        "path_identities": fingerprints,
        "requested_count": args.count,
        "created_circuit_ids": created,
        "built_circuit_ids": built,
        "final_status": {str(key): value for key, value in final_status.items()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    if len(built) != args.count:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
