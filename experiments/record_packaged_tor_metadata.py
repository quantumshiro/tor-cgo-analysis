#!/usr/bin/env python3
"""Record provenance and debug-symbol compatibility for a packaged Tor."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def command(*args: str) -> str:
    return subprocess.check_output(
        args, text=True, stderr=subprocess.DEVNULL
    ).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_id(path: Path) -> str:
    notes = command("readelf", "-n", str(path))
    for line in notes.splitlines():
        if "Build ID:" in line:
            return line.split("Build ID:", 1)[1].strip()
    raise ValueError(f"GNU Build ID is absent: {path}")


def package_fields(path: Path) -> dict[str, str]:
    keys = ("Package", "Version", "Architecture", "Source")
    values = {}
    for key in keys:
        try:
            values[key.lower()] = command("dpkg-deb", "-f", str(path), key)
        except subprocess.CalledProcessError:
            values[key.lower()] = ""
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tor-deb", required=True, type=Path)
    parser.add_argument("--dbgsym-deb", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--debug-root", required=True, type=Path)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--expected-tor-sha256", required=True)
    parser.add_argument("--expected-dbgsym-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    binary_build_id = build_id(args.binary)
    debug_file = (
        args.debug_root
        / ".build-id"
        / binary_build_id[:2]
        / f"{binary_build_id[2:]}.debug"
    )
    tor_hash = sha256(args.tor_deb)
    dbgsym_hash = sha256(args.dbgsym_deb)
    debug_build_id = build_id(debug_file)
    payload = {
        "schema": "tor-cgo-packaged-tor-provenance/0.1",
        "repository_url": args.repository_url,
        "tor_package": {
            **package_fields(args.tor_deb),
            "file": str(args.tor_deb),
            "sha256": tor_hash,
            "expected_sha256": args.expected_tor_sha256,
            "repository_hash_matches": tor_hash == args.expected_tor_sha256,
        },
        "debug_symbol_package": {
            **package_fields(args.dbgsym_deb),
            "file": str(args.dbgsym_deb),
            "sha256": dbgsym_hash,
            "expected_sha256": args.expected_dbgsym_sha256,
            "repository_hash_matches": dbgsym_hash == args.expected_dbgsym_sha256,
        },
        "executable": {
            "file": str(args.binary),
            "sha256": sha256(args.binary),
            "description": command("file", "-b", str(args.binary)),
            "build_id": binary_build_id,
            "is_stripped": "stripped" in command("file", "-b", str(args.binary)),
        },
        "external_debug_file": {
            "file": str(debug_file),
            "sha256": sha256(debug_file),
            "build_id": debug_build_id,
            "build_id_matches_executable": debug_build_id == binary_build_id,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
