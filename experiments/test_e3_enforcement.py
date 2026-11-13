#!/usr/bin/env python3
"""Negative tests for the ownership-first E3 enforcement boundary."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
from pathlib import Path


def run(command: list[str], log: Path, env: dict[str, str] | None = None) -> int:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        check=False,
    )
    log.write_text(completed.stdout)
    return completed.returncode


def container_path(repo: Path, path: Path) -> str:
    return "/work/" + str(path.resolve().relative_to(repo.resolve()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--source-core", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--container", default="tor-cgo-lab")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    scan = json.loads((args.run_dir / "core-scan.json").read_text())
    no_e3_scan = copy.deepcopy(scan)
    for circuit in no_e3_scan["circuits"]:
        circuit["evidence"]["E3_all_hops_open_with_instantiated_crypto"] = False
        if circuit.get("highest_core_evidence_level") == "E3":
            circuit["highest_core_evidence_level"] = "E2"
    no_e3_path = args.output_dir / "no-e3-scan.json"
    no_e3_path.write_text(json.dumps(no_e3_scan, indent=2, sort_keys=True) + "\n")
    no_e3_manifest = args.output_dir / "no-e3-manifest.json"
    builder_rc = run([
        "python3", str(args.repo / "experiments/build_e3_manifest.py"),
        "--scan", str(no_e3_path), "--output", str(no_e3_manifest),
    ], args.output_dir / "no-e3-builder.log")

    manifest = json.loads((args.run_dir / "e3-circuit-manifest.json").read_text())
    tampered = copy.deepcopy(manifest)
    tampered["circuits"][0]["circuit_address"] = "0x1"
    tampered_path = args.output_dir / "tampered-address-manifest.json"
    tampered_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n")

    executable = "/work/build/tor-0.4.9.16-o2/src/app/tor"
    core = container_path(args.repo, args.source_core)
    common = ["docker", "exec", args.container]
    cgo_without_rc = run(common + [
        "env", "CGO_OPENSSL_LAYOUT=openssl-3.0.22-debian-arm64",
        "CGO_SECRET_OUTPUT=/tmp/should-not-exist-cgo.json",
        "gdb", "-q", "-batch", executable, core,
        "-ex", "source /work/forensics/gdb_extract_cgo_secrets.py",
    ], args.output_dir / "cgo-without-manifest.log")

    tampered_container = container_path(args.repo, tampered_path)
    cgo_tampered_rc = run(common + [
        "env", "CGO_OPENSSL_LAYOUT=openssl-3.0.22-debian-arm64",
        f"CGO_E3_MANIFEST={tampered_container}",
        "CGO_SECRET_OUTPUT=/tmp/should-not-exist-cgo-tampered.json",
        "gdb", "-q", "-batch", executable, core,
        "-ex", "source /work/forensics/gdb_extract_cgo_secrets.py",
    ], args.output_dir / "cgo-tampered-manifest.log")

    tls_tampered_rc = run(common + [
        "env", "CGO_OPENSSL_TLS_LAYOUT=openssl-3.0.22-debian-arm64",
        f"CGO_E3_MANIFEST={tampered_container}",
        "CGO_TLS_SECRET_OUTPUT=/tmp/should-not-exist-tls-tampered.json",
        "gdb", "-q", "-batch", executable, core,
        "-ex", "source /work/forensics/gdb_extract_tls_secrets.py",
    ], args.output_dir / "tls-tampered-manifest.log")

    checks = {
        "manifest_builder_rejects_no_E3_circuits": builder_rc != 0,
        "cgo_extractor_rejects_missing_manifest": cgo_without_rc != 0,
        "cgo_extractor_rejects_manifest_address_mismatch": cgo_tampered_rc != 0,
        "tls_extractor_rejects_manifest_address_mismatch": tls_tampered_rc != 0,
    }
    report = {
        "schema": "tor-cgo-e3-enforcement-negative-tests/0.1",
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "return_codes": {
            "no_e3_builder": builder_rc,
            "cgo_without_manifest": cgo_without_rc,
            "cgo_tampered_manifest": cgo_tampered_rc,
            "tls_tampered_manifest": tls_tampered_rc,
        },
        "secrets_emitted": False,
    }
    output = args.output_dir / "summary.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(output, 0o600)
    if not report["all_checks_pass"]:
        raise SystemExit("one or more E3 enforcement negative tests failed")


if __name__ == "__main__":
    main()
