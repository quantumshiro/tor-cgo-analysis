#!/usr/bin/env python3
"""Fail-closed compatibility check between an ELF core and executable.

Linux core files do not carry the executable's GNU Build ID directly.  This
tool therefore records the candidate ELF Build ID and verifies compatibility
by matching file-backed bytes named by the core's NT_FILE note.  Relocated and
mutable bytes may differ, so a documented similarity threshold is used.  A
path match alone is never accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


PT_LOAD = 1
PT_NOTE = 4
NT_FILE = 0x46494C45
NT_GNU_BUILD_ID = 3


class ElfError(ValueError):
    pass


def align4(value: int) -> int:
    return (value + 3) & ~3


def parse_elf(path: Path) -> tuple[bytes, dict, list[dict]]:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError(f"{path} is not ELF")
    if data[4] != 2 or data[5] != 1:
        raise ElfError("only little-endian ELF64 is supported")
    machine = struct.unpack_from("<H", data, 18)[0]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or phoff + phentsize * phnum > len(data):
        raise ElfError("invalid program header table")
    phdrs = []
    for index in range(phnum):
        off = phoff + index * phentsize
        values = struct.unpack_from("<IIQQQQQQ", data, off)
        phdrs.append(dict(zip(
            ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"),
            values,
        )))
    return data, {"machine": machine, "type": struct.unpack_from("<H", data, 16)[0]}, phdrs


def iter_notes(data: bytes, phdrs: list[dict]):
    for ph in phdrs:
        if ph["type"] != PT_NOTE:
            continue
        off = ph["offset"]
        end = off + ph["filesz"]
        while off + 12 <= end:
            namesz, descsz, note_type = struct.unpack_from("<III", data, off)
            off += 12
            name = data[off:off + namesz].rstrip(b"\0")
            off += align4(namesz)
            desc = data[off:off + descsz]
            off += align4(descsz)
            if off > end:
                raise ElfError("truncated ELF note")
            yield name, note_type, desc


def build_id(data: bytes, phdrs: list[dict]) -> str | None:
    for name, note_type, desc in iter_notes(data, phdrs):
        if name == b"GNU" and note_type == NT_GNU_BUILD_ID:
            return desc.hex()
    return None


def nt_file_entries(data: bytes, phdrs: list[dict]) -> list[dict]:
    for _name, note_type, desc in iter_notes(data, phdrs):
        if note_type != NT_FILE:
            continue
        if len(desc) < 16:
            raise ElfError("short NT_FILE note")
        count, page_size = struct.unpack_from("<QQ", desc, 0)
        table_end = 16 + count * 24
        if count > 1_000_000 or table_end > len(desc):
            raise ElfError("invalid NT_FILE entry count")
        names = desc[table_end:].split(b"\0")
        if len(names) < count:
            raise ElfError("missing NT_FILE path names")
        rows = []
        for index in range(count):
            start, end, file_page = struct.unpack_from("<QQQ", desc, 16 + index * 24)
            rows.append({
                "start": start,
                "end": end,
                "file_offset": file_page * page_size,
                "path": names[index].decode("utf-8", "surrogateescape"),
                "page_size": page_size,
            })
        return rows
    raise ElfError("core has no NT_FILE note")


def core_bytes(data: bytes, loads: list[dict], address: int, size: int) -> bytes | None:
    for ph in loads:
        if ph["type"] != PT_LOAD:
            continue
        if ph["vaddr"] <= address and address + size <= ph["vaddr"] + ph["filesz"]:
            offset = ph["offset"] + address - ph["vaddr"]
            return data[offset:offset + size]
    return None


def verify(
    executable: Path, core: Path, minimum_bytes: int = 4096,
    minimum_match_fraction: float = 0.75,
) -> dict:
    exe_data, exe_header, exe_phdrs = parse_elf(executable)
    core_data, core_header, core_phdrs = parse_elf(core)
    if core_header["type"] != 4:
        raise ElfError("second input is not an ELF core")
    if exe_header["machine"] != core_header["machine"]:
        raise ElfError("ELF machine mismatch")
    mappings = nt_file_entries(core_data, core_phdrs)
    same_name = [row for row in mappings if Path(row["path"]).name == executable.name]
    if not same_name:
        raise ElfError("core NT_FILE does not name the candidate executable")

    compared = 0
    mismatched = 0
    matched_paths = set()
    for mapping in same_name:
        remaining = min(mapping["end"] - mapping["start"], 256 * 1024)
        cursor = 0
        while remaining > 0:
            size = min(4096, remaining)
            file_offset = mapping["file_offset"] + cursor
            if file_offset + size > len(exe_data):
                break
            observed = core_bytes(core_data, core_phdrs, mapping["start"] + cursor, size)
            if observed is not None:
                expected = exe_data[file_offset:file_offset + size]
                compared += size
                mismatched += sum(a != b for a, b in zip(observed, expected))
                matched_paths.add(mapping["path"])
            cursor += size
            remaining -= size
    if compared < minimum_bytes:
        raise ElfError(f"only {compared} mapped executable bytes were comparable")
    matched = compared - mismatched
    match_fraction = matched / compared
    if match_fraction < minimum_match_fraction:
        raise ElfError(
            "candidate executable is incompatible with the core mapping: "
            f"only {matched}/{compared} bytes match ({match_fraction:.3%})"
        )
    return {
        "schema": "tor-core-executable-verification/0.1",
        "verified": True,
        "method": "NT_FILE mapping plus mapped-file compatibility fingerprint",
        "executable": str(executable),
        "executable_sha256": hashlib.sha256(exe_data).hexdigest(),
        "executable_build_id": build_id(exe_data, exe_phdrs),
        "core": str(core),
        "core_sha256": hashlib.sha256(core_data).hexdigest(),
        "elf_machine": exe_header["machine"],
        "core_mapped_paths": sorted(matched_paths),
        "compared_bytes": compared,
        "matched_bytes": matched,
        "mismatched_bytes": mismatched,
        "match_fraction": match_fraction,
        "minimum_match_fraction": minimum_match_fraction,
        "note": "runtime relocation and mutable data bytes are expected to differ; clean executable pages may be omitted from gcore files",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.executable, args.core)
    except Exception as exc:
        report = {
            "schema": "tor-core-executable-verification/0.1",
            "verified": False,
            "executable": str(args.executable),
            "core": str(args.core),
            "error": str(exc),
        }
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        raise SystemExit(f"core/executable verification failed: {exc}") from exc
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
