#!/usr/bin/env python3
"""Make a selected core memory range genuinely unavailable via PT_LOAD removal."""

from __future__ import annotations

import argparse
import json
import mmap
import struct
from pathlib import Path


PT_LOAD = 1
PT_NULL = 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--virtual-address", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()

    with args.core.open("r+b") as handle, mmap.mmap(handle.fileno(), 0) as image:
        if image[:6] != b"\x7fELF\x02\x01":
            raise SystemExit("requires a little-endian ELF64 core")
        phoff = struct.unpack_from("<Q", image, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", image, 54)
        selected = None
        for index in range(phnum):
            off = phoff + index * phentsize
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                "<IIQQQQQQ", image, off
            )
            if p_type == PT_LOAD and p_vaddr <= args.virtual_address < p_vaddr + p_memsz:
                selected = {
                    "program_header_index": index,
                    "program_header_offset": off,
                    "flags": p_flags,
                    "file_offset": p_offset,
                    "virtual_address": p_vaddr,
                    "file_size": p_filesz,
                    "memory_size": p_memsz,
                    "alignment": p_align,
                }
                struct.pack_into("<I", image, off, PT_NULL)
                image.flush()
                break
        if selected is None:
            raise SystemExit("no PT_LOAD contains the requested address")

    report = {
        "schema": "tor-core-missing-load-segment/0.1",
        "core": str(args.core),
        "requested_virtual_address": hex(args.virtual_address),
        "mutation": "containing PT_LOAD changed to PT_NULL; bytes remain in the file but are not mapped by the ELF core",
        "removed_segment": {
            **selected,
            "file_offset": hex(selected["file_offset"]),
            "virtual_address": hex(selected["virtual_address"]),
        },
    }
    args.metadata.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
