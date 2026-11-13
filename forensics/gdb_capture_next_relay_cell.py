"""Evaluation-only live capture of one controlled post-snapshot relay cell.

The plaintext breakpoint supplies ground truth only.  The wire breakpoint
captures the onion-encrypted cell after Tor processing and before TLS.  The
offline replay experiment must use state extracted from the earlier core.
"""

import json
import os
import time

import gdb


TARGET_CONTROL_ID = int(os.environ["CGO_TARGET_CONTROL_ID"])
TARGET_LINK_CIRCID = int(os.environ["CGO_TARGET_LINK_CIRCID"])
OUTPUT = os.environ["CGO_CELL_OUTPUT"]
capture = {"plaintext": None, "wire": None}


def as_int(value):
    return int(value.cast(gdb.lookup_type("uintptr_t")))


def byte_array(value):
    lo, hi = value.type.range()
    return bytes(int(value[i]) & 0xFF for i in range(lo, hi + 1))


def write_report():
    report = {
        "schema": "tor-cgo-next-cell-ground-truth/0.1",
        "scope": "isolated_controlled_network_evaluation_only",
        "target_control_circuit_id": TARGET_CONTROL_ID,
        "target_entry_link_circuit_id": TARGET_LINK_CIRCID,
        **capture,
    }
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


class PostEncryptionBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, frame, cell_ptr):
        super().__init__(frame, internal=True)
        self.cell_ptr = cell_ptr

    def stop(self):
        cell = self.cell_ptr.dereference()
        capture["wire"] = {
            "circ_id": int(cell["circ_id"]),
            "command": int(cell["command"]),
            "payload_hex": byte_array(cell["payload"]).hex(),
            "captured_unix_ns": time.time_ns(),
        }
        write_report()
        return True


class PlaintextBreakpoint(gdb.Breakpoint):
    def stop(self):
        frame = gdb.newest_frame()
        circ_ptr = frame.read_var("circ")
        if int(circ_ptr.dereference()["global_identifier"]) != TARGET_CONTROL_ID:
            return False
        cell = frame.read_var("cell").dereference()
        layer_hint = frame.read_var("layer_hint")
        first = circ_ptr.dereference()["cpath"]
        current = first
        target_index = None
        for index in range(32):
            if as_int(current) == as_int(layer_hint):
                target_index = index
                break
            current = current.dereference()["next"]
            if as_int(current) == as_int(first):
                break
        if target_index is None:
            return False
        capture["plaintext"] = {
            "command": int(cell["command"]),
            "payload_hex": byte_array(cell["payload"]).hex(),
            "target_hop_index": target_index,
            "captured_unix_ns": time.time_ns(),
        }
        PostEncryptionBreakpoint(frame, frame.read_var("cell"))
        return False


PlaintextBreakpoint("relay_encrypt_cell_outbound", internal=True)
