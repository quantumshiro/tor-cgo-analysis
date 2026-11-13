"""Offline C Tor circuit/relay-crypto scanner for GDB.

Run with:
  CGO_OUTPUT=report.json gdb -q -batch TOR_BINARY CORE \
      -ex 'source forensics/gdb_scan.py'

The script consumes only the executable's debug information and a captured
core file.  It does not call functions in the captured process.
"""

import datetime
import hashlib
import json
import os
import subprocess

import gdb


ORIGIN_CIRCUIT_MAGIC = 0x35315243
CPATH_MAGIC = 0x70127012
CIRCUIT_STATE_NAMES = {
    0: "building",
    1: "onionskin_pending",
    2: "channel_wait",
    3: "guard_wait",
    4: "open",
}
CPATH_STATE_NAMES = {0: "closed", 1: "awaiting_keys", 2: "open"}
CRYPTO_KIND_NAMES = {0: "TOR1", 1: "CGO"}
ENTRY_CONNECTION_MAGIC = 0xBB4A5703


def nm_symbols(executable_path):
    output = subprocess.check_output(
        ["nm", "-a", executable_path], text=True, stderr=subprocess.DEVNULL
    )
    symbols = {}
    for line in output.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) == 3:
            try:
                symbols[fields[2]] = int(fields[0], 16)
            except ValueError:
                pass
    return symbols


def resolve_global_origin_list(executable_path):
    supplied_bias = os.environ.get("CGO_LOAD_BIAS")
    if supplied_bias is not None:
        symbols = nm_symbols(executable_path)
        candidates = ["global_origin_circuit_list"] if "global_origin_circuit_list" in symbols else sorted(
            name
            for name in symbols
            if name.startswith("global_origin_circuit_list.lto_priv.")
        )
        if len(candidates) != 1:
            raise gdb.GdbError("owner-list ELF symbol is missing or ambiguous")
        load_bias = int(supplied_bias, 0)
        runtime_variable = load_bias + symbols[candidates[0]]
        pointer_type = gdb.lookup_type("smartlist_t").pointer().pointer()
        value = gdb.Value(runtime_variable).cast(pointer_type).dereference()
        return value, {
            "method": "supplied_load_bias_and_elf_symbol",
            "symbol": candidates[0],
            "load_bias": hex(load_bias),
            "runtime_variable_address": hex(runtime_variable),
        }
    try:
        value = gdb.parse_and_eval("global_origin_circuit_list")
        as_int(value)
        return value, {
            "method": "dwarf_variable",
            "symbol": "global_origin_circuit_list",
        }
    except gdb.error as direct_error:
        symbols = nm_symbols(executable_path)
        candidates = sorted(
            name
            for name in symbols
            if name.startswith("global_origin_circuit_list.lto_priv.")
        )
        anchor = "circuit_get_global_origin_circuit_list"
        if len(candidates) != 1 or anchor not in symbols:
            raise direct_error
        runtime_anchor = as_int(gdb.parse_and_eval("&" + anchor))
        load_bias = runtime_anchor - symbols[anchor]
        runtime_variable = load_bias + symbols[candidates[0]]
        pointer_type = gdb.lookup_type("smartlist_t").pointer().pointer()
        value = gdb.Value(runtime_variable).cast(pointer_type).dereference()
        return value, {
            "method": "elf_local_symbol_lto_fallback",
            "symbol": candidates[0],
            "anchor_symbol": anchor,
            "load_bias": hex(load_bias),
            "runtime_variable_address": hex(runtime_variable),
            "direct_dwarf_error": str(direct_error),
        }


def as_int(value):
    return int(value.cast(gdb.lookup_type("uintptr_t")))


def byte_array(value):
    bounds = value.type.range()
    return bytes(int(value[i]) & 0xFF for i in range(bounds[0], bounds[1] + 1))


def nonzero(value):
    return any(byte_array(value))


def sha256_value(value):
    return hashlib.sha256(byte_array(value)).hexdigest()


def c_string_from_array(value):
    raw = byte_array(value)
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def identity_hex(extend_info_ptr):
    if as_int(extend_info_ptr) == 0:
        return None
    return byte_array(extend_info_ptr.dereference()["identity_digest"]).hex().upper()


def inspect_cgo(crypto):
    cgo_type = gdb.lookup_type("struct cgo_crypt_t").pointer()
    pair = crypto["c"]["cgo"]
    result = {
        "initialized": False,
        "forward_state_present": as_int(pair["fwd"]) != 0,
        "backward_state_present": as_int(pair["back"]) != 0,
        "forward_used": None,
        "backward_used": None,
    }
    if not result["forward_state_present"] or not result["backward_state_present"]:
        return result
    fwd = pair["fwd"].cast(cgo_type).dereference()
    back = pair["back"].cast(cgo_type).dereference()
    result.update(
        initialized=True,
        forward_used=nonzero(fwd["tprime"]),
        backward_used=nonzero(back["tprime"]),
        forward_nonce_sha256=sha256_value(fwd["nonce"]),
        backward_nonce_sha256=sha256_value(back["nonce"]),
        forward_state_sha256=sha256_value(fwd["tprime"]),
        backward_state_sha256=sha256_value(back["tprime"]),
        aes_bytes_forward=int(fwd["aes_bytes"]),
        aes_bytes_backward=int(back["aes_bytes"]),
    )
    return result


def inspect_tor1(crypto):
    tor1 = crypto["c"]["tor1"]
    ptr_fields = ("f_crypto", "b_crypto", "f_digest", "b_digest")
    present = {name: as_int(tor1[name]) != 0 for name in ptr_fields}
    return {
        "initialized": all(present.values()),
        "component_pointers_present": present,
        # This digest changes only when a cell is originated or recognized.
        # A zero value therefore cannot prove non-use.
        "originated_or_recognized_cell_evidence": nonzero(tor1["sendme_digest"]),
        "sendme_digest_sha256": sha256_value(tor1["sendme_digest"]),
    }


def inspect_hop(ptr, index, entry_addr):
    hop = ptr.dereference()
    addr = as_int(ptr)
    crypto = hop["crypto_crypt_path_private_field"]
    kind = int(crypto["kind"])
    extend_info = hop["extend_info"]
    output = {
        "index_from_entry": index,
        "address": hex(addr),
        "is_entry": addr == entry_addr,
        "magic_valid": int(hop["magic"]) == CPATH_MAGIC,
        "state": CPATH_STATE_NAMES.get(int(hop["state"]), f"unknown:{int(hop['state'])}"),
        "relay_cell_format": int(hop["relay_cell_format"]),
        "crypto_kind": CRYPTO_KIND_NAMES.get(kind, f"UNKNOWN:{kind}"),
        "next": hex(as_int(hop["next"])),
        "prev": hex(as_int(hop["prev"])),
        "identity_sha1": identity_hex(extend_info),
        "nickname": None,
        "negotiation_intent_enable_cgo": None,
        "link_consistent": False,
    }
    if as_int(extend_info):
        ei = extend_info.dereference()
        output["nickname"] = c_string_from_array(ei["nickname"])
        output["negotiation_intent_enable_cgo"] = bool(ei["enable_cgo"])
    try:
        output["link_consistent"] = (
            as_int(hop["next"].dereference()["prev"]) == addr
            and as_int(hop["prev"].dereference()["next"]) == addr
        )
    except gdb.error:
        output["link_consistent"] = False
    try:
        if kind == 1:
            output["crypto_evidence"] = inspect_cgo(crypto)
        elif kind == 0:
            output["crypto_evidence"] = inspect_tor1(crypto)
        else:
            output["crypto_evidence"] = {"initialized": False}
    except (gdb.error, MemoryError) as exc:
        output["crypto_evidence"] = {"initialized": False, "error": str(exc)}
    output["negotiation_matches_instantiated_crypto"] = (
        output["negotiation_intent_enable_cgo"] is None
        or output["negotiation_intent_enable_cgo"] == (kind == 1)
    )
    initialized = bool(output["crypto_evidence"].get("initialized"))
    if output["state"] != "open" or not initialized:
        output["forensic_crypto_state"] = "not_established"
    elif kind == 1:
        output["forensic_crypto_state"] = "CGO_established"
    elif kind == 0:
        output["forensic_crypto_state"] = "TOR1_established"
    else:
        output["forensic_crypto_state"] = "unknown_established"
    return output


def inspect_streams(first_ptr, circuit_addr):
    """Recover live AP-stream evidence owned by one origin circuit.

    The p_streams list is an ownership edge maintained by Tor itself.  It is
    therefore stronger evidence than scanning the heap for plausible SOCKS
    request structures.  Authentication fields are deliberately not emitted.
    """
    streams = []
    seen = set()
    current = first_ptr
    entry_ptr_type = gdb.lookup_type("struct entry_connection_t").pointer()
    for index in range(4096):
        current_addr = as_int(current)
        if current_addr == 0:
            return streams, None
        if current_addr in seen:
            return streams, "stream_list_cycle"
        seen.add(current_addr)
        try:
            edge = current.dereference()
            entry = current.cast(entry_ptr_type).dereference()
            base = edge["base_"]
            socks_ptr = entry["socks_request"]
            row = {
                "index": index,
                "address": hex(current_addr),
                "entry_magic_valid": int(base["magic"]) == ENTRY_CONNECTION_MAGIC,
                "connection_state": int(base["state"]),
                "connection_type": int(base["type"]),
                "global_connection_id": int(base["global_identifier"]),
                "stream_id": int(edge["stream_id"]),
                "on_circuit": hex(as_int(edge["on_circuit"])),
                "on_circuit_consistent": as_int(edge["on_circuit"]) == circuit_addr,
                "cpath_layer": (
                    hex(as_int(edge["cpath_layer"]))
                    if as_int(edge["cpath_layer"]) else None
                ),
                "bytes_read": int(edge["n_read"]),
                "bytes_written": int(edge["n_written"]),
                "socks_request_present": as_int(socks_ptr) != 0,
                "client_endpoint_emitted": False,
            }
            if os.environ.get("CGO_INCLUDE_CLIENT_ENDPOINTS") == "1":
                address_ptr = base["address"]
                row["client_endpoint"] = {
                    "address": address_ptr.string() if as_int(address_ptr) else None,
                    "port": int(base["port"]),
                    "socket_family": int(base["socket_family"]),
                    "source": "connection_t peer address from accepted SOCKS connection",
                }
                row["client_endpoint_emitted"] = True
            if as_int(socks_ptr):
                socks = socks_ptr.dereference()
                row["socks"] = {
                    "version": int(socks["socks_version"]),
                    "command": int(socks["command"]),
                    "address": c_string_from_array(socks["address"]),
                    "port": int(socks["port"]),
                    "handshake_finished": bool(socks["has_finished"]),
                    "address_type": int(socks["socks5_atyp"]),
                    # username/password are intentionally excluded: neither is
                    # needed to establish the destination-to-circuit mapping.
                    "credentials_emitted": False,
                }
            streams.append(row)
            current = edge["next_stream"]
        except (gdb.error, MemoryError) as exc:
            return streams, f"stream[{index}]: {exc}"
    return streams, "stream_list_exceeds_limit"


def inspect_circuit(ptr, expected_index):
    circuit = ptr.dereference()
    base = circuit["base_"]
    address = as_int(ptr)
    cpath = circuit["cpath"]
    cpath_addr = as_int(cpath)
    marked = int(base["marked_for_close"])
    state = int(base["state"])
    output = {
        "address": hex(address),
        "ownership": "verified_global_origin_circuit_list",
        "global_origin_list_index": expected_index,
        "stored_global_origin_list_index": int(circuit["global_origin_circuit_list_idx"]),
        "list_index_consistent": int(circuit["global_origin_circuit_list_idx"]) == expected_index,
        "magic_valid": int(base["magic"]) == ORIGIN_CIRCUIT_MAGIC,
        "control_circuit_id": int(circuit["global_identifier"]),
        "circuit_state": CIRCUIT_STATE_NAMES.get(state, f"unknown:{state}"),
        "purpose": int(base["purpose"]),
        "marked_for_close_line": marked,
        "lifecycle": "closing" if marked else ("active" if state == 4 else "building"),
        "entry_hop_address": hex(cpath_addr) if cpath_addr else None,
        "orientation": "origin_circuit.cpath_is_entry" if cpath_addr else "no_path",
        "entry_link_circuit_id": int(base["n_circ_id"]),
        "entry_link_channel_id": (
            int(base["n_chan"].dereference()["global_identifier"])
            if as_int(base["n_chan"]) else None
        ),
        "entry_link_peer_identity_sha1": (
            byte_array(base["n_chan"].dereference()["identity_digest"]).hex().upper()
            if as_int(base["n_chan"]) else None
        ),
        "hops": [],
        "streams": [],
        "path_closed_cycle": False,
    }
    try:
        output["streams"], stream_error = inspect_streams(
            circuit["p_streams"], address
        )
        output["stream_count"] = len(output["streams"])
        if stream_error:
            output["stream_error"] = stream_error
    except (gdb.error, MemoryError) as exc:
        output["stream_count"] = 0
        output["stream_error"] = str(exc)
    if not cpath_addr:
        output["path_structurally_valid"] = False
        return output
    seen = set()
    current = cpath
    for index in range(32):
        current_addr = as_int(current)
        if current_addr in seen:
            output["path_closed_cycle"] = current_addr == cpath_addr
            break
        seen.add(current_addr)
        try:
            output["hops"].append(inspect_hop(current, index, cpath_addr))
            current = current.dereference()["next"]
        except (gdb.error, MemoryError) as exc:
            output["path_error"] = str(exc)
            break
    output["path_structurally_valid"] = (
        output["path_closed_cycle"]
        and bool(output["hops"])
        and all(h["magic_valid"] and h["link_consistent"] for h in output["hops"])
    )
    return output


def assign_core_evidence(report):
    """Assign E1--E3 using the same conditions stated in the paper."""
    owner = report.get("global_origin_circuit_list", {})
    owner_complete = (
        owner.get("bounds_valid") is True
        and len(report["circuits"]) == owner.get("num_used")
        and not report["errors"]
    )
    for circuit in report["circuits"]:
        e1 = owner_complete
        e2 = (
            e1
            and circuit["magic_valid"]
            and circuit["list_index_consistent"]
            and circuit.get("path_structurally_valid") is True
        )
        hop_checks = [
            hop["state"] == "open"
            and hop["crypto_kind"] in ("CGO", "TOR1")
            and hop["crypto_evidence"].get("initialized") is True
            for hop in circuit["hops"]
        ]
        e3 = e2 and bool(hop_checks) and all(hop_checks)
        e3 = (
            e3
            and circuit["circuit_state"] == "open"
            and circuit["lifecycle"] == "active"
        )
        circuit["evidence"] = {
            "E1_owned_list_completely_enumerated": e1,
            "E2_origin_magic_index_and_entry_path_valid": e2,
            "E3_all_hops_open_with_instantiated_crypto": e3,
        }
        circuit["highest_core_evidence_level"] = (
            "E3" if e3 else "E2" if e2 else "E1" if e1 else "E0"
        )


def scan():
    executable_path = gdb.current_progspace().filename
    report = {
        "schema": "tor-cgo-memory-forensics/0.2",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": "offline_gdb_dwarf_core",
        "executable": {
            "path": executable_path,
            "sha256": file_sha256(executable_path) if executable_path else None,
        },
        "circuits": [],
        "errors": [],
        "recovery_completeness": "not_evaluated",
    }
    try:
        global_list, resolution = resolve_global_origin_list(executable_path)
        report["owner_list_resolution"] = resolution
        if as_int(global_list) == 0:
            report["global_origin_circuit_list"] = "null"
            report["recovery_completeness"] = "owner_list_null_no_recovery"
            return report
        sl = global_list.dereference()
        num_used = int(sl["num_used"])
        capacity = int(sl["capacity"])
        report["global_origin_circuit_list"] = {
            "num_used": num_used,
            "capacity": capacity,
            "bounds_valid": 0 <= num_used <= capacity <= 1_000_000,
        }
        if not report["global_origin_circuit_list"]["bounds_valid"]:
            report["errors"].append("invalid smartlist bounds")
            report["recovery_completeness"] = "invalid_owner_list_bounds"
            return report
        if num_used == 0:
            report["recovery_completeness"] = (
                "empty_owner_list_no_recovery_not_proof_of_historical_absence"
            )
            return report
        origin_ptr_type = gdb.lookup_type("struct origin_circuit_t").pointer()
        raw_list = sl["list"]
        for index in range(num_used):
            ptr = raw_list[index].cast(origin_ptr_type)
            try:
                report["circuits"].append(inspect_circuit(ptr, index))
            except (gdb.error, MemoryError) as exc:
                report["errors"].append(f"circuit[{index}]: {exc}")
        report["recovery_completeness"] = (
            "partial_owner_list_with_errors"
            if report["errors"]
            else "owner_list_enumerated"
        )
        assign_core_evidence(report)
    except gdb.error as exc:
        report["errors"].append(f"global list unavailable: {exc}")
        report["recovery_completeness"] = "owner_list_unavailable"
    return report


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


output_path = os.environ.get("CGO_OUTPUT")
report = scan()
rendered = json.dumps(report, indent=2, sort_keys=True)
if output_path:
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(rendered + "\n")
else:
    print(rendered)

if report["errors"]:
    gdb.execute("quit 3")
