"""Extract current CGO states for every eligible owned circuit in a C Tor core.

This extractor is intentionally narrow: Debian arm64 OpenSSL 3.0.x provider
contexts using the layout validated by experiments/openssl-layout evidence.
It fails closed unless CGO_OPENSSL_LAYOUT explicitly selects that layout.
Raw state is emitted only when CGO_INCLUDE_SECRETS=1.
"""

import datetime
import hashlib
import json
import os
import struct

import gdb


ORIGIN_CIRCUIT_MAGIC = 0x35315243
CPATH_MAGIC = 0x70127012


def load_e3_manifest():
    path = os.environ.get("CGO_E3_MANIFEST")
    if not path:
        raise gdb.GdbError("CGO_E3_MANIFEST is required")
    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    if (
        manifest.get("schema") != "tor-cgo-e3-circuit-manifest/0.1"
        or manifest.get("owner_list_completely_enumerated") is not True
        or manifest.get("required_evidence_level") != "E3"
        or manifest.get("external_circuit_selector_used") is not False
    ):
        raise gdb.GdbError("invalid or incomplete E3 manifest")
    return path, manifest


def as_int(value):
    return int(value.cast(gdb.lookup_type("uintptr_t")))


def bytes_of(value):
    if value.type.code == gdb.TYPE_CODE_ARRAY:
        lo, hi = value.type.range()
        return bytes(int(value[i]) & 0xFF for i in range(lo, hi + 1))
    if value.address is None:
        raise gdb.GdbError("value has no address")
    return read(as_int(value.address), value.type.sizeof)


def read(addr, size):
    return bytes(gdb.selected_inferior().read_memory(addr, size))


def read_ptr(addr):
    return struct.unpack("<Q", read(addr, 8))[0]


def aes128_key_from_evp(ctx_addr, decrypt):
    # OpenSSL 3.0.22 arm64, validated against TOR_UNIT_TESTS current keys.
    evp_algctx_offset = 168
    prov_aes_schedule_offset = 192
    aes128_last_round_offset = 10 * 16
    aes_rounds_offset = 240
    algctx = read_ptr(ctx_addr + evp_algctx_offset)
    if not algctx:
        raise gdb.GdbError("EVP_CIPHER_CTX.algctx is null")
    rounds = struct.unpack("<i", read(algctx + prov_aes_schedule_offset
                                     + aes_rounds_offset, 4))[0]
    if rounds != 10:
        raise gdb.GdbError(f"unexpected AES-128 round count: {rounds}")
    schedule = algctx + prov_aes_schedule_offset
    key_offset = aes128_last_round_offset if decrypt else 0
    return read(schedule + key_offset, 16), {
        "evp_ctx": hex(ctx_addr),
        "algctx": hex(algctx),
        "rounds": rounds,
        "schedule": hex(schedule),
        "key_schedule_position": "last_round" if decrypt else "first_round",
    }


def extract_direction(cgo_ptr, direction):
    cgo = cgo_ptr.dereference()
    j_key, j_meta = aes128_key_from_evp(as_int(cgo["uiv"]["j"]["kb"]), True)
    s_key, s_meta = aes128_key_from_evp(as_int(cgo["uiv"]["s"]["k"]), False)
    j_polyval = bytes_of(cgo["uiv"]["j"]["ku"]["key"]["h"])
    s_polyval = bytes_of(cgo["uiv"]["s"]["b"]["h"])
    nonce = bytes_of(cgo["nonce"])
    tprime = bytes_of(cgo["tprime"])
    if not all(len(part) == 16 for part in
               (j_key, j_polyval, s_key, s_polyval, nonce, tprime)):
        raise gdb.GdbError("unexpected CGO component length")
    state = j_key + j_polyval + s_key + s_polyval + nonce
    row = {
        "direction": direction,
        "cgo_address": hex(as_int(cgo_ptr)),
        "state_sha256": hashlib.sha256(state).hexdigest(),
        "tprime_sha256": hashlib.sha256(tprime).hexdigest(),
        "aes_j": j_meta,
        "aes_s": s_meta,
    }
    if os.environ.get("CGO_INCLUDE_SECRETS") == "1":
        row["state_hex"] = state.hex()
        row["tprime_hex"] = tprime.hex()
    return row


def extract_circuit(target, owner_index, cgo_type, expected):
    """Return one all-CGO circuit without using an external circuit selector."""
    circ = target.dereference()
    if as_int(target) != int(expected["circuit_address"], 16):
        raise gdb.GdbError("circuit address differs from E3 manifest")
    if int(circ["global_origin_circuit_list_idx"]) != owner_index:
        raise gdb.GdbError("stored owner index differs from E3 manifest")
    if int(circ["base_"]["magic"]) != ORIGIN_CIRCUIT_MAGIC:
        raise gdb.GdbError("origin circuit magic is invalid")
    if int(circ["base_"]["state"]) != 4 or int(circ["base_"]["marked_for_close"]):
        raise gdb.GdbError("origin circuit is not active/open")
    if int(circ["global_identifier"]) != expected["control_circuit_id"]:
        raise gdb.GdbError("control circuit ID differs from E3 manifest")
    if int(circ["base_"]["n_circ_id"]) != expected["entry_link_circuit_id"]:
        raise gdb.GdbError("entry link circuit ID differs from E3 manifest")
    first = circ["cpath"]
    if not as_int(first):
        raise gdb.GdbError("origin circuit has no cpath")
    current = first
    hops = []
    for index in range(32):
        hop = current.dereference()
        if index >= len(expected["hops"]):
            raise gdb.GdbError("cpath has more hops than E3 manifest")
        expected_hop = expected["hops"][index]
        if as_int(current) != int(expected_hop["address"], 16):
            raise gdb.GdbError(f"hop {index} address differs from E3 manifest")
        if int(hop["magic"]) != CPATH_MAGIC or int(hop["state"]) != 2:
            raise gdb.GdbError(f"hop {index} is not structurally open")
        if (
            as_int(hop["next"].dereference()["prev"]) != as_int(current)
            or as_int(hop["prev"].dereference()["next"]) != as_int(current)
        ):
            raise gdb.GdbError(f"hop {index} has inconsistent links")
        crypto = hop["crypto_crypt_path_private_field"]
        if int(crypto["kind"]) != 1:
            raise gdb.GdbError(f"hop {index} is not CGO")
        pair = crypto["c"]["cgo"]
        hops.append({
            "index_from_entry": index,
            "hop_address": hex(as_int(current)),
            "forward": extract_direction(pair["fwd"].cast(cgo_type), "forward"),
            "backward": extract_direction(pair["back"].cast(cgo_type), "backward"),
        })
        current = hop["next"]
        if as_int(current) == as_int(first):
            break
    else:
        raise gdb.GdbError("cpath did not close within 32 hops")
    if len(hops) != expected["hop_count"]:
        raise gdb.GdbError("cpath hop count differs from E3 manifest")
    return {
        "owner_index": owner_index,
        "control_circuit_id": int(circ["global_identifier"]),
        "entry_link_circuit_id": int(circ["base_"]["n_circ_id"]),
        "hops": hops,
    }


def scan():
    layout = os.environ.get("CGO_OPENSSL_LAYOUT")
    if layout != "openssl-3.0.22-debian-arm64":
        raise gdb.GdbError("unsupported or unselected OpenSSL layout")
    manifest_path, manifest = load_e3_manifest()
    owner = gdb.parse_and_eval("global_origin_circuit_list")
    sl = owner.dereference()
    origin_type = gdb.lookup_type("struct origin_circuit_t").pointer()
    cgo_type = gdb.lookup_type("struct cgo_crypt_t").pointer()
    circuits = []
    errors = []
    if int(sl["num_used"]) != manifest["owner_list_count"]:
        raise gdb.GdbError("owner-list count differs from E3 manifest")
    for expected in manifest["circuits"]:
        idx = int(expected["owner_index"])
        if idx < 0 or idx >= int(sl["num_used"]):
            raise gdb.GdbError("E3 manifest owner index is out of bounds")
        ptr = sl["list"][idx].cast(origin_type)
        try:
            circuits.append(extract_circuit(ptr, idx, cgo_type, expected))
        except Exception as exc:
            errors.append({"owner_index": idx, "reason": str(exc)})
    if errors:
        raise gdb.GdbError(f"E3-constrained CGO extraction failed: {errors}")
    return {
        "schema": "tor-cgo-current-secret-state/0.3",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "layout": layout,
        "raw_secrets_included": os.environ.get("CGO_INCLUDE_SECRETS") == "1",
        "selection": "all circuits admitted by the ownership-first E3 manifest",
        "e3_manifest_enforced": True,
        "e3_manifest_path": manifest_path,
        "e3_manifest_source_scan_sha256": manifest["source_scan_sha256"],
        "owner_list_count": int(sl["num_used"]),
        "circuits": circuits,
        "errors": errors,
    }


try:
    report = scan()
    output = os.environ["CGO_SECRET_OUTPUT"]
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(output, 0o600)
except Exception as exc:
    print(f"CGO secret extraction failed: {exc}")
    gdb.execute("quit 3")
