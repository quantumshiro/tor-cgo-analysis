"""Extract TLS 1.3 traffic secrets for every eligible owned origin circuit.

Validated profile: OpenSSL 3.0.22 Debian arm64.  The Tor object path is
origin_circuit -> n_chan(channel_tls_t) -> or_connection -> tor_tls_t -> SSL.
Raw key-log output is opt-in and written mode 0600.
"""

import datetime
import hashlib
import json
import os
import struct

import gdb


PROFILE = "openssl-3.0.22-debian-arm64"
OFF = {
    "version": 0,
    "server": 56,
    "client_random": 352,
    "client_app_traffic_secret": 1860,
    "server_app_traffic_secret": 1924,
    "read_iv": 2128,
    "write_iv": 2176,
    "read_sequence": 7416,
    "write_sequence": 7424,
    "session": 2328,
    "session_cipher": 760,
    "cipher_id": 24,
}

CIPHER_SUITES = {
    0x1301: ("TLS_AES_128_GCM_SHA256", "SHA256", 32),
    0x1302: ("TLS_AES_256_GCM_SHA384", "SHA384", 48),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "SHA256", 32),
}


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


def read(addr, size):
    return bytes(gdb.selected_inferior().read_memory(addr, size))


def read_ptr(addr):
    return struct.unpack("<Q", read(addr, 8))[0]


def secret_length(raw):
    if any(raw[48:]):
        raise gdb.GdbError("unexpected nonzero TLS secret tail")
    if any(raw[32:48]):
        return 48
    if any(raw[:32]):
        return 32
    raise gdb.GdbError("TLS application traffic secret is zero")


def extract_circuit(target, owner_index, channel_tls_type, expected):
    circ = target.dereference()
    if as_int(target) != int(expected["circuit_address"], 16):
        raise gdb.GdbError("circuit address differs from E3 manifest")
    if int(circ["global_origin_circuit_list_idx"]) != owner_index:
        raise gdb.GdbError("stored owner index differs from E3 manifest")
    if int(circ["global_identifier"]) != expected["control_circuit_id"]:
        raise gdb.GdbError("control circuit ID differs from E3 manifest")
    if int(circ["base_"]["n_circ_id"]) != expected["entry_link_circuit_id"]:
        raise gdb.GdbError("entry link circuit ID differs from E3 manifest")
    channel = circ["base_"]["n_chan"]
    if not as_int(channel):
        raise gdb.GdbError("origin circuit has no entry channel")
    tls_channel = channel.cast(channel_tls_type).dereference()
    or_conn_ptr = tls_channel["conn"]
    if not as_int(or_conn_ptr):
        raise gdb.GdbError("TLS channel has no OR connection")
    or_conn = or_conn_ptr.dereference()
    tor_tls_ptr = or_conn["tls"]
    if not as_int(tor_tls_ptr):
        raise gdb.GdbError("OR connection has no tor_tls_t")
    tor_tls = tor_tls_ptr.dereference()
    ssl_addr = as_int(tor_tls["ssl"])
    if not ssl_addr:
        raise gdb.GdbError("tor_tls_t has no SSL object")

    version = struct.unpack("<i", read(ssl_addr + OFF["version"], 4))[0]
    server = struct.unpack("<i", read(ssl_addr + OFF["server"], 4))[0]
    if version != 0x0304:
        raise gdb.GdbError(f"expected TLS 1.3, got {version:#x}")
    if server != 0 or bool(tor_tls["isServer"]):
        raise gdb.GdbError("target SSL object is not the client side")

    client_random = read(ssl_addr + OFF["client_random"], 32)
    client_raw = read(ssl_addr + OFF["client_app_traffic_secret"], 64)
    server_raw = read(ssl_addr + OFF["server_app_traffic_secret"], 64)
    client_len = secret_length(client_raw)
    server_len = secret_length(server_raw)
    if client_len != server_len:
        raise gdb.GdbError("client/server TLS secret lengths differ")
    client_secret = client_raw[:client_len]
    server_secret = server_raw[:server_len]
    read_iv = read(ssl_addr + OFF["read_iv"], 12)
    write_iv = read(ssl_addr + OFF["write_iv"], 12)
    read_sequence_raw = read(ssl_addr + OFF["read_sequence"], 8)
    write_sequence_raw = read(ssl_addr + OFF["write_sequence"], 8)
    session_addr = read_ptr(ssl_addr + OFF["session"])
    if not session_addr:
        raise gdb.GdbError("SSL session is null")
    cipher_addr = read_ptr(session_addr + OFF["session_cipher"])
    if not cipher_addr:
        raise gdb.GdbError("SSL session cipher is null")
    cipher_id_raw = struct.unpack("<I", read(cipher_addr + OFF["cipher_id"], 4))[0]
    cipher_id = cipher_id_raw & 0xFFFF
    if cipher_id not in CIPHER_SUITES:
        raise gdb.GdbError(f"unsupported TLS 1.3 cipher suite: {cipher_id:#06x}")
    cipher_suite, hash_algorithm, expected_secret_length = CIPHER_SUITES[cipher_id]
    if client_len != expected_secret_length:
        raise gdb.GdbError(
            f"secret length {client_len} disagrees with {cipher_suite}"
        )

    row = {
        "owner_index": owner_index,
        "control_circuit_id": int(circ["global_identifier"]),
        "entry_link_circuit_id": int(circ["base_"]["n_circ_id"]),
        "entry_channel_id": int(channel.dereference()["global_identifier"]),
        "or_connection_address": hex(as_int(or_conn_ptr)),
        "tor_tls_address": hex(as_int(tor_tls_ptr)),
        "ssl_address": hex(ssl_addr),
        "tls_version": "1.3",
        "ssl_is_server": False,
        "secret_length": client_len,
        "cipher_suite_id": f"0x{cipher_id:04x}",
        "cipher_suite": cipher_suite,
        "hash_algorithm": hash_algorithm,
        "cipher_suite_source": "SSL.session->cipher->id",
        "client_random": client_random.hex(),
        "client_traffic_secret_sha256": hashlib.sha256(client_secret).hexdigest(),
        "server_traffic_secret_sha256": hashlib.sha256(server_secret).hexdigest(),
        "read_iv": read_iv.hex(),
        "write_iv": write_iv.hex(),
        "read_sequence": int.from_bytes(read_sequence_raw, "big"),
        "write_sequence": int.from_bytes(write_sequence_raw, "big"),
        "raw_secrets_included": os.environ.get("CGO_INCLUDE_TLS_SECRETS") == "1",
    }
    if row["raw_secrets_included"]:
        row["client_traffic_secret"] = client_secret.hex()
        row["server_traffic_secret"] = server_secret.hex()
    return row, client_random, client_secret, server_secret


def scan():
    if os.environ.get("CGO_OPENSSL_TLS_LAYOUT") != PROFILE:
        raise gdb.GdbError("unsupported or unselected OpenSSL TLS layout")
    manifest_path, manifest = load_e3_manifest()
    owner = gdb.parse_and_eval("global_origin_circuit_list").dereference()
    origin_type = gdb.lookup_type("struct origin_circuit_t").pointer()
    channel_tls_type = gdb.lookup_type("struct channel_tls_t").pointer()
    circuits = []
    keylog_rows = []
    errors = []
    if int(owner["num_used"]) != manifest["owner_list_count"]:
        raise gdb.GdbError("owner-list count differs from E3 manifest")
    for expected in manifest["circuits"]:
        idx = int(expected["owner_index"])
        if idx < 0 or idx >= int(owner["num_used"]):
            raise gdb.GdbError("E3 manifest owner index is out of bounds")
        ptr = owner["list"][idx].cast(origin_type)
        try:
            row, client_random, client_secret, server_secret = extract_circuit(
                ptr, idx, channel_tls_type, expected
            )
            circuits.append(row)
            keylog_rows.append((client_random, client_secret, server_secret))
        except Exception as exc:
            errors.append({"owner_index": idx, "reason": str(exc)})
    if errors:
        raise gdb.GdbError(f"E3-constrained TLS extraction failed: {errors}")
    report = {
        "schema": "tor-cgo-link-tls-secret-state/0.3",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "layout": PROFILE,
        "selection": "all circuits admitted by the ownership-first E3 manifest",
        "e3_manifest_enforced": True,
        "e3_manifest_path": manifest_path,
        "e3_manifest_source_scan_sha256": manifest["source_scan_sha256"],
        "owner_list_count": int(owner["num_used"]),
        "raw_secrets_included": os.environ.get("CGO_INCLUDE_TLS_SECRETS") == "1",
        "circuits": circuits,
        "errors": errors,
    }
    return report, keylog_rows


try:
    report, keylog_rows = scan()
    output = os.environ["CGO_TLS_SECRET_OUTPUT"]
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(output, 0o600)
    keylog = os.environ.get("CGO_TLS_KEYLOG_OUTPUT")
    if keylog:
        with open(keylog, "w", encoding="ascii") as handle:
            seen = set()
            for client_random, client_secret, server_secret in keylog_rows:
                values = (client_random, client_secret, server_secret)
                if values in seen:
                    continue
                seen.add(values)
                random_hex = client_random.hex()
                handle.write(
                    f"CLIENT_TRAFFIC_SECRET_0 {random_hex} {client_secret.hex()}\n"
                )
                handle.write(
                    f"SERVER_TRAFFIC_SECRET_0 {random_hex} {server_secret.hex()}\n"
                )
        os.chmod(keylog, 0o600)
except Exception as exc:
    print(f"TLS secret extraction failed: {exc}")
    gdb.execute("quit 3")
