#!/bin/sh
set -eu

root=/work
result_dir=${CGO_RESULT_DIR:-$root/results/open-circuit-impact/live-replay}
net_dir=$result_dir/net
tor_binary=$root/build/tor-0.4.9.16-o2/src/app/tor
tor_gencert=$root/build/tor-0.4.9.16-o2/src/tools/tor-gencert
chutney=$root/third_party/chutney/chutney
python=/opt/chutney-venv/bin/python
source_ip=${CGO_SOURCE_IP:-}
payload_prefix=${CGO_PAYLOAD_PREFIX:-}
capture_pcap=${CGO_CAPTURE_PCAP:-0}
snapshot_timing=${CGO_SNAPSHOT_TIMING:-before}
mkdir -p "$result_dir" "$net_dir" "$result_dir/scans"

export PYTHON=$python CHUTNEY_DATA_DIR=$net_dir CHUTNEY_TOR=$tor_binary
export CHUTNEY_TOR_GENCERT=$tor_gencert CHUTNEY_TOR_SANDBOX=0
export CHUTNEY_ENABLE_CONTROLSOCKET=false CHUTNEY_DISABLE_IPV6=1
export CHUTNEY_START_TIME=180 CHUTNEY_BOOTSTRAP_TIME=60
stop_network() { "$chutney" --data-dir "$net_dir" stop >/dev/null 2>&1 || true; }
cleanup() {
  touch "$result_dir/traffic-stop" "$result_dir/attach-stop" 2>/dev/null || true
  [ -n "${traffic_pid:-}" ] && kill "$traffic_pid" 2>/dev/null || true
  [ -n "${attach_pid:-}" ] && kill "$attach_pid" 2>/dev/null || true
  [ -n "${pcap_pid:-}" ] && kill "$pcap_pid" 2>/dev/null || true
  [ -n "${client_pid:-}" ] && kill -CONT "$client_pid" 2>/dev/null || true
  stop_network
}
trap cleanup EXIT INT TERM

rm -f "$result_dir/traffic-stop" "$result_dir/attach-stop" \
  "$result_dir/attach-ready" "$result_dir/stream-ready" \
  "$result_dir/pause-request" "$result_dir/stream-paused" \
  "$result_dir/stream-resume" "$result_dir/cell.json"
stop_network
"$chutney" --data-dir "$net_dir" init \
  --net-from-script-path "$root/experiments/network_evaluation.py" \
  --tor "$tor_binary" --tor-gencert "$tor_gencert" \
  --tor-sandbox 0 --enable-controlsocket false --disable-ipv6 1
"$chutney" --data-dir "$net_dir" bootstrap

nodes=$(readlink -f "$net_dir/nodes")
entry=$(awk '{print $2}' "$nodes/004r/fingerprint")
middle=$(awk '{print $2}' "$nodes/000a/fingerprint")
exit_node=$(awk '{print $2}' "$nodes/005r/fingerprint")
cookie=$nodes/006c/control_auth_cookie
client_pid=$(cat "$nodes/006c/pid")

if [ "$capture_pcap" = 1 ]; then
  rm -f "$result_dir/pcap-stop" "$result_dir/pcap-ready"
  "$python" "$root/experiments/capture_loopback_pcap.py" \
    --port 5104 --output "$result_dir/entry-link.pcap" \
    --stop-file "$result_dir/pcap-stop" --ready-file "$result_dir/pcap-ready" \
    --metadata "$result_dir/pcap-capture.json" &
  pcap_pid=$!
  for _ in $(seq 1 200); do
    [ -f "$result_dir/pcap-ready" ] && break
    sleep 0.05
  done
  [ -f "$result_dir/pcap-ready" ]
fi

"$python" "$root/experiments/build_controlled_circuits.py" \
  --control-port 8006 --cookie "$cookie" --path "$entry,$middle,$exit_node" \
  --count 1 --output "$result_dir/controlled.json"
control_id=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["built_circuit_ids"][0])' "$result_dir/controlled.json")

"$python" "$root/experiments/attach_streams_to_circuits.py" \
  --control-port 8006 --cookie "$cookie" --circuits "$result_dir/controlled.json" \
  --ready-file "$result_dir/attach-ready" --stop-file "$result_dir/attach-stop" \
  --output "$result_dir/attachments.json" >"$result_dir/attach.log" 2>&1 &
attach_pid=$!
for _ in $(seq 1 200); do
  [ -f "$result_dir/attach-ready" ] && break
  sleep 0.05
done
[ -f "$result_dir/attach-ready" ]

source_option=
[ -n "$source_ip" ] && source_option="--source-ip=$source_ip"
"$python" "$root/experiments/slow_socks_stream.py" \
  --socks-port 9006 --echo-port 4848 \
  --ready-file "$result_dir/stream-ready" \
  --pause-request "$result_dir/pause-request" \
  --paused-file "$result_dir/stream-paused" \
  --resume-file "$result_dir/stream-resume" \
  --stop-file "$result_dir/traffic-stop" \
  --output "$result_dir/traffic-result.json" \
  --payload-prefix "$payload_prefix" $source_option \
  >"$result_dir/traffic.log" 2>&1 &
traffic_pid=$!
for _ in $(seq 1 200); do
  [ -f "$result_dir/stream-ready" ] && break
  sleep 0.05
done
[ -f "$result_dir/stream-ready" ]
touch "$result_dir/pause-request"
for _ in $(seq 1 200); do
  [ -f "$result_dir/stream-paused" ] && break
  sleep 0.05
done
[ -f "$result_dir/stream-paused" ]
sleep 0.2

extract_and_validate_core() {
  CGO_INCLUDE_CLIENT_ENDPOINTS=${CGO_INCLUDE_CLIENT_ENDPOINTS:-0} \
  CGO_OUTPUT="$result_dir/scans/client.json" gdb -q -batch "$tor_binary" \
    "$result_dir/client.core" -ex "source $root/forensics/gdb_scan.py" \
    >"$result_dir/scan-gdb.log" 2>&1
  "$python" - "$result_dir/scans/client.json" "$control_id" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
c = next(row for row in d["circuits"] if row["control_circuit_id"] == int(sys.argv[2]))
if c.get("stream_count") != 1:
    raise SystemExit(f"expected one attached stream, got {c.get('stream_count')}")
if [h["crypto_kind"] for h in c["hops"]] != ["CGO", "CGO", "CGO"]:
    raise SystemExit("controlled path is not all-CGO")
PY
  "$python" "$root/experiments/build_e3_manifest.py" \
    --scan "$result_dir/scans/client.json" \
    --output "$result_dir/e3-circuit-manifest.json"
  CGO_OPENSSL_LAYOUT=openssl-3.0.22-debian-arm64 \
  CGO_E3_MANIFEST="$result_dir/e3-circuit-manifest.json" \
  CGO_INCLUDE_SECRETS=1 \
  CGO_SECRET_OUTPUT="$result_dir/secret-state.json" \
    gdb -q -batch "$tor_binary" "$result_dir/client.core" \
    -ex "source $root/forensics/gdb_extract_cgo_secrets.py" \
    >"$result_dir/secret-extract-gdb.log" 2>&1
  "$python" - "$result_dir/secret-state.json" "$result_dir/selected-live-state.json" "$control_id" <<'PY'
import json, os, sys
document = json.load(open(sys.argv[1]))
matches = [row for row in document["circuits"] if row["control_circuit_id"] == int(sys.argv[3])]
if len(matches) != 1:
    raise SystemExit(f"expected one evaluation circuit, got {len(matches)}")
row = dict(matches[0])
row.update({
    "schema": "tor-cgo-current-secret-state-selected-live-evaluation/0.2",
    "layout": document["layout"],
    "raw_secrets_included": document["raw_secrets_included"],
    "external_circuit_selector_used": True,
})
with open(sys.argv[2], "w") as handle:
    json.dump(row, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.chmod(sys.argv[2], 0o600)
PY
  link_circid=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["entry_link_circuit_id"])' "$result_dir/selected-live-state.json")
}

post_cell_core=
if [ "$snapshot_timing" = before ]; then
  kill -STOP "$client_pid"
  gdb -q -batch -p "$client_pid" \
    -ex "gcore $result_dir/client.core" -ex detach -ex quit \
    >"$result_dir/gcore.log" 2>&1
  state=$(awk '/^State:/ {print $2}' "/proc/$client_pid/status")
  [ "$state" = T ]
  extract_and_validate_core
  # Attach the live debugger only after releasing the job-control stop.
  kill -CONT "$client_pid"
  for _ in $(seq 1 200); do
    state=$(awk '/^State:/ {print $2}' "/proc/$client_pid/status")
    [ "$state" != T ] && break
    sleep 0.01
  done
  [ "$state" != T ]
elif [ "$snapshot_timing" = after ]; then
  link_circid=0
  post_cell_core=$result_dir/client.core
else
  echo "unsupported CGO_SNAPSHOT_TIMING: $snapshot_timing" >&2
  exit 2
fi

if [ "$snapshot_timing" = after ]; then
  CGO_TARGET_CONTROL_ID="$control_id" CGO_TARGET_LINK_CIRCID="$link_circid" \
  CGO_CELL_OUTPUT="$result_dir/cell.json" \
    timeout 40 gdb -q -batch -p "$client_pid" \
    -ex "source $root/forensics/gdb_capture_next_relay_cell.py" \
    -ex "shell touch $result_dir/stream-resume" \
    -ex continue -ex "gcore $post_cell_core" -ex detach -ex quit \
    >"$result_dir/cell-capture-gdb.log" 2>&1
else
  CGO_TARGET_CONTROL_ID="$control_id" CGO_TARGET_LINK_CIRCID="$link_circid" \
  CGO_CELL_OUTPUT="$result_dir/cell.json" \
    timeout 40 gdb -q -batch -p "$client_pid" \
    -ex "source $root/forensics/gdb_capture_next_relay_cell.py" \
    -ex "shell touch $result_dir/stream-resume" \
    -ex continue -ex detach -ex quit \
    >"$result_dir/cell-capture-gdb.log" 2>&1
fi
[ -f "$result_dir/cell.json" ]

if [ "$snapshot_timing" = after ]; then
  [ -f "$result_dir/client.core" ]
  extract_and_validate_core
fi

touch "$result_dir/traffic-stop"
traffic_rc=0
wait "$traffic_pid" || traffic_rc=$?
traffic_pid=
printf '%s\n' "$traffic_rc" >"$result_dir/traffic-exit-code.txt"
touch "$result_dir/attach-stop"
wait "$attach_pid"
attach_pid=

"$python" "$root/experiments/build_cgo_replay_fixture.py" \
  --state "$result_dir/selected-live-state.json" --cell "$result_dir/cell.json" \
  --fixture "$result_dir/replay.bin" --metadata "$result_dir/replay-metadata.json"
if [ "$snapshot_timing" = after ]; then
  CGO_REPLAY_FIXTURE="$result_dir/replay.bin" \
  CGO_REPLAY_RESULT="$result_dir/replay-result.json" \
  CGO_REPLAY_EXPECT_UNRECOGNIZED=1 \
  CGO_REPLAY_UNRECOGNIZED_LABEL=post_cell_state_cannot_decrypt_past_cell \
    "$root/build/tor-cgo-audit-normal/src/test/test" \
    crypto/cgo/cgo_external_core_replay >"$result_dir/replay-test.log" 2>&1
else
  CGO_REPLAY_FIXTURE="$result_dir/replay.bin" \
  CGO_REPLAY_RESULT="$result_dir/replay-result.json" \
    "$root/build/tor-cgo-audit-normal/src/test/test" \
    crypto/cgo/cgo_external_core_replay >"$result_dir/replay-test.log" 2>&1
fi

if [ "$capture_pcap" = 1 ]; then
  touch "$result_dir/pcap-stop"
  wait "$pcap_pid"
  pcap_pid=
  "$python" "$root/experiments/evaluate_pcap_visibility.py" \
    --pcap "$result_dir/entry-link.pcap" --cell "$result_dir/cell.json" \
    --marker "$payload_prefix" --output "$result_dir/pcap-evaluation.json"
fi

stop_network
trap - EXIT INT TERM
