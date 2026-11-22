#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 CASE_NAME PATH_LENGTH PRE_CAPTURE_DELAY_SECONDS" >&2
  exit 2
fi

case_name=$1
path_length=$2
pre_capture_delay=$3
post_capture_delay=${CGO_POST_CAPTURE_DELAY:-0.75}
stream_iteration_delay=${CGO_STREAM_ITERATION_DELAY:-0.01}
entry_backpressure_seconds=${CGO_ENTRY_BACKPRESSURE_SECONDS:-0}
traffic_mode=${CGO_TRAFFIC_MODE:-paced}
client_bandwidth_rate=${CGO_CLIENT_BANDWIDTH_RATE:-}
snapshot_mode=${CGO_SNAPSHOT_MODE:-ordinary_gcore}
controlled_circuit_count=${CGO_CONTROLLED_CIRCUIT_COUNT:-1}
traffic_connection_count=${CGO_TRAFFIC_CONNECTION_COUNT:-1}
case "$path_length" in 1|2|3) ;; *) echo "path length must be 1, 2, or 3" >&2; exit 2;; esac

root=/work
result_root=${CGO_RESULT_ROOT:-$root/results/uncontrolled-pcap}
result_dir=$result_root/$case_name
net_dir=$result_dir/net
tor_binary=${CGO_TOR_BINARY_CONTAINER:-$root/build/tor-0.4.9.16-o2/src/app/tor}
tor_gencert=${CGO_TOR_GENCERT_CONTAINER:-$root/build/tor-0.4.9.16-o2/src/tools/tor-gencert}
distribution_label=${CGO_DISTRIBUTION_LABEL:-self-built}
chutney=$root/third_party/chutney/chutney
python=/opt/chutney-venv/bin/python
mkdir -p "$result_dir" "$net_dir"

export PYTHON=$python CHUTNEY_DATA_DIR=$net_dir CHUTNEY_TOR=$tor_binary
export CHUTNEY_TOR_GENCERT=$tor_gencert CHUTNEY_TOR_SANDBOX=0
export CHUTNEY_ENABLE_CONTROLSOCKET=false CHUTNEY_DISABLE_IPV6=1
export CHUTNEY_START_TIME=180 CHUTNEY_BOOTSTRAP_TIME=60

stop_network() { "$chutney" --data-dir "$net_dir" stop >/dev/null 2>&1 || true; }
cleanup() {
  touch "$result_dir/traffic-stop" "$result_dir/attach-stop" "$result_dir/pcap-stop" 2>/dev/null || true
  [ -n "${traffic_pid:-}" ] && kill "$traffic_pid" 2>/dev/null || true
  [ -n "${attach_pid:-}" ] && kill "$attach_pid" 2>/dev/null || true
  [ -n "${pcap_pid:-}" ] && kill "$pcap_pid" 2>/dev/null || true
  [ -n "${entry_pid:-}" ] && kill -CONT "$entry_pid" 2>/dev/null || true
  stop_network
}
trap cleanup EXIT INT TERM

rm -f "$result_dir/traffic-stop" "$result_dir/attach-stop" \
  "$result_dir/attach-ready" "$result_dir/stream-ready" \
  "$result_dir/pcap-stop" "$result_dir/pcap-ready"
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
entry_pid=$(cat "$nodes/004r/pid")
if [ -n "$client_bandwidth_rate" ]; then
  {
    printf 'BandwidthRate %s\n' "$client_bandwidth_rate"
    printf 'BandwidthBurst %s\n' "$client_bandwidth_rate"
  } >>"$nodes/006c/torrc"
  kill -HUP "$client_pid"
  sleep 1
fi
case "$path_length" in
  1) path=$exit_node; entry_port=5105 ;;
  2) path=$entry,$exit_node; entry_port=5104 ;;
  3) path=$entry,$middle,$exit_node; entry_port=5104 ;;
esac

"$python" "$root/experiments/capture_loopback_pcap.py" \
  --port "$entry_port" --output "$result_dir/entry-link.pcap" \
  --stop-file "$result_dir/pcap-stop" --ready-file "$result_dir/pcap-ready" \
  --metadata "$result_dir/pcap-capture.json" &
pcap_pid=$!
for _ in $(seq 1 200); do
  [ -f "$result_dir/pcap-ready" ] && break
  sleep 0.05
done
[ -f "$result_dir/pcap-ready" ]

"$python" "$root/experiments/build_controlled_circuits.py" \
  --control-port 8006 --cookie "$cookie" --path "$path" \
  --count "$controlled_circuit_count" --output "$result_dir/controlled.json"

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

marker="CGO-UCT-$case_name-"
payload_prefix=$("$python" -c 'import sys; m=sys.argv[1]; print((m*((4096//len(m))+1))[:4096])' "$marker")
case "$traffic_mode" in
  paced)
    "$python" "$root/experiments/slow_socks_stream.py" \
      --socks-port 9006 --echo-port 4848 \
      --ready-file "$result_dir/stream-ready" \
      --pause-request "$result_dir/pause-request-never-created" \
      --paused-file "$result_dir/stream-paused-not-expected" \
      --resume-file "$result_dir/stream-resume-not-expected" \
      --stop-file "$result_dir/traffic-stop" \
      --output "$result_dir/traffic-result.json" \
      --iteration-delay "$stream_iteration_delay" \
      --payload-prefix "$payload_prefix" >"$result_dir/traffic.log" 2>&1 &
    ;;
  flood)
    "$python" "$root/experiments/flood_socks_stream.py" \
      --socks-port 9006 --echo-port 4848 \
      --ready-file "$result_dir/stream-ready" \
      --stop-file "$result_dir/traffic-stop" \
      --output "$result_dir/traffic-result.json" \
      --connections "$traffic_connection_count" \
      --iteration-delay "$stream_iteration_delay" \
      --payload-prefix "$payload_prefix" >"$result_dir/traffic.log" 2>&1 &
    ;;
  *) echo "unsupported CGO_TRAFFIC_MODE: $traffic_mode" >&2; exit 2 ;;
esac
traffic_pid=$!
for _ in $(seq 1 200); do
  [ -f "$result_dir/stream-ready" ] && break
  sleep 0.05
done
[ -f "$result_dir/stream-ready" ]

# The delay varies between runs.  No stream pause, cell hook, or Tor-cell
# boundary signal is used.  gcore itself necessarily suspends the process
# while copying its address space.
sleep "$pre_capture_delay"
if [ "$entry_backpressure_seconds" != 0 ]; then
  kill -STOP "$entry_pid"
  sleep "$entry_backpressure_seconds"
fi
case "$snapshot_mode" in
  ordinary_gcore)
    gdb -q -batch -p "$client_pid" \
      -ex "gcore $result_dir/client.core" -ex detach -ex quit \
      >"$result_dir/gcore.log" 2>&1
    ;;
  after_cgo_before_queue)
    evaluation_control_id=$("$python" -c \
      'import json,sys; print(json.load(open(sys.argv[1]))["built_circuit_ids"][0])' \
      "$result_dir/controlled.json")
    gdb -q -batch -p "$client_pid" \
      -ex "break append_cell_to_circuit_queue if circ->magic == 0x35315243 && ((origin_circuit_t *)circ)->global_identifier == $evaluation_control_id" \
      -ex continue \
      -ex 'printf "CGO_BOUNDARY_REACHED control_id=%u\\n", ((origin_circuit_t *)circ)->global_identifier' \
      -ex 'bt 3' \
      -ex "gcore $result_dir/client.core" -ex detach -ex quit \
      >"$result_dir/gcore.log" 2>&1
    ;;
  *) echo "unsupported CGO_SNAPSHOT_MODE: $snapshot_mode" >&2; exit 2 ;;
esac
if [ "$entry_backpressure_seconds" != 0 ]; then
  kill -CONT "$entry_pid"
fi
sleep "$post_capture_delay"

touch "$result_dir/traffic-stop"
traffic_rc=0
wait "$traffic_pid" || traffic_rc=$?
traffic_pid=
printf '%s\n' "$traffic_rc" >"$result_dir/traffic-exit-code.txt"
touch "$result_dir/attach-stop"
wait "$attach_pid"
attach_pid=
touch "$result_dir/pcap-stop"
wait "$pcap_pid"
pcap_pid=

"$python" - "$result_dir/acquisition.json" "$case_name" "$path_length" \
  "$pre_capture_delay" "$marker" "$entry_port" "$tor_binary" \
  "$distribution_label" "$post_capture_delay" "$stream_iteration_delay" \
  "$entry_backpressure_seconds" "$traffic_mode" "$client_bandwidth_rate" \
  "$snapshot_mode" "$controlled_circuit_count" "$traffic_connection_count" <<'PY'
import json, subprocess, sys
from pathlib import Path
(
    out, name, path_length, delay, marker, port, tor_binary,
    distribution_label, post_delay, iteration_delay, backpressure_seconds,
    traffic_mode,
    client_bandwidth_rate,
    snapshot_mode,
    controlled_circuit_count,
    traffic_connection_count,
) = sys.argv[1:]
notes = subprocess.check_output(["readelf", "-n", tor_binary], text=True)
build_id = next(
    line.split("Build ID:", 1)[1].strip()
    for line in notes.splitlines() if "Build ID:" in line
)
Path(out).write_text(json.dumps({
    "schema": "tor-cgo-uncontrolled-pcap-acquisition/0.1",
    "case": name,
    "path_length": int(path_length),
    "pre_capture_delay_seconds": float(delay),
    "post_capture_duration_seconds": float(post_delay),
    "stream_iteration_delay_seconds": float(iteration_delay),
    "entry_relay_pause_before_snapshot_seconds": float(backpressure_seconds),
    "entry_relay_resumed_after_snapshot": float(backpressure_seconds) > 0,
    "traffic_mode": traffic_mode,
    "client_bandwidth_rate": client_bandwidth_rate or None,
    "snapshot_mode": snapshot_mode,
    "controlled_circuit_count": int(controlled_circuit_count),
    "traffic_connection_count": int(traffic_connection_count),
    "snapshot_boundary_selected_from_cell_processing": (
        snapshot_mode == "after_cgo_before_queue"
    ),
    "marker": marker,
    "entry_or_port": int(port),
    "traffic_paused_for_snapshot": False,
    "dynamic_cell_hook_used": snapshot_mode == "after_cgo_before_queue",
    "gcore_process_suspension_required": True,
    "tor_binary": tor_binary,
    "tor_version": subprocess.check_output([tor_binary, "--version"], text=True).splitlines()[0],
    "tor_build_id": build_id,
    "tor_binary_description": subprocess.check_output(["file", "-b", tor_binary], text=True).strip(),
    "distribution_label": distribution_label,
}, indent=2, sort_keys=True) + "\n")
PY

stop_network
trap - EXIT INT TERM
