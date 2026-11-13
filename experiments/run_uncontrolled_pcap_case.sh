#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 CASE_NAME PATH_LENGTH PRE_CAPTURE_DELAY_SECONDS" >&2
  exit 2
fi

case_name=$1
path_length=$2
pre_capture_delay=$3
case "$path_length" in 1|2|3) ;; *) echo "path length must be 1, 2, or 3" >&2; exit 2;; esac

root=/work
result_dir=$root/results/uncontrolled-pcap/$case_name
net_dir=$result_dir/net
tor_binary=$root/build/tor-0.4.9.16-o2/src/app/tor
tor_gencert=$root/build/tor-0.4.9.16-o2/src/tools/tor-gencert
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
  --count 1 --output "$result_dir/controlled.json"

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
"$python" "$root/experiments/slow_socks_stream.py" \
  --socks-port 9006 --echo-port 4848 \
  --ready-file "$result_dir/stream-ready" \
  --pause-request "$result_dir/pause-request-never-created" \
  --paused-file "$result_dir/stream-paused-not-expected" \
  --resume-file "$result_dir/stream-resume-not-expected" \
  --stop-file "$result_dir/traffic-stop" \
  --output "$result_dir/traffic-result.json" \
  --payload-prefix "$payload_prefix" >"$result_dir/traffic.log" 2>&1 &
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
gdb -q -batch -p "$client_pid" \
  -ex "gcore $result_dir/client.core" -ex detach -ex quit \
  >"$result_dir/gcore.log" 2>&1
sleep 0.75

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
  "$pre_capture_delay" "$marker" "$entry_port" <<'PY'
import json, sys
from pathlib import Path
out, name, path_length, delay, marker, port = sys.argv[1:]
Path(out).write_text(json.dumps({
    "schema": "tor-cgo-uncontrolled-pcap-acquisition/0.1",
    "case": name,
    "path_length": int(path_length),
    "pre_capture_delay_seconds": float(delay),
    "marker": marker,
    "entry_or_port": int(port),
    "traffic_paused_for_snapshot": False,
    "dynamic_cell_hook_used": False,
    "snapshot_boundary_selected_from_cell_processing": False,
    "gcore_process_suspension_required": True,
}, indent=2, sort_keys=True) + "\n")
PY

stop_network
trap - EXIT INT TERM
