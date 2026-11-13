#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 CASE_NAME TOR_BINARY TOR_GENCERT" >&2
    exit 2
fi

case_name=$1
tor_binary=$2
tor_gencert=$3
root=/work
result_dir=$root/results/generalization/$case_name
net_dir=$result_dir/net
chutney=$root/third_party/chutney/chutney
python=/opt/chutney-venv/bin/python

mkdir -p "$result_dir" "$net_dir"

export PYTHON=$python
export CHUTNEY_DATA_DIR=$net_dir
export CHUTNEY_TOR=$tor_binary
export CHUTNEY_TOR_GENCERT=$tor_gencert
export CHUTNEY_TOR_SANDBOX=0
export CHUTNEY_ENABLE_CONTROLSOCKET=false
export CHUTNEY_DISABLE_IPV6=1
export CHUTNEY_START_TIME=180
export CHUTNEY_BOOTSTRAP_TIME=60

stop_network() {
    "$chutney" --data-dir "$net_dir" stop >/dev/null 2>&1 || true
}
trap stop_network EXIT INT TERM

"$chutney" --data-dir "$net_dir" init \
    --net-from-script-path "$root/experiments/network_evaluation.py" \
    --tor "$tor_binary" --tor-gencert "$tor_gencert" \
    --tor-sandbox 0 --enable-controlsocket false --disable-ipv6 1
"$chutney" --data-dir "$net_dir" bootstrap

nodes=$(readlink -f "$net_dir/nodes")
entry=$(awk '{print $2}' "$nodes/004r/fingerprint")
middle=$(awk '{print $2}' "$nodes/005r/fingerprint")
exit_node=$(awk '{print $2}' "$nodes/000a/fingerprint")
client_cookie=$nodes/006c/control_auth_cookie

$python "$root/experiments/build_controlled_circuits.py" \
    --control-port 8006 --cookie "$client_cookie" \
    --path "$entry,$middle,$exit_node" --count 12 \
    --output "$result_dir/controlled-circuits.json"

$python "$root/experiments/control_ground_truth.py" \
    --port 8006 --cookie "$client_cookie" \
    --output "$result_dir/control-before.json"

client_pid=$(cat "$nodes/006c/pid")
kill -STOP "$client_pid"
gdb -q -batch -p "$client_pid" \
    -ex "gcore $result_dir/client.core" \
    -ex detach -ex quit >"$result_dir/gcore.log" 2>&1
kill -CONT "$client_pid"

$python "$root/experiments/control_ground_truth.py" \
    --port 8006 --cookie "$client_cookie" \
    --output "$result_dir/control-after.json"

CGO_OUTPUT="$result_dir/scan.json" gdb -q -batch \
    "$tor_binary" "$result_dir/client.core" \
    -ex "source $root/forensics/gdb_scan.py" \
    >"$result_dir/scan-gdb.log" 2>&1

$python "$root/experiments/evaluate_snapshot.py" \
    --scan "$result_dir/scan.json" \
    --before "$result_dir/control-before.json" \
    --after "$result_dir/control-after.json" \
    --output "$result_dir/evaluation.json"

$python "$root/experiments/write_case_metadata.py" \
    --case "$case_name" --binary "$tor_binary" \
    --core "$result_dir/client.core" \
    --output "$result_dir/metadata.json"

stop_network
trap - EXIT INT TERM
