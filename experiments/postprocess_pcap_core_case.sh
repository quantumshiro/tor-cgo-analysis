#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 source-results/path [output-results/path]" >&2
  exit 2
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir=$1
result_dir=${2:-$source_dir}
mkdir -p "$result_dir"
case "$source_dir" in
  "$root"/*) source_relative=${source_dir#"$root"/} ;;
  *) echo "source directory must be inside $root" >&2; exit 2 ;;
esac
case "$result_dir" in
  "$root"/*) result_relative=${result_dir#"$root"/} ;;
  *) echo "output directory must be inside $root" >&2; exit 2 ;;
esac
container_source_dir=/work/$source_relative
container_dir=/work/$result_relative
python3 "$root/forensics/verify_core_executable.py" \
  --executable "$root/build/tor-0.4.9.16-o2/src/app/tor" \
  --core "$source_dir/client.core" \
  --output "$result_dir/executable-verification.json"
docker exec \
  -e CGO_OUTPUT="$container_dir/core-scan.json" \
  tor-cgo-lab gdb -q -batch \
  /work/build/tor-0.4.9.16-o2/src/app/tor "$container_source_dir/client.core" \
  -ex 'source /work/forensics/gdb_scan.py' \
  >"$result_dir/core-scan-gdb.log" 2>&1

python3 "$root/experiments/build_e3_manifest.py" \
  --scan "$result_dir/core-scan.json" \
  --output "$result_dir/e3-circuit-manifest.json"

docker exec \
  -e CGO_OPENSSL_LAYOUT=openssl-3.0.22-debian-arm64 \
  -e CGO_INCLUDE_SECRETS=1 \
  -e CGO_E3_MANIFEST="$container_dir/e3-circuit-manifest.json" \
  -e CGO_SECRET_OUTPUT="$container_dir/secret-state.json" \
  tor-cgo-lab gdb -q -batch \
  /work/build/tor-0.4.9.16-o2/src/app/tor "$container_source_dir/client.core" \
  -ex 'source /work/forensics/gdb_extract_cgo_secrets.py' \
  >"$result_dir/secret-extract-gdb.log" 2>&1

docker exec \
  -e CGO_OPENSSL_TLS_LAYOUT=openssl-3.0.22-debian-arm64 \
  -e CGO_INCLUDE_TLS_SECRETS=1 \
  -e CGO_E3_MANIFEST="$container_dir/e3-circuit-manifest.json" \
  -e CGO_TLS_SECRET_OUTPUT="$container_dir/tls-secret-state.json" \
  -e CGO_TLS_KEYLOG_OUTPUT="$container_dir/tls-keylog.txt" \
  tor-cgo-lab gdb -q -batch \
  /work/build/tor-0.4.9.16-o2/src/app/tor "$container_source_dir/client.core" \
  -ex 'source /work/forensics/gdb_extract_tls_secrets.py' \
  >"$result_dir/tls-secret-extract-gdb.log" 2>&1

python3 "$root/experiments/decrypt_tls13_pcap.py" \
  --pcap "$source_dir/entry-link.pcap" \
  --tls-state "$result_dir/tls-secret-state.json" \
  --cgo-state "$result_dir/secret-state.json" \
  --output "$result_dir/tls-pcap-decryption.json" \
  --cell-output "$result_dir/pcap-extracted-cell.json" \
  --decrypted-output "$result_dir/tls-decrypted-records.bin"

python3 "$root/experiments/materialize_cgo_replay_candidates.py" \
  --states "$result_dir/secret-state.json" \
  --cells "$result_dir/pcap-extracted-cell.json" \
  --output-dir "$result_dir/replay-candidates" \
  --manifest "$result_dir/replay-candidates.json"

for fixture in "$result_dir"/replay-candidates/candidate-*.bin; do
  base=$(basename "$fixture" .bin)
  docker exec \
    -e CGO_REPLAY_FIXTURE="$container_dir/replay-candidates/$base.bin" \
    -e CGO_REPLAY_RESULT="$container_dir/replay-candidates/$base.json" \
    tor-cgo-lab /work/build/tor-cgo-audit-normal/src/test/test \
    crypto/cgo/cgo_external_core_replay \
    >"$result_dir/replay-candidates/$base.log" 2>&1
done

python3 "$root/experiments/evaluate_full_pcap_replay.py" \
  --result-dir "$result_dir" --truth-cell "$source_dir/cell.json" \
  --output "$result_dir/full-pcap-evaluation.json"
