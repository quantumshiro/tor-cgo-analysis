#!/bin/sh
set -eu

repo=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
dataset=${2:-$repo/artifacts/reanalysis-boundary-r1}
scratch=${3:-/tmp/tor-cgo-boundary-reanalysis}
image=${CGO_DOCKER_IMAGE:-tor-cgo-forensics:bookworm}

test ! -e "$scratch"
mkdir -p "$scratch"
(cd "$dataset" && shasum -a 256 -c SHA256SUMS)
zstd -q -d "$dataset/client.core.zst" -o "$scratch/client.core"
zstd -q -d "$dataset/entry-link.pcap.zst" -o "$scratch/entry-link.pcap"
zstd -q -d "$dataset/tor-0.4.9.16-o2-arm64.zst" -o "$scratch/tor"
chmod +x "$scratch/tor"
zstd -q -dc "$dataset/tor-0.4.9.16-source.tar.zst" | tar -xf - -C "$scratch"

python3 "$repo/forensics/verify_core_executable.py" \
  --executable "$scratch/tor" --core "$scratch/client.core" \
  --output "$scratch/executable-verification.json"

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" \
  -e CGO_OUTPUT=/scratch/core-scan.json "$image" gdb -q -batch \
  /scratch/tor /scratch/client.core \
  -ex 'source /work/forensics/gdb_scan.py' \
  >"$scratch/core-scan-gdb.log" 2>&1

python3 "$repo/experiments/build_e3_manifest.py" \
  --scan "$scratch/core-scan.json" --output "$scratch/e3-manifest.json"

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" \
  -e CGO_OPENSSL_LAYOUT=openssl-3.0.22-debian-arm64 \
  -e CGO_INCLUDE_SECRETS=1 -e CGO_E3_MANIFEST=/scratch/e3-manifest.json \
  -e CGO_SECRET_OUTPUT=/scratch/secret-state.json "$image" gdb -q -batch \
  /scratch/tor /scratch/client.core \
  -ex 'source /work/forensics/gdb_extract_cgo_secrets.py' \
  >"$scratch/cgo-extract-gdb.log" 2>&1

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" \
  -e CGO_OPENSSL_TLS_LAYOUT=openssl-3.0.22-debian-arm64 \
  -e CGO_INCLUDE_TLS_SECRETS=1 \
  -e CGO_E3_MANIFEST=/scratch/e3-manifest.json \
  -e CGO_TLS_SECRET_OUTPUT=/scratch/tls-secret-state.json \
  -e CGO_TLS_KEYLOG_OUTPUT=/scratch/tls-keylog.txt "$image" gdb -q -batch \
  /scratch/tor /scratch/client.core \
  -ex 'source /work/forensics/gdb_extract_tls_secrets.py' \
  >"$scratch/tls-extract-gdb.log" 2>&1

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" "$image" \
  /opt/chutney-venv/bin/python /work/experiments/decrypt_tls13_sequence.py \
  --pcap /scratch/entry-link.pcap \
  --tls-state /scratch/tls-secret-state.json \
  --cgo-state /scratch/secret-state.json \
  --output /scratch/tls-forward.json --cell-output /scratch/cells.json

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" "$image" \
  sh /work/experiments/build_dataset_replay.sh \
  /work /scratch/tor-0.4.9.16 /scratch/replay-build

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" "$image" \
  python3 /work/experiments/materialize_cgo_sequence_anchors.py \
  --states /scratch/secret-state.json --cells /scratch/cells.json \
  --output-dir /scratch/anchors --manifest /scratch/anchors.json

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" "$image" \
  python3 /work/experiments/run_cgo_anchor_candidates.py \
  --manifest /scratch/anchors.json --fixture-dir /scratch/anchors \
  --result-dir /scratch/anchor-results \
  --replay-binary /scratch/replay-build/src/test/test --jobs 8 \
  --summary /scratch/anchor-search.json

docker run --rm -v "$repo:/work:ro" -v "$scratch:/scratch" "$image" \
  python3 /work/experiments/build_cgo_sequence_fixture.py \
  --states /scratch/secret-state.json --cells /scratch/cells.json \
  --anchor-manifest /scratch/anchors.json \
  --anchor-result-dir /scratch/anchor-results --max-cells 1000 \
  --fixture /scratch/sequence.bin --metadata /scratch/sequence-metadata.json

docker run --rm -v "$scratch:/scratch" "$image" \
  env CGO_SEQUENCE_FIXTURE=/scratch/sequence.bin \
  CGO_SEQUENCE_RESULT=/scratch/sequence-result.json \
  /scratch/replay-build/src/test/test crypto/cgo/cgo_external_core_sequence

python3 "$repo/experiments/evaluate_snapshot_correspondence.py" \
  --scan "$scratch/core-scan.json" --cells "$scratch/cells.json" \
  --anchor-manifest "$scratch/anchors.json" \
  --anchor-result-dir "$scratch/anchor-results" \
  --acquisition "$dataset/metadata/acquisition.json" \
  --output "$scratch/correspondence.json"

python3 "$repo/experiments/summarize_sequence_recovery.py" \
  --case boundary-r1 "$scratch/sequence-metadata.json" \
  "$scratch/sequence-result.json" --output "$scratch/summary.json"

printf 'Reanalysis complete: %s\n' "$scratch"
