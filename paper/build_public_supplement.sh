#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/paper/public-supplement-files.txt"
output=${1:-"$root/paper/tor-cgo-forensics-public-supplement-v3.tar.gz"}

while IFS= read -r relative; do
  [ -n "$relative" ] || continue
  if [ ! -f "$root/$relative" ]; then
    echo "missing public supplement input: $relative" >&2
    exit 1
  fi
done <"$manifest"

tar -czf "$output" -C "$root" -T "$manifest"
chmod 0644 "$output"
shasum -a 256 "$output"
