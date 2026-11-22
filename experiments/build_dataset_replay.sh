#!/bin/sh
set -eu

# Build the offline CGO replay tests against the exact Tor source included in
# the public reanalysis dataset. Production CGO sources are left unchanged;
# only the test translation unit is replaced with the fixture interface.

repo=${1:-/work}
source_tree=${2:-/scratch/tor-0.4.9.16}
build_tree=${3:-/scratch/tor-cgo-replay-0.4.9.16}
overlay=$repo/third_party/tor-cgo-audit/src/test/test_crypto_cgo.c
expected_original=030dba82328961c16983f82eaa26aefb26204c1119d19879acadcc0d9de51ff6

test -f "$source_tree/configure.ac"
test -f "$overlay"
test ! -e "$build_tree"
actual_original=$(sha256sum "$source_tree/src/test/test_crypto_cgo.c" | awk '{print $1}')
test "$actual_original" = "$expected_original"

cp -R "$source_tree" "$build_tree"
cp "$overlay" "$build_tree/src/test/test_crypto_cgo.c"
cd "$build_tree"
./autogen.sh
./configure --disable-asciidoc CFLAGS='-O2 -g -fno-omit-frame-pointer'
make micro-revision.i
make -j2 src/test/test
src/test/test crypto/cgo/cgo_fwd
src/test/test crypto/cgo/cgo_external_core_sequence || test "$?" = 77
