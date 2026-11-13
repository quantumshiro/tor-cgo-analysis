#!/bin/sh
set -eu

# Build the external-core replay test from the unmodified Tor 0.4.9.17
# release tree, changing only the test translation unit that implements the
# offline fixture interface.  The production CGO implementation is never
# replaced.

repo=${1:-/work}
official=${2:-$repo/build/packaged-tor/source.reJjlS/tor-0.4.9.17}
build=${3:-$repo/build/tor-cgo-replay-0.4.9.17}
overlay=$repo/third_party/tor-cgo-audit/src/test/test_crypto_cgo.c
expected_original=030dba82328961c16983f82eaa26aefb26204c1119d19879acadcc0d9de51ff6

test -x "$official/configure"
test -f "$overlay"
test ! -e "$build"

version=$(sed -n 's/^AC_INIT(\[tor\], *\[\([^]]*\)\].*/\1/p' "$official/configure.ac")
test "$version" = 0.4.9.17
actual_original=$(sha256sum "$official/src/test/test_crypto_cgo.c" | awk '{print $1}')
test "$actual_original" = "$expected_original"

cp -R "$official" "$build"
cp "$overlay" "$build/src/test/test_crypto_cgo.c"
cd "$build"
./configure --disable-asciidoc CFLAGS='-O2 -g -fno-omit-frame-pointer'
make micro-revision.i
make -j2 src/test/test
src/test/test crypto/cgo/cgo_fwd
