#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build + install dashpay/bls-signatures ("dashbls") for the c2pool E1 Phase-L
# BLS quorum-commitment verifier. This is the SAME library dashd wraps in
# src/bls/bls.h (libdashbls 2.0, relic-backed, Apache-2.0). It is NOT on
# ConanCenter, so — like secp256k1 — c2pool consumes it as a prebuilt system
# library (find_library in the root CMakeLists, gated by -DC2POOL_DASH_BLS=ON).
# Run this once on the CI build factory / dev host, then configure c2pool with:
#
#     cmake -DC2POOL_DASH_BLS=ON -DDASHBLS_ROOT=<PREFIX> ...
#
# Requires: cmake, a C++17 compiler, and libgmp-dev (relic ARITH=gmp backend).
#
# SOURCE = dash's OWN vendored src/dashbls subtree at the v23.1.7 release tag,
# NOT the standalone dashpay/bls-signatures repo. The standalone 1.3.6 tag
# (dd683653) is functionally equivalent but NOT byte-identical to what dashd
# links: dash's subtree carries fixes applied on top (e.g. a relic bn_free leak)
# that never got a standalone tag. Pinning to the dash tag guarantees the BLS
# code is byte-identical to the daemon whose commitments we verify — the whole
# point of reuse-first. RE-PIN in lockstep with the vendored-dashcore bump that
# moves vendor/llmq_commitment.hpp (same discipline as dkg_window.hpp).
set -euo pipefail

# dash release tag whose src/dashbls subtree we build (byte-identical to dashd).
DASH_REPO="${DASH_REPO:-https://github.com/dashpay/dash.git}"
DASH_REF="${DASH_REF:-v23.1.7}"
PREFIX="${1:-${DASHBLS_ROOT:-/opt/dashbls}}"
BUILD_DIR="${BUILD_DIR:-/tmp/dashbls-build}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

echo "[build_dashbls] dash=$DASH_REPO ref=$DASH_REF (src/dashbls subtree) prefix=$PREFIX"

rm -rf "$BUILD_DIR"
# Sparse, shallow checkout of only src/dashbls at the tag (avoids cloning all of
# dash). Falls back to a full checkout if sparse is unavailable.
git clone --depth 1 --branch "$DASH_REF" --filter=blob:none --sparse \
    "$DASH_REPO" "$BUILD_DIR/dash"
git -C "$BUILD_DIR/dash" sparse-checkout set src/dashbls
DASHBLS_SRC="$BUILD_DIR/dash/src/dashbls"
if [ ! -f "$DASHBLS_SRC/CMakeLists.txt" ]; then
    echo "[build_dashbls] ERROR: src/dashbls not found at $DASH_REF" >&2
    exit 1
fi
echo "[build_dashbls] building dash $DASH_REF src/dashbls (dashd-byte-identical)"

cmake -S "$DASHBLS_SRC" -B "$BUILD_DIR/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBUILD_BLS_TESTS=0 \
    -DBUILD_BLS_BENCHMARKS=0 \
    -DBUILD_BLS_PYTHON_BINDINGS=0 \
    -DBUILD_BLS_JS_BINDINGS=0

cmake --build "$BUILD_DIR/build" -j "$JOBS"
cmake --install "$BUILD_DIR/build"

echo "[build_dashbls] installed:"
find "$PREFIX" -name 'libdashbls*' -o -name 'librelic*' -o -name 'bls.hpp' | sed 's/^/  /'
echo "[build_dashbls] done — configure c2pool with -DC2POOL_DASH_BLS=ON -DDASHBLS_ROOT=$PREFIX"
