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
# Pinned to the exact upstream commit dash v23.1.x vendors as src/dashbls
# (libdashbls 2.0 / relic 0.5.0). RE-PIN in lockstep with the vendored-dashcore
# bump that moves vendor/llmq_commitment.hpp (same discipline as dkg_window.hpp).
set -euo pipefail

DASHBLS_REPO="${DASHBLS_REPO:-https://github.com/dashpay/bls-signatures.git}"
# libdashbls 2.0 (dash v23.1.x src/dashbls subtree; relic backend, basic+legacy
# BLS schemes). Pin by commit for a reproducible, offline-cacheable build.
DASHBLS_COMMIT="${DASHBLS_COMMIT:-dd683653c6eaba7235bc9c600f46bafbb8210291}"
PREFIX="${1:-${DASHBLS_ROOT:-/opt/dashbls}}"
BUILD_DIR="${BUILD_DIR:-/tmp/dashbls-build}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

echo "[build_dashbls] repo=$DASHBLS_REPO commit=$DASHBLS_COMMIT prefix=$PREFIX"

rm -rf "$BUILD_DIR"
git clone "$DASHBLS_REPO" "$BUILD_DIR/src"
git -C "$BUILD_DIR/src" checkout --quiet "$DASHBLS_COMMIT"

cmake -S "$BUILD_DIR/src" -B "$BUILD_DIR/build" \
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
