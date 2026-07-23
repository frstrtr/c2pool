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
# Requires: autoconf/automake/libtool, a C++17 compiler, and libgmp-dev (relic
# ARITH=gmp backend). See the autotools note below for why not CMake.
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
# Sparse, shallow checkout of only src/dashbls at the tag (avoids cloning all
# of dash); falls back to a plain shallow clone when the git on this builder
# does not support --sparse/--filter (the fallback previously claimed here did
# not exist — review #814 nit).
if git clone --depth 1 --branch "$DASH_REF" --filter=blob:none --sparse \
       "$DASH_REPO" "$BUILD_DIR/dash" \
   && git -C "$BUILD_DIR/dash" sparse-checkout set src/dashbls; then
    :
else
    echo "[build_dashbls] sparse clone unsupported/failed -> full shallow clone"
    rm -rf "$BUILD_DIR/dash"
    git clone --depth 1 --branch "$DASH_REF" "$DASH_REPO" "$BUILD_DIR/dash"
fi
DASHBLS_SRC="$BUILD_DIR/dash/src/dashbls"
if [ ! -f "$DASHBLS_SRC/configure.ac" ]; then
    echo "[build_dashbls] ERROR: src/dashbls not found at $DASH_REF" >&2
    exit 1
fi
echo "[build_dashbls] building dash $DASH_REF src/dashbls (dashd-byte-identical)"

# AUTOTOOLS build (executed + validated for the v23.1.7 re-pin): dash's
# vendored subtree does NOT support its legacy CMake path at this tag — the
# relic_conf.h.in template is not vendored (the CMake configure_file step
# fails), because dashd itself builds dashbls via autotools, where autoheader
# GENERATES the relic config header (configure.ac AC_CONFIG_HEADERS). Use the
# same path. Requires: autoconf, automake, libtool (plus the cmake/gmp deps
# listed above). The resulting libdashbls.a is SELF-CONTAINED (bls + relic +
# mimalloc objects in one archive), so no separate librelic_s.a is installed —
# the c2pool CMake find treats the relic library as optional accordingly.
(
    cd "$DASHBLS_SRC"
    sh autogen.sh
    ./configure --prefix="$PREFIX" --disable-shared
    make -j "$JOBS"
    make install
)

# `make install` ships only lib/libdashbls.{a,la}; install the public headers
# the c2pool verifier compiles against: the dashbls API headers plus the relic
# headers they include ("relic.h"/"relic_conf.h" — relic_conf.h is the
# configure-generated one, part of the exact built configuration).
mkdir -p "$PREFIX/include"
cp -r "$DASHBLS_SRC/include/dashbls" "$PREFIX/include/"
cp "$DASHBLS_SRC"/depends/relic/include/*.h "$PREFIX/include/"
mkdir -p "$PREFIX/include/low"
cp "$DASHBLS_SRC"/depends/relic/include/low/*.h "$PREFIX/include/low/"
cp "$DASHBLS_SRC"/depends/mimalloc/include/*.h "$PREFIX/include/" 2>/dev/null || true

echo "[build_dashbls] installed:"
find "$PREFIX" -name 'libdashbls*' -o -name 'librelic*' -o -name 'bls.hpp' | sed 's/^/  /'
echo "[build_dashbls] done — configure c2pool with -DC2POOL_DASH_BLS=ON -DDASHBLS_ROOT=$PREFIX"
