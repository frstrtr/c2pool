#!/usr/bin/env bash
# DGB Phase-B per-coin smoke (CI entrypoint). ci-steward 2026-07-06.
# Fenced: workflow + this entrypoint over EXISTING dgb Phase-B gtest targets —
# no consensus knowledge, no coin-matrix.yml / build.yml / CMake edits (PR #47
# source guard stays untouched). Mirrors the dash-gate-g3a template.
#
# Default arm (network-free, always on): build the dgb Phase-B pillar targets
# and run their gtest suites BY NAME via ctest -R, with a false-green guard
# demanding a parsed positive test count (wrong-CWD ctest prints
# "No tests were found!!!" and EXITS 0 — that trap is caught here).
# Deterministic: exit 0 = pass; nonzero = failure / hollow run.
set -euo pipefail

GATE="DGB Phase-B smoke"
# Phase-B pillars: block assembly, witness commitment, mempool ingest, won-block
# reconstruction, header ingest/sample-build, and the share pillar.
TEST_REGEX="^(DgbBlockAssembly|DgbWitnessCommitment|MempoolIngest|DgbReconstructWonBlock|HeaderIngest|CompactToTarget|MakeHeaderSample|DGB_share_test|WorkRefHashAssembler)\."
TARGETS=(dgb_share_test dgb_block_assembly_test dgb_witness_commitment_test dgb_mempool_ingest_test dgb_reconstruct_won_block_test dgb_header_ingest_test dgb_header_sample_build_test)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

# 1. Configure (conan + cmake) only if the CI cache is cold.
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake)"
  conan install "$REPO_ROOT" -pr:a="$REPO_ROOT/ci/conan/linux-gcc13.profile" --lockfile="$REPO_ROOT/conan.lock" --build=missing --output-folder="$BUILD_DIR" --settings=build_type=Release
  cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON \
    -DCOIN_DGB=ON
fi
cmake --build "$BUILD_DIR" --target "${TARGETS[@]}" -j"$(nproc)"

# 2. Run from build/ (false-green trap: wrong CWD prints "No tests were found!!!"
#    and EXITS 0).
set +e
OUT="$(cd "$BUILD_DIR" && ctest -R "$TEST_REGEX" --output-on-failure 2>&1)"
RC=$?
set -e
echo "$OUT"

# 3. Empty-suite guard: demand a positive test count actually ran.
if grep -q "No tests were found" <<<"$OUT"; then
  echo "[$GATE] FAIL — hollow run: 0 tests matched $TEST_REGEX" >&2
  exit 1
fi
N="$(grep -oE "out of [0-9]+" <<<"$OUT" | grep -oE "[0-9]+" | tail -1)"
if [ -z "${N:-}" ] || [ "$N" -lt 1 ]; then
  echo "[$GATE] FAIL — no positive test count parsed" >&2
  exit 1
fi
if [ "$RC" -ne 0 ]; then
  echo "[$GATE] FAIL — ctest exit $RC ($N tests)" >&2
  exit "$RC"
fi
echo "[$GATE] PASS — $N dgb Phase-B pillar assertions green"
