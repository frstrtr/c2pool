#!/usr/bin/env bash
# G1 — DASH X11 byte-parity known-answer test (CI required-gate entrypoint).
# Wraps the real test_dash_x11_kat gtest suite (DashX11Kat.*): genesis + testnet3
# real-node header vectors reproduce the X11 block hash byte-for-byte (#596 vectors).
# Deterministic: exit 0 = every KAT vector reproduced; nonzero = failure / hollow run.
# Network-free, CI-runner safe (~0.1s). Fenced: a tests/gates/ entrypoint over an
# existing DASH test target — no consensus / shared-base / build.yml / CMake edits.
set -euo pipefail

GATE="G1 dash-x11-byte-parity-kat"
TEST_REGEX='^DashX11Kat\.'
TARGET=test_dash_x11_kat

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

# 1. Ensure the target exists (configure+build only if the CI cache is cold).
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake)"
  conan install "$REPO_ROOT" -pr:a="$REPO_ROOT/ci/conan/linux-gcc13.profile" --lockfile="$REPO_ROOT/conan.lock" --build=missing --output-folder="$BUILD_DIR" --settings=build_type=Release
  cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release
fi
cmake --build "$BUILD_DIR" --target "$TARGET" -j"$(nproc)"

# 2. Run from build/ and capture. Running ctest off the wrong CWD prints
#    "No tests were found!!!" and EXITS 0 — the classic false-green trap.
set +e
OUT="$(cd "$BUILD_DIR" && ctest -R "$TEST_REGEX" --output-on-failure 2>&1)"
RC=$?
set -e
echo "$OUT"

# 3. False-green guard: demand a positive test count actually ran.
if grep -q "No tests were found" <<<"$OUT"; then
  echo "[$GATE] FAIL — hollow run: 0 tests matched $TEST_REGEX (wrong CWD/target?)" >&2
  exit 1
fi
N="$(grep -oE 'out of [0-9]+' <<<"$OUT" | grep -oE '[0-9]+' | tail -1)"
if [ -z "${N:-}" ] || [ "$N" -lt 1 ]; then
  echo "[$GATE] FAIL — no positive test count parsed" >&2
  exit 1
fi
if [ "$RC" -ne 0 ]; then
  echo "[$GATE] FAIL — ctest exit $RC ($N tests)" >&2
  exit "$RC"
fi
echo "[$GATE] PASS — $N DashX11Kat byte-parity vectors reproduced"
