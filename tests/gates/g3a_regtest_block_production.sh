#!/usr/bin/env bash
# G3a — DASH populated block production (CI required-gate entrypoint).
# Default arm (CI-runner, network-free): the DashG3Assembled.* + DashBlockProducer.*
# gtest suites — c2pool-dash assembles a POPULATED block (coinbase DIP masternode
# split + >=3 diverse non-witness payload txs), X11-mines a winning nonce, serializes
# it, and the won block reaches the network on BOTH paths (embedded P2P + submitblock).
# Optional live arm (opt-in when DASH_RPC_PASS + DASH_RPC_AUTH are set): additionally
# drives scripts/dash_g3a_populated_block_regtest.sh against an isolated regtest dashd
# for a real end-to-end populated block via the submitblock RPC arm.
# Deterministic: exit 0 = pass; nonzero = failure / hollow run. Fenced: tests/gates/
# entrypoint over existing DASH targets — no consensus / shared-base / build.yml / CMake.
set -euo pipefail

GATE="G3a dash-populated-block-production"
TEST_REGEX='^(DashG3Assembled|DashBlockProducer)\.'
TARGETS=(test_dash_g3_assembled test_dash_block_producer)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

# 1. Ensure the targets exist (configure+build only if the CI cache is cold).
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake)"
  conan install "$REPO_ROOT" --build=missing --output-folder="$BUILD_DIR" --settings=build_type=Release
  cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release
fi
cmake --build "$BUILD_DIR" --target "${TARGETS[@]}" -j"$(nproc)"

# 2. Run from build/ and capture (false-green trap: wrong CWD prints
#    "No tests were found!!!" and EXITS 0).
set +e
OUT="$(cd "$BUILD_DIR" && ctest -R "$TEST_REGEX" --output-on-failure 2>&1)"
RC=$?
set -e
echo "$OUT"

# 3. False-green guard: demand a positive test count actually ran.
if grep -q "No tests were found" <<<"$OUT"; then
  echo "[$GATE] FAIL — hollow run: 0 tests matched $TEST_REGEX" >&2
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
echo "[$GATE] PASS (CI arm) — $N assembled-block / producer assertions green"

# 4. Optional live regtest arm — only when an isolated dashd is wired in via env.
if [ -n "${DASH_RPC_PASS:-}" ] && [ -n "${DASH_RPC_AUTH:-}" ]; then
  echo "[$GATE] live arm: driving scripts/dash_g3a_populated_block_regtest.sh"
  "$REPO_ROOT/scripts/dash_g3a_populated_block_regtest.sh"
  echo "[$GATE] PASS (live arm) — populated regtest block proven via c2pool-dash submitblock"
else
  echo "[$GATE] live regtest arm SKIPPED (set DASH_RPC_PASS + DASH_RPC_AUTH to enable)"
fi
