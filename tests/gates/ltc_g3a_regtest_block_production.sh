#!/usr/bin/env bash
# G3a — LTC populated-block production (CI required-gate entrypoint).
# LTC PARENT + DOGE merged-aux. Default arm (CI-runner, network-free): the
# ltc_g3a_populated_test harness (PR #679) — c2pool assembles a POPULATED LTC
# parent block (coinbase + P2PKH + P2SH + native-segwit + MWEB + the DOGE
# aux-coinbase auxpow commitment; never coinbase-only), and proves the
# FOUND->ASSEMBLED->ACCEPTED production path is IDENTICAL across the v35 / HYBRID
# / v36 share regimes for BOTH the LTC parent (dual sink: submit_block_p2p with
# submitblock RPC fallback) and the DOGE aux block it carries (embedded P2P relay
# with submitauxblock->dogecoind fallback), coupled to the parent solve but never
# gated by the version regime.
# Optional live arm (opt-in when LTC_RPC_PASS + DOGE_RPC_PASS are set): drives
# scripts/ltc_g3a_populated_block_regtest.sh against isolated regtest litecoind +
# dogecoind for a real end-to-end populated block via submitblock/submitauxblock.
# Deterministic exits: 0 pass; 3 hollow / below floor; nonzero=ctest failure.
# Fenced: tests/gates/ entrypoint over an existing src/impl/ltc target — no
# consensus / bitcoin_family / src/core / build.yml / CMake-root edits.
set -euo pipefail

GATE="G3a ltc-populated-block-production"
TEST_NAME='^LtcG3aPopulated$'
TARGET=ltc_g3a_populated_test
ASSERT_FLOOR=38   # the harness' invariant count (10 sections x regimes x versions)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

# 1. Ensure the target exists (configure+build only if the CI cache is cold).
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake)"
  . "$REPO_ROOT/tests/gates/lib/conan_prune_unreachable_remotes.sh" && prune_unreachable_conan_remotes
  conan install "$REPO_ROOT" -pr:a="$REPO_ROOT/ci/conan/linux-gcc13.profile" \
    --lockfile="$REPO_ROOT/conan.lock" --build=missing \
    --output-folder="$BUILD_DIR" --settings=build_type=Release
  cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
fi
cmake --build "$BUILD_DIR" --target "$TARGET" -j"$(nproc)"

# 2. Run via ctest (registered as LtcG3aPopulated) and capture. -V surfaces the
#    harness stdout (incl. the G3A_ASSERTIONS_PASSED= line) on success too.
set +e
OUT="$(cd "$BUILD_DIR" && ctest -R "$TEST_NAME" -V --output-on-failure 2>&1)"
RC=$?
set -e
echo "$OUT"

# 3a. Hollow guard: ctest must have matched the test (wrong CWD / dropped target
#     prints "No tests were found" and EXITS 0 — the false-green trap).
if grep -q "No tests were found" <<<"$OUT"; then
  echo "[$GATE] FAIL — hollow run: 0 tests matched $TEST_NAME" >&2
  exit 3
fi
NT="$(grep -oE 'out of [0-9]+' <<<"$OUT" | grep -oE '[0-9]+' | tail -1)"
if [ -z "${NT:-}" ] || [ "$NT" -lt 1 ]; then
  echo "[$GATE] FAIL — no positive ctest count parsed" >&2
  exit 3
fi

# 3b. Meaningful non-hollow guard: the harness' OWN invariant count. A harness
#     that compiled but asserted nothing (or was gutted) prints < ASSERT_FLOOR.
NA="$(grep -oE 'G3A_ASSERTIONS_PASSED=[0-9]+' <<<"$OUT" | grep -oE '[0-9]+' | tail -1)"
if [ -z "${NA:-}" ] || [ "$NA" -lt "$ASSERT_FLOOR" ]; then
  echo "[$GATE] FAIL — hollow: G3A_ASSERTIONS_PASSED=${NA:-<none>} < floor $ASSERT_FLOOR" >&2
  exit 3
fi

# 3c. Real failure surfaces as a nonzero ctest exit.
if [ "$RC" -ne 0 ]; then
  echo "[$GATE] FAIL — ctest exit $RC (asserted $NA)" >&2
  exit "$RC"
fi
echo "[$GATE] PASS (CI arm) — $NA populated-block LTC-parent + DOGE-aux production assertions green"

# 4. Optional live regtest arm — only when an isolated litecoind+dogecoind is wired.
if [ -n "${LTC_RPC_PASS:-}" ] && [ -n "${DOGE_RPC_PASS:-}" ]; then
  echo "[$GATE] live arm: driving scripts/ltc_g3a_populated_block_regtest.sh"
  "$REPO_ROOT/scripts/ltc_g3a_populated_block_regtest.sh"
  echo "[$GATE] PASS (live arm) — real populated regtest block proven (LTC submitblock + DOGE submitauxblock)"
else
  echo "[$GATE] live regtest arm SKIPPED (set LTC_RPC_PASS + DOGE_RPC_PASS to enable)"
fi
