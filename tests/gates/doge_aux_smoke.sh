#!/usr/bin/env bash
# DOGE AuxPoW per-coin smoke (CI entrypoint). ltc-doge-production-steward 2026-07-26.
#
# WHY this shape: DOGE is the AuxPoW *child* of the merged LTC/DOGE release, so
# there is no standalone main_doge.cpp / c2pool-doge binary to smoke — the DOGE
# path ships EMBEDDED in c2pool-ltc via impl/doge/coin/*. The coin-matrix.yml
# "doge" cell therefore skip-passes (source-presence gate: no main_doge.cpp) and
# asserts nothing (hollow-green). This gate replaces that hollow pass with real
# DOGE-specific assertions over the SAME impl/doge/coin/* objects the merged
# c2pool-ltc binary links: AuxPoW parent-link construction (parent coinbase +
# CMerkleTx.block_hash + parent 80B header, KAT against real DOGE mainnet block
# #371337) and the DOGE coin_params load (AUXPOW_CHAIN_ID 0x0062, era heights).
#
# Fenced exactly like tests/gates/dgb_phase_b_smoke.sh: workflow + this entrypoint
# over an EXISTING doge gtest target (test_doge_chain, wired at test/CMakeLists.txt).
# No coin-matrix.yml / build.yml / CMake / src/core / bitcoin_family edits.
# Deterministic: exit 0 = pass; nonzero = failure / hollow run.
set -euo pipefail

GATE="DOGE AuxPoW smoke"
# DOGE-specific suites in test_doge_chain: AuxPoW parent-link (structured +
# real-block KAT), the parser, and the coin_params/consensus-era load. These are
# the embedded impl/doge/coin/* surfaces the merged c2pool-ltc binary depends on.
TEST_REGEX="^(AuxPowKnownAnswer|AuxPowStructured|AuxPowParser|DOGEChainParams|DOGESubsidy|DigiShield|MersenneTwister)Test\."
TARGETS=(test_doge_chain)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

# 1. Configure (conan + cmake) only if the CI cache is cold.
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake)"
  . "$REPO_ROOT/tests/gates/lib/conan_prune_unreachable_remotes.sh" && prune_unreachable_conan_remotes
  conan install "$REPO_ROOT" -pr:a="$REPO_ROOT/ci/conan/linux-gcc13.profile" --lockfile="$REPO_ROOT/conan.lock" --build=missing --output-folder="$BUILD_DIR" --settings=build_type=Release
  cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=ON
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
echo "[$GATE] PASS — $N DOGE AuxPoW/coin_params assertions green"
