#!/usr/bin/env bash
# G3a — DGB populated block production (CI required-gate entrypoint).
# ci-steward 2026-08-03. Wires the DGB populated-block story into CI the way
# BCH (tests/gates/bch_g3a_regtest_block_production.sh) and DASH
# (tests/gates/g3a_regtest_block_production.sh) already are.
#
# Default arm (CI-runner, network-free): the DgbBlockAssembly.* +
# DgbWitnessCommitment.* + DgbReconstructWonBlock.* gtest suites — c2pool-dgb
# assembles a POPULATED block (diverse output-script + SegWit witness payload),
# the witness commitment survives a serialize->deserialize round-trip, and the
# won block is reconstructed for network submit. Proves populated-block
# production without a live node.
#
# Optional live arm (opt-in when DGB_REGTEST_LIVE=1 and DGB_SRC point at an
# isolated digibyted): additionally drives scripts/dgb_g3a_populated_block_regtest.sh
# for a real end-to-end populated regtest block via submitblock — the same
# machinery the G3b greenlight harness exercised (height 132, 7dd873cb4ce8).
#
# Deterministic: exit 0 = pass; nonzero = failure / hollow run. Fenced: tests/gates/
# entrypoint over EXISTING dgb targets — no consensus / shared-base / build.yml /
# CMake edits. PR #47 per-coin source-presence guard stays untouched; the workflow
# neutral-skips when these sources are absent.
set -euo pipefail

GATE="G3a dgb-populated-block-production"
TEST_REGEX='^(DgbBlockAssembly|DgbWitnessCommitment|DgbReconstructWonBlock)\.'
TARGETS=(dgb_block_assembly_test dgb_witness_commitment_test dgb_reconstruct_won_block_test)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"

# 1. Ensure the targets exist (configure+build only if the CI cache is cold).
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake)"
  . "$REPO_ROOT/tests/gates/lib/conan_prune_unreachable_remotes.sh" && prune_unreachable_conan_remotes
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
echo "[$GATE] PASS (CI arm) — $N populated-block assembly / witness / won-block assertions green"

# 4. Optional live regtest arm — only when an isolated digibyted is wired in via env.
if [ "${DGB_REGTEST_LIVE:-}" = "1" ] && [ -n "${DGB_SRC:-}" ]; then
  echo "[$GATE] live arm: driving scripts/dgb_g3a_populated_block_regtest.sh"
  "$REPO_ROOT/scripts/dgb_g3a_populated_block_regtest.sh"
  echo "[$GATE] PASS (live arm) — populated regtest block proven via digibyted submitblock"
else
  echo "[$GATE] live regtest arm SKIPPED (set DGB_REGTEST_LIVE=1 + DGB_SRC to enable)"
fi
