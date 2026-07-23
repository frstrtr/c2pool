#!/usr/bin/env bash
# G3b — BCH genuine Upgrade9 (CashTokens) activation gate (CI required-gate entrypoint).
# Companion to G3a (bch_g3a_regtest_block_production.sh): where G3a proves a
# POPULATED block is produced, G3b proves the feature is GENUINELY ACTIVATED at a
# boundary — accepted after the activation height, and IMPOSSIBLE before it — not
# merely always-on regtest convenience.
#
# The activation boundary splits across two layers, and this gate covers both:
#
# Default arm (CI-runner, network-free) — the POOL-SIDE activation semantics, via
# the c2pool-bch in-process CHECK-harnesses:
#   bch_g2_ratchet_gate_kat_test       : the 60%-by-WORK share-version SWITCH ratchet
#                                        — the pool activates the new version only
#                                        once the work-weighted supermajority crosses,
#                                        never on a flat count (the genuine switch).
#   bch_cashtokens_transparency_test   : the Upgrade9 feature itself — CashTokens
#                                        FT/NFT genesis+transfer carried transparently
#                                        through the template once active.
#   bch_coinbase_author_kat_test       : the version-gated donation author — sv<36
#                                        forrestv P2PK vs sv>=36 combined P2SH — a
#                                        second activation boundary keyed to share
#                                        version, byte-pinned.
# Optional live arm (opt-in when BCH_UPGRADE9_HEIGHT points at a running isolated
# regtest BCHN started with -upgrade9activationheight=<N>, N>0): drives
# scripts/bch_g3b_genuine_activation_regtest.py for the CONSENSUS-SIDE boundary —
# a CashToken FT-genesis tx HARD-REJECTED pre-activation ("txn-tokens-before-
# activation") and the SAME signed tx ACCEPTED into the won block post-activation.
# The reject-at-height>0 is impossible under default always-on regtest, so observing
# it proves the override took effect and activation is real.
#
# Deterministic: exit 0 = pass; nonzero = failure / hollow run. Fenced: tests/gates/
# entrypoint over existing COIN_BCH targets — no consensus / shared-base / build.yml /
# CMake / other-coin surface.
set -euo pipefail

GATE="G3b bch-genuine-activation"
TEST_REGEX='^bch_(g2_ratchet_gate_kat_test|cashtokens_transparency_test|coinbase_author_kat_test)$'
TARGETS=(bch_g2_ratchet_gate_kat_test bch_cashtokens_transparency_test \
         bch_coinbase_author_kat_test)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# COIN_BCH targets compile ONLY under -DCOIN_BCH=ON, so default to the CI build_bch
# tree; override BUILD_DIR to reuse a warm cache.
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build_bch}"

# 1. Ensure the targets exist (configure+build only if the CI cache is cold).
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake -DCOIN_BCH=ON)"
  conan install "$REPO_ROOT" -pr:a="$REPO_ROOT/ci/conan/linux-gcc13.profile" --lockfile="$REPO_ROOT/conan.lock" --build=missing --output-folder="$BUILD_DIR" --settings=build_type=Release
  cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$BUILD_DIR/conan_toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCOIN_BCH=ON
fi
cmake --build "$BUILD_DIR" --target "${TARGETS[@]}" -j"$(nproc)"

# 2. Run from build/ and capture (false-green trap: wrong CWD prints
#    "No tests were found!!!" and EXITS 0).
set +e
OUT="$(cd "$BUILD_DIR" && ctest -R "$TEST_REGEX" --output-on-failure 2>&1)"
RC=$?
set -e
echo "$OUT"

# 3. False-green guard: demand a positive test count actually ran, and that the
#    full expected set matched (a partial regex miss must not read as green).
if grep -q "No tests were found" <<<"$OUT"; then
  echo "[$GATE] FAIL — hollow run: 0 tests matched $TEST_REGEX" >&2
  exit 1
fi
N="$(grep -oE 'out of [0-9]+' <<<"$OUT" | grep -oE '[0-9]+' | tail -1)"
if [ -z "${N:-}" ] || [ "$N" -lt "${#TARGETS[@]}" ]; then
  echo "[$GATE] FAIL — expected ${#TARGETS[@]} tests, matched ${N:-0}" >&2
  exit 1
fi
if [ "$RC" -ne 0 ]; then
  echo "[$GATE] FAIL — ctest exit $RC ($N tests)" >&2
  exit "$RC"
fi
echo "[$GATE] PASS (CI arm) — $N ratchet-switch / CashTokens-transparency / version-gated-author activation assertions green"

# 4. Optional live regtest arm — only when an isolated BCHN with a >0 activation
#    override is wired in via env.
if [ -n "${BCH_UPGRADE9_HEIGHT:-}" ]; then
  echo "[$GATE] live arm: driving scripts/bch_g3b_genuine_activation_regtest.py (override height=$BCH_UPGRADE9_HEIGHT)"
  python3 "$REPO_ROOT/scripts/bch_g3b_genuine_activation_regtest.py"
  echo "[$GATE] PASS (live arm) — pre-activation HARD-REJECT + post-activation ACCEPT proven on isolated regtest BCHN"
else
  echo "[$GATE] live regtest arm SKIPPED (set BCH_UPGRADE9_HEIGHT + start BCHN with -upgrade9activationheight=<N> to enable)"
fi
