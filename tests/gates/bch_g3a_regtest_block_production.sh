#!/usr/bin/env bash
# G3a — BCH populated block production (CI required-gate entrypoint).
# Default arm (CI-runner, network-free): the c2pool-bch in-process CHECK-harnesses
# that together prove POPULATED-block production without a live BCHN node —
#   bch_embedded_daemon_assembly_test  : EmbeddedDaemon assembles the block from its
#                                        own real EmbeddedCoinNode seam (coinbase +
#                                        ABLA-bounded template), embedded-primary.
#   bch_embedded_block_broadcast_test  : the won block reaches the network on BOTH
#                                        paths (embedded P2P + submitblock fallback).
#   bch_block_ordering_test            : CTOR canonical tx ordering (A3).
#   bch_cashtokens_transparency_test   : CashTokens FT/NFT genesis+transfer carried
#                                        transparently through the template (A5).
#   bch_coinbase_kat_bytevector_test   : coinbase byte-vector KAT — no witness
#                                        commitment, standalone SHA256d (A1/A2).
# Optional live arm (opt-in when BCH_RPC_PASS + BCH_RPC_AUTH are set): additionally
# drives scripts/bch_g3a_populated_block_regtest.py against an isolated regtest BCHN
# (v29.0.0, --disable-wallet) for a real end-to-end populated block — the full A1–A7
# attestation (produced block 5fa6e22b…; CashTokens FT/NFT/transfer, P2SH32, CTOR,
# merkle, no-witness, 30-in consolidation) via the submitblock RPC arm.
# Deterministic: exit 0 = pass; nonzero = failure / hollow run. Fenced: tests/gates/
# entrypoint over existing COIN_BCH targets — no consensus / shared-base / build.yml /
# CMake / other-coin surface.
set -euo pipefail

GATE="G3a bch-populated-block-production"
TEST_REGEX='^bch_(embedded_daemon_assembly_test|embedded_block_broadcast_test|block_ordering_test|cashtokens_transparency_test|coinbase_kat_bytevector_test)$'
TARGETS=(bch_embedded_daemon_assembly_test bch_embedded_block_broadcast_test \
         bch_block_ordering_test bch_cashtokens_transparency_test \
         bch_coinbase_kat_bytevector_test)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# COIN_BCH targets compile ONLY under -DCOIN_BCH=ON, so default to the CI build_bch
# tree; override BUILD_DIR to reuse a warm cache.
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build_bch}"

# 1. Ensure the targets exist (configure+build only if the CI cache is cold).
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  echo "[$GATE] no build dir at $BUILD_DIR — configuring (conan + cmake -DCOIN_BCH=ON)"
  conan install "$REPO_ROOT" --build=missing --output-folder="$BUILD_DIR" --settings=build_type=Release
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
echo "[$GATE] PASS (CI arm) — $N populated-block assembly / broadcast / CTOR / CashTokens / coinbase-KAT assertions green"

# 4. Optional live regtest arm — only when an isolated BCHN is wired in via env.
if [ -n "${BCH_RPC_PASS:-}" ] && [ -n "${BCH_RPC_AUTH:-}" ]; then
  echo "[$GATE] live arm: driving scripts/bch_g3a_populated_block_regtest.py"
  python3 "$REPO_ROOT/scripts/bch_g3a_populated_block_regtest.py"
  echo "[$GATE] PASS (live arm) — populated regtest block proven via isolated BCHN submitblock (A1–A7)"
else
  echo "[$GATE] live regtest arm SKIPPED (set BCH_RPC_PASS + BCH_RPC_AUTH to enable)"
fi
