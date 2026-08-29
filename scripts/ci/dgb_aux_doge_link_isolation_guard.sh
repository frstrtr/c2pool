#!/usr/bin/env bash
#
# DGB AUX_DOGE link-isolation guard (negative-symbol check)
# ----------------------------------------------------------
# Companion to the compile-time src/impl/dgb/coin/aux_doge_isolation_guard.hpp.
# The compile guard pins DGB-parent traits to dgb::coin types via static_assert;
# this guard closes the gap it cannot see -- LINK-level consensus reachability.
#
# Invariant: c2pool-dgb built with -DCOIN_DGB=ON -DAUX_DOGE=ON (dual-parent,
# DGB-Scrypt parent + DOGE aux) must NOT ODR-use any LTC per-coin CONSENSUS
# symbol. A dropped dgb specialization could silently re-route the DGB parent
# through ltc::coin chain-params / header-chain serialization -- a foreign
# consensus path. That is the failure mode this guard freezes out.
#
# SCOPE (deliberate): hard-fail on the named LTC consensus entrypoints only.
# ltc::coin wire-generic types (transaction.hpp) are header-only / inlined and
# emit NO external symbols, so they are out of scope here. A wire-type
# RELOCATION toward bitcoin_family (the v37 (b) path) is caught by the D0-seam
# flag protocol with ltc-doge, not by this link guard.
#
# POSITIVE CONTROL: assert dgb::coin:: consensus symbols ARE present, so the
# guard cannot pass vacuously on a wrong / empty / stripped binary.
#
# Usage: dgb_aux_doge_link_isolation_guard.sh [path-to-c2pool-dgb]
set -euo pipefail

BIN="${1:-build_dgb_auxdoge/src/c2pool/c2pool-dgb}"

if [[ ! -f "$BIN" ]]; then
  echo "FAIL: binary not found: $BIN" >&2
  exit 2
fi

if ! command -v nm >/dev/null 2>&1; then
  echo "FAIL: nm not available on this runner" >&2
  exit 2
fi

SYMS="$(nm -C "$BIN" 2>/dev/null || true)"
if [[ -z "$SYMS" ]]; then
  echo "FAIL: nm produced no symbols (binary stripped?): $BIN" >&2
  exit 2
fi

# --- Negative: forbidden LTC consensus surface (defined T/t/W/V or referenced U) ---
FORBIDDEN_RE='make_ltc_chain_params|make_litecoin_chain_params|ltc::coin::HeaderChain|ltc::coin::ChainParams'

HITS="$(printf '%s\n' "$SYMS" | grep -E "$FORBIDDEN_RE" || true)"
if [[ -n "$HITS" ]]; then
  echo "FAIL: c2pool-dgb (AUX_DOGE) links forbidden LTC consensus symbol(s):" >&2
  printf '%s\n' "$HITS" >&2
  echo "  -> DGB parent must not reach ltc::coin consensus surface. Route to D0 seam thread." >&2
  exit 1
fi

# --- Positive control: DGB parent consensus types must be present ---
DGB_COUNT="$(printf '%s\n' "$SYMS" | grep -cE 'dgb::coin::' || true)"
if [[ "${DGB_COUNT:-0}" -eq 0 ]]; then
  echo "FAIL: no dgb::coin:: symbols found -- wrong/empty binary, guard would pass vacuously: $BIN" >&2
  exit 1
fi

echo "PASS: dgb-aux-doge link isolation"
echo "  binary           : $BIN"
echo "  forbidden LTC    : 0 hits ($FORBIDDEN_RE)"
echo "  dgb::coin:: syms : $DGB_COUNT (positive control OK)"
exit 0
