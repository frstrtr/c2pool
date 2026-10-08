#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# check_key_free.sh — the KEY-FREE guard for the c2wallet-qt ONLINE COMPANION.
#
# The companion is the ONLINE, key-free side of the two-machine model (design
# docs/design/c2wallet-qt.md §5.2). Where the signer proves it is
# network-incapable (ci/check_no_network.sh), the companion proves the mirror
# property: it holds and links NO private-key or transaction-signing code. It
# only marshals PUBLIC artifacts and talks to the node.
#
# This script is the binary-level analog of that guard. It fails (non-zero) if
# the companion object/library imports or defines any private-key / signing
# symbol.
#
# Usage:  check_key_free.sh <path-to-libc2wallet-companion.a-or-binary>
#
# ── Why symbol matching, not a source grep ─────────────────────────────────
# The proof must be about what actually LINKED, not about source text. We scan
# the produced object table with `nm` and match forbidden signing tokens as
# SUBSTRINGS of the (possibly C++-mangled) symbol names, because the signer
# core lives in namespace c2w::signer and would appear mangled. The tokens are
# specific to transaction signing / private keys so ordinary code is untouched.
#
# ── Honest limits ──────────────────────────────────────────────────────────
# This inspects the companion's own symbol table (defined + referenced). It is
# the link-time proof that the key-bearing signer core (CKey, the RFC6979/DER
# ECDSA + Schnorr signers, SignatureHash) is NOT part of the companion. TLS/
# network symbols are NOT forbidden here — the companion is the online side and
# MAY link the network (that is the whole point of the split).
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

BIN="${1:?usage: check_key_free.sh <path-to-companion-lib-or-binary>}"

if [[ ! -f "$BIN" ]]; then
    echo "FAIL: file not found: $BIN" >&2
    exit 2
fi

echo "== c2wallet-qt companion KEY-FREE guard =="
echo "target: $BIN"
echo

# All symbols (defined + undefined) in the object/archive. `nm` over a static
# archive lists every member object's symbols; that is exactly the closure we
# want to prove key-free.
syms="$(nm "$BIN" 2>/dev/null || true)"
if [[ -z "$syms" ]]; then
    # Fall back to the dynamic table for a linked binary.
    syms="$(nm -D "$BIN" 2>/dev/null || true)"
fi
names="$(echo "$syms" | awk '{print $NF}' | sed 's/@.*//' | sort -u)"

# Forbidden private-key / signing tokens (substring match against mangled
# names). These are the signer core's fingerprints:
#   * CKey / CExtKey        — the private-key types
#   * SignatureHash         — the legacy sighash producer
#   * make_legacy_sig / make_bip143_sig / make_taproot_*_sig — the M3-A/M4-A signers
#   * secp256k1_ecdsa_sign / secp256k1_schnorrsig_sign — the ec signing entry points
#   * RFC6979 / rfc6979     — deterministic-nonce signing
#   * c2w::signer namespace  — the whole key-bearing module
FORBIDDEN_RE='CKey|CExtKey|SignatureHash|make_legacy_sig|make_bip143_sig|make_taproot|secp256k1_ecdsa_sign|secp256k1_schnorrsig_sign|[Rr][Ff][Cc]6979|c2w::signer|N3c2w6signer|_ZN3c2w6signer'

echo "-- signing / private-key symbol scan --"
hits="$(echo "$names" | grep -E "$FORBIDDEN_RE" || true)"

if [[ -n "$hits" ]]; then
    echo "FAIL: companion imports/defines private-key or signing symbol(s):" >&2
    echo "$hits" | sed 's/^/   >>> /' >&2
    echo
    echo "RESULT: KEY-FREE GUARD FAILED — the companion linked signing code." >&2
    exit 1
fi

echo "OK: no private-key / signing symbol in the companion objects."
echo
echo "RESULT: PASS — c2wallet-qt companion is key-free (no CKey / sign symbols)."
