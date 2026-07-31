#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# POSITIVE assertion that a c2pool-dash binary really links the dashbls
# (BLS12-381) backend — i.e. that E1 Phase-L can verify a real type-6 quorum
# commitment instead of compiling the fail-closed stub.
#
# WHY THIS EXISTS. Passing -DC2POOL_DASH_BLS=ON is NOT evidence. Before this
# guard, a configure that could not find the library only WARNED: the option
# stayed on, dash_bls_verify compiled the stub, the build went green, and the
# packaged binary was BLS-dark — indistinguishable from a working one until it
# silently null-served a DKG-window height in production. The root CMakeLists
# now FATAL_ERRORs on that path; this script is the independent second check,
# applied to the ARTEFACT rather than to the build flags, so a future refactor
# that reintroduces a soft fallback still cannot ship a dark binary quietly.
#
#   usage: scripts/ci/dash_bls_linked_guard.sh <path-to-c2pool-dash>
#
# Two independent markers, BOTH required:
#
#   1. rodata: the BLS12-381 ciphersuite ID that dashbls' BasicSchemeMPL signs
#      under (verify_final_commitment uses BasicSchemeMPL). It is a string
#      constant, so it SURVIVES `strip` — this check works on the packaged,
#      stripped release artefact, which is the binary users actually run.
#   2. symbols: the dashbls C++ API entry points bls_verify.cpp calls. Only
#      checked when the binary still has a symbol table (pre-strip); skipped
#      with a note, never silently, on a stripped binary.
set -euo pipefail

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "dash_bls_linked_guard: usage: $0 <path-to-c2pool-dash>" >&2
    exit 2
fi

# BasicSchemeMPL::CIPHERSUITE_ID in dashbls (schemes.cpp). The "NUL_" variant is
# the basic scheme; AUG_/POP_ belong to the other two schemes and travel with
# the same object, so any of them proves the real library is in the image.
CIPHERSUITE_RE='BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_(NUL|AUG|POP)_'

fail=0

echo "dash_bls_linked_guard: target = $BIN"

# NOTE ON SHELL SHAPE: every match below is captured into a variable and tested
# with a pure-shell `case`, deliberately NOT with `grep -q` in a pipeline. Under
# `set -o pipefail`, `grep -q` exits at the FIRST match and SIGPIPEs the
# producer, so the pipeline's status is non-zero *because the match succeeded* —
# a guard written that way reports every real-BLS binary as dark. That bug was
# caught by running this script against a known-good BLS-linked c2pool-dash; the
# lesson is the same one that motivates the guard itself, so it stays written
# down here.
hits="$(strings -a "$BIN" | grep -E "$CIPHERSUITE_RE" || true)"
if [ -n "$hits" ]; then
    echo "  ok   dashbls BLS12-381 ciphersuite ID present in rodata"
else
    echo "  FAIL no BLS12-381 ciphersuite ID in $BIN — this binary is BLS-DARK"
    fail=1
fi

# Symbol leg. `nm` reports "no symbols" on a stripped binary; that is a SKIP,
# never a pass and never a failure — the rodata leg above still covers it.
syms="$(nm -C --defined-only "$BIN" 2>/dev/null || true)"
if [ -z "$syms" ]; then
    echo "  skip symbol check (binary is stripped — rodata leg above still applies)"
else
    for want in 'bls::G1Element::FromBytes' 'bls::G2Element::FromBytes'; do
        case "$syms" in
            *"$want"*) echo "  ok   symbol $want" ;;
            *)         echo "  FAIL symbol $want absent — dash_bls_verify compiled the stub"
                       fail=1 ;;
        esac
    done
fi

if [ "$fail" -ne 0 ]; then
    echo "::error::$BIN does NOT link the dashbls backend. Configure with" \
         "-DC2POOL_DASH_BLS=ON -DDASHBLS_ROOT=<prefix> after building the" \
         "library via scripts/build_dashbls.sh."
    exit 1
fi

echo "dash_bls_linked_guard: PASS — real BLS verification is linked in"
