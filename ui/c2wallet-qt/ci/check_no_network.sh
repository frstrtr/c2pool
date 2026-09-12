#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# check_no_network.sh — the network-incapable link-guard for c2wallet-qt-signer.
#
# This is defense-in-depth layer 1 from docs/design/c2wallet-qt.md §5.2, made
# mechanical: the offline signer binary must be PHYSICALLY INCAPABLE of network
# I/O. Any attempt to open a socket must be a LINK error, not a runtime toggle.
# This script is the binary-level analog of c2pool's reward-safety grep proof.
#
# It fails (non-zero) if the built binary either:
#   (1) has a NEEDED dependency on any networking shared library, or
#   (2) imports any forbidden network C-ABI symbol in its dynamic symbol table.
#
# Usage:  check_no_network.sh <path-to-c2wallet-qt-signer>
#
# ── Why symbol-NAME matching, not `grep` over raw nm output ────────────────
# QtCore is built around QObject::connect and Qt6 property bindables
# (bindableWindowTitle, ...). A naive `nm BIN | grep -E 'connect|bind'` would
# match the C++-MANGLED names of those (e.g. _ZN7QObject7connect...,
# ...bindable...) and either false-fail or, worse, train reviewers to ignore
# the guard. The libc network calls we actually care about are UNMANGLED C ABI
# names — `connect`, `socket`, `bind`, ... — so we extract the symbol-name
# column from `nm -D` and match it EXACTLY (plus a few prefix families:
# SSL_*, curl_*, res_*). A mangled C++ symbol never equals the bare token
# `connect`, so QObject::connect is correctly ignored while a real libc
# connect(2) import is caught.
#
# ── Scope / honest limits ──────────────────────────────────────────────────
# nm -D / objdump -T inspect the binary's OWN dynamic symbol table and its
# NEEDED list — i.e. what THIS binary imports and links directly. That is the
# link-time proof M0 promises. It does not, and is not meant to, cover a
# dlopen'd plugin loaded at runtime or a raw inline syscall; those belong to
# the M5 runtime seccomp belt (§5.2 layer 3). The link guard here is layer 1.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

BIN="${1:?usage: check_no_network.sh <path-to-c2wallet-qt-signer>}"

if [[ ! -f "$BIN" ]]; then
    echo "FAIL: binary not found: $BIN" >&2
    exit 2
fi

echo "== c2wallet-qt-signer network-incapable link-guard =="
echo "target: $BIN"
echo

fail=0

# ── Part 1: no networking shared library may be a load-time dependency ──────
# Qt6::Core/Gui/Widgets only. QtNetwork, QtWebEngine*, QtWebChannel, libcurl,
# OpenSSL (libssl), c-ares and boost_asio are all forbidden. Read the ELF
# NEEDED entries directly (objdump -p) so we do not require the loader to
# actually resolve the libraries on the CI host.
FORBIDDEN_LIB_RE='libQt6Network|libQt6WebEngine|libQt6WebChannel|libcurl|libssl|libcares|libc-ares|boost_asio|libboost_asio'

echo "-- NEEDED shared libraries --"
needed="$(objdump -p "$BIN" 2>/dev/null | awk '/NEEDED/{print $2}' | sort -u)"
echo "$needed" | sed 's/^/   /'
echo

if echo "$needed" | grep -Eq "$FORBIDDEN_LIB_RE"; then
    echo "FAIL: binary links a forbidden networking library:" >&2
    echo "$needed" | grep -E "$FORBIDDEN_LIB_RE" | sed 's/^/   >>> /' >&2
    fail=1
else
    echo "OK: no forbidden networking library in NEEDED list."
fi
echo

# ── Part 2: no forbidden network C-ABI symbol in the dynamic symbol table ───
# Prefer `nm -D` (dynamic symtab; survives stripping). Fall back to objdump -T.
# The symbol name is the LAST field; strip any @GLIBC_x.y version suffix.
if nm -D --undefined-only "$BIN" >/dev/null 2>&1; then
    undef_syms="$(nm -D --undefined-only "$BIN" 2>/dev/null | awk '{print $NF}')"
else
    # objdump -T marks undefined dynamic symbols with the *UND* section.
    undef_syms="$(objdump -T "$BIN" 2>/dev/null | awk '/\*UND\*/{print $NF}')"
fi
undef_syms="$(echo "$undef_syms" | sed 's/@.*//' | sort -u)"

# Exact-match forbidden C-ABI names (the set named in the M0 brief plus a few
# obvious siblings), and forbidden prefix families.
is_forbidden_symbol() {
    case "$1" in
        connect|socket|bind|listen|accept|accept4| \
        getaddrinfo|freeaddrinfo|getnameinfo|gethostbyname|gethostbyname2| \
        gethostbyaddr|sendto|recvfrom|getpeername|connectto)
            return 0 ;;
        SSL_*|curl_*|res_*)
            return 0 ;;
    esac
    return 1
}

echo "-- forbidden network symbol scan (imported dynamic symbols) --"
hits=""
while IFS= read -r sym; do
    [[ -z "$sym" ]] && continue
    if is_forbidden_symbol "$sym"; then
        hits+="$sym"$'\n'
    fi
done <<< "$undef_syms"

if [[ -n "$hits" ]]; then
    echo "FAIL: binary imports forbidden network symbol(s):" >&2
    echo "$hits" | sed '/^$/d;s/^/   >>> /' >&2
    fail=1
else
    echo "OK: no forbidden network symbol imported."
fi
echo

if [[ "$fail" -ne 0 ]]; then
    echo "RESULT: NETWORK-INCAPABLE GUARD FAILED — this binary can touch the network." >&2
    exit 1
fi

echo "RESULT: PASS — c2wallet-qt-signer is network-incapable (no net libs, no net symbols)."
