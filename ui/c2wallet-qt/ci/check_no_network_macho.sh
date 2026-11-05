#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# check_no_network_macho.sh — the network-incapable link-guard for the macOS
# (Mach-O) c2wallet-qt-signer: the sibling of check_no_network.sh (ELF), run
# by the release job on the PACKAGED binary inside the .app, after
# macdeployqt and codesign.
#
# It fails (non-zero) if, in ANY architecture slice of the binary:
#   (1) a load command names a networking library or framework (otool -L):
#       QtNetwork / QtWebEngine* / QtWebChannel, libcurl, libssl, libcrypto, c-ares,
#       boost_asio, CFNetwork.framework, Network.framework; or
#   (2) the binary imports a network C-ABI symbol (nm -u): the ELF guard's
#       token list with the Mach-O leading underscore (_connect, _socket,
#       _bind, _listen, _accept, _getaddrinfo, _gethostbyname, _sendto,
#       _recvfrom, ...), the families _SSL_*, _curl_*, _res_*, and the Apple
#       socket APIs _CFSocket* / _nw_*.
# Security.framework is allowed (QtCore uses it for non-network purposes).
#
# Usage:  check_no_network_macho.sh <path-to-Mach-O-binary>
#         (e.g. c2wallet-qt-signer.app/Contents/MacOS/c2wallet-qt-signer)
# Every slice lipo reports is checked; ARCHS="arm64 x86_64" overrides that.
# OTOOL / NM / LIPO override the tools (llvm-otool / llvm-nm work too).
#
# Honest limit, as for the ELF guard: this inspects the binary's OWN load
# commands and imports. What the Qt frameworks themselves import is out of
# scope at this layer (the package scan, check_package_no_network.sh, proves
# no network plugin or QtNetwork framework is shipped at all).
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

BIN="${1:?usage: check_no_network_macho.sh <path-to-Mach-O-binary>}"
OTOOL="${OTOOL:-otool}"
NM="${NM:-nm}"
LIPO="${LIPO:-lipo}"

if [[ ! -f "$BIN" ]]; then
    echo "FAIL: binary not found: $BIN" >&2
    exit 2
fi

echo "== c2wallet-qt-signer network-incapable link-guard (Mach-O) =="
echo "target: $BIN"

archs="${ARCHS:-}"
if [[ -z "$archs" ]]; then
    archs="$("$LIPO" -archs "$BIN" 2>/dev/null || true)"
fi
if [[ -z "$archs" ]]; then
    # older lipo: "Architectures in the fat file: X are: arm64 x86_64" or
    # "Non-fat file: X is architecture: arm64"
    archs="$("$LIPO" -info "$BIN" 2>/dev/null | sed -e 's/.*are: //' -e 's/.*architecture: //')"
fi
if [[ -z "$archs" ]]; then
    echo "FAIL: could not read the architectures of $BIN" >&2
    exit 2
fi
echo "slices: $archs"
echo

FORBIDDEN_LIB_RE='QtNetwork|Qt6Network|QtWebEngine|QtWebChannel|libcurl|libssl|libcrypto|libcares|libc-ares|boost_asio|CFNetwork\.framework|/Network\.framework'

is_forbidden_symbol() {
    case "$1" in
        _connect|_socket|_bind|_listen|_accept|_accept4| \
        _getaddrinfo|_freeaddrinfo|_getnameinfo|_gethostbyname|_gethostbyname2| \
        _gethostbyaddr|_sendto|_recvfrom|_getpeername|_connectx)
            return 0 ;;
        _SSL_*|_curl_*|_res_*|_CFSocket*|_nw_*)
            return 0 ;;
    esac
    return 1
}

fail=0
for arch in $archs; do
    echo "-- slice $arch: load commands (otool -L) --"
    libs="$("$OTOOL" -arch "$arch" -L "$BIN" | tail -n +2 | awk '{print $1}')"
    if [[ -z "$libs" ]]; then
        echo "FAIL: otool -L listed nothing for slice $arch" >&2
        fail=1
        continue
    fi
    echo "$libs" | sed 's/^/   /'
    if echo "$libs" | grep -Eq "$FORBIDDEN_LIB_RE"; then
        echo "FAIL [$arch]: links a forbidden networking library:" >&2
        echo "$libs" | grep -E "$FORBIDDEN_LIB_RE" | sed 's/^/   >>> /' >&2
        fail=1
    else
        echo "OK [$arch]: no networking library or framework in the load commands."
    fi

    echo "-- slice $arch: imported symbols (nm -u) --"
    # The symbol name is the last field; drop a $UNIX2003-style variant suffix.
    syms="$("$NM" -arch "$arch" -u "$BIN" | awk 'NF {print $NF}' | sed 's/\$.*//' | sort -u)"
    echo "   $(echo "$syms" | grep -c . || true) imported symbols"
    hits=""
    while IFS= read -r sym; do
        [[ -z "$sym" ]] && continue
        if is_forbidden_symbol "$sym"; then hits+="$sym"$'\n'; fi
    done <<< "$syms"
    if [[ -n "$hits" ]]; then
        echo "FAIL [$arch]: imports forbidden network symbol(s):" >&2
        echo "$hits" | sed '/^$/d;s/^/   >>> /' >&2
        fail=1
    else
        echo "OK [$arch]: no forbidden network symbol imported."
    fi
    echo
done

if [[ "$fail" -ne 0 ]]; then
    echo "RESULT: NETWORK-INCAPABLE GUARD FAILED — this binary can touch the network." >&2
    exit 1
fi
echo "RESULT: PASS — every slice is network-incapable (no net libraries, no net symbols)."
