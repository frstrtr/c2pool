#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# check_package_no_network.sh — the PACKAGE scan for c2wallet-qt-signer.
#
# The link-guards (check_no_network.sh / _macho.sh / _pe.ps1) prove what the
# signer binary itself links. The deploy tools (linuxdeploy-plugin-qt,
# macdeployqt, windeployqt) add Qt libraries and plugins next to it, and
# windeployqt in particular adds the TLS and network-information plugins by
# default. This scan fails if the staged package tree contains any of them:
#   - a QtNetwork library / framework (libQt6Network.so*, QtNetwork.framework,
#     Qt6Network.dll), QtWebEngine*, QtWebChannel;
#   - a plugins/tls, plugins/networkinformation (Linux, Windows) or
#     PlugIns/tls, PlugIns/networkinformation (macOS) directory;
#   - libcurl, libssl or libcrypto.
#
# Usage:  check_package_no_network.sh <package-dir | .app | AppDir>
# Portable bash + find (GNU and BSD). check_package_no_network.ps1 is the
# PowerShell twin for the Windows runner, which has no bash.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

PKG="${1:?usage: check_package_no_network.sh <package-dir>}"
if [[ ! -d "$PKG" ]]; then
    echo "FAIL: package directory not found: $PKG" >&2
    exit 2
fi

echo "== c2wallet-qt-signer package scan (no network library or plugin) =="
echo "package: $PKG"
total="$(find "$PKG" -type f | wc -l | tr -d ' ')"
echo "files:   $total"
if [[ "$total" -eq 0 ]]; then
    echo "FAIL: the package is empty" >&2
    exit 2
fi

hits="$(find "$PKG" \( -iname '*Qt6Network*' -o -iname '*QtNetwork*' \
                    -o -iname '*Qt6WebEngine*' -o -iname '*QtWebEngine*' \
                    -o -iname '*Qt6WebChannel*' -o -iname '*QtWebChannel*' \
                    -o -iname 'libcurl*' -o -iname 'libssl*' -o -iname 'libcrypto*' \
                    -o -ipath '*/plugins/tls' -o -ipath '*/plugins/tls/*' \
                    -o -ipath '*/plugins/networkinformation' -o -ipath '*/plugins/networkinformation/*' \) \
        -print | sort)"

if [[ -n "$hits" ]]; then
    echo "FAIL: the package ships networking code:" >&2
    echo "$hits" | sed 's/^/   >>> /' >&2
    echo "RESULT: PACKAGE SCAN FAILED." >&2
    exit 1
fi
echo "RESULT: PASS — no QtNetwork, TLS / network-information plugin, curl or OpenSSL in the package."
