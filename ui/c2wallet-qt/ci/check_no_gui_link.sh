#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# check_no_gui_link.sh — the HEADLESS guard for c2wallet-qt-schedd.
#
# The inject scheduler daemon runs under systemd on a node host with no
# display. It must link Qt6::Core + Qt6::Network and nothing of a GUI stack:
# a Gui/Widgets/Quick/OpenGL/X11/Wayland dependency would both fail to start
# headless and widen what runs next to the node's control token.
#
# Usage:  check_no_gui_link.sh <path-to-c2wallet-qt-schedd>
#
# It reads the dynamic section (NEEDED entries) of the linked ELF binary.
# Linux/ELF only (readelf, else objdump); the daemon targets Linux node hosts.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

BIN="${1:?usage: check_no_gui_link.sh <path-to-c2wallet-qt-schedd>}"
if [[ ! -f "$BIN" ]]; then
    echo "FAIL: file not found: $BIN" >&2
    exit 2
fi

echo "== c2wallet-qt-schedd HEADLESS link guard =="
echo "target: $BIN"

needed=""
if command -v readelf >/dev/null 2>&1; then
    needed="$(readelf -d "$BIN" 2>/dev/null | awk '/\(NEEDED\)/ { v=$NF; gsub(/[\[\]]/, "", v); print v }')"
elif command -v objdump >/dev/null 2>&1; then
    needed="$(objdump -p "$BIN" 2>/dev/null | awk '$1 == "NEEDED" { print $2 }')"
else
    echo "FAIL: neither readelf nor objdump is available" >&2
    exit 2
fi
if [[ -z "$needed" ]]; then
    echo "FAIL: no NEEDED entries read (not a dynamic ELF binary?)" >&2
    exit 2
fi
echo "-- NEEDED --"
echo "$needed" | sed 's/^/   /'

FORBIDDEN_RE='libQt6Gui|libQt6Widgets|libQt6OpenGL|libQt6Quick|libQt6Qml|libQt6WebEngine|libQt6WebChannel|libQt6Svg|libGL\.|libEGL|libX11|libxcb|libwayland'
hits="$(echo "$needed" | grep -E "$FORBIDDEN_RE" || true)"
if [[ -n "$hits" ]]; then
    echo "FAIL: the headless daemon links a GUI library:" >&2
    echo "$hits" | sed 's/^/   >>> /' >&2
    exit 1
fi
for want in libQt6Core libQt6Network; do
    if ! echo "$needed" | grep -q "^$want"; then
        echo "FAIL: expected $want among the NEEDED entries (is this the right binary?)" >&2
        exit 1
    fi
done
echo
echo "RESULT: PASS — c2wallet-qt-schedd links Qt6::Core + Qt6::Network and no GUI stack."
