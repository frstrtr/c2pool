#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Start ONE architecture slice of a macOS c2pool binary and require that it ran.
#
#   usage: scripts/ci/macos_slice_smoke.sh <arm64|x86_64> <binary> [log]
#
# Runs `arch -<arch> <binary> --help`. The binary may be thin (a per-arch build)
# or universal (arch selects the slice). On the Apple Silicon build host the
# x86_64 slice runs under Rosetta 2; a host without Rosetta is an ERROR, not a
# skip, because the x86_64 slice is cross-compiled and this is the only place it
# is ever executed before it ships.
#
# Passes only when the process exits 0 and printed something. Fails on a load
# error (missing or wrong-arch dylib, invalid signature: dyld aborts with a
# signal), a crash, or a non-zero exit. The output is kept in [log] (default
# smoke-<arch>.log) for follow-up checks such as the DASH BLS backend line.
set -uo pipefail

ARCH="${1:?usage: macos_slice_smoke.sh <arm64|x86_64> <binary> [log]}"
BIN="${2:?usage: macos_slice_smoke.sh <arm64|x86_64> <binary> [log]}"
LOG="${3:-smoke-${ARCH}.log}"

case "$ARCH" in
    arm64|x86_64) ;;
    *) echo "::error::macos_slice_smoke: unknown arch '$ARCH'"; exit 1 ;;
esac
[ -x "$BIN" ] || { echo "::error::macos_slice_smoke: $BIN is not an executable file"; exit 1; }

if ! lipo "$BIN" -verify_arch "$ARCH" 2>/dev/null; then
    echo "::error::$BIN has no $ARCH slice (lipo -archs: $(lipo -archs "$BIN" 2>&1))"
    exit 1
fi
if [ "$ARCH" = "x86_64" ] && [ "$(uname -m)" = "arm64" ]; then
    if ! arch -x86_64 /usr/bin/true 2>/dev/null; then
        echo "::error::Rosetta 2 is not installed on ${RUNNER_NAME:-this host}; the x86_64 slice cannot be started"
        exit 1
    fi
    how="Rosetta 2"
else
    how="native"
fi

rc=0
arch -"$ARCH" "$BIN" --help > "$LOG" 2>&1 || rc=$?
echo "== $(basename "$BIN") [$ARCH, $how] --help: exit $rc, $(wc -l < "$LOG" | tr -d ' ') lines"
head -n 5 "$LOG"
if [ "$rc" -ne 0 ]; then
    echo "::error::$(basename "$BIN") $ARCH slice did not start cleanly ($how): exit status $rc"
    tail -n 20 "$LOG"
    exit 1
fi
if [ ! -s "$LOG" ]; then
    echo "::error::$(basename "$BIN") $ARCH slice printed nothing for --help ($how)"
    exit 1
fi
echo "  ok   $ARCH slice starts ($how)"
