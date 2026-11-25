#!/usr/bin/env bash
# coin-matrix "Smoke test (--help)": the coin binary was built, runs, and
# prints its usage text. Used by .github/workflows/coin-matrix.yml.
#
# Before this script the step was `file "$BIN"; "$BIN" --help | head -5 || true`.
# `file` exits 0 even for a missing path, and `|| true` masked the binary, so
# the step could never fail.
#
# FAILS when:
#   1. the binary is missing or not an executable regular file;
#   2. `--help` exits non-zero, or does not return within the timeout;
#   3. `--help` prints no usage text ("usage", case-insensitive).
#
# Usage: ci/coin_help_smoke.sh <path-to-c2pool-binary>
set -uo pipefail

BIN=${1:?usage: coin_help_smoke.sh <path-to-c2pool-binary>}

fail() { echo "::error::coin --help smoke: $*" >&2; exit 1; }

[ -e "$BIN" ] || fail "binary not found: $BIN"
[ -f "$BIN" ] || fail "not a regular file: $BIN"
[ -x "$BIN" ] || fail "not executable: $BIN"
file "$BIN" || true   # informational only

rc=0
OUT=$(timeout 60 "$BIN" --help 2>&1) || rc=$?
# First lines for the log (the usage text follows the startup lines on some coins).
sed -n '1,25p' <<<"$OUT"
[ "$rc" -eq 0 ] || fail "'$(basename "$BIN") --help' exited $rc"
grep -qi 'usage' <<<"$OUT" || fail "'$(basename "$BIN") --help' printed no usage text"
echo "coin --help smoke OK: $(basename "$BIN") ($(wc -l <<<"$OUT") lines of help)"
