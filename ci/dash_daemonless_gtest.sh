#!/usr/bin/env bash
# Build ONLY the test executables behind the dash-daemonless ctest selector,
# then run the selected tests -- with a guard so the gate cannot go hollow.
#
# Used by .github/workflows/coin-matrix.yml ("Embedded daemonless gtest").
# Before this script, that step ran `cmake --build <dir>` with no --target:
# every target in the repo (~973 objects, LTC/BTC/XMR/DGB tests included) to
# run tests that live in six executables.
#
# What it builds: TARGETS (the gtest_add_tests executables that hold the
# selected suites) plus EVERY discover-mode test target (gtest_discover_tests
# PRE_TEST). A discover-mode target's tests are invisible to ctest until it is
# built: ctest lists only a "<target>_NOT_BUILT" placeholder. Building them
# all (a handful of small executables) means a selected suite that ever lands
# in one is listed, run, and caught by the drift check below.
#
# The guard FAILS the step, before any test runs, when:
#   1. a discover-mode placeholder is still listed after the build;
#   2. the selector matches 0 tests;
#   3. any selected test's executable was not built (ctest -N -V then prints
#      an empty "Test command:"): a suite moved to a target not built here;
#   4. the executables behind the selected tests differ from TARGETS in either
#      direction (drift: keep this list and the selector in step).
# After the run it fails when ctest's "out of M" plus the DISABLED_ tests
# (which ctest lists but excludes from M) differs from the listed count.
#
# Usage: ci/dash_daemonless_gtest.sh <build-dir> [jobs]
#        CHECK_ONLY=1 ci/dash_daemonless_gtest.sh <build-dir>  # guard only: no build, no run
#                                                             # (placeholders only warn)
set -euo pipefail

B=${1:?usage: dash_daemonless_gtest.sh <build-dir> [jobs]}
J=${2:-4}

# The #1293 dashd-cut family: replay/fold gtests on the daemonless self-derive
# path (no --coin-rpc arm).
SEL='^(DashBlockReplay|DashReplay|DashMnCheckpoint|DashMnPayee|DashMnAnchor|DashMnBridge|ReplayUtxo)'

# Every executable that holds a test SEL matches (test/CMakeLists.txt).
TARGETS="test_dash_block_replay test_dash_embedded_gbt test_dash_mempool test_dash_mn_state test_dash_node_reception_wire test_dash_p2p_node"

fail() { echo "::error::dash-daemonless gtest guard: $*" >&2; exit 1; }
placeholders() {   # discover-mode targets ctest cannot list yet, one per line
    local all
    all=$(ctest --test-dir "$B" -N 2>&1) || fail "ctest -N failed: $all"
    printf '%s\n' "$all" | sed -n -E 's/^ *Test +#[0-9]+: (.+)_NOT_BUILT$/\1/p' | sort -u
}

DISC=$(placeholders | tr '\n' ' ' | sed 's/ $//')
if [ "${CHECK_ONLY:-0}" != 1 ]; then
    echo "building TARGETS: $TARGETS"
    echo "building discover-mode targets: ${DISC:-none}"
    # shellcheck disable=SC2086  # deliberate word lists
    cmake --build "$B" --target $TARGETS $DISC -j"$J"
fi

# ── Guard (capture first; no `| grep -q` under pipefail) ─────────────────
LEFT=$(placeholders | tr '\n' ' ' | sed 's/ $//')
if [ -n "$LEFT" ]; then
    if [ "${CHECK_ONLY:-0}" = 1 ]; then
        echo "::warning::guard incomplete: discover-mode targets not built, their tests are unlisted: $LEFT"
    else
        fail "discover-mode targets still unlisted after the build: $LEFT"
    fi
fi

LIST=$(ctest --test-dir "$B" -N -V -R "$SEL" 2>&1) || fail "ctest -N failed: $LIST"
CMDS=$(printf '%s\n' "$LIST" | grep -E '^[0-9]+: Test command:' || true)
N=$(printf '%s\n' "$CMDS" | grep -c 'Test command:' || true)
[ "$N" -gt 0 ] || fail "selector '$SEL' matches 0 tests (hollow gate)"

MISSING=$(printf '%s\n' "$CMDS" | grep -E 'Test command: ( |$)' || true)
if [ -n "$MISSING" ]; then
    NM=$(printf '%s\n' "$MISSING" | grep -c . || true)
    echo "$MISSING" | head -20 >&2
    fail "$NM of $N selected tests have no built executable (target not built, or the suite moved to a target not in TARGETS)"
fi

HAVE=$(printf '%s\n' "$CMDS" | sed -n -E 's/^[0-9]+: Test command: ([^ ]+).*/\1/p' \
       | xargs -n1 basename | sort -u | tr '\n' ' ' | sed 's/ $//')
WANT=$(printf '%s\n' $TARGETS | sort -u | tr '\n' ' ' | sed 's/ $//')
[ "$HAVE" = "$WANT" ] || fail "selected tests come from [$HAVE] but TARGETS is [$WANT]; update TARGETS"

echo "dash-daemonless gtest guard OK: $N tests in [$HAVE]"
[ "${CHECK_ONLY:-0}" = 1 ] && exit 0

# ── Run ──────────────────────────────────────────────────────────────────
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT
rc=0
ctest --test-dir "$B" --output-on-failure --no-tests=error -R "$SEL" 2>&1 | tee "$OUT" || rc=$?
[ "$rc" -eq 0 ] || exit "$rc"
M=$(sed -n -E 's/.*tests passed, [0-9]+ tests failed out of ([0-9]+).*/\1/p' "$OUT" | tail -1)
# DISABLED_ tests are listed by -N but excluded from "out of M" (ctest 3.28:
# "N - Suite.Name (Disabled)" under "The following tests did not run").
# Skipped tests count inside M.
D=$(grep -c -E '^[[:space:]]*[0-9]+ - .+ \(Disabled\)$' "$OUT" || true)
[ -n "$M" ] && [ $((M + D)) -eq "$N" ] \
    || fail "ctest ran ${M:-?} tests + $D disabled, the guard listed $N"
echo "dash-daemonless gtest: $M run ($D disabled) of $N listed, all passed"
