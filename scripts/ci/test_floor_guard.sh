#!/usr/bin/env bash
# Zero-test guard: fail loud when a ctest lane runs fewer cases than its floor.
#
# WHY: a ctest lane reports GREEN over an EMPTY set. That happens when a -R
# subset stops matching (a case renamed, a gtest_discover_tests race dropping
# the discovered set, or the cases compiled out of existence inside #ifdef on a
# stub build). The lane goes green having asserted nothing -- a hollow green.
#
# A single FLAT floor would false-red the legitimately-small scoped lanes
# (^bch_, the 5 DASH-BLS KATs, the lone boost_sentinel), so the floor is
# LANE-KEYED via test-floors.json. This is a collapse detector, not an exact
# expectation: it catches a lane falling to (near-)zero, and pairs with
# `ctest --no-tests=error` on the ctest side as belt-and-suspenders.
#
# Usage: test_floor_guard.sh <lane-key> <junit-xml>
#   <lane-key>   key into test-floors.json (.lanes.<key>)
#   <junit-xml>  path to a `ctest --output-junit <file>` report
#
# Exit: 0 pass; 1 floor breached / no report produced; 2 misconfiguration.
set -euo pipefail

lane="${1:?lane key required}"
junit="${2:?junit xml path required}"
floors="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/test-floors.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "::error::test-floor-guard: jq not found on PATH" >&2
  exit 2
fi
if [[ ! -f "$floors" ]]; then
  echo "::error::test-floor-guard: floors file not found: $floors" >&2
  exit 2
fi
# A missing junit is itself the failure mode we exist to catch: ctest produced
# no report at all. Treat it as a breach, not a config error.
if [[ ! -f "$junit" ]]; then
  echo "::error::test-floor-guard[$lane]: junit not found ($junit) -- ctest wrote no report; the run asserted nothing." >&2
  exit 1
fi

floor="$(jq -r --arg k "$lane" '.lanes[$k] // "MISSING"' "$floors")"
if [[ "$floor" == "MISSING" ]]; then
  echo "::error::test-floor-guard: no floor defined for lane '$lane' in $floors" >&2
  exit 2
fi

# Count actual <testcase> elements rather than trusting the <testsuite tests=>
# attribute, and subtract cases marked skipped/notrun so a lane cannot satisfy
# its floor with skips. ctest --output-junit emits one <testcase ...> per line.
ran="$(grep -c '<testcase ' "$junit" 2>/dev/null || true)"
skipped="$(grep -Ec '<skipped|status="notrun"|status="disabled"' "$junit" 2>/dev/null || true)"
ran="${ran:-0}"; skipped="${skipped:-0}"
effective=$(( ran - skipped ))
(( effective < 0 )) && effective=0

echo "test-floor-guard[$lane]: floor=$floor ran=$ran skipped=$skipped effective=$effective"

if (( effective < floor )); then
  echo "::error::test-floor-guard[$lane]: only $effective effective test(s) ran, floor is $floor -- the lane collapsed to a (near-)empty set and would otherwise report a hollow green." >&2
  exit 1
fi
echo "test-floor-guard[$lane]: OK ($effective >= $floor)"
