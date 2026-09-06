#!/usr/bin/env bash
# Honesty gate for the heavy-leg disk headroom guard (guard.sh). Pure shell on a
# gh-hosted runner -- no self-hosted host, no build. Asserts:
#   A. the mtime sweep reaps an ORPHANED build tree but preserves a fresh one
#      and any non-build sibling dir;
#   B. the guard FAILS FAST (exit 1) with the infra error when the floor is
#      unreachable -- i.e. the guard actually blocks, it is not a silent no-op;
#   C. the guard PASSES (exit 0) when the floor is met.
#   D. the STALE_HOURS clamp is real -- a sub-floor stale-hours is raised to the
#      3h floor, so a tree younger than 3h is SPARED (not reaped) even though the
#      requested 1h would have reaped it. Guards the "someone lowers STALE_HOURS
#      near job runtime and starts reaping live sibling trees" foot-gun.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD="$SCRIPT_DIR/guard.sh"
SBX="$(mktemp -d)"
trap 'rm -rf "$SBX"' EXIT

fails=0
ok  () { echo "PASS: $*"; }
bad () { echo "FAIL: $*"; fails=$((fails+1)); }

export CCACHE_DIR="$SBX/ccache"   # never touch a real ccache
export HEAVY_DISK_CCACHE_MAX="1G"
export HEAVY_DISK_BUILD_VOLUME="$SBX"   # a real, writable volume with space

# ---- fixture: a fake pair of co-resident runner homes on one disk ----------
plant () {
  local runner="$1" tree="$2" age="$3"
  local d="$SBX/$runner/_work/c2pool/c2pool/$tree"
  mkdir -p "$d"
  dd if=/dev/zero of="$d/obj.o" bs=1M count=1 status=none 2>/dev/null || true
  [ -n "$age" ] && touch -d "$age" "$d"
  echo "$d"
}

# Ages are well clear of the 3h STALE_HOURS floor so CASE A's stale-hours=3 is
# used verbatim (not clamped): 4h orphan is reaped, a fresh live tree is spared.
ORPHAN="$(plant actions-runner-heavy-9 build_asan '4 hours ago')"
LIVE="$(plant   actions-runner-heavy-8 build_asan 'now')"
NONBUILD="$(plant actions-runner-heavy-7 srcdir   '4 hours ago')"

# ---- CASE A: sweep reaps the orphan, spares the live + non-build -----------
HEAVY_DISK_FLOOR_GB=0 HEAVY_DISK_STALE_HOURS=3 \
  HEAVY_DISK_SWEEP_ROOTS="$SBX/actions-runner*" \
  bash "$GUARD" >"$SBX/a.log" 2>&1
rcA=$?
[ $rcA -eq 0 ]       && ok "A: guard exit 0 with floor 0"            || bad "A: expected exit 0, got $rcA"
[ ! -d "$ORPHAN" ]   && ok "A: orphaned build tree reaped"           || bad "A: orphan survived: $ORPHAN"
[ -d "$LIVE" ]       && ok "A: live (fresh-mtime) build tree spared" || bad "A: live tree wrongly reaped: $LIVE"
[ -d "$NONBUILD" ]   && ok "A: non-build sibling dir spared"         || bad "A: non-build dir wrongly reaped: $NONBUILD"

# ---- CASE B: unreachable floor -> hard fail with the infra error -----------
HEAVY_DISK_FLOOR_GB=999999999 HEAVY_DISK_STALE_HOURS=6 \
  HEAVY_DISK_SWEEP_ROOTS="$SBX/actions-runner*" \
  bash "$GUARD" >"$SBX/b.log" 2>&1
rcB=$?
[ $rcB -ne 0 ] && ok "B: guard blocks (exit $rcB) on unreachable floor" || bad "B: guard did NOT fail on impossible floor"
grep -q "insufficient build disk" "$SBX/b.log" && ok "B: emits ::error:: insufficient build disk" || bad "B: missing infra error line"
grep -qi "not this diff"           "$SBX/b.log" && ok "B: names it as infra, not the diff"          || bad "B: missing 'not this diff' framing"

# ---- CASE C: reachable floor -> pass ---------------------------------------
HEAVY_DISK_FLOOR_GB=1 HEAVY_DISK_STALE_HOURS=6 \
  HEAVY_DISK_SWEEP_ROOTS="$SBX/actions-runner*" \
  bash "$GUARD" >"$SBX/c.log" 2>&1
rcC=$?
[ $rcC -eq 0 ] && ok "C: guard passes on reachable floor" || bad "C: expected exit 0, got $rcC"
grep -q "heavy-disk-guard: OK" "$SBX/c.log" && ok "C: prints OK line" || bad "C: missing OK line"

# ---- CASE D: STALE_HOURS clamp protects a near-runtime tree ----------------
# A 2h-old tree is younger than the 3h floor. A requested stale-hours=1 asks to
# reap it, but the clamp raises the threshold to 3h -- so it MUST be spared.
NEAR="$(plant actions-runner-heavy-6 build_asan '2 hours ago')"
HEAVY_DISK_FLOOR_GB=0 HEAVY_DISK_STALE_HOURS=1 \
  HEAVY_DISK_SWEEP_ROOTS="$SBX/actions-runner*" \
  bash "$GUARD" >"$SBX/d.log" 2>&1
rcD=$?
[ $rcD -eq 0 ]     && ok "D: guard exit 0 with clamped stale-hours"        || bad "D: expected exit 0, got $rcD"
grep -qi "clamped to 3h" "$SBX/d.log" && ok "D: emits clamp warning"       || bad "D: missing clamp warning"
[ -d "$NEAR" ]     && ok "D: 2h tree spared by clamp (would die at 1h)"    || bad "D: clamp failed -- 2h tree reaped: $NEAR"

echo "-----"
if [ "$fails" -eq 0 ]; then
  echo "heavy-disk-guard honesty gate: ALL PASS"
  exit 0
fi
echo "heavy-disk-guard honesty gate: $fails FAILURE(S)"
exit 1
