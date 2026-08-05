#!/usr/bin/env bash
# ============================================================================
# Honesty gate for the per-host heavy-leg reap-guard.
#
# Extracts the ACTUAL "Acquire per-host heavy-leg lock (reap-guard)" run: script
# out of build.yml (the shipped bytes, not a copy) and drives it in isolation
# via the HEAVY_LEG_* env overrides, proving the reap is load-bearing:
#
#   FIXED  (HEAVY_LEG_SWEEP=1): an orphaned holder whose owning job is already
#          dead is REAPED at acquire -> the lock is acquired -> exit 0 (GREEN).
#   LEAKED (HEAVY_LEG_SWEEP=0): the same orphan is NOT swept -> it blocks ->
#          acquire times out at the -w budget -> exit 1 (RED).
#
# If restoring the leak did NOT turn it red the test FAILS: that would mean the
# guard acquired despite a live orphan -- a hollow (non-load-bearing) sweep.
# Perturb -> green, restore leak -> red. No hollow pass.
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WF="$ROOT/.github/workflows/build.yml"
STEP="Acquire per-host heavy-leg lock (reap-guard)"

TMP="$(mktemp -d)"
cleanup() {
  [ "${BASHPID:-$$}" = "$$" ] || return 0   # never run inside a $(...) subshell
  # reap anything we spawned that still holds a case lock
  for lk in "$TMP"/case*.lock; do
    [ -e "$lk" ] && fuser -k "$lk" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- extract the shipped acquire script (pyyaml; on gh-hosted + workstation) -
ACQ_SH="$TMP/acquire.sh"
python3 - "$WF" "$STEP" > "$ACQ_SH" <<'PY'
import sys, yaml
wf, step = sys.argv[1], sys.argv[2]
doc = yaml.safe_load(open(wf))
for job in (doc.get("jobs") or {}).values():
    for s in (job.get("steps") or []):
        if s.get("name") == step:
            sys.stdout.write(s.get("run", ""))
            raise SystemExit(0)
raise SystemExit(3)
PY
[ -s "$ACQ_SH" ] || { echo "FATAL: could not extract '$STEP' run: from $WF"; exit 2; }
echo "===== acquire script under test (extracted from build.yml) ====="
cat "$ACQ_SH"
echo "================================================================"

# Plant a holder whose owning job is already dead: a marker pointing at a
# worker PID that no longer exists (exactly what a host-reaped job leaves).
# Single process (exec sleep) holding the exclusive flock, so a kill of it
# frees the lock at once -- same shape as the old `exec sleep 14400` holder.
plant_orphan() {  # $1 lockpath  $2 holderpath
  local lock="$1" marker="$2"
  # a guaranteed-dead worker PID: a subshell that exits immediately, then reaped
  ( exit 0 ) & local deadworker=$!
  wait "$deadworker" 2>/dev/null || true
  setsid bash -c 'exec 9>"'"$lock"'"; flock -x 9 || exit 1; exec sleep 300' \
    </dev/null >/dev/null 2>&1 &
  local orphan=$!
  printf '%s %s\n' "$orphan" "$deadworker" > "$marker"
  local i
  local i
  for ((i=0;i<100;i++)); do
    flock -n -x "$lock" -c true 2>/dev/null || return 0   # held -> orphan is up
    sleep 0.1
  done
  echo "FATAL: orphan never took the lock"; return 1
}

run_guard() {  # $1 sweep(0/1)  $2 wait(s)  $3 lockpath  $4 holderpath
  HEAVY_LEG_LOCK="$3" HEAVY_LEG_HOLDERFILE="$4" \
  HEAVY_LEG_WAIT="$2" HEAVY_LEG_TTL=3 HEAVY_LEG_SWEEP="$1" \
  RUNNER_NAME="honesty-test" GITHUB_ENV="$TMP/genv" \
  bash "$ACQ_SH"
}

reap() {
  [ -f "$2" ] && awk '{print $1}' "$2" | xargs -r kill 2>/dev/null || true
  fuser -k "$1" 2>/dev/null || true
  sleep 0.3 || true
}

fail=0

echo; echo "### CASE 1  FIXED (sweep on): orphan must be reaped -> GREEN"
L1="$TMP/case1.lock"; H1="$TMP/case1.holder"
plant_orphan "$L1" "$H1" || exit 1
if run_guard 1 20 "$L1" "$H1"; then
  echo "-> PASS: guard reaped the stale holder and acquired the lock"
else
  echo "-> FAIL: guard did NOT recover from a reapable orphan"; fail=1
fi
reap "$L1" "$H1"

echo; echo "### CASE 2  LEAKED (sweep off): same orphan must block -> RED"
L2="$TMP/case2.lock"; H2="$TMP/case2.holder"
plant_orphan "$L2" "$H2" || exit 1
if run_guard 0 5 "$L2" "$H2"; then
  echo "-> FAIL: guard acquired despite a live orphan -- sweep is not load-bearing (hollow)"; fail=1
else
  echo "-> PASS: orphan blocked acquire and it failed red, as it must without the sweep"
fi
reap "$L2" "$H2"

echo
if [ "$fail" = 0 ]; then
  echo "HONESTY GATE PASSED: perturb -> reaped -> green ; restore leak -> red"
else
  echo "HONESTY GATE FAILED"
fi
exit "$fail"
