#!/usr/bin/env bash
# ============================================================================
# Honesty gate for the per-host heavy-leg reap-guard.
#
# Extracts the ACTUAL "Acquire per-host heavy-leg lock (reap-guard)" run: script
# out of build.yml (the shipped bytes, not a copy) and drives it in isolation
# via the HEAVY_LEG_* env overrides, proving the reap is load-bearing across ALL
# HEAVY_LEG_SLOTS concurrent slots (not just one):
#
#   FIXED  (HEAVY_LEG_SWEEP=1): EVERY slot is saturated with an orphaned holder
#          whose owning job is already dead -> all are REAPED at acquire -> a
#          free slot opens -> the lock is acquired -> exit 0 (GREEN).
#   LEAKED (HEAVY_LEG_SWEEP=0): the same orphans are NOT swept -> every slot
#          stays busy -> acquire times out at the -w budget -> exit 1 (RED).
#
# If restoring the leak did NOT turn it red the test FAILS: that would mean the
# guard acquired despite live orphans on every slot -- a hollow sweep. Saturating
# all SLOTS is what keeps this load-bearing under the multi-slot semaphore: a
# single free slot would let acquire pass without reaping anything.
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WF="$ROOT/.github/workflows/build.yml"
STEP="Acquire per-host heavy-leg lock (reap-guard)"
SLOTS="${SLOTS:-2}"   # must match the guard's production HEAVY_LEG_SLOTS default

TMP="$(mktemp -d)"
cleanup() {
  [ "${BASHPID:-$$}" = "$$" ] || return 0   # never run inside a $(...) subshell
  for lk in "$TMP"/case*.lock.*; do
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

# Plant a holder whose owning job is already dead on ONE slot: a marker pointing
# at a worker PID that no longer exists (exactly what a host-reaped job leaves).
# Single process (exec sleep) holding the exclusive flock, so a kill of it frees
# the slot at once -- same shape as the old `exec sleep 14400` holder.
plant_orphan() {  # $1 slot-lockpath  $2 slot-markerpath
  local lock="$1" marker="$2"
  ( exit 0 ) & local deadworker=$!
  wait "$deadworker" 2>/dev/null || true
  setsid bash -c 'exec 9>"'"$lock"'"; flock -x 9 || exit 1; exec sleep 300' \
    </dev/null >/dev/null 2>&1 &
  local orphan=$!
  printf '%s %s\n' "$orphan" "$deadworker" > "$marker"
  local i
  for ((i=0;i<100;i++)); do
    flock -n -x "$lock" -c true 2>/dev/null || return 0   # held -> orphan is up
    sleep 0.1
  done
  echo "FATAL: orphan never took the lock $lock"; return 1
}

# Saturate every slot: ${base}.1 .. ${base}.SLOTS with a dead-owner orphan each.
saturate() {  # $1 lock-base  $2 marker-base
  local s
  for ((s=1;s<=SLOTS;s++)); do
    plant_orphan "$1.$s" "$2.$s" || return 1
  done
}

run_guard() {  # $1 sweep(0/1)  $2 wait(s)  $3 lock-base  $4 marker-base
  HEAVY_LEG_LOCK="$3" HEAVY_LEG_HOLDERFILE="$4" \
  HEAVY_LEG_WAIT="$2" HEAVY_LEG_TTL=3 HEAVY_LEG_SWEEP="$1" HEAVY_LEG_SLOTS="$SLOTS" \
  RUNNER_NAME="honesty-test" GITHUB_ENV="$TMP/genv" \
  bash "$ACQ_SH"
}

reap() {  # $1 lock-base  $2 marker-base
  local s
  for ((s=1;s<=SLOTS;s++)); do
    [ -f "$2.$s" ] && awk '{print $1}' "$2.$s" | xargs -r kill 2>/dev/null || true
    fuser -k "$1.$s" 2>/dev/null || true
  done
  sleep 0.3 || true
}

fail=0

echo; echo "### CASE 1  FIXED (sweep on): all $SLOTS slots saturated -> orphans reaped -> GREEN"
L1="$TMP/case1.lock"; H1="$TMP/case1.holder"
saturate "$L1" "$H1" || exit 1
if run_guard 1 20 "$L1" "$H1"; then
  echo "-> PASS: guard reaped the stale holders on every slot and acquired the lock"
else
  echo "-> FAIL: guard did NOT recover from reapable orphans saturating all slots"; fail=1
fi
reap "$L1" "$H1"

echo; echo "### CASE 2  LEAKED (sweep off): same saturation must block -> RED"
L2="$TMP/case2.lock"; H2="$TMP/case2.holder"
saturate "$L2" "$H2" || exit 1
if run_guard 0 5 "$L2" "$H2"; then
  echo "-> FAIL: guard acquired despite live orphans on every slot -- sweep is not load-bearing (hollow)"; fail=1
else
  echo "-> PASS: orphans blocked every slot and acquire failed red, as it must without the sweep"
fi
reap "$L2" "$H2"

echo
if [ "$fail" = 0 ]; then
  echo "HONESTY GATE PASSED: perturb -> reaped -> green ; restore leak -> red"
else
  echo "HONESTY GATE FAILED"
fi
exit "$fail"
