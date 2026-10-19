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
npass=0
nfail=0
ok()  { echo "-> PASS: $*"; npass=$((npass+1)); }
bad() { echo "-> FAIL: $*"; nfail=$((nfail+1)); fail=1; }

# Never consult the real ~/.config/c2pool-ci of whoever runs this: every case
# below reads its slot override from a sandbox dir (empty unless a case plants one).
export HEAVY_LEG_CONFIG_DIR="$TMP/cfg-none"
mkdir -p "$HEAVY_LEG_CONFIG_DIR"

echo; echo "### CASE 1  FIXED (sweep on): all $SLOTS slots saturated -> orphans reaped -> GREEN"
L1="$TMP/case1.lock"; H1="$TMP/case1.holder"
saturate "$L1" "$H1" || exit 1
if run_guard 1 20 "$L1" "$H1"; then
  ok "guard reaped the stale holders on every slot and acquired the lock"
else
  bad "guard did NOT recover from reapable orphans saturating all slots"
fi
reap "$L1" "$H1"

echo; echo "### CASE 2  LEAKED (sweep off): same saturation must block -> RED"
L2="$TMP/case2.lock"; H2="$TMP/case2.holder"
saturate "$L2" "$H2" || exit 1
if run_guard 0 5 "$L2" "$H2"; then
  bad "guard acquired despite live orphans on every slot -- sweep is not load-bearing (hollow)"
else
  ok "orphans blocked every slot and acquire failed red, as it must without the sweep"
fi
reap "$L2" "$H2"

echo; echo "### acquire.sh (composite-action body used by the SLOTS=1 disk semaphore)"
# The disk semaphore reuses the SAME reap-guard logic via .github/actions/heavy-leg-lock.
# Gate it at SLOTS=1 (its production slot count) so a hollow sweep there is caught too,
# and prove the holder-env override lands the pid under the requested var name.
ACQ2="$ROOT/.github/actions/heavy-leg-lock/acquire.sh"
[ -s "$ACQ2" ] || { echo "FATAL: missing $ACQ2"; exit 2; }
run_disk() {  # $1 sweep(0/1)  $2 wait(s)  $3 lock-base  $4 marker-base
  HEAVY_LEG_LOCK="$3" HEAVY_LEG_HOLDERFILE="$4" \
  HEAVY_LEG_WAIT="$2" HEAVY_LEG_TTL=3 HEAVY_LEG_SWEEP="$1" HEAVY_LEG_SLOTS=1 \
  HEAVY_LEG_HOLDER_ENV=HEAVY_DISK_LOCK_HOLDER \
  RUNNER_NAME="honesty-test-disk" GITHUB_ENV="$TMP/genv-disk" \
  bash "$ACQ2"
}
disk_reap() {  # $1 marker  $2 lock
  [ -f "$1" ] && awk '{print $1}' "$1" | xargs -r kill 2>/dev/null || true
  fuser -k "$2" 2>/dev/null || true
  sleep 0.3 || true
}

echo; echo "### CASE 3  DISK FIXED (sweep on, SLOTS=1): sole slot saturated -> reaped -> GREEN"
L3="$TMP/case3.lock"; H3="$TMP/case3.holder"
SLOTS=1 plant_orphan "$L3.1" "$H3.1" || exit 1
rm -f "$TMP/genv-disk"
if run_disk 1 20 "$L3" "$H3"; then
  ok "disk semaphore reaped the stale holder and acquired slot 1"
  if grep -q ^HEAVY_DISK_LOCK_HOLDER= "$TMP/genv-disk" 2>/dev/null; then
    ok "holder pid exported under HEAVY_DISK_LOCK_HOLDER"
  else
    bad "holder-env override did not export HEAVY_DISK_LOCK_HOLDER"
  fi
else
  bad "disk semaphore did NOT recover from a reapable orphan on its sole slot"
fi
disk_reap "$H3.1" "$L3.1"

echo; echo "### CASE 4  DISK LEAKED (sweep off, SLOTS=1): saturation must block -> RED"
L4="$TMP/case4.lock"; H4="$TMP/case4.holder"
SLOTS=1 plant_orphan "$L4.1" "$H4.1" || exit 1
if run_disk 0 5 "$L4" "$H4"; then
  bad "disk semaphore acquired despite a live orphan on its sole slot -- hollow sweep"
else
  ok "orphan blocked the sole slot and acquire failed red without the sweep"
fi
disk_reap "$H4.1" "$L4.1"

# ----------------------------------------------------------------------------
# Per-host slot-count override (${HOME}/.config/c2pool-ci/<lock basename>.slots).
# Every case below drives the composite acquire.sh with the disk semaphore's
# production input (slots=1) and proves the slot count BEHAVIOURALLY: how many
# holders get in concurrently, and that the next one waits.
# ----------------------------------------------------------------------------
# $1 lock-base  $2 marker-base  $3 wait(s)  $4 GITHUB_ENV file ; extra env via caller
run_slot() {
  HEAVY_LEG_LOCK="$1" HEAVY_LEG_HOLDERFILE="$2" \
  HEAVY_LEG_WAIT="$3" HEAVY_LEG_TTL=90 HEAVY_LEG_SWEEP=1 HEAVY_LEG_SLOTS=1 \
  RUNNER_NAME="honesty-test-override" GITHUB_ENV="$4" \
  bash "$ACQ2"
}
holder_of() { sed -n 's/^HEAVY_LEG_LOCK_HOLDER=//p' "$1" 2>/dev/null | tail -1; }
drop() {  # $1 GITHUB_ENV file of the holder to release
  local h; h="$(holder_of "$1")"
  [ -n "$h" ] && kill "$h" 2>/dev/null || true
  sleep 0.5 || true
}
drop_all() {  # $1 lock-base
  local lk
  for lk in "$1".*; do [ -e "$lk" ] && fuser -k "$lk" >/dev/null 2>&1 || true; done
  sleep 0.3 || true
}

echo; echo "### CASE 5  OVERRIDE ABSENT: no file for this lock -> input slots=1, a 2nd holder waits"
L5="$TMP/case5.lock"; H5="$TMP/case5.holder"; C5="$TMP/cfg5"
mkdir -p "$C5"
# A file for a DIFFERENT lock basename must not leak onto this one.
echo 3 > "$C5/c2pool-heavy-leg.lock.slots"
if HEAVY_LEG_CONFIG_DIR="$C5" run_slot "$L5" "$H5" 10 "$TMP/g5a" > "$TMP/c5a.log" 2>&1; then
  ok "CASE 5: first holder acquired"
else
  bad "CASE 5: first holder failed to acquire"
fi
grep -q "slots=1 (source: action input)" "$TMP/c5a.log" \
  && ok "CASE 5: logs slots=1 from the action input" || bad "CASE 5: source line missing/wrong: $(grep slots= "$TMP/c5a.log")"
if HEAVY_LEG_CONFIG_DIR="$C5" run_slot "$L5" "$H5" 3 "$TMP/g5b" > "$TMP/c5b.log" 2>&1; then
  bad "CASE 5: a 2nd holder got in with no override -- slot count is not 1"
else
  ok "CASE 5: 2nd holder blocked (1 slot), exactly as today"
fi
drop_all "$L5"

echo; echo "### CASE 6  OVERRIDE=2 at \${HOME}/.config/c2pool-ci: two holders run concurrently, a third waits"
L6="$TMP/case6.lock"; H6="$TMP/case6.holder"; HOME6="$TMP/home6"
mkdir -p "$HOME6/.config/c2pool-ci"
printf '# two ASan build trees fit this host\n2\n' > "$HOME6/.config/c2pool-ci/case6.lock.slots"
# Production path: no HEAVY_LEG_CONFIG_DIR, lookup derives from $HOME.
run6() { ( unset HEAVY_LEG_CONFIG_DIR; HOME="$HOME6" run_slot "$@" ); }
if run6 "$L6" "$H6" 10 "$TMP/g6a" > "$TMP/c6a.log" 2>&1; then ok "CASE 6: holder A acquired"; else bad "CASE 6: holder A failed"; fi
if run6 "$L6" "$H6" 10 "$TMP/g6b" > "$TMP/c6b.log" 2>&1; then ok "CASE 6: holder B acquired concurrently with A"; else bad "CASE 6: holder B blocked -- override not honoured"; fi
grep -q "slots=2 (source: host override $HOME6/.config/c2pool-ci/case6.lock.slots)" "$TMP/c6a.log" \
  && ok "CASE 6: logs slots=2 from the host override file" || bad "CASE 6: source line missing/wrong: $(grep slots= "$TMP/c6a.log")"
grep -q "slot 1/2" "$TMP/c6a.log" && grep -q "slot 2/2" "$TMP/c6b.log" \
  && ok "CASE 6: A and B hold distinct slots 1/2 and 2/2" || bad "CASE 6: unexpected slot numbers: $(grep -h acquired "$TMP/c6a.log" "$TMP/c6b.log")"
run6 "$L6" "$H6" 30 "$TMP/g6c" > "$TMP/c6c.log" 2>&1 &
C6PID=$!
sleep 5
if kill -0 "$C6PID" 2>/dev/null && ! grep -q "lock acquired" "$TMP/c6c.log"; then
  ok "CASE 6: third holder C is WAITING while both slots are held"
else
  bad "CASE 6: third holder C did not wait: $(cat "$TMP/c6c.log")"
fi
drop "$TMP/g6a"   # free A's slot -> C must now get in (it waits, it is not failed)
if wait "$C6PID"; then
  ok "CASE 6: C acquired as soon as A released ($(grep -o 'slot [0-9]*/[0-9]*' "$TMP/c6c.log"))"
else
  bad "CASE 6: C failed after a slot was freed: $(tail -3 "$TMP/c6c.log")"
fi
drop_all "$L6"

echo; echo "### CASE 7  OVERRIDE INVALID: falls back to input slots=1 with a warning"
n7=0
for v in abc 0 -1 1.5 99 007 ''; do
  n7=$((n7+1))
  L7="$TMP/case7-$n7.lock"; H7="$TMP/case7-$n7.holder"; C7="$TMP/cfg7-$n7"
  mkdir -p "$C7"; printf '%s\n' "$v" > "$C7/case7-$n7.lock.slots"
  if HEAVY_LEG_CONFIG_DIR="$C7" run_slot "$L7" "$H7" 10 "$TMP/g7a-$n7" > "$TMP/c7a-$n7.log" 2>&1 \
     && grep -q "::warning::heavy-leg lock: ignoring host slot override" "$TMP/c7a-$n7.log" \
     && grep -q "slots=1 (source: action input)" "$TMP/c7a-$n7.log"; then
    ok "CASE 7: value '$v' ignored with a warning, input slots=1 used"
  else
    bad "CASE 7: value '$v' not handled: $(cat "$TMP/c7a-$n7.log")"
  fi
  if [ "$v" = abc ]; then
    if HEAVY_LEG_CONFIG_DIR="$C7" run_slot "$L7" "$H7" 3 "$TMP/g7b-$n7" > "$TMP/c7b-$n7.log" 2>&1; then
      bad "CASE 7: 2nd holder got in under an invalid override -- fallback is not 1 slot"
    else
      ok "CASE 7: 2nd holder blocked under invalid override (fallback really is 1 slot)"
    fi
  fi
  drop_all "$L7"
done

echo
echo "RESULT: ${npass} passed, ${nfail} failed"
if [ "$fail" = 0 ]; then
  echo "HONESTY GATE PASSED: perturb -> reaped -> green ; restore leak -> red ; slot override honoured/ignored as specified"
else
  echo "HONESTY GATE FAILED"
fi
exit "$fail"
