#!/usr/bin/env bash
set -euo pipefail
# Per-host heavy-leg semaphore (VM905: up to 8 runners on a 32-core/62 GB box).
# History: a single slot (1 heavy leg per host) became the #1 CI failure mode --
# 8 runners serialized behind one flock while ~2/3 of the box sat idle, and
# waiters hard-failed at the -w budget (integrator measurement 2026-08-05). This
# guard now offers HEAVY_LEG_SLOTS concurrent slots with first-free acquisition:
# a leg takes the first free slot, so up to SLOTS heavy legs (ASan/UBSan build +
# CodeQL c-cpp analyze) run concurrently on one host and the (SLOTS+1)th WAITS --
# nothing is ever cancelled. 2 ASan/CodeQL legs fit 32c/62G comfortably; do NOT
# raise SLOTS past 3 without first measuring an ASan leg's peak RSS.
# Two holder invariants preserved from #1112:
#  (1) the holder dies WITH the job -- it waits on the runner-worker PID and
#      frees its slot the instant that worker dies; TTL is only a ceiling.
#  (2) a stale holder from an already-dead job is REAPED at acquire, not blocked
#      on: a recorded holder whose worker is gone, or a markerless PPID-1 legacy
#      orphan, is by definition dead.
# HEAVY_LEG_* env overrides exist ONLY for the honesty-gate test
# (.github/actions/heavy-leg-lock/test.sh); production uses the defaults.
LOCK="${HEAVY_LEG_LOCK:-/tmp/c2pool-heavy-leg.lock}"
HOLDERFILE="${HEAVY_LEG_HOLDERFILE:-/tmp/c2pool-heavy-leg.holder}"
WAIT="${HEAVY_LEG_WAIT:-5400}"
TTL="${HEAVY_LEG_TTL:-14400}"
SWEEP="${HEAVY_LEG_SWEEP:-1}"
SLOTS="${HEAVY_LEG_SLOTS:-2}"
ACQ="$(mktemp -u /tmp/c2pool-heavy-acq.XXXXXX)"

# Slot files are ${LOCK}.1 .. ${LOCK}.SLOTS; each slot's live holder records a
# ${HOLDERFILE}.<slot> marker ("holderpid workerpid"). Both are per-slot so two
# concurrent holders never clobber each other's marker.

# --- stale-holder sweep: reap the dead on each slot instead of blocking ---
if [ "$SWEEP" = 1 ]; then
  _s=1
  while [ "$_s" -le "$SLOTS" ]; do
    _mf="${HOLDERFILE}.${_s}"
    if [ -f "$_mf" ]; then
      read -r MH MW _ < "$_mf" 2>/dev/null || true
      if [ -n "${MW:-}" ] && [ "${MW:-0}" != 0 ] && ! kill -0 "$MW" 2>/dev/null; then
        echo "heavy-leg sweep: reaping holder pid ${MH:-?} on slot $_s (worker $MW dead)"
        [ -n "${MH:-}" ] && kill "$MH" 2>/dev/null || true
        rm -f "$_mf"
      fi
    fi
    # Markerless PPID-1 orphan on this slot = a pre-guard `sleep` holder: our live
    # holders always keep a marker, and a still-waiting new holder has a live
    # parent, so PPID==1 + no marker is unambiguously dead.
    if [ ! -f "$_mf" ] && command -v fuser >/dev/null 2>&1; then
      for _q in $(fuser "${LOCK}.${_s}" 2>/dev/null | tr -d ' '); do
        _qp="$(ps -o ppid= -p "$_q" 2>/dev/null | tr -d ' ' || true)"
        if [ "${_qp:-0}" = 1 ]; then
          echo "heavy-leg sweep: reaping markerless PPID-1 orphan pid $_q on slot $_s"
          kill "$_q" 2>/dev/null || true
        fi
      done
    fi
    _s=$((_s+1))
  done
fi

# --- find the runner-worker so the holder can die with the job ---
WORKER=""
_p=$$
while [ "${_p:-1}" -gt 1 ]; do
  case "$(ps -o comm= -p "$_p" 2>/dev/null || true)" in
    Runner.Worker*) WORKER="$_p"; break ;;
  esac
  _p="$(ps -o ppid= -p "$_p" 2>/dev/null | tr -d ' ' || true)"
  [ -z "${_p:-}" ] && break
done

# --- spawn the holder: first-free across SLOTS, holds its fd for the job's life ---
# Each slot opens on fd (8+slot); slot 1 -> fd 9 (as before). The held fd is
# closed (N>&-) in the sleep child so a kill of this bash frees the slot at once.
# The holder exits when the runner-worker dies, or at TTL, whichever is first; if
# the worker could not be found it falls back to a pure TTL ceiling.
env LOCK="$LOCK" HOLDERFILE="$HOLDERFILE" ACQ="$ACQ" WAIT="$WAIT" TTL="$TTL" SLOTS="$SLOTS" WORKER="$WORKER" \
bash -c '
  _s=1
  while [ "$_s" -le "$SLOTS" ]; do
    _fd=$((8+_s))
    eval "exec ${_fd}>\"\${LOCK}.\${_s}\"" || exit 1
    _s=$((_s+1))
  done
  _held_fd=""
  _deadline=$(( SECONDS + WAIT ))
  while [ "$SECONDS" -lt "$_deadline" ]; do
    _s=1
    while [ "$_s" -le "$SLOTS" ]; do
      _fd=$((8+_s))
      if flock -n "$_fd"; then _held_fd="$_fd"; break; fi
      _s=$((_s+1))
    done
    [ -n "$_held_fd" ] && break
    sleep 3
  done
  [ -z "$_held_fd" ] && exit 1
  _held_slot=$(( _held_fd - 8 ))
  printf "%s %s\n" "$$" "${WORKER:-0}" > "${HOLDERFILE}.${_held_slot}"
  echo "$_held_slot" > "$ACQ"
  _end=$(( SECONDS + TTL ))
  while [ "$SECONDS" -lt "$_end" ]; do
    if [ -n "$WORKER" ] && ! kill -0 "$WORKER" 2>/dev/null; then break; fi
    eval "sleep 15 ${_held_fd}>&-"
  done
  rm -f "${HOLDERFILE}.${_held_slot}"
' </dev/null >/dev/null 2>&1 &
HOLDER=$!
disown "$HOLDER" 2>/dev/null || true
echo "${HEAVY_LEG_HOLDER_ENV:-HEAVY_LEG_LOCK_HOLDER}=$HOLDER" >> "${GITHUB_ENV:-/dev/null}"

# --- wait for the acquire handshake ---
while kill -0 "$HOLDER" 2>/dev/null && [ ! -s "$ACQ" ]; do
  sleep 2
done
if [ ! -s "$ACQ" ]; then
  echo "::error::per-host heavy-leg lock: all $SLOTS slots busy for $((WAIT/60)) min on ${RUNNER_NAME:-?} -- blocked by live long holders, not this diff"
  _s=1
  while [ "$_s" -le "$SLOTS" ]; do
    echo "  slot $_s (${LOCK}.${_s}):"
    if command -v fuser >/dev/null 2>&1; then
      for _q in $(fuser "${LOCK}.${_s}" 2>/dev/null | tr -d ' '); do
        # pid ppid age(etimes,s) comm -- names the live holder blocking this slot
        echo "    holder [pid ppid age_s comm]: $(ps -o pid=,ppid=,etimes=,comm= -p "$_q" 2>/dev/null | tr -s ' ')"
      done
    fi
    if [ -f "${HOLDERFILE}.${_s}" ]; then
      echo "    marker (holderpid workerpid): $(cat "${HOLDERFILE}.${_s}" 2>/dev/null)"
    else
      echo "    marker: (none)"
    fi
    _s=$((_s+1))
  done
  exit 1
fi
_got="$(cat "$ACQ" 2>/dev/null)"
rm -f "$ACQ"
echo "heavy-leg lock acquired on ${RUNNER_NAME:-?} slot ${_got:-?}/$SLOTS (holder pid $HOLDER, worker ${WORKER:-none})"
