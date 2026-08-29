#!/usr/bin/env bash
#
# runner-orphan-reaper-linux.sh
#
# Detect and reap ORPHANED build trees on a self-hosted Linux CI runner host.
#
# THE FAILURE IT GUARDS (observed on 192.168.86.198, 2026-08-02):
#   A Runner.Worker died mid-job at a ~10-min zero-step with no logs. Its
#   build children (cmake / make / cc1plus / cc / c++) were reparented to
#   ppid=1 and kept running, pegging load ~8 and starving every other runner
#   on the pool. Manual reap-by-hand does not scale across the .198 / VM905 /
#   198-2 / 198-3 pattern, so this runs unattended on each host.
#
# WHY ppid=1 IS THE SIGNAL (not "no Runner.Worker anywhere on the host"):
#   A LEGIT build compiler always has a live Runner.Worker as an ANCESTOR.
#   When the Worker dies, the kernel reparents its orphaned descendants to
#   pid 1 (init) -- there is no subreaper in the runner process tree. So a
#   build-toolchain process whose parent is pid 1 has, by construction, no
#   Worker ancestor: it is orphaned. This is the precise disqualifier, and
#   it is safe on MULTI-RUNNER hosts (VM905 runs 8 runners): other runners
#   can be mid-build with live Workers -- their compilers are NOT ppid=1, so
#   they are never candidates. Gating on "no Runner.Worker exists on the
#   host" (the loose phrasing) would refuse to ever fire on a busy pool;
#   the ppid=1 ancestor test is correct there. An age floor (>15 min) is
#   layered on as belt-and-suspenders against a just-reparented transient.
#
# ACTION on a confirmed orphan root: kill -STOP the root (freeze it so it
#   spawns no more children), enumerate the full descendant set, SIGKILL the
#   descendants, then SIGKILL the root. Every kill is logged to the journal
#   and appended to a machine-parseable spool (REAP_SPOOL) that ci-steward
#   tails each heartbeat to alert decisions@ (recurrence tracking). If a
#   local mailer is configured (REAP_ALERT_MAILTO + mail/sendmail present)
#   the alert is ALSO sent inline.
#
# HARD RULE: never touch a tree that has a live Runner.Worker ancestor.
#   Enforced by the ppid=1 test + an explicit ancestor walk before any kill.
#
# SAFE REHEARSAL:  runner-orphan-reaper-linux.sh --dry-run
#   Prints exactly what WOULD be reaped and exits without signalling anything.
#
# REVERT: disable the timer and delete this file. It makes no persistent
#   change to the host beyond killing the orphaned processes it reports.
#
set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# --- tunables (env-overridable; defaults match the observed .198 incident) ---
# comm values of build-toolchain leaders we consider (ps comm, 15-char max).
REAP_COMM_RE="${REAP_COMM_RE:-^(cmake|gmake|make|cc1plus|cc1|cc|c\+\+)$}"
# cwd/argv must match this to be a CI build tree. Defaults to the CodeQL build
# dir from the incident; widen to '_work/.*/build' to cover all CI builds.
REAP_PATH_RE="${REAP_PATH_RE:-_work/.*/build}"
# orphan-root parent pid. Kernel reparents orphans to 1 (init); no subreaper
# sits in the runner tree. Override only if a host installs a subreaper.
REAP_ROOT_PPID="${REAP_ROOT_PPID:-1}"
# age floor in seconds (belt-and-suspenders vs a just-reparented transient).
REAP_MIN_AGE="${REAP_MIN_AGE:-900}"
REAP_SPOOL="${REAP_SPOOL:-$HOME/.local/state/runner-orphan-reaper/reaped.jsonl}"
REAP_ALERT_MAILTO="${REAP_ALERT_MAILTO:-}"   # empty => journal + spool only
HOST="$(hostname -s 2>/dev/null || hostname)"

log() { printf '%s [orphan-reaper:%s] %s\n' "$(date -u +%FT%TZ)" "$HOST" "$*"; }

# Walk PID -> pid 1. Return 0 if a Runner.Worker is found as an ancestor.
has_worker_ancestor() {
  local pid="$1" ppid comm
  while [ -n "$pid" ] && [ "$pid" -gt 1 ]; do
    read -r ppid comm < <(ps -o ppid=,comm= -p "$pid" 2>/dev/null || true)
    [ -z "${ppid:-}" ] && break
    case "$comm" in Runner.Worker*) return 0 ;; esac
    pid="$ppid"
  done
  return 1
}

# All descendant pids of $1, deepest-last (BFS over the ppid map snapshot).
descendants() {
  local root="$1" queue="$1" out="" p child
  # snapshot pid<space>ppid once so the tree does not shift under us
  local map; map="$(ps -eo pid=,ppid=)"
  while [ -n "$queue" ]; do
    p="${queue%% *}"; queue="${queue#$p}"; queue="${queue# }"
    while read -r pid ppid; do
      [ "$ppid" = "$p" ] || continue
      out="$out $pid"; queue="$queue $pid"
    done <<< "$map"
  done
  echo "$out"
}

emit_alert() {
  local root="$1" comm="$2" age="$3" cwd="$4" nkilled="$5" mode="$6"
  local ts; ts="$(date -u +%FT%TZ)"
  mkdir -p "$(dirname "$REAP_SPOOL")"
  # hand-built JSON (no jq dependency on the runner host)
  printf '{"ts":"%s","host":"%s","action":"%s","root_pid":%s,"comm":"%s","age_s":%s,"cwd":"%s","descendants_killed":%s}\n' \
    "$ts" "$HOST" "$mode" "$root" "$comm" "$age" "$cwd" "$nkilled" >> "$REAP_SPOOL"
  local subject body
  subject="[reap] orphaned CI build reaped on ${HOST} (pid ${root} ${comm})"
  body=$(printf 'host=%s\nmode=%s\nroot_pid=%s comm=%s age_s=%s\ncwd=%s\ndescendants_killed=%s\nspool=%s\n' \
    "$HOST" "$mode" "$root" "$comm" "$age" "$cwd" "$nkilled" "$REAP_SPOOL")
  log "ALERT $subject"
  printf '%s\n\n%s\n' "$subject" "$body" | systemd-cat -t runner-orphan-reaper -p warning 2>/dev/null || true
  if [ -n "$REAP_ALERT_MAILTO" ]; then
    if command -v mail >/dev/null 2>&1; then
      printf '%s\n' "$body" | mail -s "$subject" "$REAP_ALERT_MAILTO" 2>/dev/null \
        && log "alert mailed to $REAP_ALERT_MAILTO" || log "WARN inline mail failed; spool retained"
    elif command -v sendmail >/dev/null 2>&1; then
      { printf 'To: %s\nSubject: %s\n\n%s\n' "$REAP_ALERT_MAILTO" "$subject" "$body"; } \
        | sendmail -t 2>/dev/null && log "alert sendmail'd to $REAP_ALERT_MAILTO" \
        || log "WARN inline sendmail failed; spool retained"
    else
      log "no local mailer; alert left on spool for ci-steward heartbeat forward"
    fi
  fi
}

reap_one() {
  local root="$1" comm="$2" age="$3" cwd="$4"
  # FINAL safety gate before any signal: refuse if a Worker ancestor exists.
  if has_worker_ancestor "$root"; then
    log "SKIP pid=$root ($comm): live Runner.Worker ancestor -- NOT an orphan"
    return 0
  fi
  local kids; kids="$(descendants "$root")"
  local nkids; nkids="$(printf '%s\n' $kids | grep -c . || true)"
  if [ "$DRY_RUN" = 1 ]; then
    log "DRY-RUN would reap root=$root ($comm) age=${age}s cwd=$cwd descendants=[$kids ]"
    return 0
  fi
  log "REAP root=$root ($comm) age=${age}s cwd=$cwd descendants_count=$nkids"
  kill -STOP "$root" 2>/dev/null || true      # freeze the root: no new children
  # shellcheck disable=SC2086
  [ -n "$kids" ] && kill -KILL $kids 2>/dev/null || true
  kill -KILL "$root" 2>/dev/null || true
  emit_alert "$root" "$comm" "$age" "$cwd" "$nkids" "reap"
}

main() {
  local found=0
  # pid ppid etimes comm  -- filter to ppid==ROOT_PPID, comm in set, age>=floor
  while read -r pid ppid etimes comm; do
    [ "$ppid" = "$REAP_ROOT_PPID" ] || continue
    [[ "$comm" =~ $REAP_COMM_RE ]] || continue
    [ "${etimes:-0}" -ge "$REAP_MIN_AGE" ] || continue
    # cwd (symlink) OR argv must sit under the CI build path.
    local cwd cmd hay
    cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    cmd="$(tr "\0" " " < "/proc/$pid/cmdline" 2>/dev/null || true)"
    hay="$cwd $cmd"
    [[ "$hay" =~ $REAP_PATH_RE ]] || continue
    found=$((found + 1))
    reap_one "$pid" "$comm" "$etimes" "${cwd:-?}"
  done < <(ps -eo pid=,ppid=,etimes=,comm=)
  [ "$found" = 0 ] && log "clean: no orphaned CI build trees (ppid=$REAP_ROOT_PPID, path~$REAP_PATH_RE)"
  return 0
}

main "$@"
