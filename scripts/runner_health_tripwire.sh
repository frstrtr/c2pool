#!/usr/bin/env bash
# runner_health_tripwire.sh — self-hosted runner active-but-offline detector.
#
# Failure mode this catches (invisible to every existing check): a runner
# whose systemd unit is active on its host but which GitHub reports OFFLINE
# — a "zombie listener" (Runner.Listener alive but its HTTP/2 uplink to
# GitHub is dead). The host looks healthy locally and the service is
# "running", so nothing flags it; the runner simply never picks up jobs and
# CI silently queues or goes slow until someone notices by hand. Observed on
# c2pool-linux-905-4/-7/-8 and the 198-2/198-3 uplink signature.
#
# Mechanism: compare each runner GitHub-reported status against its host
# systemd state and report the DISAGREEMENT.
#
#   systemd active  + GitHub online   -> healthy        (quiet)
#   systemd active  + GitHub OFFLINE  -> ZOMBIE LISTENER (FIRE)
#   systemd inactive+ GitHub offline  -> legitimately down (quiet, expected)
#   systemd inactive+ GitHub online   -> draining/transient (note, no fire)
#   host unreachable                  -> unknown          (quiet — never
#                                        false-fire on an SSH-dead host)
#
# Runs on the BRIDGE VM (systemd timer), NOT on vm905 and NOT gh-hosted: it
# needs each host systemd truth, which the GitHub API cannot see and a
# gh-hosted runner cannot reach. It issues only `systemctl is-active` over
# SSH — zero build load on any runner host, safe during a P0 soak. Fix for a
# fired runner is `systemctl restart <unit>` (or reap RunnerService.js host
# for a stubborn one); this only DETECTS.
set -uo pipefail

REPO="${REPO:-frstrtr/c2pool}"
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=8 -o BatchMode=yes}"

# Map a runner name to the SSH target that owns its systemd unit. Prefixes
# are stable (name encodes host). Non-Linux runners have no systemd unit of
# this shape and are skipped. Keep this the ONLY host-specific knowledge.
host_for() {
  case "$1" in
    c2pool-linux-905*)         echo "vm905" ;;
    c2pool-linux-198-*)        echo "workstation" ;;   # the .198 host
    c2pool-linux-196-*)        echo "user0@192.168.86.196" ;;
    oplex7020-heavy-*)         echo "oplex7020" ;;
    *)                          echo "" ;;              # skip (win/mac/unknown)
  esac
}

ssh_id_for() {  # extra ssh opts for hosts that need a specific key
  case "$1" in
    *192.168.86.196) echo "-i $HOME/.ssh/agentmail_deploy" ;;
    *)               echo "" ;;
  esac
}

probe_systemd() {  # host unit -> prints active|inactive|unreachable
  local host="$1" unit="$2" out
  # -n: never read the loop stdin (a live ssh would eat the runner list).
  out=$(timeout 15 ssh -n $SSH_OPTS $(ssh_id_for "$host") "$host" \
          "systemctl is-active $unit" 2>/dev/null) \
    || { [ -n "$out" ] && { echo "$out"; return; }; echo "unreachable"; return; }
  echo "${out:-unreachable}"
}

# Sole decision point: (systemd_state, github_status) -> verdict token.
# Both the live loop and --selftest route through this, so the guard proves
# the exact code that fires in production.
classify() {  # sysd gh -> FIRE|OK|DOWN|NOTE|SKIP
  case "$1:$2" in
    active:offline)                   echo FIRE ;;   # zombie listener
    active:online)                    echo OK   ;;   # healthy
    inactive:offline|failed:offline)  echo DOWN ;;   # legitimately down
    inactive:online|failed:online)    echo NOTE ;;   # draining/transient
    unreachable:*)                    echo SKIP ;;   # cannot confirm -> no fire
    *)                                echo NOTE ;;
  esac
}

# --selftest: falsifiable guard. Proves FIRE on a zombie tuple and silence
# on healthy/down tuples WITHOUT touching a live runner. Exits non-zero if
# the fire path ever regresses (e.g. a zombie stops being flagged).
if [ "${1:-}" = "--selftest" ]; then
  fail=0
  check() { got=$(classify "$1" "$2"); [ "$got" = "$3" ] \
    && echo "ok    ($1,$2) -> $got" \
    || { echo "FAIL  ($1,$2) -> $got, want $3"; fail=1; }; }
  check active      offline FIRE   # the invisible failure MUST fire
  check active      online  OK     # healthy MUST stay quiet
  check inactive    offline DOWN   # legit-down MUST stay quiet
  check unreachable offline SKIP   # SSH-dead host MUST NOT false-fire
  check inactive    online  NOTE
  [ "$fail" -eq 0 ] && echo "selftest: PASS" || echo "selftest: FAIL"
  exit "$fail"
fi

fired=0; checked=0
while IFS=$'\t' read -r name gh_status; do
  host=$(host_for "$name"); [ -n "$host" ] || continue
  checked=$((checked+1))
  unit="actions.runner.frstrtr-c2pool.${name}.service"
  sysd=$(probe_systemd "$host" "$unit")
  case "$(classify "$sysd" "$gh_status")" in
    FIRE)
      echo "FIRE  zombie-listener  $name  (systemd=active, github=offline, host=$host) -> systemctl restart $unit"
      fired=$((fired+1)) ;;
    OK|DOWN) : ;;                                            # healthy / legit-down, quiet
    NOTE)    echo "NOTE  $name  (systemd=$sysd, github=$gh_status)" ;;
    SKIP)    echo "SKIP  host-unreachable  $name  (host=$host, github=$gh_status)" ;;
  esac
done < <(gh api "/repos/$REPO/actions/runners" --paginate \
           -q ".runners[] | [.name, .status] | @tsv")

echo "runner_health_tripwire: checked=$checked fired=$fired"
[ "$fired" -eq 0 ] || exit 1
