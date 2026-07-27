#!/usr/bin/env bash
#
# runner-watchdog-mac-arm.sh
#
# Auto-reregister watchdog for the self-hosted macOS Apple Silicon CI runner
# (Mac-mini-Alonso-227, labels: self-hosted,macOS,ARM64,c2pool-mac-arm).
#
# WHERE THIS RUNS: the CI bridge / workstation -- NOT on the Mac node.
#   The node's launchd service already has KeepAlive(SuccessfulExit=false),
#   which restarts a *crashed runner process*. That alone cannot recover a
#   runner that GitHub has *deregistered* server-side (registration removed
#   or its auth token revoked): re-registration needs a fresh registration
#   token minted with repo-admin creds, which live here on the bridge, not
#   on the Mac node. This watchdog closes that gap.
#
#   Sibling of runner-watchdog-mac-intel.sh. arm64 is a REQUIRED release leg
#   (the macOS universal package lipo-merges the arm64 + x86_64 binaries), so
#   the Apple Silicon node needs the same self-heal the Intel node already
#   has -- an unattended arm64 drop must not block a release.
#
# WHAT IT DOES (idempotent, non-destructive):
#   1. Polls the repo's runners API for Mac-mini-Alonso-227.
#   2. If the runner is absent or "offline" for >= THRESHOLD consecutive
#      checks, mints a fresh registration token and re-registers the runner
#      over SSH using `config.sh --replace` (no delete; --replace reuses the
#      same name), then reloads the launchd service.
#   3. Resets the failure counter as soon as the runner is seen online.
#
# REVERT: delete this file + remove its launchd/cron entry on the bridge.
#   It never deletes the runner; --replace is the only mutation it makes.
#
set -euo pipefail

REPO="${C2POOL_REPO:-frstrtr/c2pool}"
RUNNER_NAME="${RUNNER_NAME:-Mac-mini-Alonso-227}"
NODE_SSH="${NODE_SSH:-user0@192.168.86.227}"
NODE_KEY="${NODE_KEY:-$HOME/.ssh/id_ed25519}"
RUNNER_DIR="${RUNNER_DIR:-/Users/user0/actions-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,macOS,ARM64,c2pool-mac-arm}"
SVC_LABEL="actions.runner.frstrtr-c2pool.${RUNNER_NAME}"

# Re-register only after this many consecutive offline observations, so a
# single transient blip (job restart, brief network drop) does not trigger
# a churn. With a 5-min poll, 3 == ~15 min sustained offline.
THRESHOLD="${THRESHOLD:-3}"
STATE_FILE="${STATE_FILE:-$HOME/.cache/c2pool-runner-watchdog/${RUNNER_NAME}.fails}"

log() { printf '%s [runner-watchdog:%s] %s\n' "$(date -u +%FT%TZ)" "$RUNNER_NAME" "$*"; }

mkdir -p "$(dirname "$STATE_FILE")"
fails=$(cat "$STATE_FILE" 2>/dev/null || echo 0)

# Status as GitHub sees it: "online" | "offline" | "absent".
status=$(gh api "repos/${REPO}/actions/runners" \
  --jq ".runners[] | select(.name==\"${RUNNER_NAME}\") | .status" 2>/dev/null || true)
[ -z "$status" ] && status="absent"

if [ "$status" = "online" ]; then
  [ "$fails" -ne 0 ] && log "back online; clearing fail counter ($fails -> 0)"
  echo 0 > "$STATE_FILE"
  exit 0
fi

fails=$((fails + 1))
echo "$fails" > "$STATE_FILE"
log "status=${status} consecutive_fails=${fails}/${THRESHOLD}"
[ "$fails" -lt "$THRESHOLD" ] && exit 0

log "threshold reached -> re-registering"
TOKEN=$(gh api --method POST "repos/${REPO}/actions/runners/registration-token" --jq .token)
[ -z "$TOKEN" ] && { log "ERROR: empty registration token"; exit 1; }

ssh -i "$NODE_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "$NODE_SSH" bash -s <<EOF
set -e
cd "${RUNNER_DIR}"
./svc.sh stop || true
./config.sh remove --token "${TOKEN}" || true
./config.sh --unattended --replace \
  --url "https://github.com/${REPO}" \
  --token "${TOKEN}" \
  --name "${RUNNER_NAME}" \
  --labels "${RUNNER_LABELS}"
./svc.sh start
EOF

log "re-registration issued; clearing fail counter"
echo 0 > "$STATE_FILE"
