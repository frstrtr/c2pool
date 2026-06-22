#!/usr/bin/env bash
#
# runner-watchdog-mac-intel.sh
#
# Auto-reregister watchdog for the self-hosted macOS Intel CI runner
# (macpro-intel-204, labels: self-hosted,macOS,X64,c2pool-mac-intel).
#
# WHERE THIS RUNS: the CI bridge / workstation -- NOT on the Mac node.
#   The node's launchd service already has KeepAlive(SuccessfulExit=false),
#   which restarts a *crashed runner process*. That alone cannot recover a
#   runner that GitHub has *deregistered* server-side (registration removed
#   or its auth token revoked): re-registration needs a fresh registration
#   token minted with repo-admin creds, which live here on the bridge, not
#   on the Mac node. This watchdog closes that gap.
#
# WHAT IT DOES (idempotent, non-destructive):
#   1. Polls the repo's runners API for macpro-intel-204.
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
RUNNER_NAME="${RUNNER_NAME:-macpro-intel-204}"
NODE_SSH="${NODE_SSH:-user0@192.168.86.204}"
NODE_KEY="${NODE_KEY:-$HOME/.ssh/agentmail_deploy}"
RUNNER_DIR="${RUNNER_DIR:-/Users/user0/actions-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,macOS,X64,c2pool-mac-intel}"
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
