#!/usr/bin/env bash
# Orchestrator: generate fixtures → start mock server → capture →
# diff → stop server. Idempotent; safe to re-run.

set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-18082}"
THRESHOLD="${THRESHOLD:-0.005}"

echo "[1/4] generating fixtures"
node fixtures/generate.mjs

echo "[2/4] starting mock server on :$PORT"
node mock-server.mjs "$PORT" >out/mock-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
# Wait for server to bind.
for i in {1..30}; do
  if curl -sf "http://127.0.0.1:$PORT/sharechain/tip" >/dev/null; then break; fi
  sleep 0.2
done

echo "[3/4] capturing screenshots"
node capture.mjs "$PORT"

echo "[4/4] diffing"
node diff.mjs "$THRESHOLD"
