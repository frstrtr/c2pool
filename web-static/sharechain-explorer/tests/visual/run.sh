#!/usr/bin/env bash
# Orchestrator: generate fixtures → start mock server → capture →
# diff → stop server. Idempotent; safe to re-run.

set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-18082}"
THRESHOLD="${THRESHOLD:-0.025}"
# Bounded health-poll budget before puppeteer is allowed to navigate.
# The mock server can bind slowly on a CPU-starved self-hosted runner
# (VM905), so a too-short wait races the server start and puppeteer hits
# a dead port (net::ERR_CONNECTION_REFUSED, job 89644021788) — an infra
# flake wrongly surfaced as a page/pixel assertion failure. 60s covers
# cold-start jitter without masking a genuinely-hung server.
READY_TIMEOUT="${READY_TIMEOUT:-60}"
HEALTH_URL="http://127.0.0.1:${PORT}/sharechain/tip"

mkdir -p out

echo "[1/4] generating fixtures"
node fixtures/generate.mjs

echo "[2/4] starting mock server on :$PORT"
node mock-server.mjs "$PORT" >out/mock-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Health-poll until the server answers, bounded by READY_TIMEOUT, and
# GATE the navigate on the result. If the port never comes up we fail
# loudly with a distinguishable infra message (not a page assertion) so
# a real regression is never confused with a server-start race. Also
# bail early if the server process died (e.g. port already in use).
echo "[2b] waiting up to ${READY_TIMEOUT}s for mock server at ${HEALTH_URL}"
start=$SECONDS
deadline=$((start + READY_TIMEOUT))
ready=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "::error::INFRA (not a page regression): mock server pid $SERVER_PID exited before binding :$PORT" >&2
    break
  fi
  if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    ready=1
    echo "mock server ready after $((SECONDS - start))s"
    break
  fi
  sleep 0.5
done
if [ "$ready" -ne 1 ]; then
  echo "::error::INFRA (not a page regression): static mock server never became ready on 127.0.0.1:${PORT} within ${READY_TIMEOUT}s — puppeteer navigation skipped so a server-start race is not reported as a page-assertion failure." >&2
  echo "---- tail of out/mock-server.log ----" >&2
  tail -n 40 out/mock-server.log >&2 || true
  exit 3
fi

echo "[3/4] capturing screenshots"
node capture.mjs "$PORT"

echo "[4/4] diffing"
node diff.mjs "$THRESHOLD"
