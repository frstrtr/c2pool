#!/usr/bin/env bash
# memguard.sh PID [MIN_MB] [INTERVAL_S]
# Stops the node PID when MemAvailable drops below MIN_MB (default 1024 MB):
# first SIGINT (clean stop: the node saves its chain index), then SIGTERM
# after 60 s, then SIGKILL after 30 s more. Exits when PID is gone.
# It only ever signals PID. It never touches any other process or service.
set -u
PID="${1:?usage: memguard.sh PID [MIN_MB] [INTERVAL_S]}"
MIN_MB="${2:-1024}"
EVERY="${3:-5}"

log() { echo "memguard[$PID]: $*" >&2; }

avail_mb() { awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo; }

log "watching, stop threshold MemAvailable < ${MIN_MB} MB (now $(avail_mb) MB)"
while kill -0 "$PID" 2>/dev/null; do
    A="$(avail_mb)"
    if [ "${A:-0}" -lt "$MIN_MB" ]; then
        log "MemAvailable ${A} MB < ${MIN_MB} MB: sending SIGINT (clean stop)"
        kill -INT "$PID" 2>/dev/null
        for _ in $(seq 60); do kill -0 "$PID" 2>/dev/null || exit 0; sleep 1; done
        log "still running after 60 s: SIGTERM"
        kill -TERM "$PID" 2>/dev/null
        for _ in $(seq 30); do kill -0 "$PID" 2>/dev/null || exit 0; sleep 1; done
        log "still running after 90 s: SIGKILL"
        kill -KILL "$PID" 2>/dev/null
        exit 0
    fi
    sleep "$EVERY"
done
exit 0
