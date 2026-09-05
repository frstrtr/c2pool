#!/usr/bin/env bash
# Shared gate helper: make an unreachable Conan remote NON-FATAL.
#
# Why: every gate resolves deps with `conan install --build=missing`, which
# contacts EVERY enabled remote. A secondary/unneeded remote that is merely
# unreachable (read-timeout, DNS failure, connection refused) then aborts the
# whole install with a nonzero exit BEFORE the gate body runs — a determinism
# flap that misattributes the red to the gate's own assertion. Root incident
# 2026-09-05: secondary remote "lan905" (.178:9300) crc32c read-timeout
# red-flapped #1497/#1487/#1490, each costing a full fleet triage cycle.
#
# Fix: before conan install, probe each ENABLED remote and disable any that does
# not accept a TCP connection within a short timeout. The primary "lan" remote
# and the local cache (lockfile-pinned recipes/binaries) are left intact, so a
# reachable subset — or purely the local cache — still satisfies the resolve.
# Idempotent; the disable is scoped to this runner's conan config and self-heals
# on the next configure. No-ops cleanly when conan is absent.
#
# Usage: source this file, then call prune_unreachable_conan_remotes before the
#        `conan install` line.
prune_unreachable_conan_remotes() {
  command -v conan >/dev/null 2>&1 || return 0
  local remotes name
  remotes="$(conan remote list --format=json 2>/dev/null)" || return 0
  for name in $(printf "%s" "$remotes" | python3 - <<'PY'
import json, socket, sys, urllib.parse
try:
    remotes = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in remotes:
    if not r.get("enabled", True):
        continue
    u = urllib.parse.urlparse(r.get("url", ""))
    host = u.hostname
    if not host:
        continue
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except OSError:
        print(r.get("name"))
PY
  ); do
    echo "[conan-remote-prune] remote '$name' unreachable — disabling for this run (non-fatal secondary; primary lan + local cache retained)" >&2
    conan remote disable "$name" >/dev/null 2>&1 || true
  done
}
