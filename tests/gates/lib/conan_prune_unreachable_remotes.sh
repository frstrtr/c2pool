#!/usr/bin/env bash
# Shared gate helper: keep a flaky/unreachable secondary Conan remote from
# reddening a gate.
#
# Why: every gate resolves deps with `conan install --build=missing`, which
# contacts EVERY enabled remote. A secondary mirror that is unreachable OR that
# is reachable at probe time but flaps mid-resolve ("remote not available"
# during the "checking for binary" phase) then aborts the whole install with a
# nonzero exit BEFORE the gate body runs — a determinism flap that misattributes
# the red to the gate's own assertion. Incidents 2026-09-05: secondary remote
# "lan905" (.178:9300) crc32c read-timeout red-flapped #1497/#1487/#1490, and
# again as the from-scratch-configure red on master HEAD 345d277c (BCH G3b,
# run 33972356373) where lan905 PASSED both the curl setup-probe and this
# helper's TCP probe, then flapped mid-install. A single-shot pre-install probe
# therefore cannot make a flapping secondary non-fatal.
#
# Fix, in two passes:
#   1. Disable every enabled remote NOT on the primary allowlist,
#      UNCONDITIONALLY. A secondary binary mirror (lan905) is redundant with the
#      primary "lan" mirror + conancenter + the local cache, and --build=missing
#      covers any binary that is then absent (build from source, slower but
#      deterministic). Removing it from the resolve closes the flap window
#      entirely — it can never be contacted mid-install.
#   2. Among the remaining (primary) remotes, probe-prune any that do not accept
#      a TCP connection within a short timeout, so a dead PRIMARY still degrades
#      to the local cache rather than failing the resolve.
# The disable is scoped to this runner's conan config and self-heals on the
# next `Prefer LAN Conan remote` step. No-ops cleanly when conan is absent.
# Override the allowlist with CONAN_PRIMARY_REMOTES (space-separated).
#
# Usage: source this file, then call prune_unreachable_conan_remotes before the
#        `conan install` line.
prune_unreachable_conan_remotes() {
  command -v conan >/dev/null 2>&1 || return 0
  local remotes name primaries
  remotes="$(conan remote list --format=json 2>/dev/null)" || return 0
  primaries="${CONAN_PRIMARY_REMOTES:-lan conancenter}"

  # Pass 1 — unconditionally disable secondaries (redundant flap surface).
  for name in $(printf "%s" "$remotes" | PRIMARIES="$primaries" python3 - <<'PY'
import json, os, sys
primaries = set(os.environ.get("PRIMARIES", "").split())
try:
    remotes = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in remotes:
    if not r.get("enabled", True):
        continue
    if r.get("name") not in primaries:
        print(r.get("name"))
PY
  ); do
    echo "[conan-remote-prune] secondary remote '$name' disabled unconditionally for this run (redundant mirror; primary lan + conancenter + local cache retained, --build=missing covers the rest)" >&2
    conan remote disable "$name" >/dev/null 2>&1 || true
  done

  # Pass 2 — probe-prune any primary that is actually unreachable.
  for name in $(printf "%s" "$remotes" | PRIMARIES="$primaries" python3 - <<'PY'
import json, os, socket, sys, urllib.parse
primaries = set(os.environ.get("PRIMARIES", "").split())
try:
    remotes = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in remotes:
    if not r.get("enabled", True):
        continue
    if r.get("name") not in primaries:
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
    echo "[conan-remote-prune] primary remote '$name' unreachable — disabling for this run (falling back to local cache)" >&2
    conan remote disable "$name" >/dev/null 2>&1 || true
  done
}
