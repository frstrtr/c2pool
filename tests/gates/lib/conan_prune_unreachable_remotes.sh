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
# Fix, in three passes:
#   1. Disable every enabled remote NOT on the primary allowlist,
#      UNCONDITIONALLY. A secondary binary mirror (lan905) is redundant with the
#      primary "lan" mirror + conancenter + the local cache, and --build=missing
#      covers any binary that is then absent (build from source, slower but
#      deterministic). Removing it from the resolve closes the flap window
#      entirely — it can never be contacted mid-install.
#   2. Among the remaining (primary) remotes, probe-prune any that do not accept
#      a TCP connection within a short timeout, so a dead PRIMARY still degrades
#      to the local cache rather than failing the resolve.
#   3. Re-list and ASSERT no secondary remains enabled, echoing the resulting
#      set to the log so a stale secondary can never fake-green.
# The disable is scoped to this runner's conan config and self-heals on the
# next `Prefer LAN Conan remote` step. No-ops cleanly when conan is absent.
# Override the allowlist with CONAN_PRIMARY_REMOTES (space-separated).
#
# History (2026-09-05): the prior form piped the JSON in via
# `printf ... | python3 - <<PYHEREDOC`. `python3 -` reads the PROGRAM from
# stdin, and the heredoc REPLACES the pipe as stdin, so `json.load(sys.stdin)`
# saw an exhausted stream, raised, and hit a silent `except: sys.exit(0)` —
# every loop iterated an empty list and the helper disabled NOTHING, silently
# (no "[conan-remote-prune] ... disabled" line was ever emitted). The JSON is
# now passed by ENV (REMOTES_JSON), never stdin, and a parse failure is LOUD
# and nonzero — a guard that fails open silently is a fake-green generator.
#
# Usage: source this file, then call prune_unreachable_conan_remotes before the
#        `conan install` line.
prune_unreachable_conan_remotes() {
  command -v conan >/dev/null 2>&1 || return 0
  local remotes primaries secondaries dead after leftover name rc
  remotes="$(conan remote list --format=json 2>/dev/null)" || return 0
  primaries="${CONAN_PRIMARY_REMOTES:-lan conancenter}"

  # Pass 1 — unconditionally disable secondaries (redundant flap surface).
  secondaries="$(REMOTES_JSON="$remotes" PRIMARIES="$primaries" python3 - <<'PY'
import json, os, sys
primaries = set(os.environ.get("PRIMARIES", "").split())
try:
    remotes = json.loads(os.environ["REMOTES_JSON"])
except Exception as e:
    sys.stderr.write("[conan-remote-prune] FATAL: could not parse `conan remote list` JSON: %s\n" % e)
    sys.exit(3)
for r in remotes:
    if not r.get("enabled", True):
        continue
    if r.get("name") not in primaries:
        print(r.get("name"))
PY
  )"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[conan-remote-prune] FATAL: remote enumeration failed (rc=$rc); refusing to run conan install with an unpruned remote set" >&2
    return "$rc"
  fi
  for name in $secondaries; do
    echo "[conan-remote-prune] secondary remote '$name' disabled unconditionally for this run (redundant mirror; primary lan + conancenter + local cache retained, --build=missing covers the rest)" >&2
    conan remote disable "$name" >/dev/null 2>&1 || true
  done

  # Pass 2 — probe-prune any primary that is actually unreachable.
  dead="$(REMOTES_JSON="$remotes" PRIMARIES="$primaries" python3 - <<'PY'
import json, os, socket, sys, urllib.parse
primaries = set(os.environ.get("PRIMARIES", "").split())
try:
    remotes = json.loads(os.environ["REMOTES_JSON"])
except Exception as e:
    sys.stderr.write("[conan-remote-prune] FATAL: could not parse `conan remote list` JSON: %s\n" % e)
    sys.exit(3)
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
  )"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[conan-remote-prune] FATAL: primary probe enumeration failed (rc=$rc); refusing to run conan install with an unpruned remote set" >&2
    return "$rc"
  fi
  for name in $dead; do
    echo "[conan-remote-prune] primary remote '$name' unreachable — disabling for this run (falling back to local cache)" >&2
    conan remote disable "$name" >/dev/null 2>&1 || true
  done

  # Pass 3 — assert the resulting enabled set (proof in the log; no fake-green).
  after="$(conan remote list --format=json 2>/dev/null)" || return 0
  echo "[conan-remote-prune] enabled remotes after prune:" >&2
  REMOTES_JSON="$after" python3 - >&2 <<'PY'
import json, os, sys
try:
    remotes = json.loads(os.environ["REMOTES_JSON"])
except Exception as e:
    sys.stderr.write("[conan-remote-prune] FATAL: could not parse post-prune remote list: %s\n" % e)
    sys.exit(3)
for r in remotes:
    if r.get("enabled", True):
        sys.stderr.write("    - %s  url=%s\n" % (r.get("name"), r.get("url", "")))
PY
  leftover="$(REMOTES_JSON="$after" PRIMARIES="$primaries" python3 - <<'PY'
import json, os, sys
primaries = set(os.environ.get("PRIMARIES", "").split())
try:
    remotes = json.loads(os.environ["REMOTES_JSON"])
except Exception as e:
    sys.stderr.write("[conan-remote-prune] FATAL: could not parse post-prune remote list: %s\n" % e)
    sys.exit(3)
for r in remotes:
    if r.get("enabled", True) and r.get("name") not in primaries:
        print(r.get("name"))
PY
  )"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[conan-remote-prune] FATAL: post-prune enumeration failed (rc=$rc)" >&2
    return "$rc"
  fi
  if [ -n "$leftover" ]; then
    echo "[conan-remote-prune] FATAL: secondary remote(s) still enabled after prune: $leftover" >&2
    return 1
  fi
}
