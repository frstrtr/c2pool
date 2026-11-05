#!/usr/bin/env bash
# Selftest for conan_install_resilient (tests/gates/lib/conan_prune_unreachable_remotes.sh).
#
# Reproduces the pass-probe-then-drop flap without a real Conan server: a stub
# `conan` on PATH serves `remote list/disable` from a JSON file, and its
# `install` fails whenever an enabled remote refuses a TCP connect. Two local
# TCP listeners stand in for the "lan" and "conancenter" remotes. The drop
# fixture kills the "lan" listener INSIDE the first `conan install`, after
# prune_unreachable_conan_remotes has already probed it as healthy.
#
# Cases:
#   A  bare `conan install` after a clean prune goes red on the drop (repro)
#   B  conan_install_resilient survives the same drop: re-probe disables lan,
#      retry resolves via conancenter
#   C  remotes reachable but install keeps failing, cache warm: -nr fallback
#   D  same as C with a cold cache: nonzero (no fake-green)
# Each case runs under `set -euo pipefail`, as the gates do.
set -uo pipefail

LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/conan_prune_unreachable_remotes.sh"
WORK="$(mktemp -d -t conan-resilient-selftest.XXXXXX)"
# Listeners are started inside $(setup ...) subshells, so track them by pid file.
cleanup() { for f in "$WORK"/*/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$WORK/bin"
cat >"$WORK/bin/conan" <<'STUB'
#!/usr/bin/env bash
S="$CONAN_STUB_STATE"
case "$1 ${2:-}" in
  "remote list") cat "$S/remotes.json"; exit 0 ;;
  "remote disable")
    NAME="$3" python3 - "$S/remotes.json" <<'PY'
import json, os, sys
p = sys.argv[1]; r = json.load(open(p))
for x in r:
    if x["name"] == os.environ["NAME"]:
        x["enabled"] = False
json.dump(r, open(p, "w"))
PY
    exit 0 ;;
esac
[ "$1" = install ] || { echo "stub conan: unsupported: $*" >&2; exit 2; }
echo "install $*" >>"$S/calls"
for a in "$@"; do
  if [ "$a" = -nr ]; then
    [ -f "$S/cache_warm" ] && exit 0
    echo "ERROR: missing prebuilt package (cache-only)" >&2; exit 1
  fi
done
if [ -f "$S/drop_on_install" ]; then
  rm -f "$S/drop_on_install"
  kill "$(cat "$S/lan.pid")"
  while python3 -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)' "$(cat "$S/lan.port")" 2>/dev/null; do sleep 0.1; done
  echo "ERROR: Remote 'lan' is not available (dropped mid-resolve)" >&2; exit 1
fi
[ -f "$S/always_fail_remote" ] && { echo "ERROR: remote read timeout" >&2; exit 1; }
python3 - "$S/remotes.json" <<'PY' || { echo "ERROR: an enabled remote is not available" >&2; exit 1; }
import json, socket, sys, urllib.parse
for r in json.load(open(sys.argv[1])):
    if r.get("enabled", True):
        u = urllib.parse.urlparse(r["url"])
        socket.create_connection((u.hostname, u.port), timeout=2).close()
PY
STUB
chmod +x "$WORK/bin/conan"

start_listener() { # $1 = state dir, $2 = name
  python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(16)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept(); c.close()
' "$1/$2.port" </dev/null >/dev/null 2>&1 &
  echo $! >"$1/$2.pid"
  while [ ! -s "$1/$2.port" ]; do sleep 0.05; done
}

setup() { # $1 = case name; prints state dir
  local s="$WORK/$1"; mkdir -p "$s"
  start_listener "$s" lan; start_listener "$s" conancenter
  printf '[{"name":"lan","url":"http://127.0.0.1:%s","enabled":true},{"name":"conancenter","url":"http://127.0.0.1:%s","enabled":true}]' \
    "$(cat "$s/lan.port")" "$(cat "$s/conancenter.port")" >"$s/remotes.json"
  echo "$s"
}

# Runs a gate-shaped snippet under errexit; $2 = install command.
run_gate() { # $1 = state dir
  CONAN_STUB_STATE="$1" PATH="$WORK/bin:$PATH" bash -euo pipefail -c "
    . '$LIB' && prune_unreachable_conan_remotes
    $2 . --build=missing --output-folder=build
  " >"$1/log" 2>&1
}

enabled() { python3 -c 'import json,sys; print(" ".join(r["name"] for r in json.load(open(sys.argv[1])) if r.get("enabled",True)))' "$1/remotes.json"; }

FAIL=0
check() { # $1 = label, $2 = condition result (0 = ok), $3 = state dir
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; sed 's/^/    /' "$3/log"; FAIL=1; fi
}

s="$(setup A)"; touch "$s/drop_on_install"
run_gate "$s" "conan install"; rc=$?
check "A bare conan install goes red on pass-probe-then-drop (rc=$rc)" "$([ "$rc" -ne 0 ]; echo $?)" "$s"

s="$(setup B)"; touch "$s/drop_on_install"
run_gate "$s" conan_install_resilient; rc=$?
ok=1; [ "$rc" -eq 0 ] && [ "$(enabled "$s")" = conancenter ] && grep -q "dropped mid-resolve; re-probing" "$s/log" && ok=0
check "B resilient survives the drop; lan disabled, conancenter kept (rc=$rc, enabled=$(enabled "$s"))" "$ok" "$s"

s="$(setup C)"; touch "$s/always_fail_remote" "$s/cache_warm"
run_gate "$s" conan_install_resilient; rc=$?
ok=1; [ "$rc" -eq 0 ] && grep -q -- "-nr" "$s/calls" && grep -q "resolved from local cache only" "$s/log" && ok=0
check "C persistent remote failure + warm cache resolves via -nr (rc=$rc)" "$ok" "$s"

s="$(setup D)"; touch "$s/always_fail_remote"
run_gate "$s" conan_install_resilient; rc=$?
ok=1; [ "$rc" -ne 0 ] && grep -q "FATAL: conan install failed with remotes and cache-only" "$s/log" && ok=0
check "D persistent failure + cold cache stays red, no fake-green (rc=$rc)" "$ok" "$s"

[ "$FAIL" -eq 0 ] && echo "conan_install_resilient selftest: ALL PASS" || echo "conan_install_resilient selftest: FAILED" >&2
exit "$FAIL"
