#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# alert_relay_e2e.sh -- D-MINER.7 end-to-end rig for the miner-offline alert
# relay over the sharechain p2p. Everything runs on 127.0.0.1 with a private
# --network-id/--prefix (never touches a public sharechain) and a FAKE
# Telegram endpoint (no traffic to api.telegram.org, dummy token).
#
#   BIN=/path/to/c2pool-dash [MASTER_BIN=/path/to/master/c2pool-dash] \
#   W=/tmp/alert-e2e scripts/alert_relay_e2e.sh
#
# Phases (each asserts; the script exits non-zero on the first failure):
#   1 key exchange via --alert-relay-show-key
#   2 origin A --connect relay B; miner rig1 connects, disconnects
#       -> exactly ONE fake-Telegram POST "rig1 ... OFFLINE"
#   3 rig1 reconnects -> exactly ONE "back ONLINE"
#   4 sidecar stopped, rig1 drops -> A reports queued_at_relay, NO POST;
#       sidecar restarted -> exactly ONE more POST, A sees delivered
#   5 relay B down, rig2 drops, A restarted mid-retry (pending persisted),
#       B back -> exactly ONE POST for rig2, no duplicate outbox ids
#   6 /p2p_stats alert/alertack counters on A and B
#   7 old-peer interop: master-built C between -> C logs "Failed to parse
#       message 'alert'", stays connected (MASTER_BIN only)
#   8 flag-off parity: A,B without any --alert-relay-* flag -> alert out == 0
set -u
BIN="${BIN:?set BIN to the c2pool-dash under test}"
MASTER_BIN="${MASTER_BIN:-}"
W="${W:-/tmp/alert-e2e}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PARITY_SECS="${PARITY_SECS:-120}"
NETID=a1e27a1e27a1e27a
PREFIX=a1e27a1e27a1e27b
SUB="dash_testnet_${NETID}"
# --coin-p2p-connect to a dead loopback port: an explicitly named coin transport
# keeps the daemonless node from discovering public Dash testnet peers, so the
# rig stays entirely on 127.0.0.1.
COMMON=(--run --testnet --network-id "$NETID" --prefix "$PREFIX" --web-host 127.0.0.1
        --coin-p2p-connect 127.0.0.1:1)
FAST=(--alert-relay-offline-after 20 --alert-relay-online-after 5 --alert-relay-startup-grace 5
      --alert-relay-retry-every 5 --alert-relay-min-interval 30 --alert-relay-stall-after 0)

PIDS=()
fail() { echo "E2E FAIL: $*"; cleanup; exit 1; }
pass() { echo "E2E PASS: $*"; }
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
}
trap cleanup EXIT

start() {   # start NAME LOG CMD... ; echoes pid into var NAME_PID
  local name="$1" log="$2"; shift 2
  "$@" >"$log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  eval "${name}_PID=$pid"
}
stop() {    # stop NAME
  local v="${1}_PID"; local pid="${!v:-}"
  [ -z "$pid" ] && return
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  kill -9 "$pid" 2>/dev/null
  eval "${1}_PID="
}
wait_for() {  # wait_for SECONDS DESC CMD...
  local secs="$1" desc="$2"; shift 2
  local end=$((SECONDS + secs))
  while [ $SECONDS -lt $end ]; do "$@" && return 0; sleep 1; done
  fail "timeout ($secs s) waiting for: $desc"
}
tg_count() { # tg_count PATTERN... -> number of fake-Telegram POSTs whose text has ALL patterns
  python3 - "$W/tg.jsonl" "$@" <<'PY'
import json, sys
path, pats = sys.argv[1], sys.argv[2:]
n = 0
try:
    for line in open(path):
        t = json.loads(line)["body"].get("text", "")
        if all(p in t for p in pats): n += 1
except FileNotFoundError:
    pass
print(n)
PY
}
status() { curl -s --max-time 3 "http://127.0.0.1:$1/api/alert-relay/status"; }
p2p() { curl -s --max-time 3 "http://127.0.0.1:$1/p2p_stats"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }
peers_of() { local v; v=$(curl -s --max-time 3 "http://127.0.0.1:$1/local_stats" | jget '["peers"]["incoming"]+d["peers"]["outgoing"]' 2>/dev/null); echo "${v:-0}"; }
peers_ge() { [ "$(peers_of "$1")" -ge "$2" ] 2>/dev/null; }
tg_ge() { local n="$1"; shift; [ "$(tg_count "$@")" -ge "$n" ]; }
st_ge() {   # st_ge PORT PYPATH N
  local v; v=$(status "$1" | jget "$2" 2>/dev/null); [ -n "$v" ] && [ "$v" -ge "$3" ] 2>/dev/null; }
# The relay status JSON is the only reply carrying a top-level "role" object;
# an unrouted path on the web server (feature and master alike) answers with a
# generic getmininginfo-style JSON that also contains the substring "pubkey".
has_status() { status "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d.get("role"), dict) and "pubkey" in d else 1)' 2>/dev/null; }

rm -rf "$W"; mkdir -p "$W/A" "$W/B" "$W/C"
echo "dummy-token-never-valid" >"$W/dummy.token"; chmod 600 "$W/dummy.token"

# ── fake Telegram ───────────────────────────────────────────────────────────
cat >"$W/fake_tg.py" <<'PY'
import http.server, json, sys
out = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n) or b"{}")
        with open(out, "a") as f:
            f.write(json.dumps({"path_ok": self.path.endswith("/sendMessage"), "body": body}) + "\n")
        data = b'{"ok":true,"result":{}}'
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 19999), H).serve_forever()
PY
start TG "$W/fake_tg.log" python3 "$W/fake_tg.py" "$W/tg.jsonl"

# ── 1. key exchange ─────────────────────────────────────────────────────────
APUB=$("$BIN" --testnet --network-id "$NETID" --prefix "$PREFIX" --data-dir "$W/A" --alert-relay-show-key 2>/dev/null | tail -n1) || fail "show-key A"
BPUB=$("$BIN" --testnet --network-id "$NETID" --prefix "$PREFIX" --data-dir "$W/B" --alert-relay-show-key 2>/dev/null | tail -n1) || fail "show-key B"
[ ${#APUB} -eq 66 ] && [ ${#BPUB} -eq 66 ] || fail "pubkeys not 66 hex chars: '$APUB' '$BPUB'"
APUB2=$("$BIN" --testnet --network-id "$NETID" --prefix "$PREFIX" --data-dir "$W/A" --alert-relay-show-key 2>/dev/null | tail -n1)
[ "$APUB" = "$APUB2" ] || fail "show-key is not stable across runs"
[ "$(stat -c %a "$W/A/$SUB/alert_relay/alert.key")" = "600" ] || fail "alert.key not 0600"
pass "1 key exchange: A=$APUB B=$BPUB (key files 0600, stable)"

ADDR=$(python3 "$HERE/alert_relay_stratum_sim.py" --testnet-address 1)
BSTATE="$W/B/$SUB/alert_relay"
start_B() {
  start B "$W/B.log.$1" "$BIN" "${COMMON[@]}" --data-dir "$W/B" --listen 127.0.0.1:19802 \
    --web-port 19082 --alert-relay-telegram --alert-relay-accept "$APUB"
}
start_A() {
  start A "$W/A.log.$1" "$BIN" "${COMMON[@]}" --data-dir "$W/A" --listen 127.0.0.1:19801 \
    --connect 127.0.0.1:19802 --stratum 127.0.0.1:19901 --web-port 19081 \
    --alert-relay-origin --alert-relay-to "$BPUB" --alert-relay-label e2e-hotel "${FAST[@]}"
}
start_sidecar() {
  start SC "$W/sidecar.log.$1" python3 "$HERE/alert_relay_telegram.py" --state-dir "$BSTATE" \
    --token-file "$W/dummy.token" --chat-id 1 --telegram-api-base http://127.0.0.1:19999 --poll 1 -v
}
miner() {   # miner NAME USER HOLD
  start "$1" "$W/$1.log" python3 "$HERE/alert_relay_stratum_sim.py" --port 19901 --user "$2" --hold "$3"
}

# ── 2. offline -> exactly one Telegram message ─────────────────────────────
start_B 1
start_A 1
start_sidecar 1
wait_for 60 "A web status" has_status 19081
wait_for 60 "B web status" has_status 19082
wait_for 90 "A<->B sharechain peering" peers_ge 19082 1
miner M1 "$ADDR.rig1" 15
wait_for 20 "rig1 authorized" grep -q "authorize .* -> True" "$W/M1.log"
wait_for 20 "rig1 visible to the detector" sh -c "curl -s http://127.0.0.1:19081/api/alert-relay/status | grep -q rig1"
T_DISC=$((SECONDS + 15))
wait_for 90 "Telegram OFFLINE for rig1" tg_ge 1 rig1 OFFLINE
LAT=$((SECONDS - T_DISC))
sleep 15
[ "$(tg_count rig1 OFFLINE)" = "1" ] || fail "expected exactly 1 OFFLINE POST, got $(tg_count rig1 OFFLINE)"
[ "$(tg_count e2e-hotel)" -ge 1 ] || fail "label missing from the text"
wait_for 20 "A sees delivered=1" st_ge 19081 '["outbox"]["delivered"]' 1
pass "2 offline: exactly 1 Telegram POST for rig1 OFFLINE (~${LAT}s after disconnect), origin ledger delivered"
grep -m1 "OFFLINE" "$W/tg.jsonl" | python3 -c 'import json,sys; print("   text:", json.loads(sys.stdin.read())["body"]["text"])'

# ── 3. back online -> exactly one ───────────────────────────────────────────
miner M2 "$ADDR.rig1" 40
wait_for 60 "Telegram back ONLINE for rig1" tg_ge 1 rig1 "back ONLINE"
sleep 10
[ "$(tg_count rig1 'back ONLINE')" = "1" ] || fail "expected exactly 1 back ONLINE POST"
[ "$(tg_count rig1 OFFLINE)" = "1" ] || fail "OFFLINE count changed during back-online"
pass "3 back online: exactly 1 Telegram POST"

# ── 4. sidecar dead -> queued_at_relay, then exactly one after restart ─────
stop SC
BEFORE=$(wc -l <"$W/tg.jsonl")
wait_for 120 "A queued_at_relay after rig1 drops with the sidecar down" st_ge 19081 '["outbox"]["queued_at_relay"]' 1
sleep 10
[ "$(wc -l <"$W/tg.jsonl")" = "$BEFORE" ] || fail "a POST happened while the sidecar was down"
QB=$(status 19082 | jget '["relay"]["pending_sidecar"]')
[ "$QB" -ge 1 ] || fail "relay pending_sidecar should be >=1, got $QB"
start_sidecar 2
wait_for 30 "sidecar drains the queued alert" sh -c "[ \$(wc -l <'$W/tg.jsonl') -gt $BEFORE ]"
sleep 8
[ "$(( $(wc -l <"$W/tg.jsonl") - BEFORE ))" = "1" ] || fail "expected exactly 1 POST after sidecar restart"
[ "$(tg_count rig1 OFFLINE)" = "2" ] || fail "second rig1 OFFLINE not delivered"
wait_for 20 "A sees the late delivered ack" st_ge 19081 '["outbox"]["delivered"]' 3
pass "4 sidecar outage: queued_at_relay on origin, no POST while down, exactly 1 POST after restart, late delivered ack reached origin"

# ── 5. relay down + origin restart mid-retry -> exactly one, no dup ids ────
miner M3 "$ADDR.rig2" 12
wait_for 20 "rig2 authorized" grep -q "authorize .* -> True" "$W/M3.log"
sleep 3
stop B
wait_for 60 "A has rig2 awaiting ack" st_ge 19081 '["outbox"]["awaiting_ack"]' 1
sleep 6
stop A
# Relay first, then the origin: on master a dash node never re-dials a
# --connect peer whose FIRST dial was refused (the address stays in
# m_pending_outbound; pre-existing, independent of this feature), so the rig
# brings B up before A to exercise the persisted-pending path, not that.
start_B 2
wait_for 60 "B web status (restart)" has_status 19082
start_A 2
wait_for 90 "Telegram OFFLINE for rig2 after origin restart" tg_ge 1 rig2 OFFLINE
sleep 20
[ "$(tg_count rig2 OFFLINE)" = "1" ] || fail "expected exactly 1 rig2 OFFLINE POST, got $(tg_count rig2 OFFLINE)"
DUPS=$(python3 -c "
import json,collections
c=collections.Counter(json.loads(l)['id'] for l in open('$BSTATE/outbox.jsonl'))
print(sum(v-1 for v in c.values()))")
[ "$DUPS" = "0" ] || fail "relay outbox has $DUPS duplicate id(s)"
grep -q "event offline worker=.*rig2" "$W/A.log.1" || fail "rig2 event was not raised before the restart"
pass "5 relay outage + origin restart mid-retry: persisted frame re-sent, exactly 1 POST, 0 duplicate outbox ids ($(wc -l <"$BSTATE/outbox.jsonl") rows)"

# ── 6. wire counters ────────────────────────────────────────────────────────
AO=$(p2p 19081 | jget '["messages"]["alert"]["out"]'); AAI=$(p2p 19081 | jget '["messages"]["alertack"]["in"]')
BI=$(p2p 19082 | jget '["messages"]["alert"]["in"]'); BAO=$(p2p 19082 | jget '["messages"]["alertack"]["out"]')
[ "$AO" -ge 1 ] && [ "$AAI" -ge 1 ] && [ "$BI" -ge 1 ] && [ "$BAO" -ge 1 ] || fail "p2p counters A(out=$AO ackin=$AAI) B(in=$BI ackout=$BAO)"
pass "6 /p2p_stats (since last restart): A alert.out=$AO alertack.in=$AAI | B alert.in=$BI alertack.out=$BAO"
status 19081 >"$W/A.status.json"; status 19082 >"$W/B.status.json"
stop A; stop B; stop SC

# ── 7. old-peer interop (master build in the path) ─────────────────────────
if [ -n "$MASTER_BIN" ]; then
  start C "$W/C.log" "$MASTER_BIN" "${COMMON[@]}" --data-dir "$W/C" --listen 127.0.0.1:19803 --web-port 19083
  sleep 5
  start A "$W/A.log.old" "$BIN" "${COMMON[@]}" --data-dir "$W/A" --listen 127.0.0.1:19801 \
    --connect 127.0.0.1:19803 --stratum 127.0.0.1:19901 --web-port 19081 \
    --alert-relay-origin --alert-relay-to "$BPUB" --alert-relay-label e2e-hotel "${FAST[@]}" --alert-relay-test
  wait_for 90 "A<->C (master) peering" peers_ge 19083 1
  wait_for 90 "master C logs the unknown alert command" grep -q "Failed to parse message 'alert'" "$W/C.log"
  sleep 45   # >= 8 retransmits at 5 s
  NPARSE=$(grep -c "Failed to parse message 'alert'" "$W/C.log")
  CUNK=$(p2p 19083 | jget '["messages"]["unknown"]["in"]')
  CPEERS=$(peers_of 19083)
  DISC=$(grep -c "disconnected" "$W/C.log" || true)
  [ "$CPEERS" -ge 1 ] || fail "master C dropped the peer"
  [ "$NPARSE" -ge 2 ] || fail "expected repeated parse-drops on C, got $NPARSE"
  [ "$DISC" = "0" ] || fail "master C logged $DISC disconnect(s)"
  pass "7 old-peer interop: master C logged 'Failed to parse message alert' x$NPARSE, /p2p_stats unknown.in=$CUNK, peers=$CPEERS, disconnects=0"
  grep -m1 "Failed to parse message 'alert'" "$W/C.log" | sed 's/^/   /'
  stop A; stop C
else
  echo "E2E SKIP: 7 old-peer interop (MASTER_BIN unset)"
fi

# ── 8. flag-off parity ──────────────────────────────────────────────────────
rm -rf "$W/P"; mkdir -p "$W/P/A" "$W/P/B"
start B "$W/B.log.off" "$BIN" "${COMMON[@]}" --data-dir "$W/P/B" --listen 127.0.0.1:19802 --web-port 19082
start A "$W/A.log.off" "$BIN" "${COMMON[@]}" --data-dir "$W/P/A" --listen 127.0.0.1:19801 \
  --connect 127.0.0.1:19802 --stratum 127.0.0.1:19901 --web-port 19081
wait_for 90 "flag-off A<->B peering" peers_ge 19082 1
miner M4 "$ADDR.rig1" 10
sleep "$PARITY_SECS"
for port in 19081 19082; do
  S=$(p2p $port)
  O=$(echo "$S" | jget '["messages"]["alert"]["out"]+d["messages"]["alertack"]["out"]+d["messages"]["alert"]["in"]+d["messages"]["alertack"]["in"]')
  [ "$O" = "0" ] || fail "flag-off node :$port moved $O alert frames"
  CMDS=$(echo "$S" | python3 -c 'import json,sys; d=json.load(sys.stdin)["messages"]; print(",".join(sorted(k for k,v in d.items() if v["in"] or v["out"])))')
  echo "   :$port commands on the wire: $CMDS"
  has_status $port && fail "flag-off node :$port answers /api/alert-relay/status"
done
[ -d "$W/P/A/$SUB/alert_relay" ] && fail "flag-off node created alert_relay state"
grep -q "\[alert-relay\]" "$W/A.log.off" "$W/B.log.off" && fail "flag-off node logged [alert-relay] lines"
pass "8 flag-off parity: ${PARITY_SECS}s peered + miner churn, 0 alert/alertack frames, no status route, no state dir"
EXT=$(grep -h "COIN-P2P\] connected to" "$W"/*.log* 2>/dev/null | grep -vc "connected to 127\.0\.0\.1" || true)
[ "$EXT" = "0" ] || fail "a node dialled $EXT non-loopback coin peer(s)"
pass "rig stayed on loopback: 0 non-loopback coin-p2p connections"
echo "E2E ALL PASSED"
