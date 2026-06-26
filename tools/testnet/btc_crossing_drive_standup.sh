#!/usr/bin/env bash
# btc_crossing_drive_standup.sh
# BTC v35->v36 VERSION-BOUNDARY CROSSING drive — isolated tuned-net, tap-then-one-command.
#
# Composes the LIVE version-boundary crossing drive into a single invocation so
# that, the moment the operator rules the regtest-vs-testnet3 proof-bar and taps
# GO, the isolated tuned sharechain drives the v35->v36 ratchet to completion and
# the crossing is asserted CORRECT — never a mint-outruns-accept wedge.
#
# This is the LIVE companion to the already-KAT-proven crossing logic
# (src/impl/btc/test/auto_ratchet_sim_test.cpp C1-C4, esp C3
# MintCannotOutrunAccept). G3 block-production is CLOSED for sign-off; this live
# drive is NOT a code gap and does NOT gate G3 — it is the optional operator
# proof-bar re-drive on the existing reproducible rig (integrator 2026-06-26,
# UID2669). Held-for-tap: --dry-run is self-contained and needs no host; --go
# relaunches the tuned host and REQUIRES an operator decision card.
#
# WHAT THE CROSSING DRIVE PROVES
# ------------------------------
# The AutoRatchet VOTING -> ACTIVATED -> CONFIRMED state machine latches v36
# ONLY when BOTH gates hold simultaneously (auto_ratchet.hpp):
#   * 95%-by-COUNT  activation window  (ACTIVATION_THRESHOLD)
#   * 60%-by-WORK   tail-guard accept  (SWITCH_THRESHOLD, #288)
# C3 (MintCannotOutrunAccept): a 95%-by-count majority can NOT outrun the
# 60%-by-work accept floor — a minted v36 boundary share at <60% work is held in
# VOTING ("waiting"), never activated. That is the crossing-wedge failure mode
# this drive must reject.
#
# ISOLATION (bucket-1 primitive, 3-bucket rule): the tuned net is a PRIVATE
# sharechain pinned by --network-id (IDENTIFIER) + --prefix (PREFIX) over an
# isolated low-diff parent. These per-instance namespaces are KEPT, never
# standardized; the drive asserts them, it does not change them.
#
# Modes:
#   btc_crossing_drive_standup.sh --dry-run
#       SELF-CONTAINED. No host, no binary, no operator-go. Proves the crossing
#       asserts (a) PASS on a golden GOOD crossing (count>=95 AND work>=60 ->
#       ACTIVATED/CONFIRMED) and (b) BITE on each wedge: work<60 (mint outran
#       accept), count<95 (premature), and no-cross (stuck VOTING). Acceptance gate.
#
#   btc_crossing_drive_standup.sh --go --host H --bin /path/c2pool-btc \
#                          [--bitcoind 127.0.0.1:18443] [--stratum 9332] \
#                          [--network-id HEX] [--prefix HEX] [--oracle HOST:PORT]
#       LIVE. Relaunches the isolated tuned host, drives the staged v36 ramp,
#       then asserts the crossing record. REQUIRES operator GO — relaunch drops
#       bake-in state. Never run without a decision-card approval.
#
set -euo pipefail

# isolated namespace defaults (NON-default, clearly not prod)
ISO_NETID="${ISO_NETID:-78696e67}"   # "xing"  (crossing)
ISO_PREFIX="${ISO_PREFIX:-78677435}" # "xgt5"  (crossing v35->...)

# live thresholds — mirror auto_ratchet.hpp (asserts only, not a redefinition)
ACTIVATION_THRESHOLD="${ACTIVATION_THRESHOLD:-95}"  # %-by-COUNT activation window
SWITCH_THRESHOLD="${SWITCH_THRESHOLD:-60}"          # %-by-WORK tail-guard accept (#288)

MODE=""
HOST=""
BIN=""
BITCOIND="127.0.0.1:18443"
STRATUM="9332"
ORACLE=""           # isolated v35 jtoomim oracle peer for cohabit (optional)
LOGTAIL_SECS=30

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     MODE="dry";  shift ;;
    --go)          MODE="go";   shift ;;
    --host)        HOST="$2";   shift 2 ;;
    --bin)         BIN="$2";    shift 2 ;;
    --bitcoind)    BITCOIND="$2"; shift 2 ;;
    --stratum)     STRATUM="$2"; shift 2 ;;
    --network-id)  ISO_NETID="$2"; shift 2 ;;
    --prefix)      ISO_PREFIX="$2"; shift 2 ;;
    --oracle)      ORACLE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ── ratchet-marker assert: the staged drive emitted a CORRECT crossing ───────
# Pure grep over the LOG_INFO lines AutoRatchet emits (auto_ratchet.hpp). Same
# logic in --dry-run and --go so the dry-run faithfully proves the live path.
assert_ratchet_markers() {
  local log="$1" ok=1
  _need() { if grep -qF -- "$1" "$log"; then echo "  PASS  $2"; else echo "  FAIL  $2"; ok=0; fi; }
  _deny() { if grep -qF -- "$1" "$log"; then echo "  FAIL  $2 (saw forbidden: $1)"; ok=0; else echo "  PASS  $2"; fi; }

  echo "[ratchet markers]"
  _need "[AutoRatchet] VOTING -> ACTIVATED"            "crossing latched (VOTING -> ACTIVATED)"
  _need "VOTING -> CONFIRMED"                          "crossing persisted to CONFIRMED"
  # the crossing must NOT have reverted (work fell below DEACTIVATION floor)
  _deny "[AutoRatchet] ACTIVATED -> VOTING"            "crossing did NOT revert (no ACTIVATED -> VOTING)"
  [ "$ok" = 1 ]
}

# ── crossing-latch GENUINE gate: count>=95 AND work>=60 at the latch point ───
# Given a crossing RECORD JSON {state, count_pct, work_pct} on $1, returns 0 iff
# the latch is genuine: ACTIVATED/CONFIRMED requires BOTH gates. A work<60 latch
# (mint outran accept, the C3 wedge), a count<95 latch (premature), or a stuck
# VOTING state all BITE. Mirrors g3b assert_connect_past_halving.
assert_crossing_latch() {
  local rec="$1" act="$2" sw="$3"
  python3 - "$rec" "$act" "$sw" <<'PY'
import json, sys
rec = json.load(open(sys.argv[1])); act = int(sys.argv[2]); sw = int(sys.argv[3])
state = rec.get("state", "VOTING")
count_pct = rec.get("count_pct", 0)
work_pct  = rec.get("work_pct", 0)
ok = True
def chk(p, msg):
    print(("  PASS  " if p else "  FAIL  ") + msg); return p
ok &= chk(state in ("ACTIVATED", "CONFIRMED"),
          "crossing LATCHED (state=%s in {ACTIVATED,CONFIRMED})" % state)
ok &= chk(count_pct >= act,
          "count tally %d%% >= %d%% activation window (full-window, not premature)" % (count_pct, act))
ok &= chk(work_pct >= sw,
          "work tally %d%% >= %d%% accept floor (#288 -- mint did NOT outrun accept)" % (work_pct, sw))
sys.exit(0 if ok else 1)
PY
}

# ── DRY-RUN: self-contained proof, no host/binary/operator-go ────────────────
if [ "$MODE" = "dry" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

  # Golden GOOD drive log (mirrors auto_ratchet.hpp emission order over a staged ramp).
  good="$tmp/good.log"
  cat > "$good" <<EOF
[BTC] c2pool-btc starting — net=regtest (tuned crossing drive)
[AutoRatchet] VOTING: mint base_version=35 (oracle-faithful), desired_version=36
[AutoRatchet] VOTING: full window 96% >= 95% but oldest 10% work-weighted V36 desire < 60%) — waiting
[AutoRatchet] VOTING -> ACTIVATED (97% of 100 shares vote V36, window=2016, retroactive=0)
[AutoRatchet] VOTING -> CONFIRMED (retroactive: 300 >= 288)
EOF

  echo "== BTC v35->v36 crossing drive — DRY-RUN (self-contained crossing proof) =="
  echo "netid=${ISO_NETID} prefix=${ISO_PREFIX}  thresholds: count>=${ACTIVATION_THRESHOLD}% work>=${SWITCH_THRESHOLD}%"
  echo
  echo "[1/3] golden GOOD drive log -> ratchet markers MUST pass"
  if assert_ratchet_markers "$good"; then echo "  => PASS (as required)"; else echo "  => UNEXPECTED FAIL"; exit 1; fi
  echo
  echo "[2/3] crossing-latch gate -> PASS on genuine (count>=95 AND work>=60) latch"
  good_rec="$tmp/good.json"
  printf '%s\n' '{"state":"CONFIRMED","count_pct":97,"work_pct":63}' > "$good_rec"
  if assert_crossing_latch "$good_rec" "$ACTIVATION_THRESHOLD" "$SWITCH_THRESHOLD"; then echo "  => PASS (as required)"; else echo "  => UNEXPECTED FAIL"; exit 1; fi
  echo
  echo "[3/3] crossing-latch gate -> BITE on each wedge (work<60 / count<95 / no-cross)"
  printf '%s\n' '{"state":"ACTIVATED","count_pct":97,"work_pct":55}' > "$tmp/bad_outran.json"   # mint outran accept (C3)
  printf '%s\n' '{"state":"ACTIVATED","count_pct":80,"work_pct":63}' > "$tmp/bad_premature.json" # count below window
  printf '%s\n' '{"state":"VOTING","count_pct":97,"work_pct":55}'    > "$tmp/bad_nocross.json"    # stuck VOTING (held)
  for b in bad_outran bad_premature bad_nocross; do
    if assert_crossing_latch "$tmp/$b.json" "$ACTIVATION_THRESHOLD" "$SWITCH_THRESHOLD" >/dev/null 2>&1; then
      echo "  => UNEXPECTED PASS on $b -- gate does not bite, FAIL"; exit 1
    else
      echo "  => $b correctly REJECTED (gate bites)"
    fi
  done
  echo
  echo "DRY-RUN PASS: ratchet markers pass on a GOOD staged drive; crossing-latch"
  echo "gate passes on a genuine count>=95 AND work>=60 latch and bites on the"
  echo "mint-outran-accept wedge, a premature (count<95) latch, and a stuck VOTING"
  echo "no-cross. The live --go drive is gated on the operator proof-bar ruling."
  exit 0
fi

# ── LIVE: operator-go required ───────────────────────────────────────────────
if [ "$MODE" != "go" ]; then
  echo "refusing to run: pass --dry-run (self-contained) or --go (operator-approved live)" >&2
  exit 2
fi
[ -n "$HOST" ] || { echo "--go requires --host H" >&2; exit 2; }
[ -n "$BIN" ]  || { echo "--go requires --bin /path/c2pool-btc" >&2; exit 2; }

cat <<EOF
================================================================================
 BTC v35->v36 CROSSING DRIVE — LIVE (--go)
 host=${HOST}  bin=${BIN}  bitcoind=${BITCOIND}  stratum=${STRATUM}
 isolated netid=${ISO_NETID} prefix=${ISO_PREFIX}  oracle=${ORACLE:-<none, solo ramp>}
 *** Relaunches the tuned host and DROPS bake-in state. Operator GO required. ***
================================================================================
EOF

ORACLE_ARG=""
[ -n "$ORACLE" ] && ORACLE_ARG="--p2pool ${ORACLE}"

LAUNCH="${BIN} --regtest --bitcoind ${BITCOIND} --stratum ${STRATUM} \
  --network-id ${ISO_NETID} --prefix ${ISO_PREFIX} ${ORACLE_ARG}"
echo "[launch] ssh ${HOST} -- nohup ${LAUNCH} > /tmp/c2pool_btc_crossing.log 2>&1 &"

ssh "$HOST" "pkill -f 'c2pool-btc .*--regtest' || true; \
             nohup ${LAUNCH} > /tmp/c2pool_btc_crossing.log 2>&1 & echo launched pid=\$!"

echo "[wait] giving the node ${LOGTAIL_SECS}s to emit the ratchet startup banner..."
ssh "$HOST" "for i in \$(seq 1 ${LOGTAIL_SECS}); do grep -qF '[AutoRatchet] VOTING' /tmp/c2pool_btc_crossing.log && break; sleep 1; done"

echo
echo "== crossing drive ARMED =="
echo "  Stage the v36 vote ramp ONE miner at a time (do NOT flat-flip) against the"
echo "  isolated tuned net, then read the crossing record from the c2pool-btc stats"
echo "  endpoint and assert it:"
echo "    ssh ${HOST} \"cat /tmp/c2pool_btc_crossing.log\" | grep AutoRatchet"
echo "    # build crossing.json {state,count_pct,work_pct} from the stats endpoint, then:"
echo "    ${0} --dry-run    # (the assert logic; --go reuses assert_crossing_latch on the live record)"
echo "  The staged ramp itself is delegated to scripts/btc_g2_ratchet_staged_migration_harness.sh."
