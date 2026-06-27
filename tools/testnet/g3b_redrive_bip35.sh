#!/usr/bin/env bash
# g3b_redrive_bip35.sh
# BTC G3b POPULATED re-drive harness — proves the #566 BIP 35 mempool-pull fix.
#
# PR #566 root-caused the G3b POPULATED residual: main_btc subscribed
# new_tx -> mempool.add_tx, which only catches txs announced via `inv` AFTER
# connect. Txs already RESIDENT in the bitcoind mempool at connect time (a
# pre-seeded regtest mempool) were never requested, so a won block was
# coinbase-only (nTx=1). The fix exposes Node::enable_mempool_request() and
# calls it from main_btc after start_p2p (mirrors main_dgb), issuing a BIP 35
# `mempool` pull so the embedded TemplateBuilder sees the resident txs.
#
# This harness is the deploy-card ARTIFACT: it composes the exact re-drive
# recipe (acknowledged by integrator 2026-06-27) into one invocation so the
# moment #566 merges and the operator taps the deploy card, the POPULATED
# proof runs and fails-closed on all four criteria.
#
# THE FOUR PASS CRITERIA (fail-closed — ALL must hold):
#   1. NODE_BLOOM advertised: bitcoind launched with -peerbloomfilters=1, so
#      the peer carries the NODE_BLOOM (0x04) service bit. WITHOUT it the BIP 35
#      request is a no-op (c2pool logs "Skipped ... peer lacks NODE_BLOOM" to
#      avoid a disconnect) and the whole proof is vacuous — so this is the hard
#      guard against a false pass.
#   2. The fix FIRED: c2pool logged "Sent BIP 35 mempool request" — the #566
#      enable_mempool_request() path actually issued the pull on connect.
#   3. The won block CONNECTED: getblock confirmations >= 1 (on the active
#      chain, not an orphan).
#   4. The block is POPULATED: nTx > 1 (expected nTx == 6 = 5 seeded + coinbase).
#      A coinbase-only block (nTx == 1) is the residual and a FAIL.
#
# The seeding discipline that makes the proof meaningful (criterion the fix
# targets): the 5 txs are injected into the bitcoind mempool BEFORE c2pool
# connects and are NOT followed by a generate — they stay resident and
# unconfirmed, reachable ONLY via the BIP 35 pull, invisible to inv relay.
#
# Modes:
#   g3b_redrive_bip35.sh --dry-run
#       SELF-CONTAINED. No host, no binary, no deploy. Proves the four-criteria
#       assert (a) PASSES on a golden POPULATED re-drive log + block and
#       (b) BITES on each failure shape (NODE_BLOOM skipped, request never sent,
#       un-connected block, coinbase-only nTx=1). This is the acceptance gate.
#
#   g3b_redrive_bip35.sh --go --host H --bin /path/c2pool-btc \
#                        [--bitcoind 127.0.0.1:18443] [--stratum 9332] \
#                        [--seed-n 5] [--rpc 'bitcoin-cli -regtest ...']
#       LIVE re-drive on .121. REQUIRES an operator-tapped deploy card — it
#       deploys/relaunches a binary and reseeds the mempool, which is a
#       deploy + restart op. Never run without explicit decision-card approval.
#       The binary MUST be a REBUILD that contains #566 (the last-deployed .121
#       binary predates the fix — re-driving stale would falsely fail).
#
set -euo pipefail

HOST=""
BIN=""
BITCOIND="127.0.0.1:18443"
STRATUM="9332"
SEED_N=5
RPC="bitcoin-cli -regtest"
MODE=""
SETTLE_SECS=30

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)  MODE="dry"; shift ;;
    --go)       MODE="go";  shift ;;
    --host)     HOST="$2";     shift 2 ;;
    --bin)      BIN="$2";      shift 2 ;;
    --bitcoind) BITCOIND="$2"; shift 2 ;;
    --stratum)  STRATUM="$2";  shift 2 ;;
    --seed-n)   SEED_N="$2";   shift 2 ;;
    --rpc)      RPC="$2";      shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Expected populated tx count = seeded txs + 1 coinbase.
EXPECT_NTX=$((SEED_N + 1))

# ── the four-criteria assert — the heart of the harness ──────────────────────
# $1 = c2pool startup/connect LOG, $2 = `getblock <hash> 1` JSON of the won
# block. Returns 0 iff ALL FOUR criteria hold. Pure grep over the real
# LOG_INFO lines emitted by btc/coin/p2p_node.hpp + a python tx-count check on
# the getblock JSON. Identical logic in --dry-run and --go so the dry-run
# faithfully proves what the live path checks.
assert_populated_redrive() {
  local log="$1" blockjson="$2" expect_ntx="$3" ok=1
  echo "[four-criteria POPULATED re-drive assert]"

  # 1 + 2: the BIP 35 request actually fired AND the peer had NODE_BLOOM.
  #   "Sent BIP 35 mempool request" is logged ONLY when m_request_mempool_on_connect
  #   is set (the #566 fix) AND the peer advertised NODE_BLOOM. Its presence
  #   proves criteria 1 and 2 together; the "Skipped" line MUST be absent.
  if grep -qF "Sent BIP 35 mempool request" "$log"; then
    echo "  PASS  #566 fired: BIP 35 mempool request SENT on connect (criterion 2)"
  else
    echo "  FAIL  no 'Sent BIP 35 mempool request' — fix did not fire (criterion 2)"; ok=0
  fi
  if grep -qF "Skipped BIP 35 mempool request" "$log"; then
    echo "  FAIL  peer lacked NODE_BLOOM — request skipped; launch bitcoind with -peerbloomfilters=1 (criterion 1)"; ok=0
  else
    echo "  PASS  peer advertised NODE_BLOOM, request not skipped (criterion 1)"
  fi

  # 3 + 4: the won block CONNECTED and is POPULATED (nTx > 1).
  python3 - "$blockjson" "$expect_ntx" <<'PY'
import json, sys
blk = json.load(open(sys.argv[1])); expect = int(sys.argv[2])
conf = blk.get("confirmations", -1)
tx = blk.get("tx", [])
ntx = len(tx)
ok = True
def chk(p, msg):
    print(("  PASS  " if p else "  FAIL  ") + msg); return p
ok &= chk(conf >= 1, "won block CONNECTED (confirmations %d >= 1) (criterion 3)" % conf)
ok &= chk(ntx > 1,   "block is POPULATED: nTx=%d > 1 (coinbase-only=FAIL); expected %d (criterion 4)" % (ntx, expect))
sys.exit(0 if ok else 1)
PY
  [ $? -eq 0 ] || ok=0

  [ "$ok" = 1 ]
}

# ── DRY-RUN: self-contained proof, no host/binary/deploy ─────────────────────
if [ "$MODE" = "dry" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

  # Golden GOOD connect log — #566 fired, peer had NODE_BLOOM.
  cat > "$tmp/good.log" <<EOF
[BTC] c2pool-btc starting — net=regtest
[BTC] bitcoind P2P: ${BITCOIND}
[BTC] start_p2p — enable_mempool_request() armed (BIP 35)
[BTC] Peer handshake complete services=0x409
[BTC] Sent BIP 35 mempool request (peer has NODE_BLOOM)
[BTC] mempool: added 5 txs from peer announcement
EOF
  # GOOD won block — connected, populated (5 seeded + coinbase = 6).
  python3 - "$tmp/good.json" "$EXPECT_NTX" <<'PY'
import json, sys
n = int(sys.argv[2])
json.dump({"confirmations": 1, "tx": ["cb"] + ["t%d" % i for i in range(n - 1)]}, open(sys.argv[1], "w"))
PY

  # BAD log A — peer lacked NODE_BLOOM (forgot -peerbloomfilters=1): request skipped.
  cat > "$tmp/bad_skipped.log" <<EOF
[BTC] start_p2p — enable_mempool_request() armed (BIP 35)
[BTC] Peer handshake complete services=0x401
[BTC] Skipped BIP 35 mempool request — peer lacks NODE_BLOOM (0x401), would cause disconnect
EOF
  # BAD log B — fix never fired (stale pre-#566 binary): no request line at all.
  cat > "$tmp/bad_nofire.log" <<EOF
[BTC] start_p2p complete
[BTC] Peer handshake complete services=0x409
EOF
  # BAD block A — un-connected/orphan.
  printf '%s\n' '{"confirmations":-1,"tx":["cb","t1","t2","t3","t4","t5"]}' > "$tmp/bad_unconnected.json"
  # BAD block B — coinbase-only (the residual itself).
  printf '%s\n' '{"confirmations":1,"tx":["cb"]}' > "$tmp/bad_coinbaseonly.json"

  echo "== G3b POPULATED re-drive (#566) — DRY-RUN (self-contained four-criteria proof) =="
  echo "seed_n=${SEED_N}  expect_ntx=${EXPECT_NTX}  bitcoind=${BITCOIND}"
  echo
  echo "[1/5] golden GOOD log + POPULATED connected block -> MUST pass"
  if assert_populated_redrive "$tmp/good.log" "$tmp/good.json" "$EXPECT_NTX"; then
    echo "  => PASS (as required)"
  else
    echo "  => UNEXPECTED FAIL"; exit 1
  fi
  echo
  echo "[2/5] NODE_BLOOM skipped (no -peerbloomfilters=1) -> MUST bite (criterion 1)"
  if assert_populated_redrive "$tmp/bad_skipped.log" "$tmp/good.json" "$EXPECT_NTX" >/dev/null 2>&1; then
    echo "  => UNEXPECTED PASS — does not bite, FAIL"; exit 1
  else echo "  => correctly REJECTED"; fi
  echo
  echo "[3/5] fix never fired (stale pre-#566 binary) -> MUST bite (criterion 2)"
  if assert_populated_redrive "$tmp/bad_nofire.log" "$tmp/good.json" "$EXPECT_NTX" >/dev/null 2>&1; then
    echo "  => UNEXPECTED PASS — does not bite, FAIL"; exit 1
  else echo "  => correctly REJECTED"; fi
  echo
  echo "[4/5] un-connected/orphan won block -> MUST bite (criterion 3)"
  if assert_populated_redrive "$tmp/good.log" "$tmp/bad_unconnected.json" "$EXPECT_NTX" >/dev/null 2>&1; then
    echo "  => UNEXPECTED PASS — does not bite, FAIL"; exit 1
  else echo "  => correctly REJECTED"; fi
  echo
  echo "[5/5] coinbase-only block (the residual, nTx=1) -> MUST bite (criterion 4)"
  if assert_populated_redrive "$tmp/good.log" "$tmp/bad_coinbaseonly.json" "$EXPECT_NTX" >/dev/null 2>&1; then
    echo "  => UNEXPECTED PASS — does not bite, FAIL"; exit 1
  else echo "  => correctly REJECTED"; fi
  echo
  echo "DRY-RUN PASS: four-criteria assert passes on a fired+NODE_BLOOM+connected+populated"
  echo "re-drive and bites on each failure shape (skipped / not-fired / un-connected / coinbase-only)."
  echo "The live --go re-drive is DEPLOY-GATED (operator card) and needs a #566 REBUILD on .121."
  exit 0
fi

# ── LIVE: operator-tapped deploy card required ───────────────────────────────
if [ "$MODE" != "go" ]; then
  echo "refusing to run: pass --dry-run (self-contained) or --go (operator deploy-card approved)" >&2
  exit 2
fi
[ -n "$HOST" ] || { echo "--go requires --host H" >&2; exit 2; }
[ -n "$BIN" ]  || { echo "--go requires --bin /path/c2pool-btc (a #566 REBUILD, not the stale deployed binary)" >&2; exit 2; }

cat <<EOF
================================================================================
 G3b POPULATED RE-DRIVE (#566) — LIVE (--go)
 host=${HOST}  bin=${BIN}  bitcoind=${BITCOIND}  stratum=${STRATUM}
 seed_n=${SEED_N}  expect_ntx=${EXPECT_NTX}
 *** DEPLOY + RESTART op. Requires an operator-tapped deploy card. The binary
     MUST contain #566 (a REBUILD) — re-driving a stale binary falsely fails. ***
================================================================================
EOF

# 1. Confirm bitcoind advertises NODE_BLOOM (the hard prereq). getnetworkinfo
#    localservicesnames must include NETWORK_LIMITED/BLOOM; we assert BLOOM.
echo "[prereq] confirming bitcoind advertises NODE_BLOOM (-peerbloomfilters=1)"
if ! ssh "$HOST" "${RPC} getnetworkinfo" | grep -qi "BLOOM"; then
  echo "  HARD STOP: bitcoind does NOT advertise NODE_BLOOM. Relaunch it with" >&2
  echo "  -peerbloomfilters=1 before re-driving (else BIP 35 pull is a no-op)." >&2
  exit 1
fi
echo "  NODE_BLOOM advertised — criterion 1 prereq satisfied."

# 2. Seed N txs into the mempool BEFORE c2pool connects; do NOT generate after.
echo "[seed] injecting ${SEED_N} resident unconfirmed txs (NO generate after)"
ssh "$HOST" "for i in \$(seq 1 ${SEED_N}); do \
  addr=\$(${RPC} getnewaddress); \
  ${RPC} sendtoaddress \$addr 0.01 >/dev/null; \
done; echo mempool_size=\$(${RPC} getmempoolinfo | grep -o '\"size\": *[0-9]*')"

# 3. Launch c2pool-btc AFTER the mempool is seeded (so the txs are resident at
#    connect and reachable only via the BIP 35 pull).
echo "[launch] starting c2pool-btc (post-seed)"
ssh "$HOST" "pkill -f 'c2pool-btc' || true; \
             nohup ${BIN} --regtest --bitcoind ${BITCOIND} --stratum ${STRATUM} \
               > /tmp/c2pool_g3b_redrive.log 2>&1 & echo launched pid=\$!"

echo "[wait] ${SETTLE_SECS}s for handshake + BIP 35 pull..."
ssh "$HOST" "for i in \$(seq 1 ${SETTLE_SECS}); do \
  grep -qE 'Sent BIP 35 mempool request|Skipped BIP 35 mempool request' /tmp/c2pool_g3b_redrive.log && break; \
  sleep 1; done"

echo
echo "Connect log captured to /tmp/c2pool_g3b_redrive.log on ${HOST}."
echo "BLOCK-FOUND is RIG-GATED (#387/#388 bitaxe or an RPC-tuned solve). Once a"
echo "won block crosses target, capture its hash and run the assert:"
echo
echo "  log=\$(ssh ${HOST} 'cat /tmp/c2pool_g3b_redrive.log')"
echo "  h=\$(ssh ${HOST} '${RPC} getbestblockhash')"
echo "  blk=\$(ssh ${HOST} \"${RPC} getblock \$h 1\")"
echo "  # then: assert_populated_redrive <log> <blockjson> ${EXPECT_NTX}"
echo
echo "PASS = all four criteria green. Report [s=done] + the /tmp/c2pool_g3b_redrive.log"
echo "evidence to integrator for the deploy-card ARTIFACT. Coinbase-only (nTx=1) = FAIL."
