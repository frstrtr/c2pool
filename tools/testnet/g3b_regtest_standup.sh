#!/usr/bin/env bash
# g3b_regtest_standup.sh
# BTC G3b LIVE standup harness — isolated regtest sharechain, tap-then-one-command.
#
# Composes the whole G3b relaunch into a single invocation so that, the moment
# the operator taps GO, the isolated regtest host comes up with a sharechain
# namespace that PROVABLY cannot touch the public mainnet sharechain, and the
# dual-path won-block capture is armed and waiting for the (rig-gated) solve.
#
# The isolation invariant this harness gates on (the #506 / .121-incident fix):
#   1. net_name resolves to "bitcoin_regtest" (regtest checked FIRST — a
#      testnet-only switch would resolve to "bitcoin" = MAINNET and silently
#      join the prod sharechain; locked by config_coin.hpp:sharechain_net_name
#      + regtest_sharechain_isolation_test.cpp).
#   2. ZERO public seeds dialed — regtest never loads DEFAULT_BOOTSTRAP_HOSTS;
#      the addr store stays empty so a won block is never relayed to real peers.
#   3. The sharechain PREFIX / network-id are CLI-driven (--prefix/--network-id),
#      isolated and NON-default, so the P2P namespace cannot collide with prod.
#
# These three are the ISOLATION PRIMITIVE (3-bucket rule, bucket 1): KEEP
# per-instance, NEVER standardize. This harness asserts them, it does not change
# them.
#
# DUAL-PATH CAPTURE (the G3b proof): a won parent block must REACH THE NETWORK
# down either broadcaster leg, never silently drop:
#   ARM A  on_block_found  -> P2P block relay   (refactored.cpp m_on_block_found)
#   ARM B  submitblock RPC -> FALLBACK          (main_btc.cpp [BTC-SUBMIT] ->
#                                                node.hpp submit_block_with_fallback
#                                                -> core::broadcast_block_with_fallback)
# P2P is PRIMARY, RPC is the never-silent-drop FALLBACK. In an ISOLATED regtest
# with 0 P2P peers, ARM B (submitblock RPC to the parent regtest bitcoind) is the
# delivering leg; ARM A is exercised only when an explicit isolated tuned-net peer
# is dialed via --p2pool. The structured both-arms x 3-regime capture is delegated
# to tools/testnet/g3b_block_acceptance.py --live (this script launches + asserts
# isolation, then arms that capture).
#
# Modes:
#   g3b_regtest_standup.sh --dry-run
#       SELF-CONTAINED. No host, no binary, no operator-go required. Proves the
#       isolation asserts (a) PASS against a golden regtest startup log and
#       (b) BITE against a mainnet-shaped log, and confirms the block-FOUND
#       counter is 0 (no block produced). This is the acceptance gate.
#
#   g3b_regtest_standup.sh --go --host H --bin /path/c2pool-btc \
#                          [--bitcoind 127.0.0.1:18443] [--stratum 9332] \
#                          [--network-id HEX] [--prefix HEX] [--p2pool HOST:PORT]
#       LIVE. Relaunches the isolated regtest host, runs the SAME isolation
#       asserts against the REAL startup log, then arms the dual-path capture.
#       REQUIRES operator GO — relaunching the host drops bake-in state. Never
#       run without an explicit decision-card approval. The block-FOUND step is
#       RIG-GATED (#387/#388 bitaxe, or an RPC-tuned `generatetoaddress` solve).
#
set -euo pipefail

# ── isolated namespace defaults (NON-default, clearly not prod) ───────────────
# network-id / prefix are hex, <=8 bytes. These resolve to an isolated P2P
# sharechain namespace that cannot collide with the public mainnet prefix.
ISO_NETID="${ISO_NETID:-72656774}"   # "regt"
ISO_PREFIX="${ISO_PREFIX:-67337274}" # "g3rt"  (G3b regtest)

MODE=""
HOST=""
BIN=""
BITCOIND="127.0.0.1:18443"
STRATUM="9332"
P2POOL=""           # explicit isolated tuned-net peer for ARM A (optional)
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
    --p2pool)      P2POOL="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ── the isolation assert — the heart of the harness ──────────────────────────
# Given a c2pool-btc STARTUP log on stdin, returns 0 iff ALL isolation
# invariants hold. Pure grep over the real LOG_INFO lines emitted by
# main_btc.cpp; identical logic in --dry-run and --go so the dry-run is a
# faithful proof of what the live path checks.
assert_isolation() {
  local log="$1" prefix="$2" ok=1
  _need() { if grep -qF -- "$1" "$log"; then echo "  PASS  $2"; else echo "  FAIL  $2"; ok=0; fi; }
  _deny() { if grep -qF -- "$1" "$log"; then echo "  FAIL  $2 (saw forbidden: $1)"; ok=0; else echo "  PASS  $2"; fi; }

  echo "[isolation asserts]"
  # 1. net_name resolves to bitcoin_regtest (regtest-FIRST; #506 fix)
  _need "net=regtest"                                  "net == regtest"
  _need "bitcoin_regtest/embedded_headers"             "sharechain namespace == bitcoin_regtest (HeaderChain DB)"
  # 2. ZERO public seeds dialed
  _need "0 public seeds (isolated)"                    "regtest bootstrap == 0 public seeds"
  _need "Outbound peer dialing started (0 bootstrap addrs)" "outbound dialing == 0 bootstrap addrs"
  # 3. isolated, non-default sharechain prefix actually applied
  _need "prefix=${prefix}"                             "sharechain prefix == isolated ${prefix}"
  # negative guards — these MUST be absent under a correct regtest standup
  _deny "default seeds"                                "did NOT load DEFAULT_BOOTSTRAP_HOSTS"
  _deny "net=mainnet"                                  "did NOT start on mainnet"

  [ "$ok" = 1 ]
}

# Count block-FOUND events in a log (the dual-path trigger). In --dry-run with a
# startup-only log this is 0 — "isolation asserts pass WITHOUT a block".
count_blocks_found() { grep -cF "[BTC-SUBMIT] sending block" "$1" || true; }

# ── DRY-RUN: self-contained proof, no host/binary/operator-go ────────────────
if [ "$MODE" = "dry" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  good="$tmp/good.log"; bad="$tmp/bad.log"

  # Golden GOOD regtest startup log (mirrors main_btc.cpp emission order).
  cat > "$good" <<EOF
[BTC] c2pool-btc starting — net=regtest
[BTC] HeaderChain DB: /root/.c2pool/bitcoin_regtest/embedded_headers
[BTC] UTXO DB:        /root/.c2pool/bitcoin_regtest/utxo_view_db
[BTC] Genesis:        0f9188f13cb7b2c779a87632b35a3e8b2b1a3f3e... (regtest)
[BTC] bitcoind P2P:   ${BITCOIND}
[BTC] Sharechain bootstrap: regtest — 0 public seeds (isolated)
[BTC] Sharechain peer listening on port 9333 — proto adv=3502 min=3301 share=v35 prefix=${ISO_PREFIX}
[BTC] Outbound peer dialing started (0 bootstrap addrs)
EOF

  # NEGATIVE mainnet-shaped log — the asserts MUST reject this (proves they bite).
  cat > "$bad" <<EOF
[BTC] c2pool-btc starting — net=mainnet
[BTC] HeaderChain DB: /root/.c2pool/bitcoin/embedded_headers
[BTC] Sharechain bootstrap: 7 default seeds
[BTC] Sharechain peer listening on port 9333 — proto adv=3502 min=3301 share=v35 prefix=deadbeef
[BTC] Outbound peer dialing started (7 bootstrap addrs)
EOF

  echo "== G3b regtest standup — DRY-RUN (self-contained isolation proof) =="
  echo "netid=${ISO_NETID} prefix=${ISO_PREFIX}"
  echo
  echo "[1/3] golden GOOD regtest startup -> asserts MUST pass"
  if assert_isolation "$good" "$ISO_PREFIX"; then echo "  => PASS (as required)"; else echo "  => UNEXPECTED FAIL"; exit 1; fi
  echo
  echo "[2/3] NEGATIVE mainnet-shaped startup -> asserts MUST bite"
  if assert_isolation "$bad" "$ISO_PREFIX" >/dev/null 2>&1; then
    echo "  => UNEXPECTED PASS — asserts do not bite, FAIL"; exit 1
  else
    echo "  => correctly REJECTED (asserts bite)"
  fi
  echo
  echo "[3/3] block-FOUND counter on startup-only log (must be 0 — no block)"
  nfound="$(count_blocks_found "$good")"
  echo "  blocks_found=${nfound}"
  [ "$nfound" = "0" ] || { echo "  => UNEXPECTED block on startup log, FAIL"; exit 1; }
  echo
  echo "DRY-RUN PASS: isolation asserts pass on GOOD, bite on BAD, 0 blocks."
  echo "block-FOUND step is RIG-GATED (#387/#388 bitaxe or RPC-tuned solve) —"
  echo "the live --go run arms it; no block is mined here."
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
 G3b REGTEST STANDUP — LIVE (--go)
 host=${HOST}  bin=${BIN}  bitcoind=${BITCOIND}  stratum=${STRATUM}
 isolated netid=${ISO_NETID} prefix=${ISO_PREFIX}  p2pool=${P2POOL:-<none, ARM B only>}
 *** This relaunches the regtest host and DROPS bake-in state. Operator GO required. ***
================================================================================
EOF

P2POOL_ARG=""
[ -n "$P2POOL" ] && P2POOL_ARG="--p2pool ${P2POOL}"

LAUNCH="${BIN} --regtest --bitcoind ${BITCOIND} --stratum ${STRATUM} \
  --network-id ${ISO_NETID} --prefix ${ISO_PREFIX} ${P2POOL_ARG}"
echo "[launch] ssh ${HOST} -- nohup ${LAUNCH} > /tmp/c2pool_btc_g3b.log 2>&1 &"

# Relaunch (fail closed: any ssh/launch error aborts before asserting).
ssh "$HOST" "pkill -f 'c2pool-btc .*--regtest' || true; \
             nohup ${LAUNCH} > /tmp/c2pool_btc_g3b.log 2>&1 & echo launched pid=\$!"

echo "[wait] giving the node ${LOGTAIL_SECS}s to emit startup banner..."
# (deliberately a fixed settle window, not a sleep loop, to keep the heartbeat honest)
ssh "$HOST" "for i in \$(seq 1 ${LOGTAIL_SECS}); do grep -qF 'Outbound peer dialing started' /tmp/c2pool_btc_g3b.log && break; sleep 1; done"

tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
ssh "$HOST" "cat /tmp/c2pool_btc_g3b.log" > "$tmp"

echo
if assert_isolation "$tmp" "$ISO_PREFIX"; then
  echo "ISOLATION PROVEN on live regtest host."
else
  echo "ISOLATION ASSERT FAILED on live host — HARD STOP. Killing node." >&2
  ssh "$HOST" "pkill -f 'c2pool-btc .*--regtest' || true"
  exit 1
fi

echo
echo "== dual-path capture ARMED =="
echo "  ARM A (P2P relay):   ${P2POOL:+dialing $P2POOL}${P2POOL:-not armed — pass --p2pool for the P2P leg}"
echo "  ARM B (submitblock): live to ${BITCOIND}"
echo "  capture: tools/testnet/g3b_block_acceptance.py --live   (both arms x v35/HYBRID/v36)"
echo "  watch:   ssh ${HOST} \"tail -f /tmp/c2pool_btc_g3b.log | grep -E '\\[BTC-SUBMIT\\]|reached|lost subsidy'\""
echo
echo "BLOCK-FOUND is RIG-GATED: needs a SHA256d solve over parent target —"
echo "#387/#388 bitaxe, or an RPC-tuned 'generatetoaddress' on the regtest daemon."
echo "Until a block crosses target, no [BTC-SUBMIT] line fires; that is expected."
