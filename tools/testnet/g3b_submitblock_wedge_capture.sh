#!/bin/bash
# g3b_submitblock_wedge_capture.sh
#
# Pre-staged, one-command capture for the .234 G3b regtest submitblock lock-wedge.
#
# CONTEXT (evidence standing on its own, without frames):
#   - c2pool submitblock RPC into the regtest bitcoind climbs monotonically
#     (observed 65s -> 78s), getblockchaininfo wedges in lockstep, a bare
#     getrpcinfo still returns in ~30us, scriptcheck threads idle, debug.log
#     goes silent after a height-689 churn. That is a strong lock-wedge case.
#   - The current wedge is on a STRIPPED bitcoind (frames unreliable:
#     stripped binary + libthread_db mismatch). This script is meant to run
#     AFTER the operator relaunches the regtest bitcoind with a SYMBOLIZED
#     build, so `thread apply all bt full` yields real frames.
#
# TARGETING (do not trip on the two-daemon trap):
#   There are TWO bitcoind on .234:
#     - regtest:  -datadir=/home/ubuntu/regtest-datadir , RPC 127.0.0.1:18443
#     - the other: default ~/.bitcoin  (a bare `bitcoin-cli` hits THIS one)
#   Every RPC below pins BOTH -datadir AND -rpcport=18443 so it can only ever
#   speak to the regtest daemon. The gdb target PID is discovered by the
#   `bitcoind ... regtest-datadir` command line, never hardcoded (the old
#   wedged PID 37590 dies on relaunch).
#
# USAGE:
#   ./g3b_submitblock_wedge_capture.sh watch     # poll for wedge, auto-capture (default)
#   ./g3b_submitblock_wedge_capture.sh now       # capture immediately (wedge already live)
#   ./g3b_submitblock_wedge_capture.sh relaunch  # relaunch symbolized bitcoind + c2pool + miner
#
# ENV overrides:
#   BITCOIND_BIN   path to the SYMBOLIZED bitcoind for `relaunch` (operator-provided)
#   WEDGE_US       submitblock duration (microseconds) that triggers capture (default 20000000 = 20s)
#   OUTDIR         where captures land (default /home/ubuntu/g3b-wedge-captures)

set -u

DATADIR=/home/ubuntu/regtest-datadir
RPCPORT=18443
BCLI="bitcoin-cli -datadir=${DATADIR} -rpcconnect=127.0.0.1 -rpcport=${RPCPORT}"
LIBS=/home/ubuntu/c2pool-libs
WEDGE_US="${WEDGE_US:-20000000}"
OUTDIR="${OUTDIR:-/home/ubuntu/g3b-wedge-captures}"
BITCOIND_BIN="${BITCOIND_BIN:-/usr/local/bin/bitcoind}"
mkdir -p "$OUTDIR"

regtest_pid() {
  # the bitcoind whose command line carries our regtest datadir
  pgrep -f "bitcoind.*regtest-datadir" | head -1
}

snapshot_rpc() {
  # $1 = destination file. getrpcinfo (active commands + durations) is the
  # primary live discriminator; a bare getrpcinfo returning fast is the
  # ~30us control that proves the RPC layer itself is alive.
  local out="$1"
  {
    echo "=== $(date -u +%FT%TZ) getrpcinfo (active_commands + durations) ==="
    t0=$(date +%s%N); $BCLI getrpcinfo 2>&1; t1=$(date +%s%N)
    echo "getrpcinfo_wall_us=$(( (t1 - t0) / 1000 ))   # ~30us = RPC layer alive"
    echo "=== getblockchaininfo (expected WEDGED in lockstep if cs_main held) ==="
    timeout 5 $BCLI getblockchaininfo 2>&1 || echo "getblockchaininfo TIMED OUT (wedged) <-- consistent with cs_main contention"
  } >> "$out" 2>&1
}

do_capture() {
  local pid; pid=$(regtest_pid)
  if [ -z "$pid" ]; then echo "FATAL: no regtest bitcoind (bitcoind.*regtest-datadir) running"; exit 2; fi
  local stamp; stamp=$(date -u +%Y%m%dT%H%M%SZ)
  local base="${OUTDIR}/wedge_${stamp}_pid${pid}"
  echo "capturing regtest bitcoind pid=$pid -> ${base}.*"

  # 1) live RPC discriminator alongside the frames
  snapshot_rpc "${base}.rpc.txt"

  # 2) the frames. bt full so we can read locals (which cs_* the owner holds).
  gdb -q -batch -p "$pid" \
    -ex "set pagination off" \
    -ex "set print pretty on" \
    -ex "info inferiors" \
    -ex "info sharedlibrary" \
    -ex "info threads" \
    -ex "thread apply all bt full" \
    -ex "detach" -ex "quit" \
    > "${base}.gdb.txt" 2>&1

  echo "== capture written =="
  echo "  frames : ${base}.gdb.txt"
  echo "  rpc    : ${base}.rpc.txt"
  echo
  verdict_rubric
}

verdict_rubric() {
cat <<'RUBRIC'
================= FALSIFIABILITY RUBRIC — decide BEFORE reading frames ==========
Bitcoin Core v28.1: cs_main is `RecursiveMutex cs_main` (a recursive std mutex);
cs_wallet is per-wallet `RecursiveMutex cs_wallet`. submitblock enters
ChainstateManager::ProcessNewBlock -> ActivateBestChain (LOCK cs_main).

Method: in `thread apply all bt`, find the ONE thread doing WORK (not parked).
Every parked thread sits in __lll_lock_wait / futex_wait under
std::mutex::lock <- AnnotatedMixin<std::recursive_mutex>::lock. The single
non-parked thread is the lock OWNER. Read its top user frames:

CONFIRM  cs_main-on-submitblock  <== the hypothesis
  Owner is the httpworker running submitblock, ACTIVELY inside the
  chainstate/connect path and NOT in a lock-wait:
    ... HTTPWorkerThread -> ... -> submitblock
        -> ChainstateManager::ProcessNewBlock
        -> Chainstate::ActivateBestChain / ActivateBestChainStep
        -> ConnectTip / ConnectBlock / CCheckQueue / CheckInputScripts
  AND the getblockchaininfo httpworker is PARKED entering LOCK(cs_main).
  Corroborated by: getblockchaininfo wedged lockstep, bare getrpcinfo ~30us.

REFUTE  (points to cs_wallet instead)
  The submitblock thread is itself PARKED in a lock-wait (not doing connect
  work), and the working/owning thread is inside WALLET code holding cs_wallet:
    ... CWallet::blockConnected / SyncTransaction / AddToWallet /
        CommitTransaction / WalletBatch / leveldb write ...
  i.e. a wallet operation holds the load-bearing lock and submitblock is the
  victim, not the culprit. (Also refutes if submitblock's own top frames sit
  in cs_wallet acquisition rather than cs_main/ConnectBlock.)

UNDECIDED / re-shoot
  All threads parked (no visible owner) -> lock held by a thread in
  uninterruptible I/O (leveldb fsync): grab `bt full` of the I/O thread and
  read the datadir it's writing (regtest vs the other daemon).
================================================================================
RUBRIC
}

do_watch() {
  echo "watching regtest getrpcinfo for a submitblock duration >= ${WEDGE_US}us ..."
  while true; do
    dur=$($BCLI getrpcinfo 2>/dev/null | python3 -c '
import sys,json
try: j=json.load(sys.stdin)
except Exception: print(-1); sys.exit()
m=0
for c in j.get("active_commands",[]):
    if c.get("method")=="submitblock": m=max(m,int(c.get("duration",0)))
print(m)')
    ts=$(date -u +%FT%TZ)
    if [ "${dur:-0}" = "-1" ]; then
      echo "$ts  getrpcinfo itself not answering -> daemon may be fully wedged; capturing"
      do_capture; return
    fi
    echo "$ts  submitblock active duration=${dur}us (trigger>=${WEDGE_US})"
    if [ "${dur:-0}" -ge "$WEDGE_US" ]; then
      echo "$ts  WEDGE TRIGGER met -> capturing"
      do_capture; return
    fi
    sleep 10
  done
}

do_relaunch() {
  # Operator-gated: only run once the symbolized bitcoind is in place.
  echo "relaunch: BITCOIND_BIN=$BITCOIND_BIN"
  "$BITCOIND_BIN" -datadir="$DATADIR" -daemon \
    -testactivationheight=bip34@1 -testactivationheight=dersig@1 \
    -testactivationheight=cltv@1 -testactivationheight=csv@1 \
    -testactivationheight=segwit@1
  sleep 5
  $BCLI getblockchaininfo | python3 -c 'import sys,json;j=json.load(sys.stdin);print("chain=",j["chain"],"blocks=",j["blocks"])'
  # c2pool with the SAME env the wedge reproduced under (LD_LIBRARY_PATH per libs dir)
  screen -dmS c2poolbtc bash -c "LD_LIBRARY_PATH=${LIBS} /home/ubuntu/c2pool-btc --regtest --bitcoind 127.0.0.1:18444 --coin-rpc 127.0.0.1:${RPCPORT} --coin-rpc-auth ${DATADIR}/bitcoin.conf --stratum 9442 --data-dir /home/ubuntu/.c2pool-btc-regtest > /home/ubuntu/c2pool-btc.log 2>&1"
  echo "c2pool relaunched (screen c2poolbtc). Start the g3bmine screen, then run: $0 watch"
}

case "${1:-watch}" in
  now)      do_capture ;;
  watch)    do_watch ;;
  relaunch) do_relaunch ;;
  *) echo "usage: $0 {watch|now|relaunch}"; exit 1 ;;
esac
