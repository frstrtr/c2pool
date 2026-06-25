#!/usr/bin/env bash
# vm130_btc_standup.sh
# Full G3b standup orchestrator for the BTC live lane on VM130
# (c2pool-btc-testnet @192.168.86.234, parent bitcoind = testnet3).
#
# One command from "IBD complete" to "c2pool-btc serving work on testnet3", so the
# eventual unblock (the SHA256d rig key #387/#388 lands, or testnet3 IBD finishes)
# is a single invocation, not a fresh scramble. Composes the readiness gate
# (which fails closed on IBD / missing broadcaster landing site) with launch.
#
# Modes:
#   single   one c2pool-btc instance on the default sharechain port (9333)
#   tuned    TWO instances (A on 9333, B on --sharechain-port N) for the G2/G3b
#            staged A->B crossing, reusing the opt-in --sharechain-port flag (#457)
#            so the second sharechain P2P is isolated and IBD-independent.
#
#   vm130_btc_standup.sh --dry-run                 # print the full plan, run nothing
#   vm130_btc_standup.sh --bin /path/c2pool-btc    # single-instance live standup
#   vm130_btc_standup.sh --bin ... --tuned --portB 9334
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/vm130_btc_readiness_gate.sh"
BITCOIND_P2P=127.0.0.1:18333
PORT_A=9333
PORT_B=9334
BIN=""
TUNED=0
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --tuned)   TUNED=1 ;;
    --bin)     BIN="$2"; shift ;;
    --portB)   PORT_B="$2"; shift ;;
    --bitcoind) BITCOIND_P2P="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

die(){ echo "STANDUP-FAIL: $*" >&2; exit 1; }
[ -x "$GATE" ] || die "readiness gate not found/executable at $GATE"

plan(){
  echo "== VM130 BTC G3b standup plan =="
  echo "parent     : bitcoind testnet3 via --bitcoind $BITCOIND_P2P"
  echo "mode       : $([ $TUNED -eq 1 ] && echo 'tuned (2-instance A->B crossing)' || echo 'single')"
  echo "step 1     : $GATE            # fail-closed: IBD + dual-path broadcaster preconditions"
  if [ $TUNED -eq 1 ]; then
    echo "step 2a    : <bin> --testnet --bitcoind $BITCOIND_P2P                       # instance A (port $PORT_A)"
    echo "step 2b    : <bin> --testnet --bitcoind $BITCOIND_P2P --sharechain-port $PORT_B  # instance B (isolated sharechain)"
    echo "step 3     : migrate OUR miners A->B one-by-one (G2 ratchet); watch work-weighted vote climb"
  else
    echo "step 2     : <bin> --testnet --bitcoind $BITCOIND_P2P                       # single instance (port $PORT_A)"
  fi
  echo "step 4     : run g3b_block_acceptance.py --live  -> FOUND->ASSEMBLED->ACCEPTED->BROADCAST (both arms)"
}

if [ $DRY -eq 1 ]; then
  plan
  echo
  echo "DRY-RUN: no daemon launched, no miner moved. Re-run with --bin <c2pool-btc> to execute."
  exit 0
fi

[ -n "$BIN" ] || die "live standup needs --bin /path/to/c2pool-btc (or use --dry-run)"
[ -x "$BIN" ] || die "--bin is not an executable: $BIN"

plan
echo "--- step 1: readiness gate ---"
"$GATE"          # fails closed; aborts standup if parent not ready or an arm has no landing site

launch_one(){ # name extra-args
  local name="$1"; shift
  local log="/tmp/c2pool-btc-${name}.log"
  echo "--- launching instance $name -> $log ---"
  nohup "$BIN" --testnet --bitcoind "$BITCOIND_P2P" "$@" >"$log" 2>&1 &
  local pid=$!
  echo "instance $name pid=$pid log=$log"
  echo "$pid"
}

if [ $TUNED -eq 1 ]; then
  launch_one A >/dev/null
  launch_one B --sharechain-port "$PORT_B" >/dev/null
  echo "Tuned-net up. Migrate miners A(:$PORT_A)->B(:$PORT_B) one-by-one for the G2 ratchet."
else
  launch_one A >/dev/null
fi
echo "STANDUP-OK. Next: tools/testnet/g3b_block_acceptance.py --live"
