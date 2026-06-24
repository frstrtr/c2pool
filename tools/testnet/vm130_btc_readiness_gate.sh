#!/usr/bin/env bash
# vm130_btc_readiness_gate.sh
# G2/G3 BTC live-block prerequisite gate for VM130 (c2pool-btc-testnet @192.168.86.234).
#
# The c2pool BTC layer cannot produce valid work until its parent bitcoind has
# left initial-block-download (getblocktemplate is rejected during IBD). This gate
# FAILS CLOSED: it refuses to declare the parent ready -- and refuses to launch
# c2pool -- until GBT actually serves a template, so no G2/G3 live evidence is ever
# captured against an unsynced parent.
#
# It additionally asserts the DUAL-PATH BROADCASTER preconditions, because G3b
# requires a won parent block to reach the network by EITHER arm:
#   ARM A  on_block_found -> P2P block relay   (needs >=1 live bitcoind P2P peer)
#   ARM B  submitblock RPC fallback            (needs the submitblock method live)
# If either arm has no landing site, a "block found" would be silently lost -- so
# the gate refuses readiness rather than capture half-valid G3b evidence.
#
# Run ON VM130 as ubuntu.
#   vm130_btc_readiness_gate.sh            # check only; prints launch cmd when ready
#   vm130_btc_readiness_gate.sh --launch /path/to/c2pool-btc
set -euo pipefail

RPC_PORT=18332
BITCOIND_P2P=127.0.0.1:18333          # --bitcoind value for --testnet (testnet3)
COOKIE="${BTC_COOKIE:-$HOME/.bitcoin/testnet3/.cookie}"

die(){ echo "GATE-FAIL: $*" >&2; exit 1; }
cli(){ bitcoin-cli -rpcport="$RPC_PORT" -rpccookiefile="$COOKIE" "$@"; }

[ -r "$COOKIE" ] || die "bitcoind testnet3 cookie not readable at $COOKIE"
bci=$(cli getblockchaininfo) || die "bitcoind RPC unreachable on :$RPC_PORT"

ibd=$(echo "$bci"    | grep -o '"initialblockdownload": *[a-z]*'  | awk '{print $2}')
blocks=$(echo "$bci"  | grep -o '"blocks": *[0-9]*'              | awk '{print $2}')
headers=$(echo "$bci"| grep -o '"headers": *[0-9]*'              | awk '{print $2}')
prog=$(echo "$bci"   | grep -o '"verificationprogress": *[0-9.]*'| awk '{print $2}')
echo "bitcoind testnet3: blocks=$blocks headers=$headers progress=$prog ibd=$ibd"

[ "$ibd" = "false" ] || die "parent still in IBD (progress=$prog) -- GBT unavailable; refusing readiness (G2/G3 evidence would be invalid)"
cli getblocktemplate '{"rules":["segwit"]}' >/dev/null \
  || die "getblocktemplate rejected despite ibd=false -- investigate before launch"
echo "GATE-OK(template): parent synced and serving templates."

# --- DUAL-PATH BROADCASTER PRECONDITIONS -------------------------------------
# ARM B: the submitblock RPC must exist on this daemon (the c2pool RPC fallback
# path calls it). `help submitblock` errors if the method is absent.
cli help submitblock >/dev/null 2>&1 \
  || die "ARM B precondition: submitblock RPC method unavailable on parent daemon"
echo "GATE-OK(arm-B): submitblock RPC fallback path is live."

# ARM A: a found block relayed over P2P needs at least one connected peer to
# propagate to. A 0-peer node would accept submitblock but silently drop a P2P
# relay -- which would make ARM A pass falsely. Fail closed below the floor.
peers=$(cli getconnectioncount 2>/dev/null || echo 0)
echo "bitcoind P2P peers: $peers"
[ "${peers:-0}" -ge 1 ] \
  || die "ARM A precondition: 0 P2P peers -- on_block_found relay has no landing site (G3b ARM A would pass falsely)"
echo "GATE-OK(arm-A): >=1 P2P peer for on_block_found block relay."

echo "GATE-OK: parent synced, templating, and BOTH broadcaster arms have a landing site."

if [ "${1:-}" = "--launch" ]; then
  BIN="${2:-}"; [ -x "$BIN" ] || die "--launch needs an executable c2pool-btc path"
  echo "Launching: $BIN --testnet --bitcoind $BITCOIND_P2P"
  exec "$BIN" --testnet --bitcoind "$BITCOIND_P2P"
fi
echo "Ready. To stand up: c2pool-btc --testnet --bitcoind $BITCOIND_P2P"
