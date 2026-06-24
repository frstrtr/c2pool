#!/usr/bin/env bash
# vm130_btc_readiness_gate.sh
# G2/G3 BTC live-block prerequisite gate for VM130 (c2pool-btc-testnet @192.168.86.234).
#
# The c2pool BTC layer cannot produce valid work until its parent bitcoind has
# left initial-block-download (getblocktemplate is rejected during IBD). This gate
# FAILS CLOSED: it refuses to declare the parent ready — and refuses to launch
# c2pool — until GBT actually serves a template, so no G2/G3 live evidence is ever
# captured against an unsynced parent.
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
blocks=$(echo "$bci" | grep -o '"blocks": *[0-9]*'               | awk '{print $2}')
headers=$(echo "$bci"| grep -o '"headers": *[0-9]*'              | awk '{print $2}')
prog=$(echo "$bci"   | grep -o '"verificationprogress": *[0-9.]*'| awk '{print $2}')
echo "bitcoind testnet3: blocks=$blocks headers=$headers progress=$prog ibd=$ibd"

[ "$ibd" = "false" ] || die "parent still in IBD (progress=$prog) — GBT unavailable; refusing readiness (G2/G3 evidence would be invalid)"
cli getblocktemplate '{"rules":["segwit"]}' >/dev/null \
  || die "getblocktemplate rejected despite ibd=false — investigate before launch"
echo "GATE-OK: parent synced and serving templates."

if [ "${1:-}" = "--launch" ]; then
  BIN="${2:-}"; [ -x "$BIN" ] || die "--launch needs an executable c2pool-btc path"
  echo "Launching: $BIN --testnet --bitcoind $BITCOIND_P2P"
  exec "$BIN" --testnet --bitcoind "$BITCOIND_P2P"
fi
echo "Ready. To stand up: c2pool-btc --testnet --bitcoind $BITCOIND_P2P"
