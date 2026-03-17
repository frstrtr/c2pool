#!/usr/bin/env bash
# MinerStat custom miner launch script for c2pool
#
# MinerStat Flight Sheet mapping:
#   Pool Host       → litecoind RPC host
#   Pool Port       → litecoind RPC port (default 9332)
#   Worker/Wallet   → LTC payout address (optionally comma-separated with DOGE)
#   Password        → litecoind RPC user:password
#   Algorithm       → scrypt
#   Extra Parameters→ additional c2pool CLI flags
#
# Example msOS setup:
#   Pool host:    127.0.0.1
#   Pool port:    9332
#   Wallet:       tltc1qkek8r3uymzqyajzezqgl99d2f948st5v67a5h3
#   Password:     litecoinrpc:myrpcpassword
#   Extra params: --merged DOGE:98:127.0.0.1:44556:dogerpc:dogepass

# MinerStat provides these variables:
# $POOL_HOST, $POOL_PORT, $WALLET, $WORKER, $PASSWORD, $ALGORITHM, $EXTRA_PARAMS

POOL_HOST="${POOL_HOST:-127.0.0.1}"
POOL_PORT="${POOL_PORT:-9332}"

# Parse RPC credentials from password field
RPC_USER="${PASSWORD%%:*}"
RPC_PASSWORD="${PASSWORD#*:}"
[[ "$RPC_USER" == "$RPC_PASSWORD" ]] && RPC_PASSWORD=""
[[ -z "$RPC_USER" ]] && RPC_USER="litecoinrpc"

# Build address: wallet + optional worker suffix
ADDRESS="$WALLET"
[[ -n "$WORKER" && "$WORKER" != "default" ]] && ADDRESS="${ADDRESS}.${WORKER}"

# Build command
CMD="./c2pool --integrated --net litecoin"
CMD+=" --coind-address $POOL_HOST --coind-rpc-port $POOL_PORT"
CMD+=" --rpcuser $RPC_USER --rpcpassword $RPC_PASSWORD"
CMD+=" --address $ADDRESS"
CMD+=" --web-port 8080"

[[ -n "$EXTRA_PARAMS" ]] && CMD+=" $EXTRA_PARAMS"

echo "Starting c2pool: $CMD"
exec $CMD 2>&1
