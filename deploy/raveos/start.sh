#!/usr/bin/env bash
# RaveOS launch script for c2pool
#
# RaveOS pool configuration mapping:
#   Pool 1 Host     → litecoind RPC host
#   Pool 1 Port     → litecoind RPC port (default 9332)
#   Wallet 1        → LTC payout address
#   Password 1      → litecoind RPC user:password
#   Wallet 2        → DOGE payout address (optional, for merged mining)
#   Extra Args      → additional c2pool CLI flags
#
# Example:
#   Pool 1: 127.0.0.1:9332
#   Wallet 1: tltc1qkek8r3uymzqyajzezqgl99d2f948st5v67a5h3
#   Pass 1: litecoinrpc:myrpcpass
#   Extra: --merged DOGE:98:127.0.0.1:44556:dogerpc:dogepass

cd "$(dirname "$0")"

# RaveOS provides: $POOL_HOST, $POOL_PORT, $WALLET, $WORKER_NAME, $POOL_PASS, $EXTRA_ARGS
POOL_HOST="${POOL_HOST:-127.0.0.1}"
POOL_PORT="${POOL_PORT:-9332}"

# Parse RPC credentials
RPC_USER="${POOL_PASS%%:*}"
RPC_PASSWORD="${POOL_PASS#*:}"
[[ "$RPC_USER" == "$RPC_PASSWORD" ]] && RPC_PASSWORD=""
[[ -z "$RPC_USER" ]] && RPC_USER="litecoinrpc"

CMD="./c2pool --integrated --net litecoin"
CMD+=" --coind-address $POOL_HOST --coind-rpc-port $POOL_PORT"
CMD+=" --rpcuser $RPC_USER --rpcpassword $RPC_PASSWORD"
CMD+=" --address $WALLET"
CMD+=" --web-port 8080"

[[ -n "$EXTRA_ARGS" ]] && CMD+=" $EXTRA_ARGS"

echo "Starting c2pool: $CMD"
exec $CMD 2>&1
