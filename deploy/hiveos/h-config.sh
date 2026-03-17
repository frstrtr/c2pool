#!/usr/bin/env bash
# HiveOS config generator for c2pool
#
# Flight sheet fields mapping:
#   CUSTOM_URL      → litecoind RPC address (host:port), e.g. "127.0.0.1:9332"
#   CUSTOM_TEMPLATE → payout address(es), e.g. "LTC_ADDR" or "LTC_ADDR,DOGE_ADDR"
#   CUSTOM_PASS     → litecoind RPC credentials as "user:password"
#   CUSTOM_USER_CONFIG → extra c2pool flags (optional)
#
# Example flight sheet:
#   Pool URL:     127.0.0.1:9332
#   Wallet:       tltc1qkek8r3uymzqyajzezqgl99d2f948st5v67a5h3
#   Password:     litecoinrpc:myrpcpassword
#   Extra config: --merged DOGE:98:127.0.0.1:44556:dogerpc:dogepass

[[ -z $CUSTOM_URL ]] && echo "ERROR: Pool URL (litecoind RPC host:port) not set" && exit 1
[[ -z $CUSTOM_TEMPLATE ]] && echo "ERROR: Wallet address not set" && exit 1

# Parse RPC host:port from CUSTOM_URL
# Strip protocol prefix if present
RPC_URL="${CUSTOM_URL#stratum+tcp://}"
RPC_URL="${RPC_URL#http://}"
RPC_URL="${RPC_URL#https://}"

RPC_HOST="${RPC_URL%%:*}"
RPC_PORT="${RPC_URL##*:}"
[[ "$RPC_HOST" == "$RPC_PORT" ]] && RPC_PORT="9332"  # default if no port

# Parse RPC user:password from CUSTOM_PASS
RPC_USER="${CUSTOM_PASS%%:*}"
RPC_PASSWORD="${CUSTOM_PASS#*:}"
[[ -z "$RPC_USER" ]] && RPC_USER="litecoinrpc"
[[ "$RPC_USER" == "$RPC_PASSWORD" ]] && RPC_PASSWORD=""

# Build c2pool command line
CONF="--integrated --net litecoin"
CONF+=" --coind-address $RPC_HOST --coind-rpc-port $RPC_PORT"
CONF+=" --address $CUSTOM_TEMPLATE"
CONF+=" --web-port $MINER_API_PORT"

[[ -n "$RPC_USER" ]] && CONF+=" --rpcuser $RPC_USER"
[[ -n "$RPC_PASSWORD" ]] && CONF+=" --rpcpassword $RPC_PASSWORD"

# Log to HiveOS standard location
[[ -n "$CUSTOM_LOG_BASENAME" ]] && CONF+=" --log-file ${CUSTOM_LOG_BASENAME}.log"

# Append any extra user-supplied flags
[[ -n "$CUSTOM_USER_CONFIG" ]] && CONF+=" $CUSTOM_USER_CONFIG"

echo "$CONF" > "$MINER_DIR/$CUSTOM_MINER/config.txt"
