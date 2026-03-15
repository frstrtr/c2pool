#!/bin/bash
# Phase 4 Stress Test: 48h run in --embedded-ltc mode (no daemon)
# LTC testnet peer: 192.168.86.26:19335

set -euo pipefail

BINARY="/home/user0/Github/c2pool/build/src/c2pool/c2pool"
LOGDIR="/home/user0/Github/c2pool/stress-test-logs"
LOGFILE="$LOGDIR/stress_$(date +%Y%m%d_%H%M%S).log"
PIDFILE="$LOGDIR/c2pool.pid"

mkdir -p "$LOGDIR"

# LTC testnet address for payout (bech32 testnet format)
PAYOUT_ADDR="tltc1qg8emapewwtdxkr0m0jfvlsmflkqfkv3sdjhcne"

echo "=== Phase 4 Stress Test: $(date) ===" | tee "$LOGFILE"
echo "Mode: --embedded-ltc (no daemon)" | tee -a "$LOGFILE"
echo "LTC testnet P2P: 192.168.86.26:19335" | tee -a "$LOGFILE"
echo "Payout: $PAYOUT_ADDR" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

exec "$BINARY" \
    --integrated \
    --embedded-ltc \
    --testnet \
    --coind-p2p-address 192.168.86.26 \
    --coind-p2p-port 19335 \
    --node-owner-address "$PAYOUT_ADDR" \
    --p2pool-port 19338 \
    --worker-port 19327 \
    --web-port 8080 \
    --dashboard-dir /home/user0/Github/c2pool/web-static \
    --cors-origin '*' \
    --p2p-max-peers 20 \
    --stratum-min-diff 0.001 \
    --stratum-max-diff 65536 \
    --stratum-target-time 10 \
    --merged DOGE:2:192.168.86.27:44555:dogecoinrpc:testpass:44556 \
    2>&1 | tee -a "$LOGFILE"
