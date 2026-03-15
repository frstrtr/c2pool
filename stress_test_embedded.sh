#!/bin/bash
# c2pool Stress Test — Embedded LTC + DOGE merged mining
#
# Operating modes:
#   (default)            Both embedded + both RPC. If RPC fails, embedded keeps running.
#   --full               Both embedded only — zero daemons needed.
#   --doge-rpc           DOGE uses RPC daemon (+ embedded LTC)
#   --ltc-rpc            LTC uses RPC daemon (+ embedded DOGE)
#   --rpc                Both RPC only — legacy mode, both daemons required.

set -euo pipefail

BINARY="/home/user0/Github/c2pool/build/src/c2pool/c2pool"
LOGDIR="/home/user0/Github/c2pool/stress-test-logs"
LOGFILE="$LOGDIR/stress_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$LOGDIR"

PAYOUT_ADDR="tltc1qg8emapewwtdxkr0m0jfvlsmflkqfkv3sdjhcne"
MODE="${1:---hybrid}"

COMMON_ARGS=(
    --integrated
    --testnet
    --node-owner-address "$PAYOUT_ADDR"
    --p2pool-port 19338
    --worker-port 19327
    --web-port 8080
    --dashboard-dir /home/user0/Github/c2pool/web-static
    --cors-origin '*'
    --p2p-max-peers 20
    --stratum-min-diff 0.001
    --stratum-max-diff 65536
    --stratum-target-time 10
)

case "$MODE" in
    --full)
        echo "=== Mode: FULL EMBEDDED (zero daemons) ===" | tee "$LOGFILE"
        exec "$BINARY" "${COMMON_ARGS[@]}" \
            --embedded-ltc \
            --coind-p2p-address 192.168.86.26 \
            --coind-p2p-port 19335 \
            --header-checkpoint 4600000:da433fe7ca00dcb6ccdeda8a1e0a1e0f0111aaf081385da85a3b40d7708d410e \
            --embedded-doge \
            --merged DOGE:2 \
            --doge-p2p-address 192.168.86.27 \
            --doge-p2p-port 44556 \
            2>&1 | tee -a "$LOGFILE"
        ;;
    --ltc-rpc)
        echo "=== Mode: LTC RPC + DOGE embedded ===" | tee "$LOGFILE"
        exec "$BINARY" "${COMMON_ARGS[@]}" \
            --coind-address 192.168.86.26 \
            --coind-port 19332 \
            --coind-p2p-address 192.168.86.26 \
            --coind-p2p-port 19335 \
            --embedded-doge \
            --merged DOGE:2:192.168.86.27:44555:dogecoinrpc:testpass:44556 \
            --doge-p2p-address 192.168.86.27 \
            --doge-p2p-port 44556 \
            litecoinrpc litecoinrpc_mainnet_2026 \
            2>&1 | tee -a "$LOGFILE"
        ;;
    --doge-rpc)
        echo "=== Mode: LTC embedded + DOGE RPC ===" | tee "$LOGFILE"
        exec "$BINARY" "${COMMON_ARGS[@]}" \
            --embedded-ltc \
            --coind-p2p-address 192.168.86.26 \
            --coind-p2p-port 19335 \
            --header-checkpoint 4600000:da433fe7ca00dcb6ccdeda8a1e0a1e0f0111aaf081385da85a3b40d7708d410e \
            --merged DOGE:2:192.168.86.27:44555:dogecoinrpc:testpass:44556 \
            2>&1 | tee -a "$LOGFILE"
        ;;
    --rpc)
        echo "=== Mode: LEGACY (both daemons required) ===" | tee "$LOGFILE"
        exec "$BINARY" "${COMMON_ARGS[@]}" \
            --coind-address 192.168.86.26 \
            --coind-port 19332 \
            --coind-p2p-address 192.168.86.26 \
            --coind-p2p-port 19335 \
            --merged DOGE:2:192.168.86.27:44555:dogecoinrpc:testpass:44556 \
            litecoinrpc litecoinrpc_mainnet_2026 \
            2>&1 | tee -a "$LOGFILE"
        ;;
    *)
        echo "=== Mode: DEFAULT (LTC embedded + DOGE RPC, auto-fallback) ===" | tee "$LOGFILE"
        echo "LTC: embedded P2P (primary)" | tee -a "$LOGFILE"
        echo "DOGE: RPC 192.168.86.27:44555 (primary) → embedded fallback if daemon dies" | tee -a "$LOGFILE"
        # Note: --embedded-doge requires AuxPoW header parser wired into P2P handler.
        # Until that's done, DOGE uses RPC as primary with embedded as auto-fallback.
        exec "$BINARY" "${COMMON_ARGS[@]}" \
            --embedded-ltc \
            --coind-p2p-address 192.168.86.26 \
            --coind-p2p-port 19335 \
            --header-checkpoint 4600000:da433fe7ca00dcb6ccdeda8a1e0a1e0f0111aaf081385da85a3b40d7708d410e \
            --merged DOGE:2:192.168.86.27:44555:dogecoinrpc:testpass:44556 \
            2>&1 | tee -a "$LOGFILE"
        ;;
esac
