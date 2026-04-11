#!/bin/bash
# c2pool start script — launches pool node + block explorer
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${1:-$DIR/config/c2pool_mainnet.yaml}"
EXPLORER_PORT=9090
WEB_PORT=8080

# Parse web_port from config if present
if [ -f "$CONFIG" ]; then
    WP=$(grep -E "^web_port:" "$CONFIG" 2>/dev/null | awk '{print $2}')
    [ -n "$WP" ] && WEB_PORT="$WP"
fi

echo "=== c2pool v0.1.0-alpha ==="
echo "Config:   $CONFIG"
echo "Web:      http://0.0.0.0:${WEB_PORT}"
echo "Explorer: http://0.0.0.0:${EXPLORER_PORT}"
echo ""

# Start c2pool with bundled libs
export LD_LIBRARY_PATH="$DIR/lib:${LD_LIBRARY_PATH:-}"
"$DIR/c2pool" --config "$CONFIG" &
C2POOL_PID=$!

# Wait for the explorer API to be ready (callbacks wired after full init)
echo "Waiting for c2pool to initialize..."
for i in $(seq 1 120); do
    RESP=$(curl -s "http://127.0.0.1:${WEB_PORT}/api/explorer/getblockchaininfo" 2>/dev/null || true)
    if echo "$RESP" | grep -q '"blocks"'; then
        echo "c2pool explorer API ready."
        break
    fi
    sleep 2
done

# Start Python explorer (uses c2pool's embedded explorer API)
if command -v python3 &>/dev/null; then
    python3 "$DIR/explorer/explorer.py" \
        --web-port "$EXPLORER_PORT" \
        --ltc-c2pool "http://127.0.0.1:${WEB_PORT}/api/explorer" \
        --no-doge &
    EXPLORER_PID=$!
    echo "Explorer started (PID $EXPLORER_PID)"
else
    echo "WARNING: python3 not found — explorer not started"
    echo "Install: sudo apt install python3"
fi

# Wait for c2pool (foreground process)
wait $C2POOL_PID
