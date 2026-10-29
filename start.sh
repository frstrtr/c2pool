#!/bin/bash
# c2pool start script — launches the pool node, plus the block explorer for
# the coins whose node serves the explorer API.
#
# One script ships in every per-coin Linux/macOS package; the coin is taken
# from the c2pool-<coin> binary next to it. Each binary has its own command
# line (src/c2pool/main_<coin>.cpp), the same one the Windows installer uses
# (installer/windows/c2pool-setup.iss).
#
# Usage: ./start.sh [CONFIG] [EXTRA_ARGS...]
#   CONFIG      YAML config file. Only c2pool-ltc reads one (--config); the
#               default config/c2pool_mainnet.yaml is used only if it exists
#               (copy it from config/c2pool_mainnet.yaml.example). Without
#               it the node runs on its built-in defaults.
#   EXTRA_ARGS  appended to the node command line, e.g.
#               ./start.sh --node-owner-address <your-address>
# Set C2POOL_DRY_RUN=1 to print the commands instead of running them.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
EXPLORER_PORT=9090
WEB_PORT=8080

# A first argument that is not a flag is the config file (back-compat).
CONFIG=""
CONFIG_GIVEN=0
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    CONFIG="$1"
    CONFIG_GIVEN=1
    shift
fi
if [ -z "$CONFIG" ]; then
    CONFIG="$DIR/config/c2pool_mainnet.yaml"
    CONFIG_GIVEN=0
fi
case "$CONFIG" in
    /*) ;;
    *) CONFIG="$PWD/$CONFIG" ;;
esac

# Locate the packaged coin binary. release.yml packages it per-coin as
# c2pool-<coin> (c2pool-ltc, c2pool-btc, ...), so resolve by glob rather
# than a hard-coded name; fall back to a plain c2pool for source builds.
BIN=$(find "$DIR" -maxdepth 1 -type f -name "c2pool-*" -perm -u+x 2>/dev/null | head -1)
[ -z "$BIN" ] && [ -x "$DIR/c2pool" ] && BIN="$DIR/c2pool"
if [ -z "$BIN" ]; then
    echo "ERROR: no c2pool binary found in $DIR" >&2
    exit 1
fi
BIN_NAME=$(basename "$BIN")
COIN=$(printf '%s\n' "$BIN_NAME" | sed -n 's/^c2pool-\([a-z0-9][a-z0-9]*\).*/\1/p')
[ -z "$COIN" ] && COIN=ltc   # plain "c2pool" is the LTC dev alias

DASHBOARD="$DIR/web-static"
USE_CONFIG=0
EXPLORER_ARGS=()
EXPLORER_NOTE=""

case "$COIN" in
    ltc)
        # Integrated P2P pool with embedded LTC + DOGE SPV; Stratum 9327.
        # The YAML config, when present, is the source of truth (CLI flags
        # would override it), so only the dashboard dir is added to it.
        STRATUM_PORT=9327
        if [ -f "$CONFIG" ]; then
            USE_CONFIG=1
            NODE_ARGS=(--config "$CONFIG" --dashboard-dir "$DASHBOARD")
        else
            NODE_ARGS=(--integrated --net litecoin --dashboard-dir "$DASHBOARD")
        fi
        ;;
    dash)
        # A bare --run is daemonless (embedded serving + coin-peer discovery).
        # Dashboard is on at 8080 by default; Stratum is off unless bound.
        STRATUM_PORT=7903
        NODE_ARGS=(--run --stratum "$STRATUM_PORT" --dashboard-dir "$DASHBOARD")
        ;;
    btc)
        # Needs a coin source (--coin-p2p-discover or --bitcoind); Stratum and
        # dashboard are off unless bound. Dashboard: cwd-relative web-static.
        STRATUM_PORT=9332
        NODE_ARGS=(--coin-p2p-discover --stratum "$STRATUM_PORT" --http "$WEB_PORT")
        ;;
    dgb)
        # Without --run the binary runs its self-test and exits.
        STRATUM_PORT=5025
        NODE_ARGS=(--run --coin-p2p-discover --stratum "$STRATUM_PORT" --http "$WEB_PORT")
        ;;
    bch)
        # --pool is the pool run-loop; it needs --peer or --coin-p2p-discover.
        STRATUM_PORT=9348
        NODE_ARGS=(--pool --coin-p2p-discover --stratum "$STRATUM_PORT" --http "$WEB_PORT")
        ;;
    bip110)
        # Without --run the self-test runs and exits. --run discovers fork
        # peers by itself and binds Stratum on 9336 by default.
        STRATUM_PORT=9336
        NODE_ARGS=(--run --http "$WEB_PORT")
        ;;
    *)
        echo "ERROR: unknown coin '$COIN' (binary $BIN_NAME); run the binary directly (see --help)." >&2
        exit 1
        ;;
esac

if [ "$CONFIG_GIVEN" = 1 ]; then
    if [ "$COIN" != ltc ]; then
        echo "WARNING: $BIN_NAME does not read YAML config files; ignoring $CONFIG." >&2
        echo "         Pass options as flags instead, e.g. $0 --node-owner-address <addr>" >&2
        echo "         (see ./$BIN_NAME --help)." >&2
    elif [ "$USE_CONFIG" = 0 ]; then
        echo "ERROR: config file not found: $CONFIG" >&2
        exit 1
    fi
fi

if [ "$USE_CONFIG" = 1 ]; then
    # Coin-guard: v0.2.3 shipped the Litecoin config in every coin tarball,
    # so refuse a config whose coin header does not match the binary.
    if ! head -1 "$CONFIG" | grep -qi "$COIN"; then
        echo "ERROR: config/coin mismatch — binary is $BIN_NAME but config header reads:" >&2
        echo "         $(head -1 "$CONFIG")" >&2
        echo "       Launch with the coin-correct config, e.g.:  $0 $DIR/config/c2pool_mainnet.yaml" >&2
        exit 1
    fi
    WP=$(grep -E "^web_port:" "$CONFIG" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r')
    [ -n "$WP" ] && WEB_PORT="$WP"
    SP=$(grep -E "^stratum_port:" "$CONFIG" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r')
    [ -n "$SP" ] && STRATUM_PORT="$SP"
fi
# A web/stratum port given in EXTRA_ARGS wins (the parsers keep the last value).
prev=""
for a in "$@"; do
    case "$prev" in
        --web-port|--http-port|--http) WEB_PORT="${a##*:}" ;;
        --stratum|-w|--worker-port|--stratum-port) STRATUM_PORT="${a##*:}" ;;
    esac
    prev="$a"
done
EXPLORER_API="http://127.0.0.1:${WEB_PORT}/api/explorer"

# Explorer: explorer.py reads the node's loopback /api/explorer surface.
# c2pool-dash and c2pool-bip110 serve it by default, c2pool-ltc only with
# "explorer: true" in its config; btc, dgb and bch do not serve it.
case "$COIN" in
    ltc)
        if [ "$USE_CONFIG" = 1 ] && grep -Eq '^explorer:[[:space:]]*true' "$CONFIG"; then
            EXPLORER_ARGS=(--web-port "$EXPLORER_PORT" --ltc-c2pool "$EXPLORER_API" --doge-c2pool "$EXPLORER_API")
        else
            EXPLORER_NOTE="off (set 'explorer: true' in the config to enable it)"
        fi
        ;;
    dash|bip110)
        EXPLORER_ARGS=(--coin "$COIN" --c2pool "$EXPLORER_API" --web-port "$EXPLORER_PORT")
        ;;
    *)
        EXPLORER_NOTE="not available for $BIN_NAME (no explorer API)"
        ;;
esac
if [ ${#EXPLORER_ARGS[@]} -gt 0 ] && ! command -v python3 >/dev/null 2>&1; then
    EXPLORER_ARGS=()
    EXPLORER_NOTE="not started: python3 not found (install python3)"
fi

NODE_ARGS=("${NODE_ARGS[@]}" "$@")

echo "=== $BIN_NAME ==="
if [ "$USE_CONFIG" = 1 ]; then
    echo "Config:   $CONFIG"
else
    echo "Config:   none (built-in defaults)"
fi
echo "Web:      http://0.0.0.0:${WEB_PORT}"
echo "Stratum:  stratum+tcp://0.0.0.0:${STRATUM_PORT}"
if [ ${#EXPLORER_ARGS[@]} -gt 0 ]; then
    echo "Explorer: http://0.0.0.0:${EXPLORER_PORT}"
else
    echo "Explorer: $EXPLORER_NOTE"
fi
echo ""

if [ -n "${C2POOL_DRY_RUN:-}" ]; then
    printf 'node:     cd %q &&' "$DIR"; printf ' %q' "$BIN" "${NODE_ARGS[@]}"; echo
    if [ ${#EXPLORER_ARGS[@]} -gt 0 ]; then
        printf 'explorer:'; printf ' %q' python3 "$DIR/explorer/explorer.py" "${EXPLORER_ARGS[@]}"; echo
    fi
    exit 0
fi

# Start the explorer once the node's explorer API answers, and stop it when
# the node exits. It runs in a background subshell so the node itself can
# take over this shell (exec): it gets Ctrl-C and its exit code is ours.
start_explorer() {
    local node_pid=$1 i=0 epid
    echo "Explorer: waiting for the c2pool explorer API..."
    command -v curl >/dev/null 2>&1 || i=120   # no curl: explorer.py retries itself
    while [ $i -lt 120 ]; do
        kill -0 "$node_pid" 2>/dev/null || return 0
        if curl -s "${EXPLORER_API}/getblockchaininfo" 2>/dev/null | grep -q '"blocks"'; then
            break
        fi
        sleep 2
        i=$((i + 1))
    done
    python3 "$DIR/explorer/explorer.py" "${EXPLORER_ARGS[@]}" &
    epid=$!
    echo "Explorer started (PID $epid)"
    while kill -0 "$node_pid" 2>/dev/null && kill -0 "$epid" 2>/dev/null; do
        sleep 5
    done
    kill "$epid" 2>/dev/null || true
}

# btc, dgb, bch and bip110 serve the dashboard from a web-static directory
# relative to the working directory.
cd "$DIR"
export LD_LIBRARY_PATH="$DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if [ ${#EXPLORER_ARGS[@]} -gt 0 ]; then
    start_explorer $$ &
fi
exec "$BIN" "${NODE_ARGS[@]}"
