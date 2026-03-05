#!/bin/bash
# Litecoin Testnet Node Setup and Management Script

set -e

# Configuration
LITECOIN_DIR="$HOME/.litecoin"
TESTNET_DIR="$LITECOIN_DIR/testnet4"
CONF_FILE="$LITECOIN_DIR/litecoin.conf"
PID_FILE="$TESTNET_DIR/litecoind.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if litecoind is available
check_litecoin_binary() {
    if ! command -v litecoind &> /dev/null; then
        error "litecoind not found in PATH"
        echo "Please install Litecoin Core from: https://litecoin.org/"
        echo "Or on Ubuntu/Debian: sudo apt-get install litecoind"
        exit 1
    fi
    
    if ! command -v litecoin-cli &> /dev/null; then
        error "litecoin-cli not found in PATH"
        exit 1
    fi
    
    log "Found Litecoin binaries: $(litecoind --version | head -1)"
}

# Create Litecoin configuration
setup_config() {
    log "Setting up Litecoin testnet configuration..."
    
    mkdir -p "$LITECOIN_DIR"
    
    cat > "$CONF_FILE" << 'EOF'
# Litecoin Testnet Configuration for C2Pool Testing

# Network
testnet=1
listen=1
server=1

# RPC Configuration
rpcuser=ltctest
rpcpassword=ltctest123
rpcport=19332
rpcbind=127.0.0.1
rpcallowip=127.0.0.1

# Connections
maxconnections=50
addnode=testnet-seed.ltc.xurious.com
addnode=seed-b.litecoin.loshan.co.uk
addnode=dnsseed-testnet.thrasher.io

# Mining (for testing)
gen=0
genproclimit=1

# Logging
debug=1
logips=1
logtimestamps=1

# Performance
dbcache=512
maxmempool=300

# Features needed for pool operation
txindex=1
addressindex=1
timestampindex=1
spentindex=1

# Block creation
blockmaxweight=4000000
blockmaxsize=4000000

EOF

    success "Created Litecoin configuration at $CONF_FILE"
}

# Start Litecoin daemon
start_daemon() {
    log "Starting Litecoin testnet daemon..."
    
    if is_running; then
        warn "Litecoin daemon is already running (PID: $(cat $PID_FILE))"
        return 0
    fi
    
    # Start daemon
    litecoind -daemon -testnet -datadir="$LITECOIN_DIR" -conf="$CONF_FILE"
    
    # Wait for startup
    log "Waiting for daemon to start..."
    for i in {1..30}; do
        if litecoin-cli -testnet getblockchaininfo &>/dev/null; then
            success "Litecoin daemon started successfully"
            return 0
        fi
        sleep 1
        echo -n "."
    done
    
    error "Failed to start Litecoin daemon"
    return 1
}

# Check if daemon is running
is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$PID_FILE"
        fi
    fi
    return 1
}

# Stop daemon
stop_daemon() {
    log "Stopping Litecoin daemon..."
    
    if ! is_running; then
        warn "Litecoin daemon is not running"
        return 0
    fi
    
    litecoin-cli -testnet stop
    
    # Wait for shutdown
    for i in {1..30}; do
        if ! is_running; then
            success "Litecoin daemon stopped"
            return 0
        fi
        sleep 1
        echo -n "."
    done
    
    error "Failed to stop daemon gracefully"
    return 1
}

# Get daemon status
status() {
    if is_running; then
        success "Litecoin daemon is running (PID: $(cat $PID_FILE))"
        
        # Get blockchain info
        echo ""
        log "Blockchain Information:"
        litecoin-cli -testnet getblockchaininfo | jq '{
            chain: .chain,
            blocks: .blocks,
            headers: .headers,
            verificationprogress: .verificationprogress,
            size_on_disk: .size_on_disk,
            pruned: .pruned
        }'
        
        echo ""
        log "Network Information:"
        litecoin-cli -testnet getnetworkinfo | jq '{
            version: .version,
            subversion: .subversion,
            connections: .connections,
            localaddresses: .localaddresses
        }'
        
        echo ""
        log "Mining Information:"
        litecoin-cli -testnet getmininginfo | jq '{
            blocks: .blocks,
            difficulty: .difficulty,
            networkhashps: .networkhashps,
            pooledtx: .pooledtx,
            testnet: .testnet
        }'
        
    else
        error "Litecoin daemon is not running"
        return 1
    fi
}

# Generate test blocks
generate_blocks() {
    local count=${1:-10}
    
    log "Generating $count test blocks..."
    
    if ! is_running; then
        error "Litecoin daemon is not running"
        return 1
    fi
    
    # Get a test address
    local address=$(litecoin-cli -testnet getnewaddress "mining_test")
    log "Mining to address: $address"
    
    # Generate blocks
    local blocks=$(litecoin-cli -testnet generatetoaddress "$count" "$address")
    
    success "Generated $count blocks"
    echo "Block hashes:"
    echo "$blocks" | jq -r '.[]'
    
    # Show updated status
    echo ""
    log "Updated blockchain status:"
    litecoin-cli -testnet getblockchaininfo | jq '{blocks: .blocks, difficulty: .difficulty}'
}

# Monitor daemon logs
logs() {
    local lines=${1:-50}
    
    local debug_log="$TESTNET_DIR/debug.log"
    
    if [[ -f "$debug_log" ]]; then
        log "Showing last $lines lines from debug.log:"
        tail -n "$lines" "$debug_log"
    else
        error "Debug log not found at $debug_log"
    fi
}

# Test RPC connection
test_rpc() {
    log "Testing RPC connection..."
    
    if ! is_running; then
        error "Litecoin daemon is not running"
        return 1
    fi
    
    echo "RPC Test Results:"
    echo "=================="
    
    echo -n "getblockchaininfo: "
    if litecoin-cli -testnet getblockchaininfo &>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
    
    echo -n "getnetworkinfo: "
    if litecoin-cli -testnet getnetworkinfo &>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
    
    echo -n "getmininginfo: "
    if litecoin-cli -testnet getmininginfo &>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
    
    success "All RPC tests passed"
}

# Main command handling
case "${1:-}" in
    start)
        check_litecoin_binary
        setup_config
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        sleep 2
        start_daemon
        ;;
    status)
        status
        ;;
    generate)
        generate_blocks "${2:-10}"
        ;;
    logs)
        logs "${2:-50}"
        ;;
    test)
        test_rpc
        ;;
    setup)
        check_litecoin_binary
        setup_config
        success "Setup complete. Run '$0 start' to start the daemon."
        ;;
    *)
        echo "Litecoin Testnet Node Management"
        echo "================================"
        echo ""
        echo "Usage: $0 {start|stop|restart|status|generate|logs|test|setup}"
        echo ""
        echo "Commands:"
        echo "  setup     - Setup configuration (run this first)"
        echo "  start     - Start Litecoin testnet daemon"
        echo "  stop      - Stop Litecoin testnet daemon"
        echo "  restart   - Restart daemon"
        echo "  status    - Show daemon status and blockchain info"
        echo "  generate  - Generate test blocks (default: 10)"
        echo "  logs      - Show daemon logs (default: last 50 lines)"
        echo "  test      - Test RPC connection"
        echo ""
        echo "Examples:"
        echo "  $0 setup"
        echo "  $0 start"
        echo "  $0 generate 50"
        echo "  $0 status"
        exit 1
        ;;
esac
