#!/bin/bash
# C2Pool Physical Miner Management Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

show_help() {
    echo "🔋 C2Pool Physical Miner Management"
    echo "=================================="
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  status      - Quick status check of connected miners"
    echo "  monitor     - Real-time monitoring (Ctrl+C to stop)"
    echo "  test        - Run comprehensive mining tests"
    echo "  connections - Show detailed connection information"
    echo "  help        - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 status"
    echo "  $0 monitor"
    echo "  $0 test"
}

check_node() {
    if ! pgrep -f "c2pool" > /dev/null; then
        echo "❌ C2Pool node is not running!"
        echo "   Start it first: ./build/src/c2pool/c2pool"
        exit 1
    fi
    
    if ! netstat -tln | grep -q ":8084"; then
        echo "❌ C2Pool is not listening on port 8084!"
        echo "   Check node configuration and restart"
        exit 1
    fi
}

case "${1:-help}" in
    "status")
        echo "🔍 Checking C2Pool node and miners..."
        check_node
        python3 physical_miner_monitor.py --quick
        ;;
    
    "monitor")
        echo "🔋 Starting real-time monitoring..."
        check_node
        python3 physical_miner_monitor.py
        ;;
    
    "test")
        echo "🧪 Running comprehensive tests..."
        check_node
        python3 mining_test_client.py
        ;;
    
    "connections")
        echo "📡 Active connections to C2Pool (port 8084):"
        echo "============================================"
        netstat -an | grep ":8084" | grep "ESTABLISHED" | while read line; do
            echo "  $line"
        done
        echo ""
        echo "📊 Connection summary:"
        conn_count=$(netstat -an | grep ":8084" | grep "ESTABLISHED" | wc -l)
        unique_ips=$(netstat -an | grep ":8084" | grep "ESTABLISHED" | awk '{print $5}' | cut -d: -f1 | sort | uniq | wc -l)
        echo "  Total connections: $conn_count"
        echo "  Unique miners: $unique_ips"
        ;;
    
    "help"|*)
        show_help
        ;;
esac
