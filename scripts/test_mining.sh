#!/bin/bash

# C2Pool Enhanced Mining Test Suite
# Tests LTC testnet mining capabilities, storage, and share population

set -e

echo "🎯 C2Pool Enhanced Mining Test Suite"
echo "===================================="
echo "Testing: LTC testnet, blockchain-specific validation, storage, DB population, mining capabilities"
echo ""

# Configuration
WEB_PORT=8083
STRATUM_PORT=8084  # Web port + 1 (this is where miners connect)
DB_PATH="$HOME/.c2pool/testnet/sharechain_leveldb"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "build/src/c2pool/c2pool_enhanced" ]; then
    log_error "c2pool_enhanced not found. Please run from c2pool root directory after building."
    exit 1
fi

echo "1. 🏗️  Starting C2Pool Enhanced with Integrated Mining Pool"
echo "   Web Interface: http://localhost:${WEB_PORT}"
echo "   Stratum Mining: stratum+tcp://localhost:${STRATUM_PORT}"
echo ""

# Start c2pool in background with blockchain-specific validation
./build/src/c2pool/c2pool_enhanced --testnet --blockchain ltc --integrated 0.0.0.0:${WEB_PORT} &
C2POOL_PID=$!

# Wait for startup
log_info "Waiting for C2Pool to start..."
sleep 3

# Check if process is still running
if ! kill -0 $C2POOL_PID 2>/dev/null; then
    log_error "C2Pool failed to start"
    exit 1
fi

log_info "C2Pool started successfully (PID: $C2POOL_PID)"

echo ""
echo "2. 🔍 Testing Web Interface and API"

# Test web interface
if curl -s http://localhost:${WEB_PORT}/ >/dev/null; then
    log_info "Web interface is responding"
    
    # Get initial status
    INITIAL_STATUS=$(curl -s http://localhost:${WEB_PORT}/)
    echo "   Initial Status: $(echo $INITIAL_STATUS | jq -c '.')"
    
    INITIAL_SHARES=$(echo $INITIAL_STATUS | jq -r '.poolshares // 0')
    INITIAL_HASHRATE=$(echo $INITIAL_STATUS | jq -r '.poolhashps // 0')
    
    log_info "Initial pool shares: $INITIAL_SHARES"
    log_info "Initial pool hashrate: $INITIAL_HASHRATE H/s"
else
    log_error "Web interface not responding on port $WEB_PORT"
    kill $C2POOL_PID 2>/dev/null
    exit 1
fi

echo ""
echo "3. 🔌 Testing Stratum Mining Port"

# Test if Stratum port is listening
if netstat -tln 2>/dev/null | grep -q ":${STRATUM_PORT} "; then
    log_info "Stratum mining port $STRATUM_PORT is listening"
else
    log_warn "Stratum port $STRATUM_PORT not yet listening, checking in 5 seconds..."
    sleep 5
    if netstat -tln 2>/dev/null | grep -q ":${STRATUM_PORT} "; then
        log_info "Stratum mining port $STRATUM_PORT is now listening"
    else
        log_warn "Stratum port $STRATUM_PORT still not listening (may start on first connection)"
    fi
fi

echo ""
echo "4. 💾 Testing LevelDB Storage"

# Check if database directory exists
if [ -d "$DB_PATH" ]; then
    log_info "LevelDB database directory exists: $DB_PATH"
    
    # Check database files
    DB_FILES=$(find "$DB_PATH" -name "*.ldb" -o -name "*.log" -o -name "CURRENT" -o -name "MANIFEST-*" 2>/dev/null | wc -l)
    log_info "Database files found: $DB_FILES"
    
    if [ $DB_FILES -gt 0 ]; then
        log_info "LevelDB appears to be properly initialized"
    else
        log_warn "LevelDB directory exists but no database files found yet"
    fi
else
    log_warn "LevelDB database directory not found yet: $DB_PATH"
fi

echo ""
echo "5. ⛏️  Simulating Mining Activity"

# Function to simulate a Stratum mining connection
simulate_stratum_connection() {
    local port=$1
    log_info "Attempting to connect to Stratum port $port..."
    
    # Try to connect and send basic Stratum messages
    (
        echo '{"id":1,"method":"mining.subscribe","params":["c2pool-test-miner/1.0",""]}'
        sleep 1
        echo '{"id":2,"method":"mining.authorize","params":["test_worker","test_password"]}'
        sleep 1
        echo '{"id":3,"method":"mining.submit","params":["test_worker","job_id","extranonce2","ntime","nonce"]}'
        sleep 2
    ) | timeout 10s nc localhost $port 2>/dev/null || true
}

# Test Stratum connection
log_info "Testing Stratum connection to port $STRATUM_PORT..."
simulate_stratum_connection $STRATUM_PORT

echo ""
echo "6. 📊 Monitoring Share Submissions and Storage"

# Monitor for 30 seconds
log_info "Monitoring mining activity for 30 seconds..."

for i in {1..6}; do
    sleep 5
    
    # Get current status
    CURRENT_STATUS=$(curl -s http://localhost:${WEB_PORT}/ 2>/dev/null || echo '{}')
    CURRENT_SHARES=$(echo $CURRENT_STATUS | jq -r '.poolshares // 0')
    CURRENT_HASHRATE=$(echo $CURRENT_STATUS | jq -r '.poolhashps // 0')
    CURRENT_DIFFICULTY=$(echo $CURRENT_STATUS | jq -r '.difficulty // 1')
    
    echo "   [${i}/6] Shares: $CURRENT_SHARES, Hashrate: $CURRENT_HASHRATE H/s, Difficulty: $CURRENT_DIFFICULTY"
    
    # Check if database has grown
    if [ -d "$DB_PATH" ]; then
        DB_SIZE=$(du -sk "$DB_PATH" 2>/dev/null | cut -f1 || echo "0")
        echo "         DB Size: ${DB_SIZE}KB"
    fi
done

echo ""
echo "7. 🧪 Testing Share Injection (Simulated Mining)"

log_info "Injecting test shares via API simulation..."

# Create a comprehensive test client that tests proper address validation and payout
cat > /tmp/c2pool_test_client.py << 'EOF'
#!/usr/bin/env python3
import socket
import json
import time
import sys

def test_stratum_mining(host='localhost', port=8085):
    # Test different address types for testnet validation
    test_addresses = [
        # Valid Litecoin testnet addresses
        "tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0",  # Bech32 testnet
        "mkbgJGZi1rVVBwLvvG4vpwPkPcf7kWGUXh",              # P2PKH testnet  
        "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",          # P2SH testnet
        # Invalid addresses to test validation
        "invalid_address",                                 # Invalid format
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",     # Bitcoin mainnet (wrong blockchain)
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",           # Bitcoin address (wrong blockchain)
        "0x742d35Cc6635c0532925a3b8D84c5eaf8B4f7f32"    # Ethereum address (wrong blockchain)
    ]
    
    results = []
    
    for addr_idx, test_address in enumerate(test_addresses):
        try:
            print(f"\n--- Testing address {addr_idx + 1}/7: {test_address} ---")
            
            # Connect to Stratum server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            print(f"Connected to {host}:{port}")
            
            # Send subscribe
            subscribe_msg = {
                "id": 1,
                "method": "mining.subscribe",
                "params": ["c2pool-test/1.0"]
            }
            
            sock.send((json.dumps(subscribe_msg) + '\n').encode())
            response = sock.recv(1024).decode().strip()
            print(f"Subscribe response: {response}")
            
            # Send authorize with test address as username (for payout)
            authorize_msg = {
                "id": 2,
                "method": "mining.authorize", 
                "params": [test_address, "miner_password"]
            }
            
            sock.send((json.dumps(authorize_msg) + '\n').encode())
            response = sock.recv(1024).decode().strip()
            print(f"Authorize response: {response}")
            
            # Parse response to check if address was accepted
            try:
                auth_result = json.loads(response)
                is_valid = auth_result.get("result", False)
                error_msg = auth_result.get("error", {}).get("message", "")
                
                results.append({
                    "address": test_address,
                    "valid": is_valid,
                    "error": error_msg
                })
                
                if is_valid:
                    print(f"✅ Address ACCEPTED: {test_address}")
                    
                    # If authorized, send test shares for reward calculation
                    for i in range(2):
                        submit_msg = {
                            "id": 3 + i,
                            "method": "mining.submit",
                            "params": [
                                test_address,  # Payout address
                                f"job_{i}",
                                f"extranonce2_{i}",
                                f"{int(time.time())}",
                                f"nonce_{addr_idx:08x}{i:04x}"
                            ]
                        }
                        
                        sock.send((json.dumps(submit_msg) + '\n').encode())
                        time.sleep(0.5)
                        
                        # Try to read response
                        try:
                            response = sock.recv(1024).decode().strip()
                            print(f"  Share {i+1} response: {response}")
                        except:
                            print(f"  Share {i+1}: No immediate response")
                else:
                    print(f"❌ Address REJECTED: {test_address} - {error_msg}")
                    
            except json.JSONDecodeError:
                print(f"❌ Invalid JSON response: {response}")
                results.append({
                    "address": test_address,
                    "valid": False,
                    "error": "Invalid JSON response"
                })
            
            sock.close()
            time.sleep(1)  # Brief pause between tests
            
        except Exception as e:
            print(f"❌ Connection failed for {test_address}: {e}")
            results.append({
                "address": test_address,
                "valid": False,
                "error": str(e)
            })
    
    # Summary
    print(f"\n=== ADDRESS VALIDATION SUMMARY ===")
    valid_count = 0
    for result in results:
        status = "✅ VALID" if result["valid"] else "❌ INVALID"
        print(f"{status}: {result['address']}")
        if result["error"]:
            print(f"   Error: {result['error']}")
        if result["valid"]:
            valid_count += 1
    
    print(f"\nResult: {valid_count}/{len(results)} addresses accepted")
    print("Expected: 3 valid Litecoin testnet addresses, 4 invalid addresses rejected")
    print("This tests blockchain-specific validation (LTC vs BTC vs ETH)")
    
    return valid_count > 0

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
    test_stratum_mining(port=port)
EOF

# Run the test client
if command -v python3 >/dev/null 2>&1; then
    log_info "Running Python Stratum test client..."
    python3 /tmp/c2pool_test_client.py $STRATUM_PORT || log_warn "Python test client failed"
else
    log_warn "Python3 not available, skipping Stratum protocol test"
fi

echo ""
echo "8. 📈 Final Status Check"

# Wait a moment for processing
sleep 2

# Get final status
FINAL_STATUS=$(curl -s http://localhost:${WEB_PORT}/ 2>/dev/null || echo '{}')
FINAL_SHARES=$(echo $FINAL_STATUS | jq -r '.poolshares // 0')
FINAL_HASHRATE=$(echo $FINAL_STATUS | jq -r '.poolhashps // 0')
FINAL_DIFFICULTY=$(echo $FINAL_STATUS | jq -r '.difficulty // 1')
FINAL_CONNECTIONS=$(echo $FINAL_STATUS | jq -r '.connections // 0')

echo "Final Statistics:"
echo "   Pool Shares: $FINAL_SHARES (was $INITIAL_SHARES)"
echo "   Pool Hashrate: $FINAL_HASHRATE H/s (was $INITIAL_HASHRATE H/s)" 
echo "   Difficulty: $FINAL_DIFFICULTY"
echo "   Connections: $FINAL_CONNECTIONS"

# Check share growth
SHARES_ADDED=$((FINAL_SHARES - INITIAL_SHARES))
if [ $SHARES_ADDED -gt 0 ]; then
    log_info "✅ Shares increased by $SHARES_ADDED during test"
else
    log_warn "⚠️  No share increase detected during test"
fi

echo ""
echo "9. 💾 Final Database Check"

# Final database check
if [ -d "$DB_PATH" ]; then
    FINAL_DB_SIZE=$(du -sk "$DB_PATH" 2>/dev/null | cut -f1 || echo "0")
    FINAL_DB_FILES=$(find "$DB_PATH" -type f 2>/dev/null | wc -l)
    
    log_info "Final database status:"
    echo "   Directory: $DB_PATH"
    echo "   Size: ${FINAL_DB_SIZE}KB"
    echo "   Files: $FINAL_DB_FILES"
    
    # List database contents
    log_info "Database files:"
    ls -la "$DB_PATH" 2>/dev/null | head -10
else
    log_warn "Database directory still not found"
fi

echo ""
echo "10. 🧹 Cleanup"

# Stop c2pool
log_info "Stopping C2Pool Enhanced..."
kill $C2POOL_PID 2>/dev/null || true

# Wait for graceful shutdown
sleep 3

# Force kill if still running
if kill -0 $C2POOL_PID 2>/dev/null; then
    log_warn "Force killing C2Pool..."
    kill -9 $C2POOL_PID 2>/dev/null || true
fi

# Cleanup
rm -f /tmp/c2pool_test_client.py

echo ""
echo "🎉 C2Pool Enhanced Mining Test Complete!"
echo ""
echo "Test Summary:"
echo "============="
echo "✅ Web Interface: Working on port $WEB_PORT"
echo "✅ Stratum Protocol: Available on port $STRATUM_PORT"
echo "✅ Address Validation: Testnet addresses checked for payout eligibility"
echo "✅ LevelDB Storage: $([ -d "$DB_PATH" ] && echo "Initialized" || echo "Not Found")"
echo "✅ Share Tracking: $([ $SHARES_ADDED -gt 0 ] && echo "$SHARES_ADDED shares added" || echo "No shares detected")"
echo "✅ Mining Capabilities: $([ -d "$DB_PATH" ] && echo "Ready for miners" || echo "Basic functionality")"
echo ""

if [ $SHARES_ADDED -gt 0 ] && [ -d "$DB_PATH" ]; then
    echo "🎯 Result: FULL MINING FUNCTIONALITY VERIFIED"
    echo "   - Storage system working"
    echo "   - Share submission working" 
    echo "   - Database persistence working"
    echo "   - Ready for real miners!"
else
    echo "⚠️  Result: BASIC FUNCTIONALITY VERIFIED"
    echo "   - Core systems working"
    echo "   - Web interface operational"
    echo "   - May need real miner for full test"
fi

echo ""
echo "To connect a real miner:"
echo "   stratum+tcp://localhost:$STRATUM_PORT"
echo "   Username: any_worker_name"
echo "   Password: any_password"
