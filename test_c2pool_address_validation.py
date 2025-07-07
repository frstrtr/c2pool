#!/usr/bin/env python3
"""
Test C2Pool Address Validation with Valid LTC Testnet Addresses
Tests the fixed address validator with confirmed valid addresses
"""

import socket
import json
import time
import threading

def test_stratum_address(address, description):
    """Test address via Stratum protocol"""
    try:
        print(f"\\n🔍 Testing: {description}")
        print(f"Address: {address}")
        
        # Connect to C2Pool Stratum server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(("127.0.0.1", 8085))
        
        # Subscribe
        subscribe_msg = {"id": 1, "method": "mining.subscribe", "params": ["c2pool-test/1.0"]}
        sock.send((json.dumps(subscribe_msg) + '\\n').encode())
        
        # Wait for subscribe response
        time.sleep(0.5)
        response_data = sock.recv(1024).decode().strip()
        print(f"Subscribe response: {response_data}")
        
        # Authorize with the address
        auth_msg = {"id": 2, "method": "mining.authorize", "params": [address, "test"]}
        sock.send((json.dumps(auth_msg) + '\\n').encode())
        
        # Read authorization response
        time.sleep(1.0)
        auth_data = sock.recv(1024).decode().strip()
        print(f"Auth response: {auth_data}")
        
        # Parse the response
        for line in auth_data.split('\\n'):
            if line.strip():
                try:
                    resp = json.loads(line)
                    if resp.get('id') == 2:  # Our authorize request
                        if resp.get('result') is True:
                            print("✅ ADDRESS ACCEPTED by C2Pool")
                            sock.close()
                            return True
                        elif 'error' in resp:
                            print(f"❌ ADDRESS REJECTED: {resp['error'].get('message', 'Unknown error')}")
                            sock.close()
                            return False
                except json.JSONDecodeError:
                    continue
        
        print("❓ Unclear response")
        sock.close()
        return False
        
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def run_c2pool_server():
    """Run C2Pool server in background"""
    import subprocess
    import os
    
    # Start C2Pool in background
    cmd = ["./build/src/c2pool/c2pool", "--testnet", "--integrated", "0.0.0.0:8084", "--blockchain", "ltc"]
    
    try:
        process = subprocess.Popen(
            cmd, 
            cwd="/home/user0/Documents/GitHub/c2pool",
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Wait for server to start
        print("🚀 Starting C2Pool server...")
        time.sleep(8)  # Give it time to fully start
        
        return process
        
    except Exception as e:
        print(f"❌ Failed to start C2Pool: {e}")
        return None

def main():
    print("🧪 C2Pool Address Validation Integration Test")
    print("Testing with LTC-node-verified valid addresses")
    print("=" * 60)
    
    # Start C2Pool server
    server_process = run_c2pool_server()
    if not server_process:
        return
    
    try:
        # Test the verified valid addresses
        test_addresses = [
            ("mzgiTxxwqsFLuP1Mc7SFfRFfbDZbCvrKWL", "✅ LTC-node-verified P2PKH"),
            ("mtxCphuGjESaYCNmRYHREz7KAM8koeMv7m", "✅ LTC-node-verified P2PKH"),
            ("2N12LqSKC6yJar1sGomDZ13BT3cM6a1u72a", "✅ LTC-node-verified P2SH"),
            ("mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR", "❌ LTC-node-verified INVALID"),
            ("LaMT348PWRnrqeeWArpwQDAVWs71DTuLP9", "❌ LTC mainnet (should fail)"),
        ]
        
        print(f"Testing {len(test_addresses)} addresses against C2Pool...")
        
        accepted_count = 0
        rejected_count = 0
        
        for address, description in test_addresses:
            result = test_stratum_address(address, description)
            if result:
                accepted_count += 1
            else:
                rejected_count += 1
            time.sleep(1)  # Small delay between tests
        
        print(f"\\n" + "=" * 60)
        print("📊 C2POOL ADDRESS VALIDATION RESULTS")
        print(f"Addresses accepted: {accepted_count}")
        print(f"Addresses rejected: {rejected_count}")
        print(f"Total tested: {len(test_addresses)}")
        
        print(f"\\n✅ Expected results:")
        print("• First 3 addresses should be ACCEPTED (LTC-node verified)")
        print("• Last 2 addresses should be REJECTED (invalid/wrong network)")
        
        if accepted_count == 3 and rejected_count == 2:
            print(f"\\n🎉 SUCCESS! Address validation working correctly!")
            print("✅ C2Pool now properly validates LTC testnet addresses")
        else:
            print(f"\\n⚠️  Unexpected results - may need further investigation")
            
    finally:
        # Clean shutdown
        print(f"\\n🛑 Shutting down C2Pool server...")
        server_process.terminate()
        server_process.wait(timeout=5)

if __name__ == "__main__":
    main()
