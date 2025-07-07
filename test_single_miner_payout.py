#!/usr/bin/env python3
"""
Test single miner payout tracking
"""
import socket
import json
import time

def test_single_miner_payout():
    print("🧪 Testing payout tracking for single miner")
    
    miner_address = "n4HFXoG2xEKFyzpGarucZzAd98seabNTPq"
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(('localhost', 8084))
            
            print(f"1. Testing miner: {miner_address}")
            
            # Subscribe
            subscribe_msg = {"id": 1, "method": "mining.subscribe", "params": ["payout_test"]}
            sock.send((json.dumps(subscribe_msg) + '\n').encode())
            subscribe_resp = sock.recv(1024).decode().strip()
            print(f"   Subscribe: {subscribe_resp}")
            
            # Authorize
            auth_msg = {"id": 2, "method": "mining.authorize", "params": [miner_address, "password"]}
            sock.send((json.dumps(auth_msg) + '\n').encode())
            auth_resp = sock.recv(1024).decode().strip()
            print(f"   Authorize: {auth_resp}")
            
            # Submit shares
            for i in range(3):
                submit_msg = {
                    "id": 3 + i,
                    "method": "mining.submit",
                    "params": [miner_address, f"job_{i}", f"0000000{i}", f"5f796c4{i}", f"1234567{i}"]
                }
                sock.send((json.dumps(submit_msg) + '\n').encode())
                submit_resp = sock.recv(1024).decode().strip()
                print(f"   Share {i+1}: {submit_resp}")
                time.sleep(1)
            
            print("   ✅ Shares submitted successfully")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n2. Checking payout statistics...")
    time.sleep(2)
    
    # Check payout info via HTTP
    import requests
    try:
        response = requests.post("http://localhost:8083", json={
            "jsonrpc": "2.0",
            "method": "getminerstats", 
            "params": [],
            "id": 1
        }, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   Payout stats: {json.dumps(result, indent=2)}")
        else:
            print(f"   ❌ HTTP request failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ HTTP error: {e}")

if __name__ == "__main__":
    test_single_miner_payout()
