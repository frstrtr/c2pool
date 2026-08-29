#!/usr/bin/env python3
"""
Simple test to submit shares and check payout tracking
"""
import socket
import json
import time
import requests

def submit_shares_and_check_payout():
    host = 'localhost'
    stratum_port = 8084
    api_port = 8083
    
    test_address = "n4HFXoG2xEKFyzpGarucZzAd98seabNTPq"
    
    print("🎯 Testing Payout Tracking with Share Submission")
    print("=" * 50)
    
    # 1. Check initial payout state
    print("1. Checking initial payout state...")
    response = requests.post(f"http://{host}:{api_port}", json={
        "jsonrpc": "2.0",
        "method": "getpayoutinfo",
        "params": [],
        "id": 1
    })
    initial_state = response.json()["result"]
    print(f"   Initial state: {json.dumps(initial_state, indent=2)}")
    
    # 2. Submit some shares via Stratum
    print(f"\n2. Submitting shares from {test_address}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect((host, stratum_port))
            
            # Subscribe
            subscribe_msg = {"id": 1, "method": "mining.subscribe", "params": ["test_miner"]}
            sock.send((json.dumps(subscribe_msg) + '\n').encode())
            subscribe_response = sock.recv(1024).decode().strip()
            print(f"   Subscribe: {subscribe_response}")
            
            # Authorize
            authorize_msg = {"id": 2, "method": "mining.authorize", "params": [test_address, "pass"]}
            sock.send((json.dumps(authorize_msg) + '\n').encode())
            authorize_response = sock.recv(1024).decode().strip()
            print(f"   Authorize: {authorize_response}")
            
            # Submit multiple shares
            for i in range(5):
                submit_msg = {
                    "id": 3 + i,
                    "method": "mining.submit",
                    "params": [test_address, f"job_{i}", f"0000000{i}", f"5f796c4{i}", f"1234567{i}"]
                }
                sock.send((json.dumps(submit_msg) + '\n').encode())
                submit_response = sock.recv(1024).decode().strip()
                print(f"   Share {i+1}: {submit_response}")
                time.sleep(0.5)
                
    except Exception as e:
        print(f"   ❌ Error submitting shares: {e}")
        return
    
    # 3. Check updated payout state
    print("\n3. Checking updated payout state...")
    time.sleep(2)  # Wait for processing
    
    response = requests.post(f"http://{host}:{api_port}", json={
        "jsonrpc": "2.0",
        "method": "getpayoutinfo",
        "params": [],
        "id": 3
    })
    updated_state = response.json()["result"]
    print(f"   Updated state: {json.dumps(updated_state, indent=2)}")
    
    # 4. Check miner stats
    print("\n4. Checking miner statistics...")
    response = requests.post(f"http://{host}:{api_port}", json={
        "jsonrpc": "2.0",
        "method": "getminerstats",
        "params": [],
        "id": 4
    })
    miner_stats = response.json()["result"]
    print(f"   Miner stats: {json.dumps(miner_stats, indent=2)}")
    
    # 5. Test coinbase construction
    print("\n5. Testing coinbase construction...")
    response = requests.post(f"http://{host}:{api_port}", json={
        "jsonrpc": "2.0",
        "method": "getwork",
        "params": [],
        "id": 5
    })
    work = response.json()["result"]
    print(f"   Work generated: data={work.get('data', 'N/A')[:32]}..., difficulty={work.get('difficulty', 'N/A')}")
    
    print("\n✅ Payout tracking test completed!")

if __name__ == "__main__":
    submit_shares_and_check_payout()
