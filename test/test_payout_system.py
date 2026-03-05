#!/usr/bin/env python3
"""
Test C2Pool Payout System
"""
import socket
import json
import time
import sys
import requests
import threading
import subprocess

def test_payout_api(host='localhost', port=8084):
    """Test the payout-related API endpoints"""
    print("\n🏦 Testing C2Pool Payout API")
    
    base_url = f"http://{host}:{port}"
    
    # Test getpayoutinfo
    print("\n1. Testing getpayoutinfo...")
    try:
        response = requests.post(base_url, json={
            "method": "getpayoutinfo",
            "params": [],
            "id": 1
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ getpayoutinfo: {json.dumps(result, indent=2)}")
        else:
            print(f"❌ getpayoutinfo failed: {response.status_code}")
    except Exception as e:
        print(f"❌ getpayoutinfo error: {e}")
    
    # Test getminerstats
    print("\n2. Testing getminerstats...")
    try:
        response = requests.post(base_url, json={
            "method": "getminerstats",
            "params": [],
            "id": 2
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ getminerstats: {json.dumps(result, indent=2)}")
        else:
            print(f"❌ getminerstats failed: {response.status_code}")
    except Exception as e:
        print(f"❌ getminerstats error: {e}")

def submit_test_shares(host='localhost', port=8085):
    """Submit test shares from multiple miners to test payout distribution"""
    print("\n💰 Submitting test shares for payout calculation")
    
    test_miners = [
        "n4HFXoG2xEKFyzpGarucZzAd98seabNTPq",  # Legacy P2PKH
        "QNvFB4sd5fjN74hd77fVtWaCV1N2y1Kbmp",  # P2SH-SegWit
        "tltc1qv6nx5p0gp8dxt9qsvz908ghlstmsf8833v36t2"  # Bech32
    ]
    
    for i, miner_address in enumerate(test_miners):
        print(f"\n{i+1}. Testing miner: {miner_address}")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((host, port))
                
                # Subscribe
                subscribe_msg = {
                    "id": 1,
                    "method": "mining.subscribe",
                    "params": ["payout_test_miner", "1.0"]
                }
                sock.send((json.dumps(subscribe_msg) + '\n').encode())
                subscribe_response = sock.recv(1024).decode().strip()
                print(f"   Subscribe: {subscribe_response}")
                
                # Authorize
                authorize_msg = {
                    "id": 2,
                    "method": "mining.authorize",
                    "params": [miner_address, "password"]
                }
                sock.send((json.dumps(authorize_msg) + '\n').encode())
                authorize_response = sock.recv(1024).decode().strip()
                print(f"   Authorize: {authorize_response}")
                
                # Submit multiple shares with different difficulties
                for j in range(3):
                    submit_msg = {
                        "id": 3 + j,
                        "method": "mining.submit",
                        "params": [
                            miner_address,
                            f"job_{j}",
                            f"0000000{j}",
                            f"5f796c4{j}",
                            f"12345678{j:01d}"
                        ]
                    }
                    sock.send((json.dumps(submit_msg) + '\n').encode())
                    submit_response = sock.recv(1024).decode().strip()
                    print(f"   Share {j+1}: {submit_response}")
                    time.sleep(0.5)
                
                print(f"   ✅ Submitted 3 shares for {miner_address}")
                
        except Exception as e:
            print(f"   ❌ Error for {miner_address}: {e}")
        
        time.sleep(1)

def test_payout_distribution():
    """Test the full payout calculation flow"""
    print("\n🎯 Testing Payout Distribution System")
    
    # Wait for shares to be processed
    print("   Waiting for shares to be processed...")
    time.sleep(5)
    
    # Check updated payout info
    print("\n📊 Checking updated payout information...")
    test_payout_api()
    
    # Test coinbase construction
    print("\n⚙️  Testing coinbase construction...")
    try:
        response = requests.post("http://localhost:8084", json={
            "method": "getwork",
            "params": [],
            "id": 10
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Coinbase work generated: {json.dumps(result, indent=2)}")
        else:
            print(f"❌ Coinbase generation failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Coinbase generation error: {e}")

def main():
    print("🚀 C2Pool Payout System Integration Test")
    print("=" * 50)
    
    # Start C2Pool in background
    print("\n1. Starting C2Pool Enhanced...")
    try:
        c2pool_process = subprocess.Popen([
            "./build/src/c2pool/c2pool_enhanced",
            "--testnet",
            "--blockchain", "ltc",
            "--integrated", "0.0.0.0:8084"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for startup
        time.sleep(5)
        
        # Check if process is running
        if c2pool_process.poll() is None:
            print("   ✅ C2Pool started successfully")
        else:
            print("   ❌ C2Pool failed to start")
            return
            
    except Exception as e:
        print(f"   ❌ Failed to start C2Pool: {e}")
        return
    
    try:
        # Test initial payout API
        print("\n2. Testing initial payout API...")
        test_payout_api()
        
        # Submit test shares
        print("\n3. Submitting test shares...")
        submit_test_shares()
        
        # Test payout distribution
        print("\n4. Testing payout distribution...")
        test_payout_distribution()
        
        print("\n✅ Payout system integration test completed!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test error: {e}")
    finally:
        # Clean up
        print("\n🧹 Cleaning up...")
        try:
            c2pool_process.terminate()
            c2pool_process.wait(timeout=10)
        except:
            c2pool_process.kill()
        print("   ✅ C2Pool stopped")

if __name__ == "__main__":
    main()
