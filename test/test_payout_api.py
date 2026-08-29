#!/usr/bin/env python3
"""
Test C2Pool payout system API endpoints
"""
import requests
import json

def test_payout_api():
    print("🧪 Testing C2Pool Payout API endpoints")
    
    base_url = "http://localhost:8083"
    
    # Test getinfo
    print("\n1. Testing getinfo...")
    try:
        response = requests.post(base_url, json={
            "jsonrpc": "2.0",
            "method": "getinfo",
            "id": 1
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Pool info: {json.dumps(result['result'], indent=2)}")
        else:
            print(f"   ❌ HTTP error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test getminerstats
    print("\n2. Testing getminerstats...")
    try:
        response = requests.post(base_url, json={
            "jsonrpc": "2.0",
            "method": "getminerstats",
            "id": 2
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Miner stats: {json.dumps(result['result'], indent=2)}")
        else:
            print(f"   ❌ HTTP error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test getpayoutinfo  
    print("\n3. Testing getpayoutinfo...")
    try:
        response = requests.post(base_url, json={
            "jsonrpc": "2.0",
            "method": "getpayoutinfo",
            "id": 3
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Payout info: {json.dumps(result['result'], indent=2)}")
        else:
            print(f"   ❌ HTTP error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    test_payout_api()
