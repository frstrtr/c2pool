#!/usr/bin/env python3
"""
Simple LTC Address Validation Test
Tests addresses against the LTC testnet node when ready
"""

import json
import requests
import time
import base64

def test_ltc_connection():
    """Test connection to LTC testnet node"""
    rpc_url = "http://127.0.0.1:19332"
    auth = base64.b64encode(b"ltctest:ltctest123").decode()
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}"
    }
    
    payload = {
        "jsonrpc": "2.0",
        "method": "getblockchaininfo",
        "params": [],
        "id": 1
    }
    
    print("🔗 Testing LTC testnet node connection...")
    
    for attempt in range(30):  # Wait up to 30 seconds
        try:
            response = requests.post(rpc_url, json=payload, headers=headers, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    info = result["result"]
                    print(f"✅ Connected to LTC {info.get('chain')} node")
                    print(f"   Blocks: {info.get('blocks', 0)}")
                    print(f"   Best block: {info.get('bestblockhash', 'unknown')[:16]}...")
                    return True
            elif response.status_code == 401:
                print("❌ Authentication failed - checking credentials...")
                return False
            else:
                print(f"⏳ Node not ready (status {response.status_code}), waiting...")
        
        except requests.exceptions.RequestException:
            print(f"⏳ Waiting for node to start... ({attempt + 1}/30)")
        
        time.sleep(1)
    
    print("❌ Could not connect to LTC node after 30 seconds")
    return False

def validate_address_via_rpc(address: str) -> dict:
    """Validate an address using LTC RPC"""
    rpc_url = "http://127.0.0.1:19332"
    auth = base64.b64encode(b"ltctest:ltctest123").decode()
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth}"
    }
    
    payload = {
        "jsonrpc": "2.0",
        "method": "validateaddress",
        "params": [address],
        "id": 1
    }
    
    try:
        response = requests.post(rpc_url, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        
        result = response.json()
        return result.get("result", {})
        
    except Exception as e:
        return {"isvalid": False, "error": str(e)}

def main():
    print("🧪 LTC Testnet Address Validation Test")
    print("=" * 50)
    
    # Test connection first
    if not test_ltc_connection():
        return
    
    # Test addresses
    test_addresses = [
        ("mzgiTxxwqsFLuP1Mc7SFfRFfbDZbCvrKWL", "Generated LTC testnet P2PKH"),
        ("mtxCphuGjESaYCNmRYHREz7KAM8koeMv7m", "Generated LTC testnet P2PKH"),
        ("2N12LqSKC6yJar1sGomDZ13BT3cM6a1u72a", "Generated LTC testnet P2SH"),
        ("mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR", "Previous invalid address"),
        ("LaMT348PWRnrqeeWArpwQDAVWs71DTuLP9", "LTC mainnet (should fail)"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Bitcoin address (should fail)"),
    ]
    
    print(f"\\n🔍 Testing {len(test_addresses)} addresses...")
    print("=" * 50)
    
    valid_count = 0
    
    for address, description in test_addresses:
        print(f"\\n📋 {description}")
        print(f"Address: {address}")
        
        result = validate_address_via_rpc(address)
        
        if result.get("isvalid", False):
            print("✅ VALID (confirmed by LTC node)")
            if "type" in result:
                print(f"   Type: {result['type']}")
            if "isscript" in result:
                print(f"   Script: {result['isscript']}")
            valid_count += 1
        else:
            print("❌ INVALID (confirmed by LTC node)")
            if "error" in result:
                print(f"   Error: {result['error']}")
    
    print(f"\\n" + "=" * 50)
    print(f"📊 Results: {valid_count}/{len(test_addresses)} addresses valid")
    
    print(f"\\n✅ Address validation authority: LTC testnet node")
    print("This confirms which addresses are truly valid for LTC testnet")

if __name__ == "__main__":
    main()
