#!/usr/bin/env python3
"""
Simplified Coinbase Construction Test

This test directly validates the C2Pool coinbase construction without 
requiring the full WebServer infrastructure.
"""

import requests
import json
import time
import subprocess
import sys

# Test Configuration  
C2POOL_API_HOST = "127.0.0.1"
C2POOL_API_PORT = 8084

# Test Addresses
TEST_ADDRESSES = {
    "legacy_p2pkh": "mzgiTxxwqsFLuP1Mc7SFfRFfbDZbCvrKWL",      # Legacy P2PKH testnet
    "p2sh_segwit": "2N12LqSKC6yJar1sGomDZ13BT3cM6a1u72a",       # P2SH-SegWit testnet
    "bech32_segwit": "tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", # Bech32 testnet
}

def test_c2pool_api(method, params=None):
    """Test C2Pool API endpoints"""
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1
        }
        
        response = requests.post(
            f"http://{C2POOL_API_HOST}:{C2POOL_API_PORT}",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if "error" in result and result["error"]:
                print(f"❌ API Error for {method}: {result['error']}")
                return None
            return result.get("result")
        else:
            print(f"❌ HTTP Error for {method}: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Exception testing {method}: {e}")
        return None

def test_coinbase_construction():
    """Test coinbase construction with different scenarios"""
    print("\n🔧 Testing Coinbase Construction")
    print("=" * 50)
    
    scenarios = [
        {
            "name": "Basic P2PKH Address",
            "miner_address": TEST_ADDRESSES["legacy_p2pkh"],
            "dev_fee": 0.5,
            "node_fee": 0.0,
            "block_reward": 2500000000  # 25 LTC
        },
        {
            "name": "P2SH with Fees",  
            "miner_address": TEST_ADDRESSES["p2sh_segwit"],
            "dev_fee": 2.5,
            "node_fee": 1.0,
            "block_reward": 2500000000
        },
        {
            "name": "Bech32 with Fees",
            "miner_address": TEST_ADDRESSES["bech32_segwit"], 
            "dev_fee": 1.0,
            "node_fee": 0.5,
            "block_reward": 2500000000
        }
    ]
    
    success_count = 0
    for scenario in scenarios:
        print(f"\n📦 Testing: {scenario['name']}")
        print(f"   Miner: {scenario['miner_address']}")
        print(f"   Dev fee: {scenario['dev_fee']}%, Node fee: {scenario['node_fee']}%")
        
        params = {
            "miner_address": scenario["miner_address"],
            "block_reward": scenario["block_reward"],
            "dev_fee_percent": scenario["dev_fee"],
            "node_fee_percent": scenario["node_fee"]
        }
        
        result = test_c2pool_api("build_coinbase", params)
        if result:
            if "outputs" in result:
                print(f"   ✅ Success - {len(result['outputs'])} outputs generated")
                
                total_amount = 0
                for i, output in enumerate(result["outputs"]):
                    address = output.get("address", "")
                    amount = output.get("amount_satoshis", 0)
                    output_type = output.get("type", "unknown")
                    percent = (amount / scenario["block_reward"]) * 100
                    total_amount += amount
                    
                    print(f"      Output {i+1} ({output_type}): {amount:>12} sat ({percent:5.2f}%) → {address}")
                
                if total_amount == scenario["block_reward"]:
                    print(f"   ✅ Total amount verified: {total_amount} satoshis")
                    success_count += 1
                else:
                    print(f"   ❌ Amount mismatch: {total_amount} != {scenario['block_reward']}")
                    
                if "coinbase_hex" in result:
                    coinbase_hex = result["coinbase_hex"]
                    print(f"   📜 Coinbase hex ({len(coinbase_hex)} chars): {coinbase_hex[:80]}...")
                    
            else:
                print(f"   ❌ No outputs in result: {result}")
        else:
            print(f"   ❌ API call failed")
    
    print(f"\n📊 Coinbase Construction Summary: {success_count}/{len(scenarios)} tests passed")
    return success_count == len(scenarios)

def test_address_validation():
    """Test address validation endpoints"""
    print("\n🔍 Testing Address Validation")
    print("=" * 50)
    
    success_count = 0
    for addr_type, address in TEST_ADDRESSES.items():
        print(f"\n📍 Testing {addr_type}: {address}")
        
        result = test_c2pool_api("validate_address", [address])
        if result:
            is_valid = result.get("valid", False)
            addr_type_num = result.get("type", -1)
            blockchain = result.get("blockchain", -1)
            network = result.get("network", -1)
            
            print(f"   Valid: {'✅ YES' if is_valid else '❌ NO'}")
            print(f"   Type: {addr_type_num}, Blockchain: {blockchain}, Network: {network}")
            
            if is_valid:
                success_count += 1
            else:
                error = result.get("error", "Unknown error")
                print(f"   Error: {error}")
        else:
            print(f"   ❌ API call failed")
    
    print(f"\n📊 Address Validation Summary: {success_count}/{len(TEST_ADDRESSES)} tests passed")
    return success_count == len(TEST_ADDRESSES)

def test_coinbase_validation():
    """Test coinbase transaction validation"""
    print("\n✅ Testing Coinbase Validation")
    print("=" * 50)
    
    # Test with a valid-looking coinbase hex
    test_coinbase = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000ffffffff03510b1affffffff0100f2052a010000001976a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac00000000"
    
    print(f"📜 Testing coinbase hex validation...")
    print(f"   Hex: {test_coinbase[:80]}...")
    
    result = test_c2pool_api("validate_coinbase", [test_coinbase])
    if result:
        is_valid = result.get("valid", False)
        hex_length = result.get("hex_length", 0)
        byte_length = result.get("byte_length", 0)
        
        print(f"   Valid: {'✅ YES' if is_valid else '❌ NO'}")
        print(f"   Length: {hex_length} chars ({byte_length} bytes)")
        
        if not is_valid:
            error = result.get("error", "Unknown error")
            print(f"   Error: {error}")
            
        return is_valid
    else:
        print(f"   ❌ API call failed")
        return False

def check_c2pool_running():
    """Check if C2Pool is accessible"""
    print("🔍 Checking C2Pool Status")
    print("=" * 30)
    
    result = test_c2pool_api("getinfo")
    if result:
        print("✅ C2Pool is running and accessible")
        print(f"   Version: {result.get('version', 'unknown')}")
        print(f"   Network: {result.get('network', 'unknown')}")
        return True
    else:
        print("❌ C2Pool not accessible")
        print("   Try starting it with: ./c2pool --testnet --blockchain ltc --stratum-port 8090")
        return False

def start_c2pool_if_needed():
    """Start C2Pool in background if not running"""
    if not check_c2pool_running():
        print("\n🚀 Starting C2Pool...")
        try:
            # Start C2Pool in background
            subprocess.Popen([
                "./c2pool", 
                "--testnet", 
                "--blockchain", "ltc",
                "--stratum-port", "8090",
                "--dev-donation", "0.5",
                "--node-owner-fee", "0.5"
            ], cwd="/home/user0/Documents/GitHub/c2pool")
            
            # Wait for startup
            print("   Waiting for C2Pool to start...")
            time.sleep(10)
            
            return check_c2pool_running()
        except Exception as e:
            print(f"   ❌ Failed to start C2Pool: {e}")
            return False
    return True

def main():
    """Main test execution"""
    print("🚀 C2Pool Coinbase Construction Test")
    print("=" * 50)
    
    # Check or start C2Pool
    if not start_c2pool_if_needed():
        print("\n❌ Cannot proceed without C2Pool running")
        return False
    
    # Run tests
    tests_passed = 0
    total_tests = 3
    
    if test_address_validation():
        tests_passed += 1
        
    if test_coinbase_construction():
        tests_passed += 1
        
    if test_coinbase_validation():
        tests_passed += 1
    
    # Summary
    print(f"\n🎯 FINAL RESULTS")
    print("=" * 30)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("🎉 All tests PASSED!")
        return True
    else:
        print("💥 Some tests FAILED")
        return False

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
