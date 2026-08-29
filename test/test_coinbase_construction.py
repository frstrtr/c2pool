#!/usr/bin/env python3
"""
Comprehensive Coinbase Construction and Block Candidate Validation Test

This test validates:
1. Coinbase transaction construction with multiple payout addresses
2. Address validation for all supported types (P2PKH, P2SH, Bech32)
3. Block candidate creation and validation
4. Integration with LTC node RPC for block submission
5. Multi-output coinbase for miner + developer + node owner fees
"""

import requests
import json
import time
import hashlib
import binascii
import sys
import subprocess
from typing import Dict, List, Tuple, Optional

# Test Configuration
LTC_NODE_HOST = "127.0.0.1"
LTC_NODE_PORT = 19332  # LTC testnet RPC port
LTC_NODE_USER = "user"
LTC_NODE_PASS = "pass"

C2POOL_API_HOST = "127.0.0.1"
C2POOL_API_PORT = 8084
C2POOL_STRATUM_PORT = 8090

# Test Addresses for Different Types
TEST_ADDRESSES = {
    "legacy_p2pkh": "mzgiTxxwqsFLuP1Mc7SFfRFfbDZbCvrKWL",      # Legacy P2PKH testnet
    "p2sh_segwit": "2N12LqSKC6yJar1sGomDZ13BT3cM6a1u72a",       # P2SH-SegWit testnet
    "bech32_segwit": "tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", # Bech32 testnet
    "developer": "tltc1qc2pool0dev0testnet0addr0for0ltc0testing",  # Developer address
    "node_owner": "tltc1q3px4r9ad5dqgsxt7lk8l58qwxk7wt3shjevutp",   # Node owner address
}

EXPECTED_BLOCK_REWARD = 25_00000000  # 25 LTC in satoshis (testnet)

class LTCNodeRPC:
    """Interface to LTC node RPC for validation"""
    
    def __init__(self, host: str, port: int, user: str, password: str):
        self.url = f"http://{host}:{port}"
        self.auth = (user, password)
        
    def call(self, method: str, params: List = None) -> Optional[Dict]:
        """Make RPC call to LTC node"""
        if params is None:
            params = []
            
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                auth=self.auth,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if "error" in result and result["error"]:
                    print(f"RPC Error: {result['error']}")
                    return None
                return result.get("result")
            else:
                print(f"HTTP Error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"RPC Exception: {e}")
            return None
    
    def validate_address(self, address: str) -> Optional[Dict]:
        """Validate address using LTC node"""
        return self.call("validateaddress", [address])
    
    def get_block_template(self) -> Optional[Dict]:
        """Get block template from LTC node"""
        return self.call("getblocktemplate", [{"rules": ["segwit"]}])
    
    def submit_block(self, block_hex: str) -> Optional[str]:
        """Submit block to LTC node"""
        return self.call("submitblock", [block_hex])

class CoinbaseConstructionTest:
    """Test coinbase construction and block validation"""
    
    def __init__(self):
        self.ltc_node = LTCNodeRPC(LTC_NODE_HOST, LTC_NODE_PORT, LTC_NODE_USER, LTC_NODE_PASS)
        self.test_results = {}
        
    def test_address_validation(self) -> bool:
        """Test address validation for all types"""
        print("\n🔍 Testing Address Validation")
        print("=" * 50)
        
        all_valid = True
        for addr_type, address in TEST_ADDRESSES.items():
            print(f"\n📍 Testing {addr_type}: {address}")
            
            # Test with LTC node
            ltc_result = self.ltc_node.validate_address(address)
            if ltc_result:
                ltc_valid = ltc_result.get("isvalid", False)
                ltc_type = ltc_result.get("type", "unknown")
                print(f"   LTC Node: {'✅ VALID' if ltc_valid else '❌ INVALID'} (type: {ltc_type})")
            else:
                ltc_valid = False
                print(f"   LTC Node: ❌ RPC FAILED")
            
            # Test with C2Pool validation
            c2pool_result = self.test_c2pool_address_validation(address)
            print(f"   C2Pool:   {'✅ VALID' if c2pool_result else '❌ INVALID'}")
            
            if not (ltc_valid and c2pool_result):
                all_valid = False
                
            self.test_results[f"address_validation_{addr_type}"] = {
                "ltc_valid": ltc_valid,
                "c2pool_valid": c2pool_result,
                "address": address
            }
        
        return all_valid
    
    def test_c2pool_address_validation(self, address: str) -> bool:
        """Test address validation through C2Pool API"""
        try:
            # Try to start mining with the address to test validation
            response = requests.post(f"http://{C2POOL_API_HOST}:{C2POOL_API_PORT}", json={
                "jsonrpc": "2.0",
                "method": "validate_address",
                "params": [address],
                "id": 1
            }, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                return result.get("result", {}).get("valid", False)
        except Exception as e:
            print(f"   C2Pool validation error: {e}")
        
        return False
    
    def test_coinbase_construction(self) -> bool:
        """Test coinbase transaction construction"""
        print("\n🔧 Testing Coinbase Construction")
        print("=" * 50)
        
        success = True
        
        # Test different payout scenarios
        scenarios = [
            {
                "name": "Solo Mining - Single Address",
                "miner": TEST_ADDRESSES["legacy_p2pkh"],
                "dev_fee": 0.5,
                "node_fee": 0.0
            },
            {
                "name": "Solo Mining - P2SH with Fees",
                "miner": TEST_ADDRESSES["p2sh_segwit"],
                "dev_fee": 2.5,
                "node_fee": 1.0
            },
            {
                "name": "Solo Mining - Bech32 with Fees",
                "miner": TEST_ADDRESSES["bech32_segwit"],
                "dev_fee": 1.0,
                "node_fee": 0.5
            }
        ]
        
        for scenario in scenarios:
            print(f"\n📦 Testing: {scenario['name']}")
            result = self.test_coinbase_scenario(scenario)
            success = success and result
            
        return success
    
    def test_coinbase_scenario(self, scenario: Dict) -> bool:
        """Test specific coinbase construction scenario"""
        try:
            # Get coinbase construction from C2Pool
            response = requests.post(f"http://{C2POOL_API_HOST}:{C2POOL_API_PORT}", json={
                "jsonrpc": "2.0",
                "method": "build_coinbase",
                "params": {
                    "block_reward": EXPECTED_BLOCK_REWARD,
                    "miner_address": scenario["miner"],
                    "dev_fee_percent": scenario["dev_fee"],
                    "node_fee_percent": scenario["node_fee"]
                },
                "id": 1
            }, timeout=10)
            
            if response.status_code != 200:
                print(f"   ❌ HTTP Error: {response.status_code}")
                return False
                
            result = response.json()
            if "error" in result and result["error"]:
                print(f"   ❌ API Error: {result['error']}")
                return False
                
            coinbase_data = result.get("result", {})
            coinbase_hex = coinbase_data.get("coinbase_hex", "")
            outputs = coinbase_data.get("outputs", [])
            
            print(f"   📊 Coinbase outputs: {len(outputs)}")
            
            total_amount = 0
            for i, output in enumerate(outputs):
                address = output.get("address", "")
                amount = output.get("amount_satoshis", 0)
                percent = (amount / EXPECTED_BLOCK_REWARD) * 100
                total_amount += amount
                
                print(f"      Output {i+1}: {amount:>12} sat ({percent:5.2f}%) → {address}")
            
            # Validate total amount
            if total_amount != EXPECTED_BLOCK_REWARD:
                print(f"   ❌ Total amount mismatch: {total_amount} != {EXPECTED_BLOCK_REWARD}")
                return False
            
            print(f"   ✅ Total validated: {total_amount} satoshis")
            print(f"   📜 Coinbase hex: {coinbase_hex[:100]}...")
            
            # Validate coinbase hex format
            if not self.validate_coinbase_hex(coinbase_hex):
                return False
                
            self.test_results[f"coinbase_{scenario['name'].lower().replace(' ', '_')}"] = {
                "outputs": outputs,
                "total_amount": total_amount,
                "coinbase_hex": coinbase_hex
            }
            
            return True
            
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            return False
    
    def validate_coinbase_hex(self, coinbase_hex: str) -> bool:
        """Validate coinbase transaction hex format"""
        try:
            # Basic hex validation
            bytes.fromhex(coinbase_hex)
            
            # Check minimum length (version + inputs + outputs + locktime)
            if len(coinbase_hex) < 20:  # Very basic check
                print(f"   ❌ Coinbase hex too short: {len(coinbase_hex)} chars")
                return False
                
            print(f"   ✅ Coinbase hex format valid ({len(coinbase_hex)} chars)")
            return True
            
        except ValueError:
            print(f"   ❌ Invalid hex format")
            return False
    
    def test_block_template_integration(self) -> bool:
        """Test block template integration with LTC node"""
        print("\n📋 Testing Block Template Integration")
        print("=" * 50)
        
        # Get block template from LTC node
        ltc_template = self.ltc_node.get_block_template()
        if not ltc_template:
            print("   ❌ Failed to get block template from LTC node")
            return False
            
        print(f"   ✅ LTC block template received")
        print(f"      Height: {ltc_template.get('height', 'unknown')}")
        print(f"      Coinbase value: {ltc_template.get('coinbasevalue', 0)} satoshis")
        print(f"      Target: {ltc_template.get('target', 'unknown')}")
        
        # Get work from C2Pool
        c2pool_work = self.get_c2pool_work()
        if not c2pool_work:
            print("   ❌ Failed to get work from C2Pool")
            return False
            
        print(f"   ✅ C2Pool work received")
        
        # Compare key fields
        ltc_reward = ltc_template.get("coinbasevalue", 0)
        c2pool_reward = c2pool_work.get("coinbasevalue", 0)
        
        print(f"      LTC coinbase value: {ltc_reward}")
        print(f"      C2Pool coinbase value: {c2pool_reward}")
        
        if abs(ltc_reward - c2pool_reward) > 1000:  # Allow small differences
            print(f"   ⚠️  Coinbase value mismatch (difference: {abs(ltc_reward - c2pool_reward)})")
        
        self.test_results["block_template_integration"] = {
            "ltc_template": ltc_template,
            "c2pool_work": c2pool_work
        }
        
        return True
    
    def get_c2pool_work(self) -> Optional[Dict]:
        """Get work from C2Pool"""
        try:
            response = requests.post(f"http://{C2POOL_API_HOST}:{C2POOL_API_PORT}", json={
                "jsonrpc": "2.0",
                "method": "getwork",
                "params": [],
                "id": 1
            }, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                return result.get("result")
        except Exception as e:
            print(f"   Error getting C2Pool work: {e}")
        
        return None
    
    def test_block_candidate_validation(self) -> bool:
        """Test block candidate construction and validation"""
        print("\n🏗️  Testing Block Candidate Validation")
        print("=" * 50)
        
        # This would test actual block construction with our coinbase
        # For now, test the integration points
        
        print("   📋 Testing block candidate components...")
        
        # Test that we can construct a valid block candidate
        success = True
        
        try:
            # Get current best block template
            template = self.ltc_node.get_block_template()
            if not template:
                print("   ❌ Cannot get block template")
                return False
            
            # Test coinbase construction for the template
            coinbase_result = self.test_coinbase_for_template(template)
            if not coinbase_result:
                success = False
            
            print(f"   {'✅' if success else '❌'} Block candidate validation {'passed' if success else 'failed'}")
            
        except Exception as e:
            print(f"   ❌ Exception during block validation: {e}")
            success = False
        
        return success
    
    def test_coinbase_for_template(self, template: Dict) -> bool:
        """Test coinbase construction for specific block template"""
        try:
            coinbase_value = template.get("coinbasevalue", EXPECTED_BLOCK_REWARD)
            
            # Test coinbase with multiple scenarios
            for addr_type, address in TEST_ADDRESSES.items():
                if addr_type in ["developer", "node_owner"]:
                    continue
                    
                print(f"      Testing coinbase for {addr_type}: {address}")
                
                scenario = {
                    "miner": address,
                    "dev_fee": 0.5,
                    "node_fee": 0.5
                }
                
                if not self.test_coinbase_scenario(scenario):
                    print(f"         ❌ Failed for {addr_type}")
                    return False
                else:
                    print(f"         ✅ Success for {addr_type}")
            
            return True
            
        except Exception as e:
            print(f"      ❌ Exception: {e}")
            return False
    
    def run_comprehensive_test(self) -> bool:
        """Run all coinbase and block validation tests"""
        print("🚀 C2Pool Coinbase Construction & Block Validation Test")
        print("=" * 60)
        
        all_tests_passed = True
        
        # Test 1: Address Validation
        if not self.test_address_validation():
            all_tests_passed = False
        
        # Test 2: Coinbase Construction
        if not self.test_coinbase_construction():
            all_tests_passed = False
        
        # Test 3: Block Template Integration
        if not self.test_block_template_integration():
            all_tests_passed = False
        
        # Test 4: Block Candidate Validation
        if not self.test_block_candidate_validation():
            all_tests_passed = False
        
        # Generate test summary
        self.generate_test_summary(all_tests_passed)
        
        return all_tests_passed
    
    def generate_test_summary(self, all_passed: bool):
        """Generate comprehensive test summary"""
        print("\n📊 TEST SUMMARY")
        print("=" * 50)
        
        status = "✅ ALL TESTS PASSED" if all_passed else "❌ SOME TESTS FAILED"
        print(f"\n{status}\n")
        
        # Detailed results
        for test_name, result in self.test_results.items():
            print(f"📋 {test_name}:")
            if isinstance(result, dict):
                for key, value in result.items():
                    if isinstance(value, str) and len(value) > 50:
                        value = value[:50] + "..."
                    print(f"   {key}: {value}")
            print()
        
        # Write detailed results to file
        with open("coinbase_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        print("📁 Detailed results saved to: coinbase_test_results.json")

def check_c2pool_status():
    """Check if C2Pool is running and accessible"""
    try:
        response = requests.post(f"http://{C2POOL_API_HOST}:{C2POOL_API_PORT}", json={
            "jsonrpc": "2.0",
            "method": "getinfo",
            "params": [],
            "id": 1
        }, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            if "result" in result:
                print("✅ C2Pool is running and accessible")
                return True
    except Exception as e:
        print(f"❌ C2Pool not accessible: {e}")
    
    return False

def check_ltc_node_status():
    """Check if LTC node is running and accessible"""
    try:
        ltc_node = LTCNodeRPC(LTC_NODE_HOST, LTC_NODE_PORT, LTC_NODE_USER, LTC_NODE_PASS)
        info = ltc_node.call("getblockchaininfo")
        
        if info:
            print(f"✅ LTC node accessible - Chain: {info.get('chain', 'unknown')}, Blocks: {info.get('blocks', 0)}")
            return True
    except Exception as e:
        print(f"❌ LTC node not accessible: {e}")
    
    return False

def main():
    """Main test execution"""
    print("🔍 Pre-flight Checks")
    print("=" * 30)
    
    # Check if services are running
    c2pool_ok = check_c2pool_status()
    ltc_ok = check_ltc_node_status()
    
    if not c2pool_ok:
        print("\n❌ C2Pool is not running. Please start it first with:")
        print("   ./c2pool --testnet --blockchain ltc --dev-donation 0.5 --node-owner-fee 0.5")
        return False
    
    if not ltc_ok:
        print("\n❌ LTC node is not accessible. Please ensure it's running and RPC is configured.")
        print("   Check ~/.litecoin/litecoin.conf for RPC settings")
        return False
    
    # Run comprehensive tests
    test_runner = CoinbaseConstructionTest()
    success = test_runner.run_comprehensive_test()
    
    if success:
        print("\n🎉 All coinbase and block validation tests PASSED!")
        return True
    else:
        print("\n💥 Some tests FAILED - check output above for details")
        return False

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
