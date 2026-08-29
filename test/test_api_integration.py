#!/usr/bin/env python3
"""
Real API Integration Test for C2Pool Enhanced Payout System

This test script validates the integration of the enhanced coinbase construction
and address validation system with the actual C2Pool web server APIs.
"""

import json
import requests
import time
import subprocess
import sys
from typing import Dict, List, Any

class C2PoolAPITester:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'C2Pool-API-Tester/1.0'
        })

    def call_rpc(self, method: str, params: Any = None) -> Dict:
        """Call RPC method on C2Pool server"""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": int(time.time() * 1000)
        }
        
        try:
            response = self.session.post(self.base_url, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if "error" in result:
                raise Exception(f"RPC Error: {result['error']}")
            
            return result.get("result", {})
        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP Error: {str(e)}")

    def test_server_connection(self) -> bool:
        """Test basic server connectivity"""
        try:
            result = self.call_rpc("getinfo")
            print(f"✅ Server connected: {result.get('version', 'Unknown version')}")
            return True
        except Exception as e:
            print(f"❌ Server connection failed: {e}")
            return False

    def test_address_validation(self) -> bool:
        """Test the enhanced address validation API"""
        print("\n=== Testing Address Validation API ===")
        
        test_addresses = [
            ("mhCjy1SRgJLWKNMEv23kSjGrTgpXzJ1X7L", "Legacy testnet", True),
            ("tltc1qh5sfw4hm9rq4cj8rrz6cstl5w3uhl36kgjg4vt", "Bech32 testnet", True),
            ("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", "P2SH testnet", True),
            ("invalid_address", "Invalid", False),
            ("", "Empty", False)
        ]
        
        all_passed = True
        for address, description, expected_valid in test_addresses:
            try:
                result = self.call_rpc("validate_address", [address])
                is_valid = result.get("valid", False)
                address_type = result.get("type", "unknown")
                
                if is_valid == expected_valid:
                    status = "✅"
                else:
                    status = "❌"
                    all_passed = False
                
                print(f"{status} {description}: {address}")
                print(f"   Valid: {is_valid}, Type: {address_type}")
                
                if not is_valid and "error" in result:
                    print(f"   Error: {result['error']}")
                    
            except Exception as e:
                print(f"❌ {description}: API call failed - {e}")
                all_passed = False
        
        return all_passed

    def test_coinbase_construction(self) -> bool:
        """Test the enhanced coinbase construction API"""
        print("\n=== Testing Coinbase Construction API ===")
        
        test_scenarios = [
            {
                "name": "Basic miner only",
                "params": {
                    "block_reward": 312500000,
                    "miner_address": "mhCjy1SRgJLWKNMEv23kSjGrTgpXzJ1X7L"
                }
            },
            {
                "name": "Miner + Node owner",
                "params": {
                    "block_reward": 312500000,
                    "miner_address": "mhCjy1SRgJLWKNMEv23kSjGrTgpXzJ1X7L",
                    "node_fee_percent": 2.0,
                    "node_owner_address": "tltc1qh5sfw4hm9rq4cj8rrz6cstl5w3uhl36kgjg4vt"
                }
            },
            {
                "name": "Multi-output with dev fee",
                "params": {
                    "block_reward": 312500000,
                    "miner_address": "tltc1qh5sfw4hm9rq4cj8rrz6cstl5w3uhl36kgjg4vt",
                    "dev_fee_percent": 1.0,
                    "node_fee_percent": 3.0,
                    "node_owner_address": "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc"
                }
            }
        ]
        
        all_passed = True
        for scenario in test_scenarios:
            try:
                print(f"\nTesting: {scenario['name']}")
                result = self.call_rpc("build_coinbase", scenario['params'])
                
                if "error" in result:
                    print(f"❌ Error: {result['error']}")
                    all_passed = False
                    continue
                
                # Validate result structure
                required_fields = ["coinbase_hex", "outputs", "total_amount"]
                missing_fields = [field for field in required_fields if field not in result]
                
                if missing_fields:
                    print(f"❌ Missing fields: {missing_fields}")
                    all_passed = False
                    continue
                
                outputs = result.get("outputs", [])
                total_amount = result.get("total_amount", 0)
                coinbase_hex = result.get("coinbase_hex", "")
                
                print(f"✅ Coinbase constructed: {len(coinbase_hex)} hex chars")
                print(f"   Outputs: {len(outputs)}")
                print(f"   Total amount: {total_amount} sat")
                
                # Validate outputs
                output_total = sum(output.get("amount", 0) for output in outputs)
                if output_total == total_amount:
                    print(f"✅ Output amounts sum correctly")
                else:
                    print(f"❌ Output amount mismatch: {output_total} != {total_amount}")
                    all_passed = False
                
                for i, output in enumerate(outputs):
                    output_type = output.get("type", "unknown")
                    address = output.get("address", "")
                    amount = output.get("amount", 0)
                    print(f"   Output {i+1}: {output_type} -> {address} ({amount} sat)")
                
            except Exception as e:
                print(f"❌ {scenario['name']}: API call failed - {e}")
                all_passed = False
        
        return all_passed

    def test_block_template_integration(self) -> bool:
        """Test block template retrieval with enhanced coinbase"""
        print("\n=== Testing Block Template Integration ===")
        
        try:
            # Get standard block template
            result = self.call_rpc("getblocktemplate")
            
            if "error" in result:
                print(f"❌ Block template error: {result['error']}")
                return False
            
            print(f"✅ Block template retrieved")
            print(f"   Height: {result.get('height', 'unknown')}")
            print(f"   Coinbase value: {result.get('coinbasevalue', 0)} sat")
            print(f"   Previous block: {result.get('previousblockhash', '')[:16]}...")
            print(f"   Transactions: {len(result.get('transactions', []))}")
            
            return True
            
        except Exception as e:
            print(f"❌ Block template test failed: {e}")
            return False

    def test_block_candidate_generation(self) -> bool:
        """Test enhanced block candidate generation"""
        print("\n=== Testing Block Candidate Generation ===")
        
        try:
            params = {
                "miner_address": "mhCjy1SRgJLWKNMEv23kSjGrTgpXzJ1X7L",
                "node_fee_percent": 2.5,
                "node_owner_address": "tltc1qh5sfw4hm9rq4cj8rrz6cstl5w3uhl36kgjg4vt"
            }
            
            result = self.call_rpc("getblockcandidate", params)
            
            if "error" in result:
                print(f"❌ Block candidate error: {result['error']}")
                return False
            
            print(f"✅ Block candidate generated")
            print(f"   Height: {result.get('height', 'unknown')}")
            print(f"   Payout distribution: {result.get('payout_distribution', False)}")
            
            if "coinbase_outputs" in result:
                outputs = result["coinbase_outputs"]
                print(f"   Coinbase outputs: {len(outputs)}")
                for output in outputs:
                    output_type = output.get("type", "unknown")
                    amount = output.get("amount", 0)
                    print(f"     {output_type}: {amount} sat")
            
            return True
            
        except Exception as e:
            print(f"❌ Block candidate test failed: {e}")
            return False

    def test_mining_workflow(self) -> bool:
        """Test complete mining workflow simulation"""
        print("\n=== Testing Complete Mining Workflow ===")
        
        try:
            # Step 1: Validate miner address
            miner_address = "mhCjy1SRgJLWKNMEv23kSjGrTgpXzJ1X7L"
            addr_result = self.call_rpc("validate_address", [miner_address])
            
            if not addr_result.get("valid", False):
                print(f"❌ Invalid miner address: {miner_address}")
                return False
            
            print(f"✅ Step 1: Miner address validated")
            
            # Step 2: Get block template
            template_result = self.call_rpc("getblocktemplate")
            if "error" in template_result:
                print(f"❌ Step 2 failed: {template_result['error']}")
                return False
            
            print(f"✅ Step 2: Block template retrieved")
            
            # Step 3: Generate enhanced block candidate
            candidate_params = {
                "miner_address": miner_address,
                "node_fee_percent": 1.5
            }
            
            candidate_result = self.call_rpc("getblockcandidate", candidate_params)
            if "error" in candidate_result:
                print(f"❌ Step 3 failed: {candidate_result['error']}")
                return False
            
            print(f"✅ Step 3: Enhanced block candidate generated")
            
            # Step 4: Simulate mining (getwork)
            work_result = self.call_rpc("getwork")
            if "error" in work_result:
                print(f"⚠️  Step 4: Getwork not available (normal for pool mode)")
            else:
                print(f"✅ Step 4: Work data retrieved")
            
            print(f"✅ Complete mining workflow tested successfully")
            
            # Summary
            print(f"\nWorkflow Summary:")
            print(f"  Block height: {template_result.get('height', 'unknown')}")
            print(f"  Coinbase value: {template_result.get('coinbasevalue', 0)} sat")
            print(f"  Enhanced: {candidate_result.get('payout_distribution', False)}")
            print(f"  Ready for mining: ✅")
            
            return True
            
        except Exception as e:
            print(f"❌ Mining workflow test failed: {e}")
            return False

def check_litecoin_node():
    """Check if Litecoin testnet node is running"""
    try:
        result = subprocess.run([
            "litecoin-cli", "-testnet", "getblockchaininfo"
        ], capture_output=True, text=True, cwd="/home/user0/Documents/GitHub/c2pool")
        
        if result.returncode == 0:
            info = json.loads(result.stdout)
            print(f"✅ Litecoin testnet node running (blocks: {info['blocks']})")
            return True
        else:
            print(f"❌ Litecoin node error: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Litecoin node check failed: {e}")
        return False

def main():
    print("C2Pool Enhanced Payout System - API Integration Test")
    print("====================================================")
    
    # Check prerequisites
    print("\n=== Prerequisites Check ===")
    
    if not check_litecoin_node():
        print("❌ Litecoin testnet node not available")
        return 1
    
    # Initialize tester
    tester = C2PoolAPITester()
    
    # Run tests
    print("\n=== API Integration Tests ===")
    
    tests = [
        ("Server Connection", tester.test_server_connection),
        ("Address Validation", tester.test_address_validation),
        ("Coinbase Construction", tester.test_coinbase_construction),
        ("Block Template Integration", tester.test_block_template_integration),
        ("Block Candidate Generation", tester.test_block_candidate_generation),
        ("Complete Mining Workflow", tester.test_mining_workflow)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_function in tests:
        print(f"\n{'='*50}")
        print(f"Running: {test_name}")
        print(f"{'='*50}")
        
        try:
            if test_function():
                passed_tests += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} CRASHED: {e}")
    
    # Final report
    print(f"\n{'='*60}")
    print(f"TEST RESULTS: {passed_tests}/{total_tests} tests passed")
    print(f"{'='*60}")
    
    if passed_tests == total_tests:
        print("🎉 All tests passed! Enhanced payout system is working correctly.")
        print("\n📋 Ready for production deployment:")
        print("   ✅ Address validation for all types")
        print("   ✅ Multi-output coinbase construction")
        print("   ✅ Block template integration")
        print("   ✅ API endpoint functionality")
        print("   ✅ Complete mining workflow")
        return 0
    else:
        print(f"⚠️  {total_tests - passed_tests} tests failed. Review implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
