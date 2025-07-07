#!/usr/bin/env python3
"""
LTC Testnet Address Validation via JSON-RPC
Uses the running Litecoin testnet daemon to validate addresses authoritatively
"""

import json
import requests
import time
import subprocess
import sys

class LTCNodeValidator:
    def __init__(self, rpc_host="127.0.0.1", rpc_port=19332, rpc_user="ltctest", rpc_password="ltctest123"):
        self.rpc_url = f"http://{rpc_host}:{rpc_port}/"
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.session = requests.Session()
        self.session.auth = (rpc_user, rpc_password)
        
    def rpc_call(self, method, params=None):
        """Make a JSON-RPC call to the LTC node"""
        if params is None:
            params = []
            
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        try:
            response = self.session.post(self.rpc_url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if "error" in result and result["error"] is not None:
                raise Exception(f"RPC Error: {result['error']}")
                
            return result.get("result")
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection error: {e}")
    
    def validate_address(self, address):
        """Validate an address using validateaddress RPC call"""
        try:
            result = self.rpc_call("validateaddress", [address])
            return result
        except Exception as e:
            return {"isvalid": False, "error": str(e)}
    
    def get_address_info(self, address):
        """Get detailed address info using getaddressinfo RPC call"""
        try:
            result = self.rpc_call("getaddressinfo", [address])
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def get_network_info(self):
        """Get network information"""
        try:
            result = self.rpc_call("getnetworkinfo")
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def is_testnet(self):
        """Check if the node is running on testnet"""
        try:
            blockchain_info = self.rpc_call("getblockchaininfo")
            return blockchain_info.get("chain") == "test"
        except Exception as e:
            print(f"Could not determine network: {e}")
            return False

def start_ltc_testnet_node():
    """Start the LTC testnet node if not running"""
    print("🚀 Starting LTC Testnet Node...")
    
    try:
        # Check if litecoin_testnet.sh exists
        import os
        script_path = "/home/user0/Documents/GitHub/c2pool/litecoin_testnet.sh"
        if os.path.exists(script_path):
            result = subprocess.run([script_path, "start"], 
                                 capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("✅ LTC testnet node started successfully")
                time.sleep(5)  # Give it time to start
                return True
            else:
                print(f"❌ Failed to start LTC node: {result.stderr}")
        else:
            print("⚠️  litecoin_testnet.sh not found, trying direct litecoind")
            
            # Try to start litecoind directly
            cmd = ["litecoind", "-testnet", "-daemon", "-rpcuser=user", "-rpcpassword=password", "-rpcport=19332"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("✅ LTC testnet node started directly")
                time.sleep(10)  # Give it more time to start
                return True
            else:
                print(f"❌ Failed to start litecoind: {result.stderr}")
        
    except Exception as e:
        print(f"❌ Error starting LTC node: {e}")
    
    return False

def test_node_connection():
    """Test connection to the LTC node"""
    print("🔗 Testing LTC Node Connection...")
    
    validator = LTCNodeValidator()
    
    try:
        network_info = validator.get_network_info()
        if "error" in network_info:
            print(f"❌ Connection failed: {network_info['error']}")
            return False
        
        print(f"✅ Connected to LTC node")
        print(f"   Version: {network_info.get('version', 'unknown')}")
        print(f"   Subversion: {network_info.get('subversion', 'unknown')}")
        
        # Check if testnet
        is_testnet = validator.is_testnet()
        print(f"   Network: {'testnet' if is_testnet else 'mainnet'}")
        
        if not is_testnet:
            print("⚠️  Warning: Node is not on testnet!")
            
        return True
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        return False

def test_address_validation_rpc():
    """Test address validation using LTC node RPC"""
    print("\n🧪 LTC Address Validation via JSON-RPC")
    print("=" * 50)
    
    validator = LTCNodeValidator()
    
    # Test addresses - mix of valid and invalid
    test_addresses = [
        # Generate some test addresses first
        ("mzgiTxxwqsFLuP1Mc7SFfRFfbDZbCvrKWL", "Generated LTC testnet P2PKH"),
        ("mtxCphuGjESaYCNmRYHREz7KAM8koeMv7m", "Generated LTC testnet P2PKH"),
        ("2N12LqSKC6yJar1sGomDZ13BT3cM6a1u72a", "Generated LTC testnet P2SH"),
        ("tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", "LTC testnet bech32"),
        
        # Known invalid
        ("mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR", "Previously invalid address"),
        ("LaMT348PWRnrqeeWArpwQDAVWs71DTuLP9", "LTC mainnet address"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Bitcoin address"),
        ("invalid_address", "Random string"),
        ("", "Empty address"),
    ]
    
    valid_addresses = []
    invalid_addresses = []
    
    for address, description in test_addresses:
        print(f"\nTesting: {description}")
        print(f"Address: {address}")
        
        # Basic validation
        validation_result = validator.validate_address(address)
        
        if validation_result.get("isvalid", False):
            print("✅ VALID according to LTC node")
            
            # Get additional info
            addr_info = validator.get_address_info(address)
            if "error" not in addr_info:
                print(f"   Type: {addr_info.get('type', 'unknown')}")
                print(f"   Script type: {addr_info.get('script_type', 'unknown')}")
                if addr_info.get('ismine', False):
                    print("   🏦 Address is in wallet")
                if addr_info.get('iswatchonly', False):
                    print("   👀 Watch-only address")
            
            valid_addresses.append((address, description))
            
        else:
            print("❌ INVALID according to LTC node")
            if "error" in validation_result:
                print(f"   Error: {validation_result['error']}")
            invalid_addresses.append((address, description))
    
    return valid_addresses, invalid_addresses

def generate_new_testnet_addresses():
    """Generate new testnet addresses using the LTC node"""
    print("\n🆕 Generating New Testnet Addresses")
    print("=" * 40)
    
    validator = LTCNodeValidator()
    generated_addresses = []
    
    try:
        # Generate legacy address
        legacy_addr = validator.rpc_call("getnewaddress", ["", "legacy"])
        if legacy_addr:
            print(f"Legacy P2PKH: {legacy_addr}")
            generated_addresses.append((legacy_addr, "P2PKH", "Generated by LTC node"))
        
        # Generate P2SH-wrapped SegWit address  
        p2sh_addr = validator.rpc_call("getnewaddress", ["", "p2sh-segwit"])
        if p2sh_addr:
            print(f"P2SH-SegWit: {p2sh_addr}")
            generated_addresses.append((p2sh_addr, "P2SH", "Generated by LTC node"))
        
        # Generate native SegWit address
        bech32_addr = validator.rpc_call("getnewaddress", ["", "bech32"])
        if bech32_addr:
            print(f"Bech32 SegWit: {bech32_addr}")
            generated_addresses.append((bech32_addr, "Bech32", "Generated by LTC node"))
            
    except Exception as e:
        print(f"❌ Error generating addresses: {e}")
    
    return generated_addresses

def update_test_files_with_rpc_addresses(valid_addresses):
    """Update test files with RPC-validated addresses"""
    print(f"\n📝 Updating Test Files with RPC-Validated Addresses")
    print("=" * 50)
    
    if len(valid_addresses) < 3:
        print("⚠️  Not enough valid addresses to update test files")
        return
    
    # Update physical_miner_test.py
    try:
        with open("/home/user0/Documents/GitHub/c2pool/physical_miner_test.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Create new address list with RPC-validated addresses
        valid_addrs = [addr for addr, _ in valid_addresses[:5]]  # Take first 5
        
        new_addresses = f'''        ltc_testnet_addresses = [
            "{valid_addrs[0]}",  # RPC-validated LTC testnet address
            "{valid_addrs[1]}",  # RPC-validated LTC testnet address  
            "{valid_addrs[2]}",  # RPC-validated LTC testnet address
            "{valid_addrs[3] if len(valid_addrs) > 3 else valid_addrs[0]}",  # RPC-validated LTC testnet address
            "{valid_addrs[4] if len(valid_addrs) > 4 else valid_addrs[1]}"   # RPC-validated LTC testnet address
        ]'''
        
        # Replace the address list
        import re
        pattern = r'ltc_testnet_addresses = \[.*?\]'
        
        if re.search(pattern, content, re.DOTALL):
            new_content = re.sub(pattern, new_addresses, content, flags=re.DOTALL)
            
            with open("/home/user0/Documents/GitHub/c2pool/physical_miner_test.py", "w", encoding="utf-8") as f:
                f.write(new_content)
            print("✅ Updated physical_miner_test.py with RPC-validated addresses")
        
    except Exception as e:
        print(f"❌ Error updating physical_miner_test.py: {e}")

def main():
    print("🔧 LTC Testnet Address Validation via JSON-RPC")
    print("=" * 60)
    
    # Step 1: Try to start LTC node if needed
    if not test_node_connection():
        print("\n🚀 Attempting to start LTC testnet node...")
        if start_ltc_testnet_node():
            time.sleep(5)
            if not test_node_connection():
                print("❌ Could not establish connection to LTC node")
                print("\nManual steps:")
                print("1. Start litecoind: litecoind -testnet -daemon -rpcuser=user -rpcpassword=password")
                print("2. Wait for sync: litecoin-cli -testnet getblockchaininfo")
                print("3. Re-run this script")
                return
        else:
            print("❌ Could not start LTC testnet node")
            return
    
    # Step 2: Test address validation
    valid_addresses, invalid_addresses = test_address_validation_rpc()
    
    # Step 3: Generate new addresses
    generated_addresses = generate_new_testnet_addresses()
    valid_addresses.extend(generated_addresses)
    
    # Step 4: Update test files
    if valid_addresses:
        update_test_files_with_rpc_addresses(valid_addresses)
    
    # Step 5: Summary
    print(f"\n📊 VALIDATION SUMMARY")
    print("=" * 30)
    print(f"✅ Valid addresses: {len(valid_addresses)}")
    print(f"❌ Invalid addresses: {len(invalid_addresses)}")
    
    if valid_addresses:
        print(f"\n✅ RPC-Validated LTC Testnet Addresses:")
        for addr, desc in valid_addresses:
            print(f"   {addr} ({desc})")
    
    print(f"\n🔧 Next Steps:")
    print("1. Rebuild C2Pool: ./build-debug.sh")
    print("2. Test with validated addresses: python3 test_address_validation.py")
    print("3. Run physical miner test: python3 physical_miner_test.py")

if __name__ == "__main__":
    main()
