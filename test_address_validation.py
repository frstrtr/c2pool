#!/usr/bin/env python3
"""
Advanced address validation test for C2Pool Enhanced
Tests multiple address formats and edge cases
"""

import socket
import json
import time
import sys

def test_address(host, port, address, description):
    """Test a single address via Stratum protocol"""
    try:
        # Connect to Stratum server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        
        # Subscribe
        subscribe_msg = {"id": 1, "method": "mining.subscribe", "params": ["c2pool-test/1.0"]}
        sock.send((json.dumps(subscribe_msg) + '\n').encode())
        response = sock.recv(1024).decode().strip()
        
        # Authorize with the address
        auth_msg = {"id": 2, "method": "mining.authorize", "params": [address, "test"]}
        sock.send((json.dumps(auth_msg) + '\n').encode())
        
        # Read responses
        auth_response = ""
        start_time = time.time()
        while time.time() - start_time < 2:
            try:
                data = sock.recv(1024).decode().strip()
                if data:
                    auth_response += data
                    # Look for the authorize response
                    for line in auth_response.split('\n'):
                        if line.strip():
                            try:
                                resp = json.loads(line)
                                if resp.get('id') == 2:  # Our authorize request
                                    sock.close()
                                    return resp
                                elif 'error' in resp and resp.get('error', {}).get('message'):
                                    sock.close()
                                    return resp
                            except json.JSONDecodeError:
                                continue
            except socket.timeout:
                break
        
        sock.close()
        return {"result": None, "error": {"message": "No response"}}
        
    except Exception as e:
        return {"result": None, "error": {"message": str(e)}}

def main():
    host = "localhost"
    port = 8084
    
    # Test addresses - comprehensive set
    test_cases = [
        # Valid Litecoin testnet addresses
        ("tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", "Litecoin testnet bech32 (native SegWit)"),
        ("2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br", "Litecoin testnet P2SH (wrapped SegWit)"),
        ("mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR", "Litecoin testnet legacy P2PKH"),
        
        # Valid mainnet addresses (should be rejected on testnet)
        ("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "Litecoin mainnet bech32"),
        ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Litecoin mainnet P2SH"),
        ("LaMT348PWRnrqeeWArpwQDAVWs71DTuLP9", "Litecoin mainnet legacy P2PKH"),
        
        # Bitcoin addresses (should be rejected)
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "Bitcoin mainnet bech32"),
        ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Bitcoin mainnet P2SH"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Bitcoin mainnet legacy"),
        
        # Invalid addresses
        ("", "Empty address"),
        ("invalid_address", "Random string"),
        ("1234567890", "Numbers only"),
        ("tltc1invalid", "Invalid bech32 checksum"),
        ("2InvalidAddress", "Invalid P2SH format"),
        ("mInvalidLegacy", "Invalid legacy format"),
    ]
    
    print("🧪 Comprehensive Address Validation Test")
    print("=" * 50)
    
    valid_count = 0
    invalid_count = 0
    
    for address, description in test_cases:
        print(f"\nTesting: {description}")
        print(f"Address: {address}")
        
        result = test_address(host, port, address, description)
        
        if result.get('result') is True or (result.get('result') is None and not result.get('error')):
            print("✅ ACCEPTED")
            valid_count += 1
        elif result.get('error'):
            error_msg = result['error'].get('message', 'Unknown error')
            print(f"❌ REJECTED: {error_msg}")
            invalid_count += 1
        else:
            print("❓ UNKNOWN RESPONSE")
            invalid_count += 1
        
        time.sleep(0.1)  # Small delay between tests
    
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print(f"Total addresses tested: {len(test_cases)}")
    print(f"Valid addresses: {valid_count}")
    print(f"Invalid addresses: {invalid_count}")
    
    # Expected results for testnet
    expected_valid = ["tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", 
                      "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br", 
                      "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR"]
    
    print(f"\nExpected valid on testnet: {len(expected_valid)} addresses")
    print("Expected: Only Litecoin testnet addresses should be accepted")

if __name__ == "__main__":
    main()
