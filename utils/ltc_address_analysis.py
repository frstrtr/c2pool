#!/usr/bin/env python3
"""
Direct C++ Address Validation Test
Tests the address validation logic directly through the C++ executable
"""

import subprocess
import json
import sys

def test_address_validation_cpp():
    """Test address validation directly through C++ code"""
    
    # Create a simple C++ test program
    test_cpp = """
#include <iostream>
#include <vector>
#include <string>
#include <core/address_validator.hpp>

using namespace c2pool::address;

int main() {
    // Initialize validator for Litecoin testnet
    BlockchainAddressValidator validator(Blockchain::LITECOIN, Network::TESTNET);
    
    std::vector<std::pair<std::string, std::string>> test_addresses = {
        {"tltc1qea8gdr057k9gyjnurk7v3d9enha8qgds58ajt0", "LTC testnet bech32"},
        {"2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br", "LTC testnet P2SH"},  
        {"mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR", "LTC testnet legacy P2PKH"},
        {"LaMT348PWRnrqeeWArpwQDAVWs71DTuLP9", "LTC mainnet legacy (should fail)"},
        {"ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "LTC mainnet bech32 (should fail)"},
        {"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC address (should fail)"},
        {"invalid_address", "Invalid string (should fail)"}
    };
    
    std::cout << "Address Validation Test Results:\\n";
    std::cout << "================================\\n";
    
    for (const auto& test_case : test_addresses) {
        const std::string& address = test_case.first;
        const std::string& description = test_case.second;
        
        std::cout << "\\nTesting: " << description << "\\n";
        std::cout << "Address: " << address << "\\n";
        
        auto result = validator.validate_address_strict(address);
        
        if (result.is_valid) {
            std::cout << "Result: ✅ VALID\\n";
            std::cout << "Type: " << validator.get_address_type_name(result.type) << "\\n";
            std::cout << "Network: " << validator.get_network_name(result.network) << "\\n";
        } else {
            std::cout << "Result: ❌ INVALID\\n";
            std::cout << "Error: " << result.error_message << "\\n";
        }
    }
    
    return 0;
}
"""
    
    return test_cpp

def analyze_ltc_address_format():
    """Analyze the LTC testnet address format to identify potential issues"""
    
    print("🔍 Analyzing LTC Testnet Address Format")
    print("=" * 50)
    
    # Test address from the miner test
    test_address = "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR"
    
    print(f"Address: {test_address}")
    print(f"Length: {len(test_address)}")
    print(f"First char: '{test_address[0]}' (should be 'm' or 'n' for testnet)")
    
    # Check if it's a valid Base58 string
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    is_base58 = all(c in base58_chars for c in test_address)
    print(f"Valid Base58: {is_base58}")
    
    # Try to decode it manually (simplified)
    try:
        import base58
        decoded = base58.b58decode_check(test_address)
        print(f"Base58Check decode: SUCCESS")
        print(f"Decoded length: {len(decoded)}")
        print(f"Version byte: {decoded[0]} (0x{decoded[0]:02x})")
        print(f"Expected LTC testnet version: 111 (0x6F)")
        
        if decoded[0] == 111:
            print("✅ Version byte matches LTC testnet P2PKH")
        else:
            print("❌ Version byte mismatch")
            
    except ImportError:
        print("⚠️  base58 module not available for manual decode")
    except Exception as e:
        print(f"❌ Base58Check decode failed: {e}")
    
    print("\n📋 Expected LTC Testnet Address Formats:")
    print("• Legacy P2PKH: starts with 'm' or 'n', version byte 111 (0x6F)")
    print("• Legacy P2SH: starts with '2', version byte 196 (0xC4)")
    print("• Bech32: starts with 'tltc1'")
    
    return test_address

def check_current_validator_config():
    """Check the current address validator configuration in the source"""
    
    print("\\n🔧 Current Validator Configuration")
    print("=" * 40)
    
    # Read the address validator source to check LTC testnet config
    try:
        with open("/home/user0/Documents/GitHub/c2pool/src/core/address_validator.cpp", "r") as f:
            content = f.read()
            
        # Find LTC testnet configuration
        lines = content.split('\\n')
        in_ltc_testnet = False
        for i, line in enumerate(lines):
            if "Litecoin Testnet" in line:
                in_ltc_testnet = True
                print(f"Found LTC testnet config at line {i+1}:")
            elif in_ltc_testnet and "p2pkh_versions" in line:
                print(f"  {line.strip()}")
            elif in_ltc_testnet and "p2sh_versions" in line:
                print(f"  {line.strip()}")  
            elif in_ltc_testnet and "bech32_prefixes" in line:
                print(f"  {line.strip()}")
            elif in_ltc_testnet and line.strip().startswith("m_configs"):
                in_ltc_testnet = False
                
    except Exception as e:
        print(f"❌ Could not read validator config: {e}")

def main():
    print("🧪 LTC Address Validation Analysis")
    print("=" * 50)
    
    # Analyze the address format
    test_address = analyze_ltc_address_format()
    
    # Check current configuration
    check_current_validator_config()
    
    # Create and write the C++ test program
    test_cpp_content = test_address_validation_cpp()
    
    try:
        with open("/home/user0/Documents/GitHub/c2pool/temp/test_address_validation.cpp", "w") as f:
            f.write(test_cpp_content)
        
        print("\\n✅ Created C++ test program: temp/test_address_validation.cpp")
        print("\\nTo compile and run:")
        print("cd /home/user0/Documents/GitHub/c2pool")
        print("g++ -std=c++17 -I src -I include temp/test_address_validation.cpp src/core/address_validator.cpp src/btclibs/base58.cpp src/btclibs/hash.cpp -o test_addr_validation")
        print("./test_addr_validation")
        
    except Exception as e:
        print(f"❌ Could not create test program: {e}")

if __name__ == "__main__":
    main()
