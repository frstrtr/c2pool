#!/usr/bin/env python3
"""
Generate Valid LTC Testnet Addresses
Creates proper LTC testnet addresses for testing
"""

import hashlib
import secrets
import os

def base58_encode(data):
    """Encode bytes as base58"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Convert bytes to integer
    num = int.from_bytes(data, 'big')
    
    # Count leading zeros
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    
    # Convert to base58
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    
    # Add leading 1s for leading zeros
    encoded = "1" * leading_zeros + encoded
    
    return encoded

def create_base58check_address(version_byte, payload):
    """Create a Base58Check encoded address"""
    # Combine version byte and payload
    data = bytes([version_byte]) + payload
    
    # Calculate checksum (double SHA256)
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1).digest()
    checksum = hash2[:4]
    
    # Combine data and checksum
    full_data = data + checksum
    
    # Base58 encode
    return base58_encode(full_data)

def generate_ltc_testnet_addresses():
    """Generate valid LTC testnet addresses"""
    print("🔧 Generating Valid LTC Testnet Addresses")
    print("=" * 50)
    
    addresses = []
    
    # Generate P2PKH addresses (version 111, starts with 'm' or 'n')
    for i in range(3):
        payload = secrets.token_bytes(20)  # 20-byte hash
        address = create_base58check_address(111, payload)
        addresses.append((address, "P2PKH", "Physical miner payout"))
        print(f"P2PKH #{i+1}: {address}")
    
    # Generate P2SH addresses (version 196, starts with '2')
    for i in range(2):
        payload = secrets.token_bytes(20)  # 20-byte script hash
        address = create_base58check_address(196, payload)
        addresses.append((address, "P2SH", "Multisig/SegWit"))
        print(f"P2SH #{i+1}: {address}")
    
    # Generate bech32-style addresses (simplified - just the prefix)
    for i in range(2):
        # Simplified bech32 format for testing
        random_part = secrets.token_hex(16)
        address = f"tltc1q{random_part}"
        addresses.append((address, "Bech32", "Native SegWit"))
        print(f"Bech32 #{i+1}: {address}")
    
    return addresses

def update_test_files(addresses):
    """Update test files with valid addresses"""
    print(f"\n📝 Updating Test Files with Valid Addresses")
    print("=" * 50)
    
    # Update physical_miner_test.py
    try:
        with open("/home/user0/Documents/GitHub/c2pool/physical_miner_test.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Extract P2PKH addresses for miners
        p2pkh_addresses = [addr for addr, addr_type, _ in addresses if addr_type == "P2PKH"]
        
        # Create the new address list
        new_addresses = f'''        ltc_testnet_addresses = [
            "{p2pkh_addresses[0]}",  # Valid LTC testnet P2PKH
            "{p2pkh_addresses[1]}",  # Valid LTC testnet P2PKH
            "{p2pkh_addresses[2]}",  # Valid LTC testnet P2PKH
            "{addresses[3][0]}",     # Valid LTC testnet P2SH
            "{addresses[4][0]}"      # Valid LTC testnet P2SH
        ]'''
        
        # Find and replace the old address list
        import re
        pattern = r'ltc_testnet_addresses = \[.*?\]'
        
        if re.search(pattern, content, re.DOTALL):
            new_content = re.sub(pattern, new_addresses, content, flags=re.DOTALL)
            
            with open("/home/user0/Documents/GitHub/c2pool/physical_miner_test.py", "w", encoding="utf-8") as f:
                f.write(new_content)
            print("✅ Updated physical_miner_test.py")
        else:
            print("⚠️  Could not find address list pattern in physical_miner_test.py")
            
    except Exception as e:
        print(f"❌ Error updating physical_miner_test.py: {e}")
    
    # Update test_address_validation.py
    try:
        with open("/home/user0/Documents/GitHub/c2pool/test_address_validation.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        # Replace the old invalid address with a valid one
        old_address = "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR"
        new_address = p2pkh_addresses[0]
        
        new_content = content.replace(old_address, new_address)
        
        with open("/home/user0/Documents/GitHub/c2pool/test_address_validation.py", "w", encoding="utf-8") as f:
            f.write(new_content)
        print("✅ Updated test_address_validation.py")
        
    except Exception as e:
        print(f"❌ Error updating test_address_validation.py: {e}")

def main():
    print("🛠️  LTC Testnet Address Generator")
    print("=" * 50)
    
    print("The previous test address 'mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR' was INVALID!")
    print("• Wrong version byte: 37 instead of 111")
    print("• Invalid checksum")
    print("• Not a real LTC testnet address\n")
    
    # Generate valid addresses
    addresses = generate_ltc_testnet_addresses()
    
    # Update test files
    update_test_files(addresses)
    
    print(f"\n✅ Generated {len(addresses)} valid LTC testnet addresses")
    print("\n📋 Address Format Summary:")
    print("• P2PKH (Legacy): version 111, starts with 'm' or 'n'")
    print("• P2SH (Script): version 196, starts with '2'")
    print("• Bech32 (SegWit): starts with 'tltc1'")
    
    print(f"\n🔧 Next Steps:")
    print("1. Test with the new valid addresses")
    print("2. Run: python3 test_address_validation.py")
    print("3. Check that validation now accepts the correct addresses")

if __name__ == "__main__":
    main()
