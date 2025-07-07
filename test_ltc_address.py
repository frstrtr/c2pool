#!/usr/bin/env python3
"""
Simple LTC Address Format Test
Tests the format of the problematic LTC testnet address
"""

import hashlib

def manual_base58_decode(s):
    """Manual Base58 decode to understand the address format"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Count leading zeros
    leading_zeros = 0
    for c in s:
        if c == '1':
            leading_zeros += 1
        else:
            break
    
    # Convert to number
    num = 0
    for c in s:
        if c not in alphabet:
            return None
        num = num * 58 + alphabet.index(c)
    
    # Convert to bytes
    encoded = []
    while num > 0:
        encoded.append(num % 256)
        num //= 256
    
    # Add leading zeros
    encoded.extend([0] * leading_zeros)
    encoded.reverse()
    
    return bytes(encoded)

def test_ltc_address(address):
    """Test the LTC address format"""
    print(f"Testing address: {address}")
    print(f"Length: {len(address)} characters")
    print(f"First character: '{address[0]}'")
    
    # Manual decode
    decoded = manual_base58_decode(address)
    if decoded is None:
        print("❌ Invalid Base58 encoding")
        return False
    
    print(f"Decoded length: {len(decoded)} bytes")
    print(f"Decoded hex: {decoded.hex()}")
    
    if len(decoded) < 4:
        print("❌ Too short for checksum")
        return False
    
    # Split version, payload, and checksum
    version = decoded[0]
    payload = decoded[1:-4]
    checksum = decoded[-4:]
    
    print(f"Version byte: {version} (0x{version:02x})")
    print(f"Payload length: {len(payload)} bytes")
    print(f"Payload hex: {payload.hex()}")
    print(f"Checksum: {checksum.hex()}")
    
    # Verify checksum
    data_for_hash = decoded[:-4]
    hash1 = hashlib.sha256(data_for_hash).digest()
    hash2 = hashlib.sha256(hash1).digest()
    calculated_checksum = hash2[:4]
    
    print(f"Calculated checksum: {calculated_checksum.hex()}")
    
    if checksum == calculated_checksum:
        print("✅ Checksum valid")
    else:
        print("❌ Checksum invalid")
        return False
    
    # Check version byte for LTC testnet
    if version == 111:  # 0x6F
        print("✅ Version byte matches LTC testnet P2PKH (111)")
        return True
    elif version == 196:  # 0xC4
        print("✅ Version byte matches LTC testnet P2SH (196)")
        return True
    else:
        print(f"❌ Unknown version byte {version} for LTC testnet")
        print("Expected: 111 (0x6F) for P2PKH or 196 (0xC4) for P2SH")
        return False

def main():
    print("🔍 LTC Testnet Address Format Analysis")
    print("=" * 50)
    
    # Test the problematic address
    test_address = "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztR"
    is_valid = test_ltc_address(test_address)
    
    print(f"\n{'✅ Valid' if is_valid else '❌ Invalid'} LTC testnet address")
    
    print("\n📋 Expected LTC Testnet Address Formats:")
    print("• P2PKH: version byte 111 (0x6F), starts with 'm' or 'n'")
    print("• P2SH: version byte 196 (0xC4), starts with '2'")
    print("• Address length after decoding: 25 bytes (1 version + 20 payload + 4 checksum)")
    print("• After checksum removal: 21 bytes (1 version + 20 payload)")

if __name__ == "__main__":
    main()
