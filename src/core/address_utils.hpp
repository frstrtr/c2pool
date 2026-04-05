#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace core {

/// Result of classify_script(): script type + decoded addresses.
struct ScriptClassification {
    std::string type;                     // "pubkeyhash", "scripthash", "witness_v0_keyhash",
                                          // "witness_v0_scripthash", "witness_v1_taproot",
                                          // "pubkey", "multisig", "nulldata", "nonstandard"
    std::vector<std::string> addresses;   // decoded addresses (may be >1 for P2MS)
    std::string hex;                      // raw scriptPubKey hex

    // P2PK extra
    std::string pubkey;                   // raw pubkey hex (only for type=="pubkey")

    // P2MS extra
    int multisig_required{0};
    int multisig_total{0};
    std::vector<std::string> multisig_pubkeys;   // raw hex per pubkey
    std::vector<std::string> multisig_addresses;  // derived P2PKH address per pubkey

    // OP_RETURN extra
    std::string op_return_hex;            // payload hex (without OP_RETURN + push)
};

/// Decode a Base58Check-encoded address (P2PKH or P2SH) and return the
/// 20-byte hash160 payload as a 40-char lowercase hex string.
/// Returns "" on invalid address or checksum failure.
std::string base58check_to_hash160(const std::string& address);

/// Decode any supported address format (bech32 or base58) to its hash160.
/// Sets addr_type to "p2wpkh", "p2pkh", or "p2sh".
/// Returns 40-char hex string, or "" on failure.
std::string address_to_hash160(const std::string& address, std::string& addr_type);

/// Build a scriptPubKey from hash160 and address type.
/// P2PKH/P2WPKH → OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
/// P2SH → OP_HASH160 <20> OP_EQUAL
std::vector<unsigned char> hash160_to_merged_script(
    const std::string& h160_hex, const std::string& addr_type);

/// Check if an address belongs to a specific chain by testing HRP/version bytes.
bool is_address_for_chain(const std::string& address,
    const std::vector<std::string>& chain_hrps,
    const std::vector<uint8_t>& chain_versions);

/// Build a scriptPubKey from either a Base58Check or Bech32 address.
/// Returns empty vector on failure.
std::vector<unsigned char> address_to_script(const std::string& address);

/// Convert a raw scriptPubKey to a human-readable address string.
/// Supports P2PKH, P2SH, P2WPKH, P2WSH. Returns "" on unrecognised script.
/// bech32_hrp: "tltc", "ltc", "bc", "tb" etc.
/// p2pkh_ver / p2sh_ver: base58check version bytes for the chain.
std::string script_to_address(const std::vector<unsigned char>& script,
    const std::string& bech32_hrp, uint8_t p2pkh_ver, uint8_t p2sh_ver);

/// Convenience overload: derive chain params from blockchain + testnet flags.
/// blockchain: "litecoin" or "bitcoin" (case-insensitive prefix match).
std::string script_to_address(const std::vector<unsigned char>& script,
    bool is_litecoin, bool is_testnet);

/// Classify a scriptPubKey and decode all address types including P2PK and P2MS.
/// Decodes pubkeys to P2PKH addresses via Hash160. Handles OP_RETURN payloads.
ScriptClassification classify_script(const std::vector<unsigned char>& script,
    const std::string& bech32_hrp, uint8_t p2pkh_ver, uint8_t p2sh_ver);

/// Convenience overload with chain flags.
ScriptClassification classify_script(const std::vector<unsigned char>& script,
    bool is_litecoin, bool is_testnet);

/// Derive a P2PKH address from a raw compressed/uncompressed public key via Hash160.
std::string pubkey_to_p2pkh_address(const unsigned char* pubkey, size_t len, uint8_t p2pkh_ver);

} // namespace core
