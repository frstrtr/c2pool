#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace core {

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

} // namespace core
