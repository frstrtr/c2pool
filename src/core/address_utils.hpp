// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

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

// -- Per-coin address validation (issue #961) ---------------------------------
// The plain address_to_script()/address_to_hash160() decoders are chain-AGNOSTIC:
// they accept the version byte / bech32 HRP of ANY supported coin and then build
// a scriptPubKey for whatever coin the caller happens to be running. Fed a
// foreign-coin payout address that path silently emits a wrong-coin script and
// MISDIRECTS the miner's funds. classify_address_for_coin() closes that hole by
// validating the version byte / HRP against the running coin BEFORE building a
// script, so a foreign address is rejected loudly instead of being repurposed.

/// Result of classify_address_for_coin().
enum class AddressCoinMatch {
    Invalid,   ///< Not a Base58Check or bech32 address this decoder understands
               ///< (e.g. a CashAddr, or a checksum failure). out_script empty.
               ///< The caller MAY consult a coin-specific decoder next.
    Foreign,   ///< Well-formed address, but for a DIFFERENT coin (version byte /
               ///< bech32 HRP not in this coin's accepted set). out_script empty;
               ///< the caller MUST reject — never pay it.
    Own        ///< Valid address for THIS coin. out_script holds its scriptPubKey.
};

/// Decode `address` and classify it against the running coin's accepted
/// Base58Check version bytes and bech32 HRPs. On Own, out_script is the
/// scriptPubKey (P2PKH/P2SH for base58, witness program for bech32); on
/// Foreign/Invalid out_script is left empty. `accepted_hrps` are BARE prefixes
/// with NO trailing '1' (e.g. {"ltc","tltc"}); pass {} for coins without bech32.
AddressCoinMatch classify_address_for_coin(
    const std::string& address,
    const std::vector<uint8_t>& p2pkh_versions,
    const std::vector<uint8_t>& p2sh_versions,
    const std::vector<std::string>& accepted_hrps,
    std::vector<unsigned char>& out_script);

/// Convenience wrapper: returns the scriptPubKey ONLY for an own-coin address,
/// and an EMPTY vector for a foreign-coin OR unparseable address. Use this in
/// place of address_to_script() on the payout money-path so a foreign address
/// can never be repurposed into a wrong-coin script.
std::vector<unsigned char> address_to_script_for_coin(
    const std::string& address,
    const std::vector<uint8_t>& p2pkh_versions,
    const std::vector<uint8_t>& p2sh_versions,
    const std::vector<std::string>& accepted_hrps);

/// Build a scriptPubKey from either a Base58Check or Bech32 address.
/// Returns empty vector on failure.
std::vector<unsigned char> address_to_script(const std::string& address);

// -- Generic coin-registered fallback decoders --------------------------------
// A coin module may register an opaque address decoder that address_to_script
// consults AFTER its built-in bech32/base58 formats fail. Core holds NO
// coin-specific address knowledge -- the decoder is a plain functor mapping an
// address string to a scriptPubKey ({} == "not my format, try the next one").
using AddressDecoderFn = std::function<std::vector<unsigned char>(const std::string&)>;
void register_address_decoder(AddressDecoderFn fn);

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