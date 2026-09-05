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

/// The set of Base58Check version bytes and bech32 HRPs a given coin accepts as
/// its OWN payout addresses on a given network (mainnet / testnet / regtest).
/// Populated by each coin's registry (address_acceptance()) from its chainparams
/// SSOT — NEVER hardcoded at a stratum money-path call site (issue #961 blocker
/// #3) — and network-derived so a --regtest address is accepted rather than
/// silently rejected as Foreign (blocker #2).
struct CoinAddressAcceptance {
    std::vector<uint8_t>     p2pkh_versions;   ///< accepted P2PKH version bytes
    std::vector<uint8_t>     p2sh_versions;    ///< accepted P2SH version bytes
    std::vector<std::string> bech32_hrps;      ///< BARE HRPs, NO trailing '1' (e.g. "ltc")
};

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

/// Overloads taking a registry-sourced CoinAddressAcceptance (issue #961). Every
/// stratum payout money-path passes the running coin's acceptance for the ACTIVE
/// network so the check needs no hardcoded version bytes and honours regtest.
inline AddressCoinMatch classify_address_for_coin(
    const std::string& address, const CoinAddressAcceptance& acc,
    std::vector<unsigned char>& out_script)
{
    return classify_address_for_coin(address, acc.p2pkh_versions,
        acc.p2sh_versions, acc.bech32_hrps, out_script);
}
inline std::vector<unsigned char> address_to_script_for_coin(
    const std::string& address, const CoinAddressAcceptance& acc)
{
    return address_to_script_for_coin(address, acc.p2pkh_versions,
        acc.p2sh_versions, acc.bech32_hrps);
}

/// Normalise a CoinParams-style bech32 HRP to the BARE form the acceptance set
/// wants (issue #961 blocker #3). CoinParams.bech32_hrp is stored inconsistently
/// across the lanes — LTC keeps the separator ("ltc1"), DGB/BIP-110 store it bare
/// ("dgb"/"bc") — so a registry-derived address_acceptance() strips a single
/// trailing '1' (the bech32 HRP/data separator) to get the bare prefix. A bare
/// HRP never ends in '1' (it is the separator), so this is loss-free.
inline std::string bare_bech32_hrp(const std::string& hrp)
{
    if (!hrp.empty() && hrp.back() == '1') return hrp.substr(0, hrp.size() - 1);
    return hrp;
}

/// A CONFIGURED merged-mining chain's address-identification triple (issue #961).
/// bech32 HRPs (bare) + Base58Check version bytes, exactly as the stratum server's
/// merged-chain table records them — passed to decide_payout_address() so a
/// legitimate merged-mining payout (same secp256k1 key, spendable on the parent's
/// P2PKH) is accepted while an UNconfigured foreign coin's address is rejected.
struct MergedChainAddr {
    std::vector<std::string> hrps;
    std::vector<uint8_t>     versions;
};

/// The stratum payout money-path decision for a miner-supplied address on a node
/// that has published its own acceptance set (issue #961 blocker #1). This is the
/// SSOT the stratum server consults at BOTH mining.authorize (reject at the door)
/// and per-job coinbase build (guard: never build a zero/foreign payout):
///   • AcceptOwn    — an own-coin address; the caller builds its script.
///   • AcceptMerged — a CONFIGURED merged chain's address; the caller builds the
///                    parent P2PKH to the same hash160 (the intended reuse).
///   • Reject       — foreign-and-unconfigured, or unparseable; the caller MUST
///                    refuse (no empty/zero-hash160 payout, which PPLNS would burn).
enum class PayoutAddressDecision { AcceptOwn, AcceptMerged, Reject };

inline PayoutAddressDecision decide_payout_address(
    const std::string& address,
    const CoinAddressAcceptance& own,
    const std::vector<MergedChainAddr>& configured_merged)
{
    std::vector<unsigned char> own_script;
    auto m = classify_address_for_coin(address, own, own_script);
    if (m == AddressCoinMatch::Own)
        return PayoutAddressDecision::AcceptOwn;
    // Only a well-formed-but-Foreign address can still be a configured merged
    // chain; an Invalid (unparseable) address is never payable.
    if (m == AddressCoinMatch::Foreign) {
        for (const auto& c : configured_merged) {
            if (is_address_for_chain(address, c.hrps, c.versions))
                return PayoutAddressDecision::AcceptMerged;
        }
    }
    return PayoutAddressDecision::Reject;
}

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