// SPDX-License-Identifier: AGPL-3.0-or-later
#include "KeyScan.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

// Reused M1-A hdkeys core (btclibs closure). NO dashscript / signer headers.
#include "../hdkeys/Bip39.hpp"
#include "../hdkeys/Bip32.hpp"
#include "../hdkeys/Derivation.hpp"
#include "../hdkeys/Secp.hpp"

#include <array>
#include <optional>

namespace c2w::dash {

namespace {

// One scan over [account_first, account_first + accounts) x {0[,1]} x
// [0, indices), compressed first and then (when asked) uncompressed at every
// index. nullopt when nothing matches; the callers word the abort.
std::optional<FoundKey> scan(const std::string& mnemonic,
                             const std::string& passphrase,
                             const std::string& address,
                             bool testnet,
                             uint32_t account_first,
                             uint32_t accounts,
                             uint32_t indices,
                             bool scan_internal,
                             bool try_uncompressed)
{
    const std::array<uint8_t, 20> expected_h160 = addr_to_h160(address, testnet);
    const uint32_t coin_type = testnet ? 1u : 5u; // DASH SLIP-44 = 5', testnet = 1'

    // Validate word count AND the real BIP39 checksum before deriving anything.
    // On failure report only the word count — NEVER interpolate the phrase
    // (some errors would otherwise echo the mnemonic text).
    const hdkeys::Bip39Error verr = hdkeys::Bip39::validate(mnemonic);
    if (verr != hdkeys::Bip39Error::Ok) {
        size_t words = mnemonic.empty() ? 0 : 1;
        for (char c : mnemonic) if (c == ' ') ++words;
        throw DashAbort("invalid BIP39 mnemonic (" + std::to_string(words) + " words given): it "
                        "must be 12/15/18/21/24 words from the BIP39 wordlist with a valid "
                        "checksum. Nothing was derived or signed.");
    }

    secure::SecureBytes seed = hdkeys::Bip39::to_seed(mnemonic, passphrase);
    auto master = hdkeys::HDKey::from_seed(seed.data(), seed.size());
    if (!master)
        throw DashAbort("could not derive a BIP32 master key from the seed");

    std::vector<uint32_t> chains = {0};
    if (scan_internal) chains.push_back(1);

    for (uint32_t a = 0; a < accounts; ++a) {
        const uint32_t account = account_first + a;
        for (uint32_t chain : chains) {
            for (uint32_t i = 0; i < indices; ++i) {
                std::vector<uint32_t> path =
                    hdkeys::build_bip_path(hdkeys::Purpose::BIP44, coin_type, account, chain, i);
                auto leaf = master->derive_path(path);
                if (!leaf) continue; // rare invalid child — try i+1 (design §3.3)

                for (int pass = 0; pass < (try_uncompressed ? 2 : 1); ++pass) {
                    const bool compressed = pass == 0;
                    const std::vector<uint8_t> pub =
                        compressed ? leaf->pubkey() // 33-byte compressed
                                   : hdkeys::Secp::instance().pubkey_create(
                                         leaf->privkey().data(), false);
                    if (pub.empty()) continue;
                    std::array<uint8_t, 20> h = hdkeys::hash160(pub.data(), pub.size());
                    if (h != expected_h160) continue;

                    // Double-check: our own re-encode of this hash160 must
                    // reproduce the requested address (independent of the decode
                    // above).
                    const std::string reencoded = h160_to_addr(h, testnet);
                    if (reencoded != address)
                        throw DashAbort("internal cross-check failed: a derived key's hash160 "
                                        "matches but its address re-encode disagrees with the "
                                        "funding address");

                    FoundKey fk;
                    fk.priv.assign(leaf->privkey().data(), leaf->privkey().size());
                    fk.pub = pub;
                    fk.path = hdkeys::format_path(path) + (compressed ? "" : " (uncompressed)");
                    fk.address = address;
                    fk.compressed = compressed;
                    return fk;
                }
            }
        }
    }
    return std::nullopt;
}

} // namespace

FoundKey find_key_for_address(const std::string& mnemonic,
                              const std::string& passphrase,
                              const std::string& address,
                              bool testnet,
                              uint32_t account,
                              uint32_t scan_limit,
                              bool scan_internal)
{
    // The original single-account, compressed-only scan, unchanged.
    auto hit = scan(mnemonic, passphrase, address, testnet, account, 1, scan_limit, scan_internal,
                    /*try_uncompressed*/ false);
    if (hit) return std::move(*hit);

    const uint32_t coin_type = testnet ? 1u : 5u;
    throw DashAbort("no derivation index in m/44'/" + std::to_string(coin_type) + "'/" +
                    std::to_string(account) + "'/{0" + (scan_internal ? ",1" : "") + "}/0.." +
                    std::to_string(scan_limit - 1) + " produces " + address +
                    ". REFUSING TO SIGN — check the mnemonic/passphrase, or widen the scan.");
}

FoundKey find_key_for_address(const std::string& mnemonic,
                              const std::string& passphrase,
                              const std::string& address,
                              bool testnet,
                              const KeyScanRange& range)
{
    if (range.accounts == 0 || range.indices == 0)
        throw DashAbort("key scan range is empty (accounts and indices must be >= 1)");

    auto hit = scan(mnemonic, passphrase, address, testnet, 0, range.accounts, range.indices,
                    range.scan_internal, range.try_uncompressed);
    if (hit) return std::move(*hit);

    const uint32_t coin_type = testnet ? 1u : 5u;
    throw DashAbort("no derivation path in m/44'/" + std::to_string(coin_type) + "'/{0.." +
                    std::to_string(range.accounts - 1) + "}'/{0" +
                    (range.scan_internal ? ",1" : "") + "}/0.." +
                    std::to_string(range.indices - 1) + " (compressed" +
                    (range.try_uncompressed ? " and uncompressed" : " only") + ") produces " +
                    address +
                    ". REFUSING TO SIGN — check the mnemonic/passphrase, or widen the scan.");
}

} // namespace c2w::dash
