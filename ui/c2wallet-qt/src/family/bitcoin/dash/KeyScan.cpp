// SPDX-License-Identifier: AGPL-3.0-or-later
#include "KeyScan.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

// Reused M1-A hdkeys core (btclibs closure). NO dashscript / signer headers.
#include "../hdkeys/Bip39.hpp"
#include "../hdkeys/Bip32.hpp"
#include "../hdkeys/Derivation.hpp"

#include <array>

namespace c2w::dash {

FoundKey find_key_for_address(const std::string& mnemonic,
                              const std::string& passphrase,
                              const std::string& address,
                              bool testnet,
                              uint32_t account,
                              uint32_t scan_limit,
                              bool scan_internal)
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

    struct Chain { uint32_t no; };
    std::vector<Chain> chains = {{0}};
    if (scan_internal) chains.push_back({1});

    for (const Chain& ch : chains) {
        for (uint32_t i = 0; i < scan_limit; ++i) {
            std::vector<uint32_t> path =
                hdkeys::build_bip_path(hdkeys::Purpose::BIP44, coin_type, account, ch.no, i);
            auto leaf = master->derive_path(path);
            if (!leaf) continue; // rare invalid child — try i+1 (design §3.3)
            const std::vector<uint8_t>& pub = leaf->pubkey(); // 33-byte compressed
            std::array<uint8_t, 20> h = hdkeys::hash160(pub.data(), pub.size());
            if (h != expected_h160) continue;

            // Double-check: our own re-encode of this hash160 must reproduce the
            // requested address (independent of the decode above).
            const std::string reencoded = h160_to_addr(h, testnet);
            if (reencoded != address)
                throw DashAbort("internal cross-check failed: a derived key's hash160 matches "
                                "but its address re-encode disagrees with the funding address");

            FoundKey fk;
            fk.priv.assign(leaf->privkey().data(), leaf->privkey().size());
            fk.pub = pub;
            fk.path = hdkeys::format_path(path);
            fk.address = address;
            return fk;
        }
    }

    throw DashAbort("no derivation index in m/44'/" + std::to_string(coin_type) + "'/" +
                    std::to_string(account) + "'/{0" + (scan_internal ? ",1" : "") + "}/0.." +
                    std::to_string(scan_limit - 1) + " produces " + address +
                    ". REFUSING TO SIGN — check the mnemonic/passphrase, or widen the scan.");
}

} // namespace c2w::dash
