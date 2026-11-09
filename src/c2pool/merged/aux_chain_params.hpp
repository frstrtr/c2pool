// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Per-chain parameters of the scrypt AuxPoW chains c2pool merge-mines under
/// a Litecoin parent, taken from each coin's own source (chainparams.cpp
/// base58Prefixes / bech32_hrp, consensus.h and CheckBlock's bad-blk-length):
///
///   DOGE  dogecoin v1.14.9        PEP   pepecoin v1.1.0 (Dogecoin 1.14)
///   BELLS bellscoin v3.x (Core 26/28, segwit)
///   LKY   luckycoin v5.0.1        JKC   junkcoin-core v4.0.3.1 (Litecoin 0.21)
///   SHIC  shibacoin v1.2.1        DINGO dingocoin v1.18.2.0
///   NMC   namecoin-core (segwit)
///
/// Used to validate the address handed to a daemon's createauxblock (the
/// daemon refuses one of another network: Dogecoin-family -8 "Invalid coinbase
/// payout address", Bellscoin -5) and to size-check an assembled aux block.

#include <core/address_utils.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace c2pool {
namespace merged {

/// The parent's network: c2pool runs mainnet or testnet. An aux daemon
/// beside a testnet parent may be on its testnet or its regtest.
enum class AuxNetwork { mainnet, testnet };

struct AuxNetVersions {
    std::vector<uint8_t>     p2pkh;
    std::vector<uint8_t>     p2sh;
    std::vector<std::string> hrps;   // bare bech32 HRPs
};

struct AuxChainParams {
    const char*    symbol;
    uint32_t       chain_id;            // AuxPoW chain id (mainnet)
    AuxNetVersions main, test, regtest;
    // CheckBlock's limit on the serialized block (auxpow header included).
    // Dogecoin-family: non-witness size <= 1,000,000 (MAX_BLOCK_BASE_SIZE).
    // Segwit chains (BELLS, JKC, NMC): stripped size * 4 <= 4,000,000 and
    // weight <= 4,000,000; the submitted bytes carry witnesses, so the guard
    // is the full size bound weight implies (4,000,000).
    uint32_t       max_block_bytes;
    // createauxblock address used when the operator gives none: only an
    // address known to be valid and unowned (a burn), else nullptr and the
    // operator must configure one.
    const char*    default_main_address;
    const char*    default_test_address;
};

inline const std::vector<AuxChainParams>& aux_chain_params_table()
{
    static const std::vector<AuxChainParams> t = {
        // Dogecoin: main 30/22, testnet 113/196, regtest 111/196.
        {"DOGE", 98, {{30}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 1'000'000,
         "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr", "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt"},
        // Pepecoin: main 56/22, testnet 113/196, regtest 111/196.
        {"PEP", 63, {{56}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 1'000'000, nullptr, nullptr},
        // Bellscoin: main 25/30 "bel", testnet 33/22 "tbel", regtest 111/196 "bcrt".
        {"BELLS", 16, {{25}, {30}, {"bel"}}, {{33}, {22}, {"tbel"}}, {{111}, {196}, {"bcrt"}}, 4'000'000,
         nullptr, nullptr},
        // Luckycoin: main 47/5, testnet 113/196, regtest 113/196.
        {"LKY", 8211, {{47}, {5}, {}}, {{113}, {196}, {}}, {{113}, {196}, {}}, 1'000'000, nullptr, nullptr},
        // Junkcoin v4: main 16/5 "jc", testnet 111/5 "tjc", regtest 47/5 "rjc"
        // (testnet/regtest chain id 8225).
        {"JKC", 8224, {{16}, {5}, {"jc"}}, {{111}, {5}, {"tjc"}}, {{47}, {5}, {"rjc"}}, 4'000'000,
         nullptr, nullptr},
        // Shibacoin: main 63/22, testnet 113/196, regtest 111/196.
        {"SHIC", 74, {{63}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 1'000'000, nullptr, nullptr},
        // Dingocoin: main 30/22, testnet 113/196, regtest 111/196. Chain id 50
        // since mainnet height 265,000 (98 before); blocks up to 10,000,000
        // bytes after height 2,254,540.
        {"DINGO", 50, {{30}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 10'000'000, nullptr, nullptr},
        // Namecoin: main 52/13 "nc", testnet 111/196 "tn", regtest 111/196 "ncrt".
        {"NMC", 1, {{52}, {13}, {"nc"}}, {{111}, {196}, {"tn"}}, {{111}, {196}, {"ncrt"}}, 4'000'000,
         nullptr, nullptr},
    };
    return t;
}

inline const AuxChainParams* find_aux_chain_params(const std::string& symbol)
{
    std::string up = symbol;
    for (auto& c : up)
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 32);
    for (const auto& p : aux_chain_params_table())
        if (up == p.symbol)
            return &p;
    return nullptr;
}

/// The versions accepted on the parent's network: mainnet's, or on a testnet
/// parent the aux chain's testnet and regtest ones.
inline AuxNetVersions aux_accepted_versions(const AuxChainParams& p, AuxNetwork net)
{
    if (net == AuxNetwork::mainnet)
        return p.main;
    AuxNetVersions v = p.test;
    auto add = [](auto& to, const auto& from) {
        for (const auto& x : from)
            if (std::find(to.begin(), to.end(), x) == to.end())
                to.push_back(x);
    };
    add(v.p2pkh, p.regtest.p2pkh);
    add(v.p2sh, p.regtest.p2sh);
    add(v.hrps, p.regtest.hrps);
    return v;
}

/// The address a chain's createauxblock gets, and where it came from.
struct AuxPayoutAddress {
    bool        ok{false};
    std::string address;
    std::string source;   // "configured" or "built-in"
    std::string error;    // why the chain cannot be mined (ok == false)
};

/// The operator's address for the chain (configured), else the built-in
/// one, checked against the chain's own address versions on the parent's
/// network. Not ok when there is none or it is not an address of that chain:
/// the chain must not be registered (createauxblock would refuse every call).
/// A chain c2pool has no parameters for keeps a configured address unchecked.
inline AuxPayoutAddress resolve_aux_payout_address(const std::string& symbol, AuxNetwork net,
                                                   const std::string& configured)
{
    AuxPayoutAddress r;
    const auto* p = find_aux_chain_params(symbol);
    const std::string option = "--merged-payout-address " + symbol + ":<address>";
    if (!configured.empty()) {
        r.address = configured;
        r.source = "configured";
    } else if (p) {
        const char* d = net == AuxNetwork::mainnet ? p->default_main_address : p->default_test_address;
        if (d) {
            r.address = d;
            r.source = "built-in";
        }
    }
    if (r.address.empty()) {
        r.error = "no " + symbol + " payout address for createauxblock (c2pool has no built-in one for "
                  + symbol + "); set " + option;
        return r;
    }
    if (!p) {
        r.ok = true;   // unknown chain: the daemon is the only judge
        return r;
    }
    const auto v = aux_accepted_versions(*p, net);
    std::vector<unsigned char> script;
    const auto m = core::classify_address_for_coin(r.address, v.p2pkh, v.p2sh, v.hrps, script);
    if (m == core::AddressCoinMatch::Own) {
        r.ok = true;
        return r;
    }
    auto list = [](const std::vector<uint8_t>& xs) {
        std::string s;
        for (auto x : xs)
            s += (s.empty() ? "" : "/") + std::to_string(x);
        return s;
    };
    r.error = std::string(r.source == "configured" ? "the configured " : "the built-in ") + symbol
              + " payout address " + r.address
              + (m == core::AddressCoinMatch::Invalid ? " is not a valid address (bad encoding or checksum)"
                                                      : " is not a " + symbol + " address of this network")
              + " (" + symbol + (net == AuxNetwork::mainnet ? " mainnet" : " testnet/regtest")
              + " P2PKH version " + list(v.p2pkh) + ", P2SH " + list(v.p2sh)
              + (v.hrps.empty() ? std::string() : ", bech32 " + v.hrps.front()) + "); set " + option;
    return r;
}

} // namespace merged
} // namespace c2pool
