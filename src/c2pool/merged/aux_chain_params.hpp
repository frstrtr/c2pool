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
/// payout address", Bellscoin -5), to size-check an assembled aux block, and
/// by the stratum server to tell which merged chain a miner's address is of.
///
/// Checked against the daemons themselves (validateaddress / getnewaddress on
/// mainnet, testnet and regtest): DOGE (dogecoind 1.14.9), PEP (pepecoind
/// 1.1.0). Read from local source: NMC (namecoin-core chainparams.cpp,
/// validation.cpp). Read from the upstream repositories only, not checked
/// against a running daemon: BELLS, LKY, JKC, SHIC, DINGO.

#include <core/address_utils.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2pool {
namespace merged {

/// The parent's network: c2pool runs mainnet or testnet. An aux daemon
/// beside a testnet parent may be on its testnet or its regtest; the exact
/// network is checked once the daemon answers (check_aux_address_on_chain).
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
    // CheckBlock's limits on the block serialized with the AuxPoW in its
    // header (bad-blk-length / bad-blk-weight). Dogecoin family:
    // GetSerializeSize(block, NO_WITNESS) <= MAX_BLOCK_BASE_SIZE. Segwit
    // chains (Namecoin validation.cpp, Bellscoin, Junkcoin v4):
    // stripped size * 4 <= MAX_BLOCK_WEIGHT (4,000,000), i.e. stripped <=
    // 1,000,000, and weight (stripped * 3 + full) <= 4,000,000.
    uint32_t       max_stripped_bytes;
    uint32_t       max_weight;          // 0: no weight rule (no segwit)
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
        {"DOGE", 98, {{30}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 1'000'000, 0,
         "DDogepartyxxxxxxxxxxxxxxxxxxw1dfzr", "nUCAGGgZEPN1QyknmQe1oAku817bQAFKFt"},
        // Pepecoin: main 56/22, testnet 113/196, regtest 111/196.
        {"PEP", 63, {{56}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 1'000'000, 0, nullptr, nullptr},
        // Bellscoin: main 25/30 "bel", testnet 33/22 "tbel", regtest 111/196 "bcrt".
        {"BELLS", 16, {{25}, {30}, {"bel"}}, {{33}, {22}, {"tbel"}}, {{111}, {196}, {"bcrt"}}, 1'000'000,
         4'000'000, nullptr, nullptr},
        // Luckycoin: main 47/5, testnet 113/196, regtest 113/196.
        {"LKY", 8211, {{47}, {5}, {}}, {{113}, {196}, {}}, {{113}, {196}, {}}, 1'000'000, 0, nullptr, nullptr},
        // Junkcoin v4: main 16/5 "jc", testnet 111/5 "tjc", regtest 47/5 "rjc"
        // (testnet/regtest chain id 8225).
        {"JKC", 8224, {{16}, {5}, {"jc"}}, {{111}, {5}, {"tjc"}}, {{47}, {5}, {"rjc"}}, 1'000'000,
         4'000'000, nullptr, nullptr},
        // Shibacoin: main 63/22, testnet 113/196, regtest 111/196.
        {"SHIC", 74, {{63}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 1'000'000, 0, nullptr, nullptr},
        // Dingocoin: main 30/22, testnet 113/196, regtest 111/196. Chain id 50
        // since mainnet height 265,000 (98 before); blocks up to 10,000,000
        // bytes after height 2,254,540.
        {"DINGO", 50, {{30}, {22}, {}}, {{113}, {196}, {}}, {{111}, {196}, {}}, 10'000'000, 0, nullptr, nullptr},
        // Namecoin: main 52/13 "nc", testnet 111/196 "tn", regtest 111/196 "ncrt".
        {"NMC", 1, {{52}, {13}, {"nc"}}, {{111}, {196}, {"tn"}}, {{111}, {196}, {"ncrt"}}, 1'000'000,
         4'000'000, nullptr, nullptr},
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

/// The versions of the daemon's own network, from its getblockchaininfo
/// "chain" ("main", "test", "regtest"); nullopt for a network not in the
/// table (e.g. signet), which is then not judged.
inline std::optional<AuxNetVersions> aux_versions_on_chain(const AuxChainParams& p, const std::string& chain)
{
    if (chain == "main")
        return p.main;
    if (chain == "test" || chain == "testnet" || chain == "testnet3" || chain == "testnet4")
        return p.test;
    if (chain == "regtest")
        return p.regtest;
    return std::nullopt;
}

/// "" when `address` is an address of `symbol` on the daemon's network
/// `chain` (or either is not known), else why not.
inline std::string check_aux_address_on_chain(const std::string& symbol, const std::string& chain,
                                              const std::string& address)
{
    const auto* p = find_aux_chain_params(symbol);
    if (!p)
        return {};
    const auto v = aux_versions_on_chain(*p, chain);
    if (!v)
        return {};
    std::vector<unsigned char> script;
    if (core::classify_address_for_coin(address, v->p2pkh, v->p2sh, v->hrps, script) == core::AddressCoinMatch::Own)
        return {};
    return "the createauxblock payout address " + address + " is not a " + symbol + " address of the daemon's "
           + chain + " network; set --merged-payout-address " + symbol + ":<address>";
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

/// The merged address written into the node operator's own shares: the
/// node-fee (-f) shares and the redistributed shares that land on the
/// operator's key with no merged address. p2pool's cascade
/// (work.py _resolve_operator_merged_addresses), so both implementations put
/// the same bytes into those shares:
///   P1 the operator's address of the chain: for DOGE --node-owner-merged-address
///      (p2pool --merged-operator-address), for another chain
///      --merged-payout-address SYMBOL:ADDRESS; used when it is an address of
///      the chain on the parent's network;
///   P2 else the operator's parent key (--node-owner-address) converted, as the
///      auto-derive does (P2SH stays P2SH, P2PKH/P2WPKH become P2PKH);
///   P3 else (a P2WSH/P2TR operator address) the pool donation script.
struct OperatorMergedScript {
    std::vector<unsigned char> script;
    std::string source;
    std::string warning;   // a P1 address that was set but is not usable
};

inline OperatorMergedScript resolve_operator_merged_script(const std::string& symbol, AuxNetwork net,
                                                           const std::string& node_owner_address,
                                                           const std::string& node_owner_merged_address,
                                                           const std::string& merged_payout_address,
                                                           const std::vector<unsigned char>& donation_script)
{
    OperatorMergedScript r;
    std::string up = symbol;
    for (auto& c : up)
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 32);
    const std::string p1 = up == "DOGE" ? node_owner_merged_address : merged_payout_address;
    const std::string p1_option = up == "DOGE" ? "--node-owner-merged-address" : "--merged-payout-address " + up;
    if (!p1.empty()) {
        if (const auto* p = find_aux_chain_params(up)) {
            const auto v = aux_accepted_versions(*p, net);
            std::vector<unsigned char> script;
            if (core::classify_address_for_coin(p1, v.p2pkh, v.p2sh, v.hrps, script) == core::AddressCoinMatch::Own
                && !script.empty()) {
                r.script = std::move(script);
                r.source = p1_option;
                return r;
            }
            r.warning = p1_option + " " + p1 + " is not a " + up + " address of this network";
        } else {
            r.warning = "c2pool has no address parameters for " + up + " to check " + p1_option + " " + p1;
        }
    }
    std::string atype;
    const auto h160 = core::address_to_hash160(node_owner_address, atype);
    if (h160.size() == 40 && (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh")) {
        r.script = core::hash160_to_merged_script(h160, atype);
        r.source = "--node-owner-address key";
        return r;
    }
    r.script = donation_script;
    r.source = "donation script";
    return r;
}

} // namespace merged
} // namespace c2pool
