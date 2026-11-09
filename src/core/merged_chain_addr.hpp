// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Merged-chain address identification for the stratum server (issue #961):
// which configured merged chain a miner's address belongs to, and the script
// it pays there.

#include <c2pool/merged/aux_chain_params.hpp>
#include <core/address_utils.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace core {
namespace merged_addr {

// ─── Merged-chain address identification table (issue #961) ──────────────────
// Shared by handle_authorize() (merged-chain resolution) and send_notify_work()
// (the #961 payout money-path check). A username that resolves to a CONFIGURED
// merged chain here is a legitimate merged-mining payout — the same hash160 /
// secp256k1 key is spendable on the parent and the merged chain.
// Built from c2pool::merged::aux_chain_params_table() (each coin's own
// chainparams: P2PKH and P2SH versions and bech32 HRPs per network), the one
// source the merged manager checks createauxblock addresses with. Versions
// are shared between chains (P2SH 22: DOGE, PEP, SHIC; DOGE P2PKH 30 is
// Bellscoin's P2SH; testnet 113 / regtest 111 across the Dogecoin family):
// an address that is an address of two configured chains is never assigned
// to either by guessing (the miner names the chain: PRIMARY/CHAIN_ID:ADDR).
struct ChainAddrInfo {
    uint32_t chain_id;
    std::vector<std::string> hrps;
    std::vector<uint8_t> versions;   // P2PKH and P2SH (the #961 decision)
    std::vector<uint8_t> p2pkh;
    std::vector<uint8_t> p2sh;
};
inline const std::vector<ChainAddrInfo>& merged_chain_table(bool testnet) {
    static const auto build = [](bool tn) {
        std::vector<ChainAddrInfo> t;
        for (const auto& p : c2pool::merged::aux_chain_params_table()) {
            const auto v = c2pool::merged::aux_accepted_versions(
                p, tn ? c2pool::merged::AuxNetwork::testnet : c2pool::merged::AuxNetwork::mainnet);
            ChainAddrInfo i;
            // Junkcoin's testnet and regtest chain id is 8225 (8224 on mainnet).
            i.chain_id = (tn && p.chain_id == 8224) ? 8225 : p.chain_id;
            i.hrps = v.hrps;
            i.p2pkh = v.p2pkh;
            i.p2sh = v.p2sh;
            i.versions = v.p2pkh;
            i.versions.insert(i.versions.end(), v.p2sh.begin(), v.p2sh.end());
            t.push_back(std::move(i));
        }
        return t;
    };
    static const std::vector<ChainAddrInfo> main_t = build(false), test_t = build(true);
    return testnet ? test_t : main_t;
}
inline const ChainAddrInfo* merged_chain_info(bool testnet, uint32_t chain_id) {
    for (const auto& c : merged_chain_table(testnet))
        if (c.chain_id == chain_id)
            return &c;
    return nullptr;
}
// An address of this chain, by its own versions and HRPs.
inline bool is_own_address(const std::string& addr, const ChainAddrInfo& c) {
    std::vector<unsigned char> script;
    return core::classify_address_for_coin(addr, c.p2pkh, c.p2sh, c.hrps, script)
        == core::AddressCoinMatch::Own;
}

// The configured chains (configured(chain_id)) this address is an address of.
inline std::vector<const ChainAddrInfo*> chains_of(const std::string& addr, bool testnet,
                                                   const std::function<bool(uint32_t)>& configured)
{
    std::vector<const ChainAddrInfo*> out;
    for (const auto& c : merged_chain_table(testnet))
        if (configured(c.chain_id) && is_own_address(addr, c))
            out.push_back(&c);
    return out;
}

// The scriptPubKey an address of this chain pays there (P2PKH, P2SH or a
// witness program by the chain's own versions / HRPs); empty when it is not
// an address of that chain.
inline std::vector<unsigned char> script_on_chain(const ChainAddrInfo& c, const std::string& addr)
{
    std::vector<unsigned char> script;
    if (core::classify_address_for_coin(addr, c.p2pkh, c.p2sh, c.hrps, script) != core::AddressCoinMatch::Own)
        script.clear();
    return script;
}

} // namespace merged_addr
} // namespace core
