// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Merged-chain address resolution for the stratum server (issue #961): which
// configured merged chain each address in a miner's login is for, and the
// script it pays there. A pure function of the login, the configured chains
// and the parent coin's address versions, so every login shape can be pinned
// against the pre-change behaviour (merged_aux_hardening_test.cpp,
// MergedAuxStratumLogin).
//
// The chains identified are the ones the stratum server always knew (DOGE,
// PEP, BELLS, LKY, JKC, SHIC). Their identification versions are taken from
// c2pool::merged::aux_chain_params_table() (each coin's chainparams): the
// mainnet and testnet P2PKH/P2SH versions, minus every version the parent
// coin uses on any network (an address the parent could own is never claimed
// by a merged chain). For DOGE that is exactly {30, 22, 113}, the list the
// server had. Versions are still shared between merged chains (P2SH 22:
// DOGE, PEP, SHIC; Bellscoin's P2SH 30 is DOGE's P2PKH): with several chains
// configured, an address that two of them could take, or that none
// identifies, is refused rather than given to one of them by guessing — the
// miner names its chain (PRIMARY/CHAIN_ID:ADDR). With one merged chain the
// resolution is the pre-change one.
//
// Script: an address of the chain itself (its own versions on the node's
// network) pays that chain's script type (a Bellscoin P2SH stays P2SH, a
// Junkcoin P2PKH "7..." stays P2PKH); any other address (the primary reused,
// another coin's) pays its hash160 with the chain-agnostic type, as before.
// For DOGE the two agree on every version.

#include <c2pool/merged/aux_chain_params.hpp>
#include <core/address_utils.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace core {
namespace merged_addr {

struct ChainAddrInfo {
    uint32_t chain_id;
    std::vector<std::string> hrps;       // identification (mainnet and testnet)
    std::vector<uint8_t> versions;       // identification, P2PKH and P2SH (the #961 decision)
    std::vector<uint8_t> p2pkh;          // the chain's own versions on the node's network (scripts)
    std::vector<uint8_t> p2sh;
    std::vector<std::string> own_hrps;
};

/// The identification table for the node's network. `parent_versions`: the
/// parent coin's P2PKH and P2SH versions on every network.
inline std::vector<ChainAddrInfo> merged_chain_table(bool testnet, const std::vector<uint8_t>& parent_versions)
{
    static const std::vector<std::string> known = {"DOGE", "PEP", "BELLS", "LKY", "JKC", "SHIC"};
    std::vector<ChainAddrInfo> t;
    for (const auto& sym : known) {
        const auto* p = c2pool::merged::find_aux_chain_params(sym);
        if (!p)
            continue;
        ChainAddrInfo i;
        i.chain_id = p->chain_id;
        auto add = [&](const std::vector<uint8_t>& vs) {
            for (auto v : vs)
                if (std::find(parent_versions.begin(), parent_versions.end(), v) == parent_versions.end()
                    && std::find(i.versions.begin(), i.versions.end(), v) == i.versions.end())
                    i.versions.push_back(v);
        };
        add(p->main.p2pkh);
        add(p->main.p2sh);
        add(p->test.p2pkh);
        add(p->test.p2sh);
        for (const auto* hs : {&p->main.hrps, &p->test.hrps})
            for (const auto& h : *hs)
                if (std::find(i.hrps.begin(), i.hrps.end(), h) == i.hrps.end())
                    i.hrps.push_back(h);
        const auto own = c2pool::merged::aux_accepted_versions(
            *p, testnet ? c2pool::merged::AuxNetwork::testnet : c2pool::merged::AuxNetwork::mainnet);
        i.p2pkh = own.p2pkh;
        i.p2sh = own.p2sh;
        i.own_hrps = own.hrps;
        t.push_back(i);
        // Junkcoin's testnet and regtest chain id is 8225 (8224 on mainnet).
        if (sym == "JKC") {
            i.chain_id = 8225;
            t.push_back(i);
        }
    }
    return t;
}

inline const ChainAddrInfo* find_chain(const std::vector<ChainAddrInfo>& t, uint32_t chain_id)
{
    for (const auto& c : t)
        if (c.chain_id == chain_id)
            return &c;
    return nullptr;
}

/// The script a merged entry pays on its chain (as described above); empty
/// when the address decodes to nothing payable.
inline std::vector<unsigned char> merged_payout_script(const ChainAddrInfo* chain, const std::string& addr)
{
    if (chain) {
        std::vector<unsigned char> script;
        if (core::classify_address_for_coin(addr, chain->p2pkh, chain->p2sh, chain->own_hrps, script)
                == core::AddressCoinMatch::Own
            && !script.empty())
            return script;
    }
    std::string atype;
    const auto h160 = core::address_to_hash160(addr, atype);
    return h160.size() == 40 ? core::hash160_to_merged_script(h160, atype) : std::vector<unsigned char>{};
}

struct LoginResolution {
    std::string primary;                         // the parent payout address (after a swap)
    std::map<uint32_t, std::string> addresses;   // chain id -> address
    std::vector<uint32_t> to_owner;              // chains given the node owner's address
    std::string refuse;                          // set: refuse the authorize with this text
    std::vector<std::string> notes;              // for the log
};

/// Resolve a login: `primary` and the optional second address `merged_raw`
/// (comma/pipe/space/semicolon form), `explicit_addrs` from the slash form
/// (PRIMARY/CHAIN_ID:ADDR) and mining.set_merged_addresses, the configured
/// chains, and the parent coin's own versions/HRPs on the node's network.
///
/// `owner_for_unspecified` (--merged-unspecified-to-owner; chain id -> the
/// node owner's address on that chain): a configured chain in it for which
/// the miner gave no address is paid to the owner's address instead of the
/// primary's hash160. "Gave" is every address the login or
/// mining.set_merged_addresses names (the comma form, the slash form, a
/// swapped pair, a merged chain's address as the primary); the auto-derive is
/// not. Only for a login whose primary is a payout identity (an address whose
/// hash160 the auto-derive reuses, or a parent-coin address it cannot reduce,
/// P2WSH/P2TR): an empty or unusable primary keeps the existing handling
/// (redistribution / refusal), merged chains included. Empty map: the
/// resolution is the one without the option.
inline LoginResolution resolve_merged_login(std::string primary, const std::string& merged_raw,
                                            std::map<uint32_t, std::string> explicit_addrs,
                                            const std::vector<ChainAddrInfo>& table,
                                            const std::function<bool(uint32_t)>& configured,
                                            const std::vector<uint8_t>& parent_versions_now,
                                            const std::vector<std::string>& parent_hrps,
                                            const std::map<uint32_t, std::string>& owner_for_unspecified = {})
{
    LoginResolution r;
    r.addresses = std::move(explicit_addrs);
    std::vector<const ChainAddrInfo*> conf;   // table order: "the first configured chain"
    for (const auto& c : table)
        if (configured(c.chain_id))
            conf.push_back(&c);
    const auto chains_taking = [&](const std::string& addr) {
        std::vector<const ChainAddrInfo*> out;
        for (const auto* c : conf)
            if (core::is_address_for_chain(addr, c->hrps, c->versions))
                out.push_back(c);
        return out;
    };
    const auto ids = [](const std::vector<const ChainAddrInfo*>& cs) {
        std::string l;
        for (const auto* c : cs)
            l += (l.empty() ? "" : " and ") + std::to_string(c->chain_id);
        return l;
    };
    // `parent`: the parent-coin address of the example (the second one of a swapped pair).
    const auto refuse = [&](const std::string& addr, const std::string& why, const std::string& parent) {
        r.refuse = "merged address " + addr + " " + why + "; name its chain: PRIMARY/CHAIN_ID:ADDRESS (e.g. "
                   + parent + "/" + (conf.empty() ? std::string("98") : std::to_string(conf.front()->chain_id))
                   + ":" + addr + ")";
    };
    const auto is_parent = [&](const std::string& a) {
        return core::is_address_for_chain(a, parent_hrps, parent_versions_now);
    };

    if (!merged_raw.empty()) {
        const auto m = chains_taking(merged_raw);
        if (m.size() == 1) {
            r.addresses[m[0]->chain_id] = merged_raw;
        } else if (m.size() > 1) {
            refuse(merged_raw, "is an address of merged chains " + ids(m), primary);
            return r;
        } else {
            // Swapped order: the first address is a merged chain's, the second the parent's.
            const auto u = chains_taking(primary);
            if (!u.empty() && is_parent(merged_raw)) {
                if (u.size() > 1) {
                    refuse(primary, "is an address of merged chains " + ids(u), merged_raw);
                    return r;
                }
                r.notes.push_back("swapped address order — auto-correcting");
                r.addresses[u[0]->chain_id] = primary;
                primary = merged_raw;
            } else {
                // No chain identifies it: its hash160 goes to the one merged
                // chain configured (the pre-change fallback); with several,
                // which chain it is for cannot be told.
                std::string t;
                if (core::address_to_hash160(merged_raw, t).size() == 40 && !conf.empty()) {
                    if (conf.size() > 1) {
                        refuse(merged_raw, "is not an address of any configured merged chain (" + ids(conf) + ")",
                               primary);
                        return r;
                    }
                    r.addresses[conf[0]->chain_id] = merged_raw;
                    r.notes.push_back("assigned merged address to chain_id=" + std::to_string(conf[0]->chain_id));
                }
            }
        }
    }

    // Case 5: the primary address is a merged chain's, not the parent's.
    if (merged_raw.empty() && !primary.empty() && !is_parent(primary)) {
        const auto u = chains_taking(primary);
        if (u.size() == 1) {
            r.addresses[u[0]->chain_id] = primary;
            r.notes.push_back("Case 5: primary address is chain_id=" + std::to_string(u[0]->chain_id)
                              + " (not the parent's): the parent payout uses its hash160");
        } else if (u.size() > 1) {
            refuse(primary, "(the primary) is an address of merged chains " + ids(u), "PRIMARY");
            return r;
        }
    }

    std::string atype;
    const auto h160 = core::address_to_hash160(primary, atype);
    const bool derivable = h160.size() == 40 && (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh");

    // --merged-unspecified-to-owner: the chains the miner gave no address
    // for, to the node owner's address (before the auto-derive takes them).
    if (!owner_for_unspecified.empty() && (derivable || (!primary.empty() && is_parent(primary))))
        for (const auto& [id, owner] : owner_for_unspecified)
            if (configured(id) && !r.addresses.count(id) && !owner.empty()) {
                r.addresses[id] = owner;
                r.to_owner.push_back(id);
                r.notes.push_back("no merged address given for chain_id=" + std::to_string(id)
                                  + ": paid to the node owner's address " + owner
                                  + " (--merged-unspecified-to-owner)");
            }

    // Auto-derive: each configured chain without an address reuses the
    // primary's hash160 (the same key spends on both chains).
    if (derivable)
        for (const auto* c : conf)
            if (!r.addresses.count(c->chain_id)) {
                r.addresses[c->chain_id] = primary;
                r.notes.push_back("auto-derived merged address for chain_id=" + std::to_string(c->chain_id)
                                  + " from primary " + atype + " address");
            }
    r.primary = std::move(primary);
    return r;
}

} // namespace merged_addr
} // namespace core
