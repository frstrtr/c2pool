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
// identifies, is not given to one of them by guessing: it is ignored (with a
// warning) and the chains get the primary's key — the miner names its chain
// with PRIMARY/CHAIN_ID:ADDR. With one merged chain the resolution is the
// pre-change one.
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
    std::vector<uint32_t> from_login;            // chains the comma form / swap / case 5 named
    // The primary is the parent coin's address, or a configured merged
    // chain's (case 5: the parent payout uses its hash160). False (empty,
    // invalid, another coin's): the parent payout is redistributed, or comes
    // from case 4 (parent_script).
    bool usable_primary{false};
    // Case 4 (p2pool work.py): an unusable primary with a valid DOGE address
    // as the second one: the parent payout is that address's hash160 (P2SH
    // stays P2SH).
    std::vector<unsigned char> parent_script;
    // A P2SH primary's key was auto-derived for some configured chain (paid
    // as P2SH; unsafe if segwit-wrapped): shown with the worker.
    bool p2sh_derived{false};
    std::vector<std::string> notes;              // for the log
    std::vector<std::string> warnings;           // for the log, at warning level
};

/// Resolve a login: `primary` and the optional second address `merged_raw`
/// (comma/pipe/space/semicolon form), `explicit_addrs` from the slash form
/// (PRIMARY/CHAIN_ID:ADDR) and mining.set_merged_addresses, the configured
/// chains, and the parent coin's own versions/HRPs on the node's network.
///
/// No login is refused here: an address that cannot be given to exactly one
/// configured chain never loses the miner's work, it is left unspecified and
/// the chain is resolved as if the miner had named none (with a warning):
///   - an address that pays nothing (bad checksum, not an address at all), as
///     p2pool does with such a second address;
///   - with several merged chains, an address two of them could take (shared
///     version bytes) or none identifies: the chain gets the primary's key,
///     which the miner holds, never a guess between chains (no cross-pay).
/// With one merged chain an address no chain identifies keeps the
/// pre-change fallback (its hash160 goes to that chain).
///
/// An unusable primary (empty, invalid, another coin's) gets no auto-derived
/// address: its shares are redistributed by the work source, merged chains
/// included, as p2pool does (its "Case 3"); with a valid DOGE address as the
/// second address the parent payout is that address's key (p2pool's "Case 4").
inline LoginResolution resolve_merged_login(std::string primary, const std::string& merged_raw,
                                            std::map<uint32_t, std::string> explicit_addrs,
                                            const std::vector<ChainAddrInfo>& table,
                                            const std::function<bool(uint32_t)>& configured,
                                            const std::vector<uint8_t>& parent_versions_now,
                                            const std::vector<std::string>& parent_hrps)
{
    LoginResolution r;
    // An address that pays something on `chain` (chain-agnostic when null).
    const auto pays = [](const ChainAddrInfo* chain, const std::string& a) {
        return !merged_payout_script(chain, a).empty();
    };
    for (auto it = explicit_addrs.begin(); it != explicit_addrs.end();) {
        if (pays(find_chain(table, it->first), it->second)) {
            ++it;
            continue;
        }
        r.warnings.push_back("merged address " + it->second + " for chain_id=" + std::to_string(it->first)
                             + " is not a valid address: ignored");
        it = explicit_addrs.erase(it);
    }
    r.addresses = std::move(explicit_addrs);
    std::vector<const ChainAddrInfo*> conf;   // table order: "the first configured chain"
    for (const auto& c : table)
        if (configured(c.chain_id))
            conf.push_back(&c);
    const auto chains_taking = [&](const std::string& addr) {
        std::vector<const ChainAddrInfo*> out;
        for (const auto* c : conf)
            if (core::is_address_for_chain(addr, c->hrps, c->versions) && pays(c, addr))
                out.push_back(c);
        return out;
    };
    const auto ids = [](const std::vector<const ChainAddrInfo*>& cs) {
        std::string l;
        for (const auto* c : cs)
            l += (l.empty() ? "" : " and ") + std::to_string(c->chain_id);
        return l;
    };
    const auto is_parent = [&](const std::string& a) {
        return core::is_address_for_chain(a, parent_hrps, parent_versions_now) && !core::address_to_script(a).empty();
    };
    const std::string name_it = " (name its chain: PRIMARY/CHAIN_ID:ADDRESS)";

    std::string merged = merged_raw;
    // A first address that is not an address at all before a parent address
    // (a mistyped merged address in a swapped pair): the parent address is
    // the primary, as the pre-change server paid it; the first one is ignored.
    if (!merged.empty() && is_parent(merged) && chains_taking(primary).empty() && !pays(nullptr, primary)
        && !is_parent(primary)) {
        r.warnings.push_back("first address " + primary + " is not a valid address: ignored, the parent address "
                             + merged + " is paid");
        primary = merged;
        merged.clear();
    }
    if (!merged.empty() && chains_taking(merged).empty() && !pays(nullptr, merged) && !is_parent(merged)) {
        r.warnings.push_back("merged address " + merged + " is not a valid address: ignored");
        merged.clear();
    }

    bool second_used = false;
    if (!merged.empty()) {
        const auto m = chains_taking(merged);
        if (m.size() == 1) {
            r.addresses[m[0]->chain_id] = merged;
            r.from_login.push_back(m[0]->chain_id);
            second_used = true;
        } else if (m.size() > 1) {
            r.warnings.push_back("merged address " + merged + " is an address of merged chains " + ids(m)
                                 + ": ignored, they get the primary's key" + name_it);
        } else {
            // Swapped order: the first address is a merged chain's, the second the parent's.
            const auto u = chains_taking(primary);
            if (!u.empty() && is_parent(merged)) {
                if (u.size() == 1) {
                    r.notes.push_back("swapped address order — auto-correcting");
                    r.addresses[u[0]->chain_id] = primary;
                    r.from_login.push_back(u[0]->chain_id);
                } else {
                    r.warnings.push_back("swapped address order; merged address " + primary
                                         + " is an address of merged chains " + ids(u)
                                         + ": ignored, they get the primary's key" + name_it);
                }
                primary = merged;
                second_used = true;
            } else {
                std::string t;
                if (core::address_to_hash160(merged, t).size() == 40 && conf.size() == 1
                    && (is_parent(primary) || !chains_taking(primary).empty())) {
                    // The one merged chain configured: the pre-change fallback
                    // (only beside a usable primary: p2pool takes a second
                    // address for DOGE only when it is one).
                    r.addresses[conf[0]->chain_id] = merged;
                    r.from_login.push_back(conf[0]->chain_id);
                    r.notes.push_back("assigned merged address to chain_id=" + std::to_string(conf[0]->chain_id));
                    second_used = true;
                } else if (!conf.empty()) {
                    r.warnings.push_back("merged address " + merged
                                         + " is not an address of any configured merged chain (" + ids(conf)
                                         + "): ignored" + name_it);
                }
            }
        }
    }

    // Case 5: the primary address is a merged chain's, not the parent's.
    const auto u = chains_taking(primary);
    if (!second_used && !primary.empty() && !is_parent(primary)) {
        if (u.size() == 1) {
            r.addresses[u[0]->chain_id] = primary;
            r.from_login.push_back(u[0]->chain_id);
            r.notes.push_back("Case 5: primary address is chain_id=" + std::to_string(u[0]->chain_id)
                              + " (not the parent's): the parent payout uses its hash160");
            if (primary.find('1') != std::string::npos
                && std::any_of(u[0]->hrps.begin(), u[0]->hrps.end(),
                               [&](const std::string& h) { return primary.rfind(h + "1", 0) == 0; }))
                r.warnings.push_back("primary " + primary + " is a bech32 address of merged chain "
                                     + std::to_string(u[0]->chain_id) + ": the parent payout is its witness "
                                     "program as a parent-coin segwit output; give a parent address first");
        } else if (u.size() > 1) {
            r.warnings.push_back("primary address " + primary + " is an address of merged chains " + ids(u)
                                 + ": the parent payout and those chains use its key" + name_it);
        }
    }
    r.usable_primary = !primary.empty() && (is_parent(primary) || !u.empty());

    if (r.usable_primary) {
        // Auto-derive: each configured chain without an address reuses the
        // primary's hash160 (the same key spends on both chains): P2PKH and
        // P2WPKH as P2PKH, a P2SH as the chain's P2SH. Right for a legacy
        // P2SH; a segwit-wrapped one (P2SH-P2WPKH / P2WSH, an LTC "M..."
        // address) becomes spendable by anyone on a chain without segwit
        // (DOGE) once its redeem script is public: the login is warned.
        std::string atype;
        const auto h160 = core::address_to_hash160(primary, atype);
        if (h160.size() == 40 && (atype == "p2pkh" || atype == "p2wpkh" || atype == "p2sh")) {
            std::string derived;
            for (const auto* c : conf)
                if (!r.addresses.count(c->chain_id)) {
                    r.addresses[c->chain_id] = primary;
                    r.notes.push_back("auto-derived merged address for chain_id=" + std::to_string(c->chain_id)
                                      + " from primary " + atype + " address");
                    derived += (derived.empty() ? "" : " and ") + std::to_string(c->chain_id);
                }
            if (atype == "p2sh" && !derived.empty()) {
                r.p2sh_derived = true;
                r.warnings.push_back("primary " + primary + " is a P2SH address, paid as the same P2SH on "
                                     "merged chain(s) " + derived + ": if this is a segwit-wrapped wallet "
                                     "address (P2SH-P2WPKH/P2WSH, e.g. M...), give your DOGE address "
                                     "explicitly (LTC_ADDRESS,DOGE_ADDRESS); on DOGE (no segwit) such an "
                                     "output becomes spendable by anyone once the redeem script is public");
            }
        }
    } else if (!primary.empty()) {
        // Case 4: a valid DOGE address of this network as the second address.
        const auto* doge = find_chain(table, 98);
        const auto it = r.addresses.find(98);
        if (doge && it != r.addresses.end() && std::find(r.from_login.begin(), r.from_login.end(), 98u)
                                                   != r.from_login.end()) {
            std::vector<unsigned char> script;
            if (core::classify_address_for_coin(it->second, doge->p2pkh, doge->p2sh, doge->own_hrps, script)
                    == core::AddressCoinMatch::Own
                && (script.size() == 25 || script.size() == 23)) {
                r.parent_script = script;   // P2PKH or P2SH of the DOGE address's hash160
                r.notes.push_back("Case 4: primary " + primary + " is not a usable address; the parent payout uses"
                                  " the DOGE address " + it->second + "'s key");
            }
        }
    }
    r.primary = std::move(primary);
    return r;
}

} // namespace merged_addr
} // namespace core
