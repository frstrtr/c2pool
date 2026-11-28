// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB dashboard's sharechain documents (/sharechain/delta, /web/share/<h>,
// /current_payouts), built with core::sharechain_views (#2348) in the field
// shape the LTC node serves. DASHBOARD-GAPS-DGB.md item 1.
//
// Addresses: the core views render a script with bitcoin parameters
// (sharechain_views::script_address), so every address they put in a
// document is re-rendered here with DGB's own (dgb_address_of: the V35
// canonical string, the P2PK donation as python's donation address,
// D.../S.../dgb1...). The rows of a snapshot and the "shares" array of the
// document built from it are in the same order, one to one.
//
// Locking: as the core views, the caller holds the node's read guard across
// the snapshot / share_detail calls; the JSON is built after it is released.
// ---------------------------------------------------------------------------

#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/share_check.hpp>    // dgb::get_share_script
#include <impl/dgb/share_tracker.hpp>  // dgb::ShareTracker
#include <impl/dgb/v35_address.hpp>    // v35_script_to_address, v35_donation_address

#include <core/sharechain_dashboard_views.hpp>
#include <core/target_utils.hpp>

#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <map>
#include <type_traits>
#include <string>
#include <vector>

namespace dgb {
namespace dashboard {

inline constexpr double kShareDonationDivisor = 65535.0;
inline constexpr std::size_t kDeltaCap = 200;

/// A payout script as a DGB address: the V35 canonical string (P2PKH, P2SH,
/// lowercase bech32 v0), the P2PK donation as its P2PKH address (python's
/// donation_script_to_address), else raw hex.
inline std::string dgb_address_of(const std::vector<unsigned char>& script)
{
    const auto net = dgb::v35_address_net(dgb::PoolConfig::is_testnet);
    std::string a = dgb::v35_script_to_address(script, net);
    if (a.empty())
        a = dgb::v35_donation_address(script, net);
    return a.empty() ? HexStr(script) : a;
}

struct ShareScript {
    template <typename ShareT>
    std::vector<unsigned char> operator()(const ShareT* obj) const { return dgb::get_share_script(obj); }
};

inline core::sharechain_views::ChainSnapshot delta_snapshot(dgb::ShareTracker& tracker, const std::string& since)
{
    return core::sharechain_views::snapshot(tracker, dgb::PoolConfig::chain_length(), ShareScript{}, since,
                                            kDeltaCap);
}

/// Re-renders the "m" of each row of `doc["shares"]` (built from `snap`) with
/// DGB's address parameters.
inline void relabel_rows(nlohmann::json& doc, const core::sharechain_views::ChainSnapshot& snap)
{
    if (!doc.contains("shares") || !doc["shares"].is_array())
        return;
    auto& shares = doc["shares"];
    std::map<std::vector<unsigned char>, std::string> cache;
    for (std::size_t i = 0; i < shares.size() && i < snap.rows.size(); ++i) {
        const auto& script = snap.rows[i].script;
        auto it = cache.find(script);
        if (it == cache.end())
            it = cache.emplace(script, dgb_address_of(script)).first;
        shares[i]["m"] = it->second;
    }
}

inline nlohmann::json delta_json(const core::sharechain_views::ChainSnapshot& snap, const std::string& fee_hash160,
                                 const std::vector<std::string>& found_share_hashes)
{
    nlohmann::json doc = core::sharechain_views::delta_json(snap, fee_hash160, found_share_hashes,
                                                            dgb::PoolConfig::is_testnet);
    relabel_rows(doc, snap);
    return doc;
}

/// /web/share/<hash>, the payout address in DGB's parameters.
inline nlohmann::json share_detail(dgb::ShareTracker& tracker, const std::string& hash_hex)
{
    nlohmann::json detail = core::sharechain_views::share_detail(tracker, hash_hex, ShareScript{},
                                                                 dgb::PoolConfig::is_testnet,
                                                                 kShareDonationDivisor);
    if (detail.contains("error"))
        return detail;
    uint256 hash;
    hash.SetHex(hash_hex);
    std::vector<unsigned char> script;
    tracker.chain.get_share(hash).invoke([&](auto* obj) { script = dgb::get_share_script(obj); });
    if (detail.contains("share_data") && detail["share_data"].is_object())
        detail["share_data"]["payout_address"] = dgb_address_of(script);
    return detail;
}

/// /current_payouts: the PPLNS split at `best` for a block of `block_bits`
/// paying `subsidy` (the tracker's own get_expected_payouts, the split the
/// generation transaction makes), as {DGB address: DGB}. Empty when there is
/// nothing to split.
inline nlohmann::json current_payouts(dgb::ShareTracker& tracker, const uint256& best, uint32_t block_bits,
                                      uint64_t subsidy)
{
    if (best.IsNull() || block_bits == 0 || subsidy == 0 || !tracker.chain.contains(best))
        return nlohmann::json::object();
    int64_t version = 35;
    tracker.chain.get_share(best).invoke([&](auto* obj) {
        version = std::remove_pointer_t<decltype(obj)>::version;
    });
    std::map<std::vector<unsigned char>, double> raw;
    try {
        raw = tracker.get_expected_payouts(best, chain::bits_to_target(block_bits), subsidy,
                                           dgb::PoolConfig::get_donation_script(version));
    } catch (const std::exception&) {
        return nlohmann::json::object();
    }
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [script, sat] : raw) {
        if (sat <= 0.0)
            continue;
        const std::string addr = dgb_address_of(script);
        const double coins = sat / 1e8;
        out[addr] = out.contains(addr) ? out[addr].get<double>() + coins : coins;
    }
    return out;
}

} // namespace dashboard
} // namespace dgb
