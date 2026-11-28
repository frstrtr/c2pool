// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB sharechain stats for the dashboard (MiningInterface
// set_sharechain_stats_fn), in LTC's field shape: /global_stats,
// /local_stats, the sync status and the version-signaling card read them.
// Display only. Built under the tracker read guard (main_dgb); the walk is
// at most CHAIN_LENGTH shares back from the anchor.
//
// Anchor: the verified best share when it is in the chain, else the tallest
// raw head (so the fields fill during sync). DASHBOARD-GAPS-DGB.md item 2:
// before, the fn read chain.size() without the guard and emitted only
// total_shares, so current_height and chain_size were 0.
// ---------------------------------------------------------------------------

#include <impl/dgb/config_pool.hpp>

#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>
#include <sharechain/pool_rate_head_select.hpp>   // sharechain::average_stale_prop

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>

namespace dgb {

template <typename TrackerT>
nlohmann::json sharechain_stats_json(TrackerT& tracker, const uint256& verified_best)
{
    auto& chain = tracker.chain;
    nlohmann::json r = nlohmann::json::object();

    uint256 anchor;
    if (!verified_best.IsNull() && chain.contains(verified_best)) {
        anchor = verified_best;
    } else {
        int32_t tallest = -1;
        for (const auto& [head, tail] : chain.get_heads()) {
            (void)tail;
            const auto h = static_cast<int32_t>(chain.get_height(head));
            if (h > tallest) {
                tallest = h;
                anchor = head;
            }
        }
    }
    const int height = anchor.IsNull() ? 0 : static_cast<int>(chain.get_height(anchor));
    const int chain_length = static_cast<int>(PoolConfig::chain_length());
    const int period = static_cast<int>(PoolConfig::share_period());
    const int lookbehind = std::min(height, 3600 / (period > 0 ? period : 1));

    int count = 0, orphan = 0, dead = 0, stales_in_lookbehind = 0;
    double difficulty_sum = 0.0;
    std::map<std::string, int> by_version, by_desired, by_miner;
    uint32_t anchor_max_bits = 0;
    uint256 pos = anchor;
    for (int i = 0; i < std::min(height, chain_length) && !pos.IsNull() && chain.contains(pos); ++i) {
        chain.get(pos).share.invoke([&](auto* s) {
            if (i == 0)
                anchor_max_bits = s->m_max_bits;
            ++count;
            const int stale = static_cast<int>(s->m_stale_info);
            if (stale == 253)
                ++orphan;
            else if (stale == 254)
                ++dead;
            if ((stale == 253 || stale == 254) && i < lookbehind)
                ++stales_in_lookbehind;
            ++by_version[std::to_string(s->version)];
            ++by_desired[std::to_string(s->m_desired_version)];
            difficulty_sum += chain::target_to_difficulty(chain::bits_to_target(s->m_bits));
            std::string miner;
            if constexpr (requires { s->m_address; })
                miner = HexStr(s->m_address.m_data);
            else if constexpr (requires { s->m_pubkey_hash; })
                miner = s->m_pubkey_hash.GetHex();
            if (!miner.empty())
                ++by_miner[miner];
            pos = s->m_prev_hash;
        });
    }

    r["chain_tip_hash"] = anchor.IsNull() ? "" : anchor.GetHex();
    r["chain_height"] = height;
    r["chain_length"] = chain_length;
    r["fork_count"] = static_cast<int>(chain.get_heads().size());
    r["verified_count"] = static_cast<int>(tracker.verified.size());
    r["total_shares"] = count;
    r["orphan_shares"] = orphan;
    r["dead_shares"] = dead;
    r["shares_by_version"] = by_version;
    r["shares_by_desired_version"] = by_desired;
    r["shares_by_miner"] = by_miner;
    r["average_difficulty"] = count > 0 ? difficulty_sum / count : 1.0;
    // p2pool web.py: the pool's share-difficulty floor, from the anchor's max_bits.
    if (anchor_max_bits != 0)
        r["min_difficulty"] = chain::target_to_difficulty(chain::bits_to_target(anchor_max_bits));
    r["pool_stale_prop"] = sharechain::average_stale_prop(stales_in_lookbehind, lookbehind);
    return r;
}

} // namespace dgb
