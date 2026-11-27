// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCH sharechain views for the dashboard: /sharechain/window,
// /sharechain/delta, /sharechain/tip and /web/share/<hash>, built by
// core/sharechain_dashboard_views.hpp over bch::ShareTracker.
// bch::standup_pool_run (pool_entrypoint.hpp) serves exactly these functions;
// bch_dashboard_pplns_current_test checks them.
//
// The caller holds the node's read_tracker() guard across every call that
// takes the tracker, and releases it before turning a snapshot into JSON.

#include "share_tracker.hpp"   // bch::ShareTracker
#include "share_check.hpp"     // bch::get_share_script
#include "config_pool.hpp"     // bch::PoolConfig::chain_length

#include <core/sharechain_dashboard_views.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace bch {
namespace dashboard {

// p2pool donation encoding: the share's donation field over 65535.
inline constexpr double kShareDonationDivisor = 65535.0;

// /sharechain/delta sends at most this many new shares.
inline constexpr std::size_t kDeltaCap = 200;

struct ShareScript {
    template <typename ShareT>
    std::vector<unsigned char> operator()(const ShareT* obj) const { return bch::get_share_script(obj); }
};

inline core::sharechain_views::ChainSnapshot window_snapshot(bch::ShareTracker& tracker)
{
    return core::sharechain_views::snapshot(tracker, bch::PoolConfig::chain_length(), ShareScript{});
}

inline core::sharechain_views::ChainSnapshot delta_snapshot(bch::ShareTracker& tracker,
                                                            const std::string& since)
{
    return core::sharechain_views::snapshot(tracker, bch::PoolConfig::chain_length(),
                                            ShareScript{}, since, kDeltaCap);
}

inline nlohmann::json chain_stats(bch::ShareTracker& tracker)
{
    return core::sharechain_views::chain_stats(tracker, bch::PoolConfig::chain_length());
}

inline nlohmann::json share_detail(bch::ShareTracker& tracker, const std::string& hash_hex,
                                   bool testnet)
{
    return core::sharechain_views::share_detail(tracker, hash_hex, ShareScript{}, testnet,
                                                kShareDonationDivisor);
}

} // namespace dashboard
} // namespace bch
