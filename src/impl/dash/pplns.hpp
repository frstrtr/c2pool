#pragma once

// PPLNS payout computation for c2pool-dash.
//
// Walks the Dash sharechain backward from a tip, aggregates weight per
// recipient pubkey_hash, and splits a total miner_value proportionally.
// Dust-sized allocations are dropped and their residue pushed onto the
// largest remaining payout.
//
// If the chain has fewer than min_shares_for_pplns reachable ancestors,
// compute_payouts() falls back to a single-recipient payout to the caller's
// fallback_script (typically --mining-address). This mirrors p2pool's
// genesis behavior: when no share history exists, the node mines solo.
//
// Scope boundary:
//   * We treat the chain's recorded shares as authoritative contributors.
//     Shares we received from the network count — that's the whole point
//     of p2pool cooperative mining.
//   * We do NOT (yet) create shares from our own miner's submits; that's
//     Phase 5c. Until then, our local miner only gets payouts via the
//     fallback path (cold chain) or via ambient shares we may have
//     previously produced and downloaded back via peer gossip.

#include "share_chain.hpp"                 // dash::ShareChain, DashShare
#include "share_check.hpp"                 // dash::pubkey_hash_to_script2
#include "coinbase_builder.hpp"            // dash::coinbase::bits_to_difficulty

#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <type_traits>

#include <core/uint256.hpp>
#include <core/log.hpp>

namespace dash {
namespace pplns {

struct Payout {
    std::vector<unsigned char> script;   // scriptPubKey for the recipient
    uint64_t                   amount{0};
};

struct Result {
    std::vector<Payout> payouts;
    size_t shares_used{0};               // how many shares contributed weight
    bool   used_fallback{false};         // true when chain is cold/insufficient
    double total_weight{0.0};            // sum of all share weights (diagnostic)
};

inline Result compute_payouts(
    dash::ShareChain& chain,
    const uint256& best_share_hash,
    size_t window_size,
    uint64_t miner_value,
    const std::vector<unsigned char>& fallback_script,
    size_t   min_shares_for_pplns = 20,
    uint64_t dust_threshold       = 54600)   // Dash dust sat
{
    Result r;
    if (miner_value == 0 || fallback_script.empty()) return r;

    auto use_fallback = [&]() {
        r.used_fallback = true;
        r.payouts.clear();
        r.payouts.push_back({fallback_script, miner_value});
    };

    if (best_share_hash.IsNull() || !chain.contains(best_share_hash)) {
        use_fallback();
        return r;
    }
    int32_t avail = 0;
    try { avail = chain.get_height(best_share_hash); }
    catch (...) { use_fallback(); return r; }
    if (avail < static_cast<int32_t>(min_shares_for_pplns)) {
        use_fallback();
        return r;
    }
    size_t win = std::min<size_t>(window_size, static_cast<size_t>(avail));
    if (win == 0) { use_fallback(); return r; }

    // Aggregate weight by pubkey_hash. Key on pubkey hex for deterministic
    // iteration; value carries the original uint160 for script building.
    struct Entry { uint160 pubkey_hash; double weight{0.0}; };
    std::map<std::string, Entry> by_key;
    double total_weight = 0.0;
    size_t shares_seen  = 0;

    try {
        for (auto&& [h, data] : chain.get_chain(best_share_hash, win)) {
            (void)h;
            data.share.invoke([&](auto* obj) {
                using S = std::remove_pointer_t<decltype(obj)>;
                if constexpr (std::is_same_v<S, dash::DashShare>) {
                    double w = dash::coinbase::bits_to_difficulty(obj->m_bits);
                    if (w <= 0.0) return;
                    std::string key = obj->m_pubkey_hash.ToString();
                    auto& e = by_key[key];
                    e.pubkey_hash = obj->m_pubkey_hash;
                    e.weight += w;
                    total_weight += w;
                    shares_seen += 1;
                }
            });
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "[PPLNS] walk failed: " << e.what();
        use_fallback();
        return r;
    }

    r.total_weight = total_weight;
    r.shares_used  = shares_seen;

    if (total_weight <= 0.0 || by_key.empty()) {
        use_fallback();
        return r;
    }

    // Proportional split with dust handling.
    std::vector<Payout> tentative;
    uint64_t allocated = 0;
    for (auto& [key, e] : by_key) {
        double frac = e.weight / total_weight;
        uint64_t amt = static_cast<uint64_t>(frac * static_cast<double>(miner_value));
        if (amt < dust_threshold) continue;
        tentative.push_back({
            dash::pubkey_hash_to_script2(e.pubkey_hash),
            amt
        });
        allocated += amt;
    }

    if (tentative.empty()) {
        use_fallback();
        return r;
    }

    // Dust-drop residue + rounding → largest payout gets the difference.
    if (miner_value > allocated) {
        uint64_t residue = miner_value - allocated;
        auto it = std::max_element(tentative.begin(), tentative.end(),
            [](const Payout& a, const Payout& b) { return a.amount < b.amount; });
        it->amount += residue;
    }

    // Deterministic coinbase output order: sort by script bytes.
    std::sort(tentative.begin(), tentative.end(),
        [](const Payout& a, const Payout& b) { return a.script < b.script; });

    r.payouts = std::move(tentative);
    return r;
}

} // namespace pplns
} // namespace dash
