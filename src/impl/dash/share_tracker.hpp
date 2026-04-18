#pragma once

// Dash ShareTracker: wraps ShareChain with verification + PPLNS.
// Uses CoinParams for all coin-specific constants.

#include "share.hpp"
#include "share_chain.hpp"
#include "share_check.hpp"

#include <core/coin_params.hpp>
#include <core/target_utils.hpp>

namespace dash
{

class ShareTracker
{
public:
    ShareChain chain;
    ShareChain verified;
    const core::CoinParams* m_params = nullptr;

    // B1 persistence hook: fires when a share transitions into verified.
    // ltc::NodeImpl sets this from its constructor to append to
    // m_verified_flush_buf which gets flushed to LevelDB in batches.
    std::function<void(const uint256&)> m_on_share_verified;

    ShareTracker() = default;
    explicit ShareTracker(const core::CoinParams* params) : m_params(params) {}

    ~ShareTracker()
    {
        verified.clear_unowned();
    }

    // Add share to chain
    template <typename ShareT>
    void add(ShareT* share)
    {
        if (!chain.contains(share->m_hash))
            chain.add(share);
    }

    void add(ShareType share)
    {
        auto h = share.hash();
        if (!chain.contains(h))
            chain.add(share);
    }

    // Attempt to verify a share (check PoW + PPLNS)
    bool attempt_verify(const uint256& share_hash)
    {
        if (verified.contains(share_hash))
            return true;

        auto [height, last] = chain.get_height_and_last(share_hash);

        if (height < static_cast<int32_t>(m_params->chain_length) + 1 && !last.IsNull())
            return false;

        try
        {
            auto& share_var = chain.get_share(share_hash);
            share_var.ACTION({
                auto computed_hash = share_init_verify(*obj, *m_params);
                (void)computed_hash;
            });
        }
        catch (const std::exception& e)
        {
            return false;
        }

        // Move to verified
        auto& entry = chain.get(share_hash);
        verified.add(entry.share);
        return true;
    }

    // Pool attempts per second (from recent shares)
    uint288 get_pool_attempts_per_second(const uint256& tip, int32_t lookbehind)
    {
        if (tip.IsNull()) return uint288(0);
        auto [height, last] = chain.get_height_and_last(tip);
        int32_t actual_lookbehind = std::min(height, lookbehind);
        if (actual_lookbehind < 2) return uint288(0);

        auto tip_data = chain.get(tip);
        uint32_t tip_ts = 0;
        tip_data.share.invoke([&](auto* obj) { tip_ts = obj->m_timestamp; });

        auto ancestor_hash = chain.get_nth_parent_key(tip, actual_lookbehind);
        auto ancestor_data = chain.get(ancestor_hash);
        uint32_t ancestor_ts = 0;
        ancestor_data.share.invoke([&](auto* obj) { ancestor_ts = obj->m_timestamp; });

        if (tip_ts <= ancestor_ts) return uint288(0);
        uint32_t dt = tip_ts - ancestor_ts;

        // Sum work in window
        uint288 total_work;
        auto walk = chain.get_chain(tip, actual_lookbehind);
        for (auto&& [h, data] : walk)
        {
            data.share.invoke([&](auto* obj) {
                total_work += chain::target_to_average_attempts(chain::bits_to_target(obj->m_bits));
            });
        }

        if (dt == 0) return uint288(0);
        return total_work / dt;
    }
};

} // namespace dash
