#pragma once

// Redistribute: configurable redistribution policy for shares from miners
// with empty/invalid/broken stratum credentials.
//
// 4 modes:
//   pplns  : distribute by PPLNS weight proportionally (default)
//   fee    : 100% to node operator
//   boost  : give to active stratum miners with ZERO PPLNS shares,
//            falls back to PPLNS if no zero-share miners connected
//   donate : 100% to donation script
//
// Consensus-safe: only affects pubkey_hash stamped into shares on this node.
//
// Port of p2pool-v36 work.py --redistribute flag (commit de76224a).

#include "config_pool.hpp"
#include "share_tracker.hpp"
#include "share_check.hpp"

#include <core/log.hpp>
#include <core/target_utils.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <random>
#include <string>
#include <vector>

namespace ltc
{

enum class RedistributeMode
{
    PPLNS,   // distribute by PPLNS weight proportionally (default)
    FEE,     // 100% to node operator
    BOOST,   // give to active miners with ZERO PPLNS shares
    DONATE   // 100% to donation script
};

inline RedistributeMode parse_redistribute_mode(const std::string& s)
{
    if (s == "fee")    return RedistributeMode::FEE;
    if (s == "boost")  return RedistributeMode::BOOST;
    if (s == "donate") return RedistributeMode::DONATE;
    return RedistributeMode::PPLNS;
}

inline const char* redistribute_mode_str(RedistributeMode m)
{
    switch (m)
    {
    case RedistributeMode::FEE:    return "fee";
    case RedistributeMode::BOOST:  return "boost";
    case RedistributeMode::DONATE: return "donate";
    default:                       return "pplns";
    }
}

struct RedistributeResult
{
    uint160 pubkey_hash;
    uint8_t pubkey_type = 0; // 0=P2PKH, 1=P2WPKH, 2=P2SH
};

class Redistributor
{
public:
    Redistributor() = default;

    void set_mode(RedistributeMode mode) { mode_ = mode; }
    RedistributeMode mode() const { return mode_; }

    // Set the node operator's payout identity (for "fee" mode)
    void set_operator_identity(const uint160& hash, uint8_t type)
    {
        operator_hash_ = hash;
        operator_type_ = type;
    }

    // Set the donation script identity (for "donate" mode)
    void set_donation_identity(const uint160& hash, uint8_t type)
    {
        donation_hash_ = hash;
        donation_type_ = type;
    }

    // Pick a (pubkey_hash, pubkey_type) for shares from unnamed/broken miners.
    RedistributeResult pick(ShareTracker& tracker, const uint256& best_share_hash)
    {
        // MODE: fee — 100% to node operator
        if (mode_ == RedistributeMode::FEE)
            return {operator_hash_, operator_type_};

        // MODE: donate — 100% to donation script
        if (mode_ == RedistributeMode::DONATE)
            return {donation_hash_, donation_type_};

        // MODE: boost — give to connected miners with zero PPLNS weight
        if (mode_ == RedistributeMode::BOOST)
        {
            auto zero_miners = get_zero_pplns_miners(tracker, best_share_hash);
            if (!zero_miners.empty())
            {
                std::uniform_int_distribution<size_t> dist(0, zero_miners.size() - 1);
                return zero_miners[dist(rng_)];
            }
            // fallthrough to PPLNS
        }

        // MODE: pplns (default + fallback)
        return pick_pplns(tracker, best_share_hash);
    }

    // Register a callback that returns connected miner identities.
    // Used by "boost" mode to find miners with zero PPLNS weight.
    using connected_miners_fn = std::function<std::vector<RedistributeResult>()>;
    void set_connected_miners_fn(connected_miners_fn fn) { connected_miners_fn_ = std::move(fn); }

private:
    RedistributeMode mode_ = RedistributeMode::PPLNS;
    uint160 operator_hash_;
    uint8_t operator_type_ = 0;
    uint160 donation_hash_;
    uint8_t donation_type_ = 2; // P2SH for combined donation
    std::mt19937 rng_{std::random_device{}()};

    // PPLNS cache
    struct PplnsEntry { std::vector<unsigned char> script; uint160 hash; uint8_t type; uint64_t weight; };
    std::vector<PplnsEntry> pplns_cache_;
    int64_t pplns_cache_ts_ = 0;

    // Zero-PPLNS cache
    std::vector<RedistributeResult> zero_cache_;
    int64_t zero_cache_ts_ = 0;

    connected_miners_fn connected_miners_fn_;

    RedistributeResult pick_pplns(ShareTracker& tracker, const uint256& best)
    {
        refresh_pplns_cache(tracker, best);

        if (pplns_cache_.empty())
            return {operator_hash_, operator_type_};

        uint64_t total = 0;
        for (auto& e : pplns_cache_) total += e.weight;
        if (total == 0)
            return {operator_hash_, operator_type_};

        std::uniform_int_distribution<uint64_t> dist(0, total - 1);
        uint64_t r = dist(rng_);
        uint64_t cumulative = 0;
        for (auto& e : pplns_cache_)
        {
            cumulative += e.weight;
            if (r < cumulative)
                return {e.hash, e.type};
        }
        return {pplns_cache_.back().hash, pplns_cache_.back().type};
    }

    void refresh_pplns_cache(ShareTracker& tracker, const uint256& best)
    {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now - pplns_cache_ts_ < 30 && !pplns_cache_.empty())
            return;

        pplns_cache_.clear();
        pplns_cache_ts_ = now;

        if (best.IsNull())
            return;

        auto [height, last] = tracker.chain.get_height_and_last(best);
        int32_t depth = std::min(height, static_cast<int32_t>(tracker.m_params->real_chain_length));
        if (depth < 1)
            return;

        // Walk the chain and accumulate per-script work
        struct AccumEntry { std::vector<unsigned char> script; uint160 hash; uint8_t type; uint64_t weight; };
        std::map<std::vector<unsigned char>, AccumEntry> addr_work;
        auto chain_view = tracker.chain.get_chain(best, depth);
        for (auto& [hash, data] : chain_view)
        {
            std::vector<unsigned char> script;
            uint160 pk_hash;
            uint8_t pk_type = 0;
            uint64_t work = 0;
            data.share.invoke([&](auto* obj) {
                script = get_share_script(obj);
                auto target = chain::bits_to_target(obj->m_bits);
                auto att = chain::target_to_average_attempts(target);
                work = att.GetLow64();
                // Extract pubkey_hash from script
                if constexpr (requires { obj->m_pubkey_type; }) {
                    pk_hash = obj->m_pubkey_hash;
                    pk_type = obj->m_pubkey_type;
                } else if constexpr (requires { obj->m_pubkey_hash; }) {
                    pk_hash = obj->m_pubkey_hash;
                    pk_type = 0;
                } else {
                    // V34/V35: extract from script
                    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9)
                        std::memcpy(pk_hash.data(), script.data() + 3, 20);
                    else if (script.size() >= 22 && script[0] == 0x00 && script[1] == 0x14)
                        std::memcpy(pk_hash.data(), script.data() + 2, 20);
                    else if (script.size() >= 20)
                        std::memcpy(pk_hash.data(), script.data(), 20);
                }
            });
            auto& entry = addr_work[script];
            entry.script = script;
            entry.hash = pk_hash;
            entry.type = pk_type;
            entry.weight += work;
        }

        pplns_cache_.reserve(addr_work.size());
        for (auto& [_, e] : addr_work)
            pplns_cache_.push_back({e.script, e.hash, e.type, e.weight});
    }

    std::vector<RedistributeResult> get_zero_pplns_miners(
        ShareTracker& tracker, const uint256& best)
    {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now - zero_cache_ts_ < 30)
            return zero_cache_;

        zero_cache_.clear();
        zero_cache_ts_ = now;

        if (!connected_miners_fn_)
            return zero_cache_;

        // Get connected miners
        auto connected = connected_miners_fn_();
        if (connected.empty())
            return zero_cache_;

        // Refresh PPLNS cache
        refresh_pplns_cache(tracker, best);

        // Build set of PPLNS addresses
        std::set<uint160> pplns_addrs;
        for (auto& e : pplns_cache_)
            pplns_addrs.insert(e.hash);

        // Find connected miners not in PPLNS
        for (auto& m : connected)
        {
            if (pplns_addrs.find(m.pubkey_hash) == pplns_addrs.end())
                zero_cache_.push_back(m);
        }

        return zero_cache_;
    }
};

} // namespace ltc
