#pragma once

// Redistribute V2: advanced redistribution policy for shares from miners
// with empty/invalid/broken stratum credentials.
//
// V1 modes (4):
//   pplns  : distribute by PPLNS weight proportionally (default)
//   fee    : 100% to node operator
//   boost  : give to active stratum miners with ZERO PPLNS shares
//   donate : 100% to donation script
//
// V2 enhancements:
//   Graduated boost  : weight by uptime × pseudoshares × difficulty
//   Hybrid mode      : --redistribute boost:70,donate:20,fee:10
//   Threshold boost  : boost "unlucky" miners with < 10% expected PPLNS weight
//   Explicit opt-in  : miners signal via stratum password "boost:true"
//
// Consensus-safe: only affects pubkey_hash stamped into shares on this node.
//
// Port of p2pool-v36 work.py --redistribute (commit de76224a) + FUTURE.md V2 spec.

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
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace ltc
{

enum class RedistributeMode
{
    PPLNS,   // distribute by PPLNS weight proportionally (default)
    FEE,     // 100% to node operator
    BOOST,   // give to active miners with zero/low PPLNS shares
    DONATE   // 100% to donation script
};

inline RedistributeMode parse_single_mode(const std::string& s)
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

// --- V2: Hybrid mode weight entry ---
struct HybridWeight
{
    RedistributeMode mode;
    uint32_t weight;
};

// Parse hybrid mode string: "boost:70,donate:20,fee:10" or single "boost"
inline std::vector<HybridWeight> parse_redistribute_spec(const std::string& spec)
{
    std::vector<HybridWeight> result;
    if (spec.empty())
    {
        result.push_back({RedistributeMode::PPLNS, 100});
        return result;
    }

    // Check for hybrid format (contains ':')
    if (spec.find(':') != std::string::npos)
    {
        std::istringstream ss(spec);
        std::string token;
        while (std::getline(ss, token, ','))
        {
            auto colon = token.find(':');
            if (colon != std::string::npos)
            {
                auto mode_str = token.substr(0, colon);
                auto weight_str = token.substr(colon + 1);
                auto mode = parse_single_mode(mode_str);
                uint32_t w = 0;
                try { w = static_cast<uint32_t>(std::stoul(weight_str)); } catch (...) {}
                if (w > 0)
                    result.push_back({mode, w});
            }
        }
    }

    // Single mode fallback
    if (result.empty())
        result.push_back({parse_single_mode(spec), 100});

    return result;
}

// Backward-compatible: returns the primary mode (first/only entry)
inline RedistributeMode parse_redistribute_mode(const std::string& spec)
{
    auto weights = parse_redistribute_spec(spec);
    return weights.empty() ? RedistributeMode::PPLNS : weights[0].mode;
}

// Format hybrid weights for display
inline std::string format_hybrid_weights(const std::vector<HybridWeight>& weights)
{
    if (weights.size() == 1)
        return redistribute_mode_str(weights[0].mode);
    std::ostringstream oss;
    for (size_t i = 0; i < weights.size(); ++i) {
        if (i > 0) oss << ",";
        oss << redistribute_mode_str(weights[i].mode) << ":" << weights[i].weight;
    }
    return oss.str();
}

struct RedistributeResult
{
    uint160 pubkey_hash;
    uint8_t pubkey_type = 0; // 0=P2PKH, 1=P2WPKH, 2=P2SH
};

// --- V2: Graduated boost entry with scoring ---
struct GraduatedMinerInfo
{
    uint160 pubkey_hash;
    uint8_t pubkey_type = 0;
    double  uptime_hours = 0;        // connection duration (capped at 24)
    uint64_t pseudoshares = 0;        // accepted pseudoshare count
    double  difficulty = 0;           // current stratum difficulty
    bool    opt_in_boost = false;     // explicit opt-in via password
};

// --- V2: Stratum password options ---
struct StratumPasswordOpts
{
    bool boost = false;       // boost:true
    double min_diff = 0;      // d=N
};

inline StratumPasswordOpts parse_stratum_password(const std::string& password)
{
    StratumPasswordOpts opts;
    if (password.empty()) return opts;

    std::istringstream ss(password);
    std::string token;
    while (std::getline(ss, token, ','))
    {
        auto eq = token.find(':');
        if (eq == std::string::npos) eq = token.find('=');
        if (eq == std::string::npos) continue;

        auto key = token.substr(0, eq);
        auto val = token.substr(eq + 1);

        if (key == "boost")
            opts.boost = (val == "true" || val == "1" || val == "yes");
        else if (key == "d")
            try { opts.min_diff = std::stod(val); } catch (...) {}
    }
    return opts;
}

class Redistributor
{
public:
    Redistributor() = default;

    // V1: single mode
    void set_mode(RedistributeMode mode)
    {
        hybrid_weights_.clear();
        hybrid_weights_.push_back({mode, 100});
    }
    RedistributeMode mode() const
    {
        return hybrid_weights_.empty() ? RedistributeMode::PPLNS : hybrid_weights_[0].mode;
    }

    // V2: hybrid mode
    void set_hybrid_weights(const std::vector<HybridWeight>& weights)
    {
        hybrid_weights_ = weights;
    }
    const std::vector<HybridWeight>& hybrid_weights() const { return hybrid_weights_; }

    // V2: threshold ratio (default 0.1 = 10% of expected weight)
    void set_threshold_ratio(double ratio) { threshold_ratio_ = ratio; }

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
        if (hybrid_weights_.empty())
            return {operator_hash_, operator_type_};

        // V2: Hybrid mode — roll random, pick mode by weight
        RedistributeMode selected_mode;
        if (hybrid_weights_.size() == 1)
        {
            selected_mode = hybrid_weights_[0].mode;
        }
        else
        {
            uint32_t total_weight = 0;
            for (auto& hw : hybrid_weights_) total_weight += hw.weight;
            std::uniform_int_distribution<uint32_t> dist(0, total_weight - 1);
            uint32_t r = dist(rng_);
            uint32_t cumul = 0;
            selected_mode = hybrid_weights_.back().mode;
            for (auto& hw : hybrid_weights_)
            {
                cumul += hw.weight;
                if (r < cumul) { selected_mode = hw.mode; break; }
            }
        }

        return pick_for_mode(selected_mode, tracker, best_share_hash);
    }

    // Register a callback that returns connected miner stats (V2 graduated).
    using graduated_miners_fn = std::function<std::vector<GraduatedMinerInfo>()>;
    void set_graduated_miners_fn(graduated_miners_fn fn) { graduated_miners_fn_ = std::move(fn); }

    // V1 compat: register simple connected miners callback
    using connected_miners_fn = std::function<std::vector<RedistributeResult>()>;
    void set_connected_miners_fn(connected_miners_fn fn) { connected_miners_fn_ = std::move(fn); }

    // V2: pool hashrate callback (for threshold boost)
    using pool_hashrate_fn = std::function<double()>;
    void set_pool_hashrate_fn(pool_hashrate_fn fn) { pool_hashrate_fn_ = std::move(fn); }

private:
    std::vector<HybridWeight> hybrid_weights_ = {{RedistributeMode::PPLNS, 100}};
    double threshold_ratio_ = 0.1; // 10% of expected weight
    uint160 operator_hash_;
    uint8_t operator_type_ = 0;
    uint160 donation_hash_;
    uint8_t donation_type_ = 2; // P2SH for combined donation
    std::mt19937 rng_{std::random_device{}()};

    // PPLNS cache
    struct PplnsEntry { std::vector<unsigned char> script; uint160 hash; uint8_t type; uint64_t weight; };
    std::vector<PplnsEntry> pplns_cache_;
    int64_t pplns_cache_ts_ = 0;

    graduated_miners_fn graduated_miners_fn_;
    connected_miners_fn connected_miners_fn_;
    pool_hashrate_fn pool_hashrate_fn_;

    RedistributeResult pick_for_mode(RedistributeMode mode, ShareTracker& tracker, const uint256& best)
    {
        switch (mode)
        {
        case RedistributeMode::FEE:
            return {operator_hash_, operator_type_};

        case RedistributeMode::DONATE:
            return {donation_hash_, donation_type_};

        case RedistributeMode::BOOST:
            return pick_boost(tracker, best);

        case RedistributeMode::PPLNS:
        default:
            return pick_pplns(tracker, best);
        }
    }

    // V2: graduated boost with threshold support
    RedistributeResult pick_boost(ShareTracker& tracker, const uint256& best)
    {
        // Try V2 graduated boost first
        if (graduated_miners_fn_)
        {
            auto miners = graduated_miners_fn_();
            refresh_pplns_cache(tracker, best);

            // Build PPLNS address set + weight map
            std::set<uint160> pplns_addrs;
            std::map<uint160, uint64_t> pplns_weight_map;
            uint64_t total_pplns_weight = 0;
            for (auto& e : pplns_cache_)
            {
                pplns_addrs.insert(e.hash);
                pplns_weight_map[e.hash] = e.weight;
                total_pplns_weight += e.weight;
            }

            // Score each miner
            struct ScoredMiner { RedistributeResult result; double score; };
            std::vector<ScoredMiner> candidates;

            for (auto& m : miners)
            {
                bool is_zero_share = (pplns_addrs.find(m.pubkey_hash) == pplns_addrs.end());
                bool is_threshold_eligible = false;

                // V2: threshold boost — check luck ratio
                if (!is_zero_share && total_pplns_weight > 0 && m.difficulty > 0)
                {
                    double actual_weight = static_cast<double>(pplns_weight_map[m.pubkey_hash]);
                    double actual_ratio = actual_weight / static_cast<double>(total_pplns_weight);

                    // Estimate expected ratio from miner's hashrate
                    double pool_hr = pool_hashrate_fn_ ? pool_hashrate_fn_() : 0;
                    if (pool_hr > 0)
                    {
                        double miner_hr = m.pseudoshares * m.difficulty / std::max(m.uptime_hours * 3600.0, 1.0);
                        double expected_ratio = miner_hr / pool_hr;
                        double luck_ratio = (expected_ratio > 0) ? (actual_ratio / expected_ratio) : 1.0;
                        is_threshold_eligible = (luck_ratio < threshold_ratio_);
                    }
                }

                // Eligible: zero-share miners, threshold-eligible miners, or opt-in miners
                if (is_zero_share || is_threshold_eligible || m.opt_in_boost)
                {
                    // V2: graduated score = uptime × pseudoshares × difficulty
                    double uptime_w = std::min(m.uptime_hours, 24.0);
                    double pseudo_w = static_cast<double>(m.pseudoshares + 1);
                    double diff_w = std::max(m.difficulty, 0.001);
                    double score = uptime_w * pseudo_w * diff_w;

                    // Threshold-eligible miners get inverse-luck bonus
                    if (is_threshold_eligible && total_pplns_weight > 0)
                    {
                        double actual = static_cast<double>(pplns_weight_map[m.pubkey_hash]);
                        double ratio = actual / static_cast<double>(total_pplns_weight);
                        score *= 1.0 / std::max(ratio, 0.001); // unluckier = higher score
                    }

                    if (score > 0)
                        candidates.push_back({{m.pubkey_hash, m.pubkey_type}, score});
                }
            }

            if (!candidates.empty())
            {
                // Weighted random selection by score
                double total_score = 0;
                for (auto& c : candidates) total_score += c.score;
                std::uniform_real_distribution<double> dist(0, total_score);
                double r = dist(rng_);
                double cumul = 0;
                for (auto& c : candidates)
                {
                    cumul += c.score;
                    if (r < cumul)
                        return c.result;
                }
                return candidates.back().result;
            }
        }

        // V1 fallback: simple zero-share boost
        if (connected_miners_fn_)
        {
            auto connected = connected_miners_fn_();
            refresh_pplns_cache(tracker, best);
            std::set<uint160> pplns_addrs;
            for (auto& e : pplns_cache_) pplns_addrs.insert(e.hash);

            std::vector<RedistributeResult> zero_miners;
            for (auto& m : connected)
            {
                if (pplns_addrs.find(m.pubkey_hash) == pplns_addrs.end())
                    zero_miners.push_back(m);
            }
            if (!zero_miners.empty())
            {
                std::uniform_int_distribution<size_t> dist(0, zero_miners.size() - 1);
                return zero_miners[dist(rng_)];
            }
        }

        // Final fallback: PPLNS
        return pick_pplns(tracker, best);
    }

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
        int32_t depth = std::min(height, static_cast<int32_t>(PoolConfig::real_chain_length()));
        if (depth < 1)
            return;

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
                if constexpr (requires { obj->m_pubkey_type; }) {
                    pk_hash = obj->m_pubkey_hash;
                    pk_type = obj->m_pubkey_type;
                } else if constexpr (requires { obj->m_pubkey_hash; }) {
                    pk_hash = obj->m_pubkey_hash;
                    pk_type = 0;
                } else {
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
};

} // namespace ltc
