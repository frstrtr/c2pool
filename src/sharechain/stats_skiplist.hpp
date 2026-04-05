// stats_skiplist.hpp — O(log n) sharechain statistics via probabilistic skip list
//
// Same pattern as weights_skiplist.hpp but aggregates dashboard stats
// (version counts, miner distribution, difficulty) instead of PPLNS weights.
//
// The skip list caches aggregated StatsDelta at geometric power-of-2
// distances along the share chain. Queries walk from highest level down,
// halving remaining distance each step → O(log n) amortized.
//
// Timeline bucketing (time-dependent) is NOT included — bucket boundaries
// shift with "now" and can't be pre-aggregated. The caller does a short
// walk for recent shares only (last hour ≈ few hundred shares).

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include <core/uint256.hpp>

namespace chain {

// ============================================================================
// StatsDelta — the "delta" type accumulated by the skip list.
// One per share: version, miner, difficulty, count.
// ============================================================================

struct StatsDelta
{
    int32_t share_count{0};
    double difficulty_sum{0.0};
    std::map<std::string, int32_t> version_counts;           // format version: "35" → N, "36" → M
    std::map<std::string, int32_t> desired_version_counts;   // desired version: "35" → N, "36" → M
    std::map<std::string, int32_t> miner_counts;             // miner_hex → count
};

inline StatsDelta combine_stats_deltas(const StatsDelta& a, const StatsDelta& b)
{
    StatsDelta r;
    r.share_count = a.share_count + b.share_count;
    r.difficulty_sum = a.difficulty_sum + b.difficulty_sum;
    r.version_counts = a.version_counts;
    for (const auto& [k, v] : b.version_counts) r.version_counts[k] += v;
    r.desired_version_counts = a.desired_version_counts;
    for (const auto& [k, v] : b.desired_version_counts) r.desired_version_counts[k] += v;
    r.miner_counts = a.miner_counts;
    for (const auto& [k, v] : b.miner_counts) r.miner_counts[k] += v;
    return r;
}

// ============================================================================
// StatsResult — query output
// ============================================================================

struct StatsResult
{
    int32_t share_count{0};
    double difficulty_sum{0.0};
    std::map<std::string, int32_t> version_counts;
    std::map<std::string, int32_t> desired_version_counts;
    std::map<std::string, int32_t> miner_counts;
};

// ============================================================================
// StatsSkipList — O(log n) dashboard statistics accumulator
//
// get_delta_fn: (share_hash) → StatsDelta for that single share
// previous_fn:  (share_hash) → prev_share_hash (null if at chain end)
// ============================================================================

struct Uint256StatsHasher
{
    size_t operator()(const uint256& h) const { return h.GetLow64(); }
};

class StatsSkipList
{
public:
    using get_delta_fn = std::function<StatsDelta(const uint256&)>;
    using previous_fn  = std::function<uint256(const uint256&)>;

    StatsSkipList() = default;

    StatsSkipList(get_delta_fn get_delta, previous_fn previous)
        : m_get_delta(std::move(get_delta))
        , m_previous(std::move(previous))
        , m_rng(std::random_device{}())
    {}

    void forget(const uint256& hash) { m_nodes.erase(hash); }
    void clear()                     { m_nodes.clear(); }

    /// Accumulate stats over `max_shares` shares backward from `start`.
    StatsResult query(const uint256& start, int32_t max_shares)
    {
        if (start.IsNull() || !m_get_delta || max_shares <= 0)
            return {};

        // Phase 1: ensure nodes are cached (build tail→head)
        {
            std::vector<uint256> uncached;
            uint256 pos = start;
            for (int32_t i = 0; i < max_shares && !pos.IsNull(); ++i)
            {
                if (m_nodes.contains(pos))
                    break;
                uncached.push_back(pos);
                pos = m_previous(pos);
            }
            for (auto it = uncached.rbegin(); it != uncached.rend(); ++it)
                build_node(*it);
        }

        // Phase 2: walk cached skip levels (largest jumps first)
        uint256 pos = start;
        int32_t sol_count = 0;
        double sol_diff = 0.0;
        std::map<std::string, int32_t> sol_versions;
        std::map<std::string, int32_t> sol_desired;
        std::map<std::string, int32_t> sol_miners;

        for (int32_t safety = 0; safety < max_shares + 32; ++safety)
        {
            if (pos.IsNull() || sol_count >= max_shares)
                break;

            auto it = m_nodes.find(pos);
            if (it == m_nodes.end())
                break;
            auto& node = it->second;

            bool jumped = false;
            for (int i = static_cast<int>(node.levels.size()) - 1; i >= 0; --i)
            {
                auto& d = node.levels[i].delta;
                if (d.share_count == 0)
                    continue;

                int32_t new_count = sol_count + d.share_count;
                if (new_count > max_shares)
                    continue;  // overshoot — try smaller level

                // Take this jump
                sol_count = new_count;
                sol_diff += d.difficulty_sum;
                for (const auto& [k, v] : d.version_counts) sol_versions[k] += v;
                for (const auto& [k, v] : d.desired_version_counts) sol_desired[k] += v;
                for (const auto& [k, v] : d.miner_counts) sol_miners[k] += v;
                pos = node.levels[i].target;
                jumped = true;
                break;
            }

            if (!jumped)
                break;
        }

        return {sol_count, sol_diff, std::move(sol_versions), std::move(sol_desired), std::move(sol_miners)};
    }

private:
    struct SkipNode
    {
        int32_t skip_length{0};
        struct Level
        {
            uint256 target;
            StatsDelta delta;
        };
        std::vector<Level> levels;
    };

    void build_node(const uint256& hash)
    {
        if (m_nodes.contains(hash))
            return;

        auto& node = m_nodes[hash];

        // Geometric random skip height: P(height >= k) = 0.5^k, max 30
        node.skip_length = 1;
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        while (dist(m_rng) < 0.5 && node.skip_length < 30)
            node.skip_length++;

        // Level 0: single share delta
        auto prev = m_previous(hash);
        auto delta = m_get_delta(hash);
        node.levels.push_back({prev, std::move(delta)});

        // Build higher levels by combining with predecessor's cached levels
        for (int i = 1; i < node.skip_length; ++i)
        {
            auto& prev_target = node.levels[i - 1].target;
            if (prev_target.IsNull())
                break;

            auto pit = m_nodes.find(prev_target);
            if (pit == m_nodes.end() || static_cast<int>(pit->second.levels.size()) < i)
                break;

            auto combined = combine_stats_deltas(
                node.levels[i - 1].delta,
                pit->second.levels[i - 1].delta);
            node.levels.push_back({pit->second.levels[i - 1].target, std::move(combined)});
        }
    }

    get_delta_fn m_get_delta;
    previous_fn  m_previous;
    std::mt19937 m_rng;
    std::unordered_map<uint256, SkipNode, Uint256StatsHasher> m_nodes;
};

} // namespace chain
