// weights_skiplist.hpp — O(log n) PPLNS weight computation via probabilistic skip list
//
// Port of p2pool/util/skiplist.py + p2pool/data.py WeightsSkipList.
//
// The skip list caches aggregated weight deltas at geometric power-of-2
// distances along the share chain.  Queries walk from highest level down,
// halving remaining distance each step → O(log n) amortized.
//
// Nodes are built iteratively (tail→head) to avoid deep recursion.
//
// Usage:
//   Construct with get_delta(hash) and previous(hash) lambdas.
//   Call query(start, max_shares, desired_weight) for PPLNS computation.
//   Call forget(hash) when a share is removed from the chain.
//   Call clear() when the underlying chain is structurally modified.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <random>
#include <unordered_map>
#include <vector>

#include <core/uint256.hpp>

namespace chain {

// Simple hasher for uint256 keys in unordered containers
struct Uint256Hasher
{
    size_t operator()(const uint256& h) const { return h.GetLow64(); }
};

// ============================================================================
// WeightsDelta — the "delta" type accumulated by the skip list.
// Matches Python: (share_count, {addr: weight}, total_weight, donation_weight)
// ============================================================================

struct WeightsDelta
{
    int32_t share_count{0};
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

inline WeightsDelta combine_deltas(const WeightsDelta& a, const WeightsDelta& b)
{
    WeightsDelta result;
    result.share_count = a.share_count + b.share_count;
    result.total_weight = a.total_weight + b.total_weight;
    result.total_donation_weight = a.total_donation_weight + b.total_donation_weight;
    result.weights = a.weights;
    for (const auto& [key, val] : b.weights)
        result.weights[key] += val;
    return result;
}

// ============================================================================
// CumulativeWeightsResult — query output
// ============================================================================

struct CumulativeWeightsResult
{
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

// ============================================================================
// WeightsSkipList — O(log n) PPLNS weight accumulator
//
// get_delta_fn: (share_hash) → WeightsDelta for that single share
//               Must return {share_count=0, ...} for non-existent hashes.
// previous_fn:  (share_hash) → prev_share_hash (null if at chain end)
// ============================================================================

class WeightsSkipList
{
public:
    using get_delta_fn = std::function<WeightsDelta(const uint256&)>;
    using previous_fn  = std::function<uint256(const uint256&)>;

    WeightsSkipList() = default;

    WeightsSkipList(get_delta_fn get_delta, previous_fn previous)
        : m_get_delta(std::move(get_delta))
        , m_previous(std::move(previous))
        , m_rng(std::random_device{}())
    {}

    void forget(const uint256& hash) { m_nodes.erase(hash); }
    void clear()                     { m_nodes.clear(); }

    // Main query: accumulate weights from `start` backward, stopping at
    // `max_shares` or when `desired_weight` is reached.
    // Proportional partial share at the boundary for exact weight cutoff.
    CumulativeWeightsResult query(const uint256& start,
                                  int32_t max_shares,
                                  const uint288& desired_weight)
    {
        if (start.IsNull() || !m_get_delta)
            return {};

        // Phase 1: ensure all nodes along the walk path are cached.
        // Walk tail-ward, collect uncached hashes, then build bottom-up
        // so build_node never recurses.
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

        // Phase 2: walk cached skip levels
        uint256 pos = start;
        int32_t sol_count = 0;
        std::vector<std::map<std::vector<unsigned char>, uint288>> weight_parts;
        uint288 sol_total;
        uint288 sol_donation;

        for (int32_t safety = 0; safety < max_shares + 32; ++safety)
        {
            if (pos.IsNull())
                break;

            auto it = m_nodes.find(pos);
            if (it == m_nodes.end())
                break;
            auto& node = it->second;

            bool jumped = false;
            // Walk levels in reverse (largest jump first)
            for (int i = static_cast<int>(node.levels.size()) - 1; i >= 0; --i)
            {
                auto& level = node.levels[i];
                auto& d = level.delta;
                if (d.share_count == 0)
                    continue;

                int32_t new_count = sol_count + d.share_count;
                uint288 new_total = sol_total + d.total_weight;

                // Overshoot?
                if (new_count > max_shares || new_total > desired_weight)
                {
                    // Proportional partial only for single-share weight overshoot
                    if (d.share_count == 1 && new_total > desired_weight)
                    {
                        auto remaining = desired_weight - sol_total;
                        if (!d.total_weight.IsNull() && !d.weights.empty())
                        {
                            std::map<std::vector<unsigned char>, uint288> partial;
                            for (const auto& [key, w] : d.weights)
                                partial[key] = remaining / 65535 * w / (d.total_weight / 65535);
                            weight_parts.push_back(std::move(partial));
                            sol_donation += remaining / 65535 * d.total_donation_weight
                                           / (d.total_weight / 65535);
                        }
                        sol_total = desired_weight;
                        return finalize(weight_parts, sol_total, sol_donation);
                    }
                    continue; // Try smaller level
                }

                // Exact hit?
                if (new_count == max_shares || new_total == desired_weight)
                {
                    weight_parts.push_back(d.weights);
                    sol_total = new_total;
                    sol_donation += d.total_donation_weight;
                    return finalize(weight_parts, sol_total, sol_donation);
                }

                // Undershoot — take this jump
                weight_parts.push_back(d.weights);
                sol_count = new_count;
                sol_total = new_total;
                sol_donation += d.total_donation_weight;
                pos = level.target;
                jumped = true;
                break;
            }

            if (!jumped)
                break;
        }

        return finalize(weight_parts, sol_total, sol_donation);
    }

private:
    struct SkipNode
    {
        int32_t skip_length{0};
        struct Level
        {
            uint256 target;
            WeightsDelta delta;
        };
        std::vector<Level> levels;
    };

    // Build a single node — non-recursive.  Predecessors must already be in
    // m_nodes for higher levels to be constructed.
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

            auto combined = combine_deltas(
                node.levels[i - 1].delta,
                pit->second.levels[i - 1].delta);
            node.levels.push_back({pit->second.levels[i - 1].target, std::move(combined)});
        }
    }

    static CumulativeWeightsResult finalize(
        const std::vector<std::map<std::vector<unsigned char>, uint288>>& parts,
        const uint288& total, const uint288& donation)
    {
        std::map<std::vector<unsigned char>, uint288> merged;
        for (const auto& part : parts)
            for (const auto& [key, val] : part)
                merged[key] += val;
        return {std::move(merged), total, donation};
    }

    get_delta_fn m_get_delta;
    previous_fn  m_previous;
    std::mt19937 m_rng;
    std::unordered_map<uint256, SkipNode, Uint256Hasher> m_nodes;
};

} // namespace chain
