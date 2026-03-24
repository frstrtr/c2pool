#pragma once
/**
 * Skip list — C++ implementation of p2pool's skiplist.py.
 *
 * Provides O(log n) ancestor lookups via geometric jump distances.
 * Each position has (skip_length, [(target, delta), ...]) cached entries.
 * forget_item(hash) clears only that hash's entry — O(1).
 *
 * Used by:
 *   DistanceSkipList → get_nth_parent_hash() in O(log n)
 *   WeightsSkipList  → PPLNS cumulative weights in O(log n) (future)
 */

#include <unordered_map>
#include <vector>
#include <cmath>
#include <random>
#include <functional>
#include <cassert>

namespace chain {

/// Geometric random: p2pool math.geometric(p)
/// Returns integer >= 1 with P(k) = (1-p)^(k-1) * p
inline int geometric_random(double p = 0.5) {
    static thread_local std::mt19937 gen(std::random_device{}());
    // p2pool: int(log1p(-random()) / log1p(-p)) + 1
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double r = dist(gen);
    if (r == 0.0) r = 1e-18;  // avoid log(0)
    return static_cast<int>(std::log1p(-r) / std::log1p(-p)) + 1;
}

/**
 * DistanceSkipList — O(log n) get_nth_parent_hash.
 *
 * Direct translation of p2pool forest.py DistanceSkipList.
 *
 * Delta = (from_hash, distance, to_hash)
 * combine: (h1, d1, h2) + (h2, d2, h3) = (h1, d1+d2, h3)
 * judge: dist > n → overshoot(1), dist == n → exact(0), dist < n → undershoot(-1)
 */
template <typename HashType, typename HasherType>
class DistanceSkipList
{
    using hash_t = HashType;
    using hasher_t = HasherType;

    struct Delta {
        hash_t from;
        int32_t dist;
        hash_t to;
    };

    struct SkipNode {
        int skip_length;
        std::vector<std::pair<hash_t, Delta>> jumps;  // [(target_hash, delta)]
    };

    std::unordered_map<hash_t, SkipNode, hasher_t> m_skips;
    double m_p{0.5};

    // Callbacks
    std::function<hash_t(const hash_t&)> m_previous_fn;
    std::function<bool(const hash_t&)> m_contains_fn;

    Delta get_delta(const hash_t& element) {
        return {element, 1, m_previous_fn(element)};
    }

    Delta combine_deltas(const Delta& d1, const Delta& d2) {
        // d1.to == d2.from (chain concatenation)
        return {d1.from, d1.dist + d2.dist, d2.to};
    }

public:
    DistanceSkipList() = default;

    void init(
        std::function<hash_t(const hash_t&)> previous_fn,
        std::function<bool(const hash_t&)> contains_fn)
    {
        m_previous_fn = std::move(previous_fn);
        m_contains_fn = std::move(contains_fn);
    }

    /// p2pool: forget_item — O(1)
    void forget_item(const hash_t& hash) {
        m_skips.erase(hash);
    }

    void clear() { m_skips.clear(); }

    /**
     * Get the hash of the nth parent.
     * Matches p2pool: tracker.get_nth_parent_hash(hash, n)
     * O(log n) via skip list acceleration.
     *
     * Translation of skiplist.py __call__ with DistanceSkipList's
     * initial_solution, apply_delta, judge, finalize.
     */
    hash_t get_nth_parent(const hash_t& start, int32_t n)
    {
        if (n == 0) return start;
        if (!m_previous_fn || !m_contains_fn) return hash_t();

        // initial_solution: (dist=0, hash=start)
        int32_t sol_dist = 0;
        hash_t sol_hash = start;

        // Updates for building skip entries as we walk
        // updates[i] = (hash, delta_or_null)
        std::unordered_map<int, std::pair<hash_t, Delta>> updates;

        hash_t pos = start;

        while (true) {
            if (!m_contains_fn(pos)) break;

            // Lazily build skip entry at pos
            if (m_skips.find(pos) == m_skips.end()) {
                auto prev = m_previous_fn(pos);
                SkipNode node;
                node.skip_length = geometric_random(m_p);
                node.jumps.push_back({prev, get_delta(pos)});
                m_skips[pos] = std::move(node);
            }

            auto& node = m_skips[pos];

            // Fill previous updates into this node's jumps
            for (int i = 0; i < node.skip_length; ++i) {
                auto uit = updates.find(i);
                if (uit != updates.end()) {
                    auto& [that_hash, delta] = uit->second;
                    auto& target_node = m_skips[that_hash];
                    // Append jump: from that_hash, skip over 'i' shares to reach pos
                    if (static_cast<int>(target_node.jumps.size()) == i) {
                        target_node.jumps.push_back({pos, delta});
                    }
                    updates.erase(uit);
                }
            }

            // Put desired skip nodes in updates
            for (int i = static_cast<int>(node.jumps.size()); i < node.skip_length; ++i) {
                updates[i] = {pos, Delta{}};
            }

            // Try jumps from largest to smallest
            bool jumped = false;
            Delta used_delta{};
            for (int j = static_cast<int>(node.jumps.size()) - 1; j >= 0; --j) {
                auto& [jump_target, delta] = node.jumps[j];
                int32_t new_dist = sol_dist + delta.dist;
                hash_t new_hash = delta.to;

                if (new_dist > n) {
                    continue;  // overshoot
                } else if (new_dist == n) {
                    return new_hash;  // exact match
                } else {
                    // undershoot — take this jump
                    sol_dist = new_dist;
                    sol_hash = new_hash;
                    used_delta = delta;
                    pos = jump_target;
                    jumped = true;
                    break;
                }
            }

            if (!jumped) {
                // All jumps overshoot — should not happen with geometric(0.5)
                // Fall back to single step
                auto prev = m_previous_fn(pos);
                sol_dist += 1;
                sol_hash = prev;
                if (sol_dist == n) return sol_hash;
                pos = prev;
                used_delta = get_delta(pos);
            }

            // Update pending entries with the delta we just used
            for (auto& [idx, entry] : updates) {
                auto& [uhash, udelta] = entry;
                if (udelta.dist == 0 && udelta.from.IsNull()) {
                    udelta = used_delta;
                } else {
                    udelta = combine_deltas(udelta, used_delta);
                }
            }
        }

        return sol_hash;
    }
};

} // namespace chain
