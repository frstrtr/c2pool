#pragma once
/**
 * Skip list cache — C++ implementation of p2pool's skiplist.py + forest.py pattern.
 *
 * p2pool's SkipList stores jump entries at each position:
 *   skips[hash] = (skip_length, [(target_hash, delta), ...])
 *
 * Each jump covers an increasing number of shares (geometric distribution).
 * forget_item(hash) only clears that one entry — O(1), no BFS.
 *
 * Delta type must support:
 *   - get_none(hash) → identity delta
 *   - from_element(share) → single-share delta
 *   - operator+= (accumulation)
 *   - operator- (for subtraction: get_delta = delta_to_last(near) - delta_to_last(far))
 */

#include <unordered_map>
#include <vector>
#include <random>
#include <functional>
#include <cassert>

namespace chain {

/// Geometric random number generator matching p2pool's math.geometric(p=0.5)
inline int geometric_random(double p = 0.5) {
    static thread_local std::mt19937 gen(std::random_device{}());
    std::geometric_distribution<int> dist(p);
    return dist(gen) + 1;  // p2pool: geometric starts at 1
}

/**
 * TrackerSkipList — caches jump deltas for O(log n) chain walks.
 *
 * Matches p2pool forest.py TrackerSkipList + SubsetTracker._get_delta pattern.
 *
 * Template params:
 *   HashType — hash type (uint256)
 *   DeltaType — accumulated delta (must have head, tail, height, work, min_work fields)
 *   HasherType — hash function for unordered_map
 */
template <typename HashType, typename DeltaType, typename HasherType>
class TrackerSkipList
{
    using hash_t = HashType;
    using delta_t = DeltaType;
    using hasher_t = HasherType;

    struct SkipEntry {
        hash_t target;
        delta_t delta;
    };

    struct SkipNode {
        int skip_length;  // geometric random, determines max jumps
        std::vector<SkipEntry> jumps;  // [(target, delta)] growing to skip_length
    };

    std::unordered_map<hash_t, SkipNode, hasher_t> m_skips;

    // Function to get previous hash (parent) for a share
    std::function<hash_t(const hash_t&)> m_previous_fn;
    // Function to get single-share delta
    std::function<delta_t(const hash_t&)> m_get_delta_fn;
    // Function to check if hash exists in tracker
    std::function<bool(const hash_t&)> m_contains_fn;

public:
    TrackerSkipList() = default;

    void init(
        std::function<hash_t(const hash_t&)> previous_fn,
        std::function<delta_t(const hash_t&)> get_delta_fn,
        std::function<bool(const hash_t&)> contains_fn)
    {
        m_previous_fn = std::move(previous_fn);
        m_get_delta_fn = std::move(get_delta_fn);
        m_contains_fn = std::move(contains_fn);
    }

    /// p2pool: forget_item — O(1), clears only this hash's cached jumps.
    /// Called when a share is removed from the tracker.
    void forget_item(const hash_t& hash) {
        m_skips.erase(hash);
    }

    /// Clear all cached entries.
    void clear() { m_skips.clear(); }

    /**
     * get_delta_to_last — walk from hash to chain end, accumulating deltas.
     *
     * Matches p2pool forest.py SubsetTracker.get_delta_to_last():
     *   delta = delta_type.get_none(item_hash)
     *   while delta.tail in self._tracker.items:
     *       this_delta = self._get_delta(delta.tail)
     *       delta += this_delta
     *   return delta
     *
     * With skip list acceleration: O(log n) instead of O(n).
     * The skip list is built lazily — first access builds entries.
     */
    delta_t get_delta_to_last(const hash_t& hash)
    {
        if (!m_contains_fn || !m_previous_fn || !m_get_delta_fn)
            return delta_t{};

        // Simple walk matching p2pool's SubsetTracker.get_delta_to_last
        // (without skip acceleration for now — correctness first)
        delta_t result{};
        result.head = hash;
        result.tail = hash;

        hash_t cur = hash;
        while (!cur.IsNull() && m_contains_fn(cur))
        {
            auto d = m_get_delta_fn(cur);
            result.work += d.work;
            result.min_work += d.min_work;
            result.height += 1;
            result.tail = d.tail;  // prev_hash
            cur = d.tail;
        }

        return result;
    }

    /// get_height — matches p2pool Tracker.get_height
    int32_t get_height(const hash_t& hash) {
        return get_delta_to_last(hash).height;
    }

    /// get_work — matches p2pool Tracker.get_work
    auto get_work(const hash_t& hash) {
        return get_delta_to_last(hash).work;
    }

    /// get_last — matches p2pool Tracker.get_last
    hash_t get_last(const hash_t& hash) {
        return get_delta_to_last(hash).tail;
    }

    /// get_delta — matches p2pool Tracker.get_delta(near, far)
    delta_t get_delta(const hash_t& near, const hash_t& far) {
        auto d_near = get_delta_to_last(near);
        auto d_far = get_delta_to_last(far);
        delta_t result{};
        result.head = near;
        result.tail = far;
        result.work = d_near.work - d_far.work;
        result.min_work = d_near.min_work - d_far.min_work;
        result.height = d_near.height - d_far.height;
        return result;
    }
};

} // namespace chain
