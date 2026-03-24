#pragma once
/**
 * p2pool DistanceSkipList — O(log n) amortized ancestor lookups.
 *
 * Direct translation of p2pool util/skiplist.py + util/forest.py DistanceSkipList.
 * Uses relative distance jumps (no absolute heights) and geometric random
 * skip distances. Builds skip pointers lazily during traversal.
 *
 * p2pool source: util/skiplist.py (SkipList base), util/forest.py:21-48 (DistanceSkipList)
 *
 * Key differences from Bitcoin Core skip list:
 *   - No stored heights (safe after pruning)
 *   - Relative distances, not absolute positions
 *   - Lazy skip pointer construction (built during traversal)
 *   - Geometric random skip_length per node (geometric(0.5))
 *   - O(log n) amortized, O(n) worst-case for first query
 */

#include <cstdint>
#include <functional>
#include <random>
#include <unordered_map>
#include <vector>

namespace chain {

/**
 * DistanceSkipList — p2pool's skip list for O(log n) get_nth_parent.
 *
 * Delta = (from_hash, distance, to_hash) — a relative jump.
 * combine_deltas: (h1,d1,h2) + (h2,d2,h3) = (h1, d1+d2, h3)
 *
 * Each node gets a random skip_length ~ geometric(0.5).
 * Level 0 = direct parent (always present).
 * Higher levels built lazily during traversal.
 *
 * p2pool ref: util/forest.py:21-48, util/skiplist.py:3-59
 */
template <typename HashType, typename HasherType>
class DistanceSkipList
{
    using hash_t = HashType;
    using hasher_t = HasherType;

    /// Delta = (from_hash, distance, to_hash)
    /// p2pool: DistanceSkipList.get_delta returns (element, 1, previous(element))
    /// p2pool: combine_deltas((h1,d1,h2), (h2,d2,h3)) = (h1, d1+d2, h3)
    struct Delta {
        hash_t from_hash;
        int32_t distance;
        hash_t to_hash;
    };

    /// Per-node skip data.
    /// p2pool: self.skips[pos] = (skip_length, [(jump_target, delta), ...])
    /// jump_target == delta.to_hash always (proven by induction on the lazy build).
    struct SkipEntry {
        int skip_length;                  // geometric(0.5): how many levels this node will have
        std::vector<Delta> levels;        // levels[0] = parent, levels[i] = 2^i-ish ancestor
    };

    /// Skip data per node. Mutable because skip pointers are built lazily
    /// during read operations (the skip list is a cache, not source data).
    /// p2pool: self.skips = {}
    mutable std::unordered_map<hash_t, SkipEntry, hasher_t> m_skips;

    /// Callback: get previous element hash.
    /// p2pool: TrackerSkipList.previous(element) → tracker.items[element].previous_hash
    std::function<hash_t(const hash_t&)> m_previous_fn;

    /// Geometric distribution with p=0.5.
    /// p2pool: math.geometric(0.5) → 0, 1, 2, ... with Pr(k) = (1-p)^k * p
    static int geometric_random() {
        static thread_local std::mt19937 rng(std::random_device{}());
        static thread_local std::geometric_distribution<int> dist(0.5);
        return dist(rng);
    }

public:
    DistanceSkipList() = default;

    void init(std::function<hash_t(const hash_t&)> previous_fn) {
        m_previous_fn = std::move(previous_fn);
    }

    /// forget_item — O(1), removes skip data for a hash.
    /// Called via removed signal when a share is pruned.
    /// p2pool: TrackerSkipList.__init__ watches tracker.removed → forget_item
    void forget_item(const hash_t& hash) {
        m_skips.erase(hash);
    }

    /**
     * Get the nth ancestor of start.
     * Matches p2pool: tracker.get_nth_parent_hash(start, n)
     *
     * Translation of util/skiplist.py SkipList.__call__(start, n) with
     * DistanceSkipList's get_delta/combine_deltas/initial_solution/apply_delta/judge/finalize.
     *
     * On first traversal, builds skip pointers lazily → O(n).
     * Subsequent queries through same region → O(log n) amortized.
     */
    hash_t get_nth_parent(const hash_t& start, int32_t n) const
    {
        if (n <= 0) return start;

        // p2pool: sol = self.initial_solution(start, (n,)) = (0, start)
        int32_t sol_dist = 0;
        hash_t sol_hash = start;

        // p2pool: if self.judge(sol, args) == 0: return self.finalize(sol, args)
        // (sol_dist == n already? Only if n==0, handled above)

        // p2pool: updates = {} — tracks nodes needing higher-level skip pointers
        // updates[level] = (node_hash, delta_or_null)
        struct UpdateEntry {
            hash_t node_hash;
            bool has_delta;
            Delta delta;
        };
        std::unordered_map<int, UpdateEntry> updates;

        hash_t pos = start;

        // Safety: max iterations = 2*n (each iteration makes progress of ≥1)
        for (int32_t safety = 0; safety < 2 * n + 100; ++safety) {
            if (pos.IsNull()) return hash_t();  // chain too short

            // p2pool: if pos not in self.skips:
            //   self.skips[pos] = math.geometric(self.p), [(self.previous(pos), self.get_delta(pos))]
            auto it = m_skips.find(pos);
            if (it == m_skips.end()) {
                hash_t prev = m_previous_fn(pos);
                SkipEntry entry;
                entry.skip_length = geometric_random();
                entry.levels.push_back(Delta{pos, 1, prev});  // level 0: single step to parent
                auto [ins_it, _] = m_skips.emplace(pos, std::move(entry));
                it = ins_it;
            }

            auto& entry = it->second;

            // p2pool: fill previous updates
            // for i in xrange(skip_length):
            //     if i in updates:
            //         that_hash, delta = updates.pop(i)
            //         x, y = self.skips[that_hash]
            //         assert len(y) == i
            //         y.append((pos, delta))
            for (int i = 0; i < entry.skip_length; i++) {
                auto upd_it = updates.find(i);
                if (upd_it != updates.end()) {
                    auto& upd = upd_it->second;
                    auto skip_it = m_skips.find(upd.node_hash);
                    if (skip_it != m_skips.end() &&
                        static_cast<int>(skip_it->second.levels.size()) == i) {
                        skip_it->second.levels.push_back(upd.delta);
                    }
                    updates.erase(upd_it);
                }
            }

            // p2pool: put desired skip nodes in updates
            // for i in xrange(len(skip), skip_length):
            //     updates[i] = pos, None
            for (int i = static_cast<int>(entry.levels.size()); i < entry.skip_length; i++) {
                updates[i] = UpdateEntry{pos, false, {}};
            }

            // p2pool: for jump, delta in reversed(skip):
            //     sol_if = self.apply_delta(sol, delta, args)
            //     decision = self.judge(sol_if, args)
            //     if decision == 0: return self.finalize(sol_if, args)
            //     elif decision < 0: sol = sol_if; break
            // else: raise AssertionError()
            Delta taken_delta{};
            bool found = false;

            for (int i = static_cast<int>(entry.levels.size()) - 1; i >= 0; i--) {
                const auto& delta = entry.levels[i];
                // apply_delta: (sol_dist + delta.distance, delta.to_hash)
                int32_t new_dist = sol_dist + delta.distance;

                // judge: new_dist > n → overshoot (+1), == n → exact (0), < n → undershoot (-1)
                if (new_dist == n) {
                    // finalize: assert dist == n; return hash
                    return delta.to_hash;
                } else if (new_dist < n && !delta.to_hash.IsNull()) {
                    // Undershoot — take this jump, continue from delta.to_hash
                    sol_dist = new_dist;
                    sol_hash = delta.to_hash;
                    taken_delta = delta;
                    found = true;
                    break;
                }
                // new_dist > n: overshoot, try smaller jump
            }

            if (!found) {
                // All jumps overshoot or chain end — shouldn't happen
                // with level 0 always being a single step.
                // Guard against null/missing previous.
                return hash_t();
            }

            // p2pool: sol = sol_if; pos = jump
            // Since jump == delta.to_hash (proven), pos = taken_delta.to_hash = sol_hash
            pos = sol_hash;

            // p2pool: for x in updates:
            //     updates[x] = updates[x][0], self.combine_deltas(updates[x][1], delta) if updates[x][1] is not None else delta
            for (auto& [level, upd] : updates) {
                if (upd.has_delta) {
                    // combine_deltas: (h1,d1,h2) + (h2,d2,h3) = (h1, d1+d2, h3)
                    upd.delta.distance += taken_delta.distance;
                    upd.delta.to_hash = taken_delta.to_hash;
                } else {
                    upd.delta = taken_delta;
                    upd.has_delta = true;
                }
            }

            // Safety: if we reached a null hash, stop
            if (pos.IsNull()) return hash_t();
        }
    }

    void clear() { m_skips.clear(); }
    size_t size() const { return m_skips.size(); }
    bool contains(const hash_t& hash) const { return m_skips.contains(hash); }
};

} // namespace chain
