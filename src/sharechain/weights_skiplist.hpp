// weights_skiplist.hpp — O(log n) PPLNS weight computation via skip list
//
// Faithful port of:
//   p2pool/util/skiplist.py  — SkipList base class (__call__ loop)
//   p2pool/data.py           — WeightsSkipList subclass
//
// Skip levels are built LAZILY during query walks via the "updates"
// mechanism (skiplist.py lines 24-34, 54-56).  Level 0 is created
// on first visit; higher levels are filled in as future walks pass
// through predecessor nodes.
//
// Usage:
//   Construct with get_delta(hash) and previous(hash) lambdas.
//   Call query(start, max_shares, desired_weight) for PPLNS computation.
//   Call forget(hash) when a share is removed from the chain.
//   Call clear() when the underlying chain is structurally modified.

#pragma once

#include <cassert>
#include <cmath>
#include <cstdint>
#include <deque>
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
// WeightsDelta — single or combined share delta.
// Matches Python: (share_count, {addr: weight}, total_weight, donation_weight)
// ============================================================================

struct WeightsDelta
{
    int32_t share_count{0};
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

// Pure summation of two deltas.  Matches p2pool combine_deltas (data.py:1909).
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
// Faithful port of p2pool SkipList.__call__ + WeightsSkipList.
//
// Storage: m_skips[hash] = (skip_length, levels_deque)
//   skip_length: geometric random height (max levels this node can have)
//   levels_deque: built lazily; [0] always present (single share),
//                 higher levels filled in during walks via "updates".
//   std::deque: push_back does NOT invalidate references to existing
//               elements — critical for pointer stability during walks.
//
// get_delta_fn: (share_hash) → WeightsDelta for that single share.
// previous_fn:  (share_hash) → prev_share_hash (null if at chain end).
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

    void forget(const uint256& hash) { m_skips.erase(hash); }
    void clear()                     { m_skips.clear(); }

    // ------------------------------------------------------------------
    // query — faithful port of SkipList.__call__ (skiplist.py:13-56)
    // + WeightsSkipList.apply_delta/judge/finalize (data.py:1912-1935)
    //
    // Walks tail-ward from `start`, accumulating PPLNS weights until
    // either max_shares shares are traversed or desired_weight is
    // reached.  At the boundary share, proportional partial scaling
    // is applied (p2pool data.py:1917-1921).
    // ------------------------------------------------------------------
    CumulativeWeightsResult query(const uint256& start,
                                  int32_t max_shares,
                                  const uint288& desired_weight)
    {
        if (start.IsNull() || !m_get_delta)
            return {};

        // --- updates dict (skiplist.py:14) ---
        // Pending higher-level pointers to be filled in when a future
        // node is visited that should carry that level.
        // updates[level] = (that_hash, delta_or_none)
        struct UpdateEntry {
            uint256 hash;
            bool    has_delta{false};
            WeightsDelta delta;
        };
        std::unordered_map<int, UpdateEntry> updates;

        uint256 pos = start;

        // --- initial_solution (data.py:1912-1914) ---
        // sol = (share_count=0, weights_list=None, total_weight=0, donation=0)
        int32_t sol_count = 0;
        uint288 sol_total;
        uint288 sol_donation;
        // Cons-list of weight dicts, merged only in finalize.
        // Matches p2pool's (prev_list, dict) linked list.
        std::vector<std::map<std::vector<unsigned char>, uint288>> weight_parts;

        // judge(initial) → count=0 < max, total=0 < desired → -1 (continue)

        for (int safety = 0; safety < max_shares + 100; ++safety)
        {
            if (pos.IsNull())
                break;

            // --- Ensure pos has a skip entry (skiplist.py:20-21) ---
            // p2pool: if pos not in self.skips:
            //     self.skips[pos] = math.geometric(self.p),
            //                       [(self.previous(pos), self.get_delta(pos))]
            ensure_skip(pos);

            auto skip_it = m_skips.find(pos);
            if (skip_it == m_skips.end())
                break;
            auto& [skip_length, skip] = skip_it->second;

            // --- Fill previous updates (skiplist.py:24-30) ---
            // For each level i in [0, skip_length), if an update is
            // pending at level i, attach (pos, accumulated_delta) to
            // that_hash's skip levels.
            for (int i = 0; i < skip_length; ++i)
            {
                auto uit = updates.find(i);
                if (uit == updates.end())
                    continue;

                auto& [u_hash, u_has_delta, u_delta] = uit->second;
                // p2pool: x, y = self.skips[that_hash]
                //         assert len(y) == i
                //         y.append((pos, delta))
                auto sit = m_skips.find(u_hash);
                if (sit != m_skips.end())
                {
                    auto& [tsl, tskip] = sit->second;
                    if (static_cast<int>(tskip.size()) == i)
                        tskip.push_back({pos, std::move(u_delta)});
                }
                updates.erase(uit);
            }

            // --- Put desired skip nodes in updates (skiplist.py:32-34) ---
            // For levels this node should have but doesn't yet
            for (int i = static_cast<int>(skip.size()); i < skip_length; ++i)
                updates[i] = {pos, false, {}};

            // --- Try levels highest to lowest (skiplist.py:39-47) ---
            bool took_jump = false;
            uint256 jump_target;
            WeightsDelta taken_delta_copy; // copy of the accepted delta

            for (int i = static_cast<int>(skip.size()) - 1; i >= 0; --i)
            {
                auto& [target, delta] = skip[i];
                if (delta.share_count == 0)
                    continue;

                // --- apply_delta (data.py:1916-1922) ---
                int32_t new_count = sol_count + delta.share_count;
                uint288 new_total = sol_total + delta.total_weight;

                // Boundary case: single-share weight overshoot.
                // p2pool: if total_weight1 + total_weight2 > desired_weight
                //             and share_count2 == 1:
                if (new_total > desired_weight && delta.share_count == 1)
                {
                    // Proportional partial scaling for boundary share.
                    // p2pool data.py:1918-1921
                    auto remaining = desired_weight - sol_total;

                    std::map<std::vector<unsigned char>, uint288> partial;
                    uint288 scaled_donation;
                    if (!delta.total_weight.IsNull() && !delta.weights.empty())
                    {
                        // p2pool: {script: (remaining//65535) * w // (tw//65535)}
                        auto rem_frac = remaining / 65535;
                        auto tw_frac  = delta.total_weight / 65535;
                        for (const auto& [key, w] : delta.weights)
                            partial[key] = rem_frac * w / tw_frac;
                        scaled_donation = rem_frac * delta.total_donation_weight
                                          / tw_frac;
                    }

                    // After apply_delta: total = desired_weight.
                    // judge: total == desired → 0 (exact) → finalize.
                    weight_parts.push_back(std::move(partial));
                    return finalize(weight_parts, desired_weight,
                                    sol_donation + scaled_donation);
                }

                // --- judge (data.py:1924-1930) ---
                int decision;
                if (new_count > max_shares || new_total > desired_weight)
                    decision = 1;  // overshot
                else if (new_count == max_shares || new_total == desired_weight)
                    decision = 0;  // exact match
                else
                    decision = -1; // undershoot

                if (decision == 0)
                {
                    // Exact match → finalize and return
                    weight_parts.push_back(delta.weights); // copy by value
                    return finalize(weight_parts, new_total,
                                    sol_donation + delta.total_donation_weight);
                }
                else if (decision < 0)
                {
                    // Undershoot → accept this jump
                    weight_parts.push_back(delta.weights); // copy by value
                    sol_count = new_count;
                    sol_total = new_total;
                    sol_donation += delta.total_donation_weight;
                    jump_target = target;
                    taken_delta_copy = delta; // safe copy for updates propagation
                    took_jump = true;
                    break;
                }
                // decision > 0 → overshoot, try smaller level (continue)
            }

            if (!took_jump)
            {
                // p2pool: else: raise AssertionError()
                // No level worked.  Chain too short to satisfy constraints.
                break;
            }

            // --- Update pending entries (skiplist.py:54-56) ---
            // p2pool: for x in updates:
            //     updates[x] = updates[x][0],
            //         self.combine_deltas(updates[x][1], delta)
            //         if updates[x][1] is not None else delta
            for (auto& [level, entry] : updates)
            {
                if (entry.has_delta)
                    entry.delta = combine_deltas(entry.delta, taken_delta_copy);
                else
                {
                    entry.delta = taken_delta_copy;
                    entry.has_delta = true;
                }
            }

            pos = jump_target;
        }

        return finalize(weight_parts, sol_total, sol_donation);
    }

private:
    struct SkipLevel
    {
        uint256 target;
        WeightsDelta delta;
    };

    // m_skips[hash] = (skip_length, levels)
    // skip_length: maximum height.  levels grows lazily ≤ skip_length.
    // std::deque: push_back does not invalidate references to existing
    // elements — critical because fill-updates appends to OTHER nodes'
    // level deques while we hold references into the current node's.
    using SkipEntry = std::pair<int, std::deque<SkipLevel>>;

    // Create level-0 entry if not present.
    // p2pool: self.skips[pos] = math.geometric(self.p),
    //                           [(self.previous(pos), self.get_delta(pos))]
    void ensure_skip(const uint256& hash)
    {
        if (m_skips.contains(hash))
            return;
        int sl = geometric();
        auto prev = m_previous(hash);
        auto delta = m_get_delta(hash);
        auto& entry = m_skips[hash];
        entry.first = sl;
        entry.second.push_back({std::move(prev), std::move(delta)});
    }

    // Geometric distribution — p2pool util/math.py:56-61
    // int(math.log1p(-random.random()) / math.log1p(-p)) + 1
    int geometric()
    {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        double u = dist(m_rng);
        if (u <= 0.0) u = 1e-18; // avoid log(0)
        return std::max(1, static_cast<int>(
            std::log1p(-u) / std::log1p(-0.5)) + 1);
    }

    // Merge all weight-dict parts into a single map.
    // p2pool: math.add_dicts(*math.flatten_linked_list(weights_list))
    static CumulativeWeightsResult finalize(
        const std::vector<std::map<std::vector<unsigned char>, uint288>>& parts,
        const uint288& total,
        const uint288& donation)
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
    std::unordered_map<uint256, SkipEntry, Uint256Hasher> m_skips;
};

} // namespace chain
