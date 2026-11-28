// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// Randomised share-chain forests for the old-against-new differential tests
// (X1: share-chain walks). A forest is grown by a seeded sequence of the
// operations the live tracker sees:
//   * a share extending a head, or forking from any share (a new head);
//   * a share whose parent is missing (a disconnected segment);
//   * the missing parent of a segment arriving later (children before parents);
//   * a genesis share (null parent);
//   * removal of a head (remove() branches 1/2), of a tail child (branches
//     3/4) and of a share with children (aborted: remove() returns false);
//   * re-adding a removed hash.
// Shares are ltc::MergedMiningShare with only the fields the chain reads
// (hash, prev, bits); `bits` varies so work differs between shares.

#include <algorithm>
#include <cstdint>
#include <random>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>

namespace forest_test {

inline uint64_t mix64(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

// A distinct, well-spread hash for every (salt, n); never null.
inline uint256 make_hash(uint64_t salt, uint64_t n)
{
    uint256 h;
    uint32_t* p = h.begin();
    uint64_t s = mix64(salt * 0x100000001B3ull + n);
    for (int i = 0; i < 8; i += 2) {
        s = mix64(s + static_cast<uint64_t>(i));
        p[i] = static_cast<uint32_t>(s);
        p[i + 1] = static_cast<uint32_t>(s >> 32);
    }
    p[7] |= 0x80000000u;   // never null
    return h;
}

inline uint32_t bits_for(uint64_t n)
{
    // Easy share targets with a few distinct difficulties.
    static const uint32_t kBits[] = {0x1e0fffff, 0x1e07ffff, 0x1e03ffff, 0x1d7fffff};
    return kBits[n % 4];
}

// One share object for `chain.add` / `tracker.add`. Ownership passes to the
// chain (it destroys the shares it holds).
inline ltc::ShareType make_share(const uint256& hash, const uint256& prev, uint32_t bits,
                                 uint32_t timestamp = 1700000000u)
{
    auto* sh = new ltc::MergedMiningShare();
    sh->m_hash = hash;
    sh->m_prev_hash = prev;
    sh->m_bits = bits;
    sh->m_max_bits = bits;
    sh->m_timestamp = timestamp;
    ltc::ShareType st;
    st = sh;
    return st;
}

// A forest grown on one chain-like target. `Add(hash, prev, bits)` inserts a
// share; `Remove(hash)` removes one and returns what ShareChain::remove
// returned. The model keeps the prev link of every hash ever added, so a
// removed hash can be re-added with its own parent. Every hash has a rank and
// every prev link points to a strictly lower rank, so no sequence of
// operations can close a prev-link cycle (cycles are tested on their own).
template <typename Chain>
struct ForestGrower
{
    Chain& chain;
    uint64_t salt;
    std::mt19937_64 rng;
    uint64_t next_id{0};
    std::unordered_map<uint256, uint256, ltc::ShareHasher> prev_of;   // every hash ever made
    std::vector<uint256> removed;                                       // removed, re-addable
    std::vector<uint256> missing;                                       // parents not yet added
    std::unordered_map<uint256, double, ltc::ShareHasher> rank_of;      // prev rank < child rank
    double top_rank{0};

    ForestGrower(Chain& c, uint64_t seed) : chain(c), salt(seed), rng(seed) {}

    // A new hash ranked above everything made so far.
    uint256 fresh()
    {
        uint256 h = make_hash(salt, next_id++);
        rank_of[h] = (top_rank += 1.0);
        return h;
    }
    // A new missing-parent hash for `child`: ranked just below it.
    uint256 fresh_parent_of(const uint256& child)
    {
        uint256 h = make_hash(salt, next_id++);
        rank_of[h] = rank_of[child] - 1e-3;
        missing.push_back(h);
        return h;
    }

    size_t pick(size_t n) { return std::uniform_int_distribution<size_t>(0, n - 1)(rng); }
    bool chance(int pct) { return std::uniform_int_distribution<int>(0, 99)(rng) < pct; }

    template <typename AddFn>
    void add_share(const uint256& h, const uint256& prev, AddFn&& add)
    {
        prev_of[h] = prev;
        add(h, prev, bits_for(mix64(h.GetLow64())));
    }

    std::vector<uint256> present_hashes() const
    {
        std::vector<uint256> out;
        for (const auto& [h, p] : prev_of)
            if (chain.contains(h))
                out.push_back(h);
        std::sort(out.begin(), out.end());
        return out;
    }

    std::vector<uint256> sorted_heads() const
    {
        std::vector<uint256> out;
        for (const auto& [h, t] : chain.get_heads())
            out.push_back(h);
        std::sort(out.begin(), out.end());
        return out;
    }

    // Children of the tails (the shares remove() takes down branches 3/4).
    std::vector<uint256> tail_children() const
    {
        std::vector<uint256> out;
        const auto& rev = chain.get_reverse();
        for (const auto& [t, hs] : chain.get_tails()) {
            auto it = rev.find(t);
            if (it == rev.end())
                continue;
            for (const auto& c : it->second)
                if (chain.contains(c))
                    out.push_back(c);
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

    // One random growth step (no removals).
    template <typename AddFn>
    void grow_step(AddFn&& add)
    {
        auto present = present_hashes();
        const int r = std::uniform_int_distribution<int>(0, 99)(rng);
        if (present.empty() || r < 4) {
            // genesis (null parent) or a disconnected segment
            const uint256 h = fresh();
            uint256 prev;
            if (chance(50))
                prev = fresh_parent_of(h);
            add_share(h, prev, add);
            return;
        }
        if (r < 70) {
            // extend a head
            auto heads = sorted_heads();
            const uint256 parent = heads.empty() ? present[pick(present.size())]
                                                 : heads[pick(heads.size())];
            add_share(fresh(), parent, add);
            return;
        }
        if (r < 82) {
            // fork from any present share
            add_share(fresh(), present[pick(present.size())], add);
            return;
        }
        if (r < 94 && !missing.empty()) {
            // a missing parent arrives (children-before-parents)
            const size_t i = pick(missing.size());
            const uint256 h = missing[i];
            missing.erase(missing.begin() + static_cast<long>(i));
            if (chain.contains(h))
                return;
            uint256 prev;
            const int k = std::uniform_int_distribution<int>(0, 2)(rng);
            if (k == 0) {
                prev = fresh_parent_of(h);
            } else if (k == 1) {
                std::vector<uint256> below;   // lower rank: cannot be a descendant
                for (const auto& x : present)
                    if (rank_of[x] < rank_of[h])
                        below.push_back(x);
                if (!below.empty())
                    prev = below[pick(below.size())];
            }   // else: genesis
            add_share(h, prev, add);
            return;
        }
        if (!removed.empty()) {
            // re-add a removed hash with its own parent
            const size_t i = pick(removed.size());
            const uint256 h = removed[i];
            removed.erase(removed.begin() + static_cast<long>(i));
            if (!chain.contains(h))
                add_share(h, prev_of[h], add);
            return;
        }
        add_share(fresh(), present[pick(present.size())], add);
    }

    // One random removal step. Returns whether something was removed.
    template <typename RemoveFn>
    bool remove_step(RemoveFn&& remove)
    {
        const int r = std::uniform_int_distribution<int>(0, 99)(rng);
        std::vector<uint256> cand;
        if (r < 45)
            cand = sorted_heads();            // branches 1/2
        else if (r < 85)
            cand = tail_children();           // branches 3/4
        else
            cand = present_hashes();          // mostly aborted (has children)
        if (cand.empty())
            return false;
        const uint256 h = cand[pick(cand.size())];
        if (!chain.contains(h))
            return false;
        const bool ok = remove(h);
        if (ok)
            removed.push_back(h);
        return ok;
    }
};

}  // namespace forest_test
