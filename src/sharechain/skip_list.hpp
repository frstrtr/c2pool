#pragma once
/**
 * Deterministic Skip List for O(log n) ancestor lookups.
 *
 * Direct translation of Bitcoin Core's CBlockIndex::pskip + GetAncestor()
 * pattern (MIT licensed, commit c9a0918), adapted for hash-based navigation
 * (no raw pointers — safe from use-after-free).
 *
 * Bitcoin Core: each block stores pskip (pointer to skip ancestor).
 * c2pool: each share stores skip_hash (hash of skip ancestor).
 *
 * BuildSkip() is called once at add() time.
 * GetAncestor() is O(log n) using skip_hash + prev_hash navigation.
 * forget_item() is O(1) — clears only the removed hash.
 *
 * Source: bitcoin/src/chain.cpp (MIT license)
 * https://github.com/bitcoin/bitcoin/blob/master/src/chain.cpp
 */

#include <cstdint>
#include <functional>

namespace chain {

/// Turn the lowest '1' bit in the binary representation of a number into a '0'.
/// Bitcoin Core: chain.cpp:70
inline int InvertLowestOne(int n) { return n & (n - 1); }

/// Compute what height to jump back to with the skip pointer.
/// Any number strictly lower than height is acceptable, but this expression
/// performs well in simulations (max 110 steps to go back up to 2^18 blocks).
/// Bitcoin Core: chain.cpp:73-81
inline int GetSkipHeight(int height) {
    if (height < 2)
        return 0;
    return (height & 1)
        ? InvertLowestOne(InvertLowestOne(height - 1)) + 1
        : InvertLowestOne(height);
}

/**
 * ShareSkipList — O(log n) ancestor lookup for share chains.
 *
 * Each share stores:
 *   - height (accumulated from chain root)
 *   - prev_hash (parent share)
 *   - skip_hash (skip ancestor, set by BuildSkip)
 *
 * Navigation uses hash lookups instead of pointers (safe).
 *
 * Template params:
 *   HashType — hash type (uint256)
 *   HasherType — hash function for unordered_map
 */
template <typename HashType, typename HasherType>
class ShareSkipList
{
    using hash_t = HashType;
    using hasher_t = HasherType;

    struct SkipData {
        int32_t height;     // accumulated height from chain root
        hash_t prev_hash;   // parent share (direct predecessor)
        hash_t skip_hash;   // skip ancestor (GetSkipHeight distance back)
    };

    std::unordered_map<hash_t, SkipData, hasher_t> m_data;

    // Callbacks to access share chain
    std::function<hash_t(const hash_t&)> m_get_prev_fn;    // share.prev_hash
    std::function<bool(const hash_t&)> m_contains_fn;       // chain.contains(hash)

public:
    ShareSkipList() = default;

    void init(
        std::function<hash_t(const hash_t&)> get_prev_fn,
        std::function<bool(const hash_t&)> contains_fn)
    {
        m_get_prev_fn = std::move(get_prev_fn);
        m_contains_fn = std::move(contains_fn);
    }

    /**
     * BuildSkip — called when a share is added to the chain.
     * Sets skip_hash by navigating to GetSkipHeight(height) via GetAncestor.
     *
     * Bitcoin Core: CBlockIndex::BuildSkip() (chain.cpp:115-119)
     *   if (pprev) pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
     *
     * @param hash — the new share's hash
     * @param prev_hash — the new share's parent hash
     */
    void build_skip(const hash_t& hash, const hash_t& prev_hash)
    {
        SkipData data;
        data.prev_hash = prev_hash;

        // Compute height from parent
        if (!prev_hash.IsNull() && m_data.contains(prev_hash)) {
            data.height = m_data[prev_hash].height + 1;
        } else {
            data.height = 1;  // root or disconnected
        }

        // Build skip: skip_hash = GetAncestor(GetSkipHeight(height)) via prev
        // Bitcoin Core: pskip = pprev->GetAncestor(GetSkipHeight(nHeight))
        int skip_height = GetSkipHeight(data.height);
        if (!prev_hash.IsNull() && m_data.contains(prev_hash)) {
            data.skip_hash = get_ancestor_hash(prev_hash, skip_height);
        }

        m_data[hash] = data;

        // Propagate to existing children that arrived before this parent.
        // Bitcoin Core doesn't need this (blocks arrive in order).
        // Share chains may receive children before parents (P2P).
        // Rebuild skip for children whose height was wrong (height=1).
        // This is done lazily — children will be rebuilt on next access
        // if their height is inconsistent.
    }

    /**
     * Rebuild skip data for a share (e.g., after parent arrives).
     * Called when we detect stale height (parent now available).
     */
    void rebuild_skip(const hash_t& hash)
    {
        auto it = m_data.find(hash);
        if (it == m_data.end()) return;

        auto& data = it->second;
        auto parent_it = m_data.find(data.prev_hash);
        if (parent_it == m_data.end()) return;

        int32_t new_height = parent_it->second.height + 1;
        if (new_height == data.height) return;  // already correct

        data.height = new_height;
        int skip_height = GetSkipHeight(data.height);
        data.skip_hash = get_ancestor_hash(data.prev_hash, skip_height);
    }

    /**
     * GetAncestor — O(log n) ancestor lookup.
     *
     * Bitcoin Core: CBlockIndex::GetAncestor(int height) (chain.cpp:83-108)
     *
     * Returns the hash of the ancestor at the given height.
     * Uses skip_hash for large jumps, prev_hash for single steps.
     */
    hash_t get_ancestor_hash(const hash_t& start, int32_t target_height) const
    {
        auto it = m_data.find(start);
        if (it == m_data.end()) return hash_t();

        int32_t current_height = it->second.height;
        if (target_height > current_height || target_height < 0)
            return hash_t();

        hash_t current = start;

        while (current_height > target_height) {
            auto cur_it = m_data.find(current);
            if (cur_it == m_data.end()) break;

            const auto& d = cur_it->second;
            int heightSkip = GetSkipHeight(current_height);
            int heightSkipPrev = GetSkipHeight(current_height - 1);

            // Bitcoin Core logic: follow pskip if it's better than pprev->pskip
            if (!d.skip_hash.IsNull() && m_data.contains(d.skip_hash) &&
                (heightSkip == target_height ||
                 (heightSkip > target_height &&
                  !(heightSkipPrev < heightSkip - 2 &&
                    heightSkipPrev >= target_height)))) {
                current = d.skip_hash;
                current_height = heightSkip;
            } else {
                // Single step back
                if (d.prev_hash.IsNull()) break;
                current = d.prev_hash;
                current_height--;
            }
        }

        return current;
    }

    /**
     * get_nth_parent — get ancestor at distance n from start.
     * Equivalent to p2pool's tracker.get_nth_parent_hash(hash, n).
     */
    hash_t get_nth_parent(const hash_t& start, int32_t n) const
    {
        auto it = m_data.find(start);
        if (it == m_data.end()) return hash_t();
        int32_t target = it->second.height - n;
        if (target < 0) target = 0;
        return get_ancestor_hash(start, target);
    }

    /// Get accumulated height (from chain root to this share)
    int32_t get_height(const hash_t& hash) const
    {
        auto it = m_data.find(hash);
        return it != m_data.end() ? it->second.height : 0;
    }

    /// forget_item — O(1), matches p2pool TrackerSkipList.forget_item
    /// Called via removed signal when a share is pruned.
    void forget_item(const hash_t& hash) {
        m_data.erase(hash);
    }

    /// Check if hash has skip data
    bool contains(const hash_t& hash) const {
        return m_data.contains(hash);
    }

    /// Clear all data
    void clear() { m_data.clear(); }

    /// Get size
    size_t size() const { return m_data.size(); }
};

} // namespace chain
