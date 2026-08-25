// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ─────────────────────────────────────────────────────────────────────────
// task #154 — incremental merkleRootMNList cache for the DASH replay fold.
//
// THE PROBLEM. The daemonless replay fold advances the deterministic
// masternode list block-by-block and, as a reward-safe self-check, recomputes
// merkleRootMNList every block and compares it to the block's committed CbTx
// root (replay_fold_engine.hpp fold_block). The naive recompute
// (CSimplifiedMNList::CalcMerkleRoot) rebuilds the WHOLE ~4900-leaf tree from
// scratch on EVERY block:
//     * ~4900 leaf hashes  — CalcHash() serialize+SHA256d of each MN entry;
//     * ~4900 internal pair hashes — the SHA256d merkle tree.
// A DIP3→tip fold is ~1.5M blocks, so that is ~1.5M × ~9800 SHA256d ≈ 1.4e10
// hashings — the dominant cost that makes the fold take ~2 days versus dashd's
// <12 h genesis→tip WITH full block validation.
//
// WHY dashd IS FAST (the ported insight). dashd does NOT recompute the merkle
// every block. Its simplified-MN entry (CDeterministicMN::to_sml_entry,
// deterministicmns.cpp) is built ONLY from consensus-committed fields —
// proRegTxHash, confirmedHash, netInfo, pubKeyOperator, keyIDVoting, isValid,
// nType, platform* — and DELIBERATELY EXCLUDES nLastPaidHeight and
// nPoSePenalty. The per-block payment rotation and PoSe-score decay bump those
// two excluded fields, so on the overwhelming majority of blocks the SML is
// byte-for-byte UNCHANGED and dashd returns a cached root having hashed
// nothing (CalcCbTxMerkleRootMNList's single-slot cache + the DMN list's
// UpdateMN-only-invalidates-if-to_sml_entry-changed guard,
// deterministicmns.cpp).
//
// WHAT THIS CLASS DOES. It ports that invariance into c2pool and takes it one
// step further to also make the RARE change-blocks cheap:
//   (1) LEAF-HASH CACHE. Each cached leaf remembers its CSimplifiedMNListEntry
//       and its CalcHash(). On the next block we diff the incoming entry set
//       against the cache; a leaf whose SML entry is byte-identical REUSES its
//       cached hash and is NEVER re-hashed. Payment-rotation-only blocks touch
//       zero SML entries → zero leaf hashes.
//   (2) INCREMENTAL TREE. The full pairwise tree (all levels) is cached. When
//       a block changes the VALUE of k leaves without changing the leaf set
//       (confirmedHash crossing, ProUpServ/ProUpReg, PoSe ban↔revive isValid
//       flip — same proRegTxHash, same sorted positions), only the O(k·log n)
//       internal nodes on the changed leaves' root-paths are recomputed; the
//       rest of the tree is reused. When the leaf SET changes (ProReg adds,
//       collateral spend removes — the rarest ops, which shift sorted
//       positions) the tree is rebuilt from the cached leaf hashes: still no
//       leaf re-hashing of the ~4900 unchanged entries, only the cheap pair
//       hashing.
//
// HARD CORRECTNESS INVARIANT (reward-safety). The whole point of the fold
// self-check is to CATCH divergence from consensus; a fast-but-wrong root
// would serve a forked list. So update() is REQUIRED to return a value
// byte-identical to CSimplifiedMNList(entries).CalcMerkleRoot() for EVERY
// block. This is guaranteed structurally — the leaf hashes come from the exact
// same CalcHash(), the pairing from the exact same merkle_pair_hash(), and the
// leaf order from the exact same memcmp(proRegTxHash) sort — and is proven by
// the KAT (test_dash_replay_fold.cpp, IncrementalMerkleCache suite) which
// recomputes both across a synthetic mutation sequence and asserts equality at
// every step, plus a debug-build assert in the fold engine. The self-check's
// committed-root compare remains the final authority: a caching bug fails
// CLOSED (poison + re-seed), never mis-folds.
// ─────────────────────────────────────────────────────────────────────────

#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// PERF/TEST SEAM (task #154 delta path). Counts the SML entries the incremental
// path had to EXAMINE — materialize a CSimplifiedMNListEntry for, sort, and
// byte-diff. This is the per-block O(n) cost the #1297 consolidation
// reintroduced by re-deriving the WHOLE ~4900-entry set from the fold's MN map
// every block (replay_fold_engine.hpp compute_sml_root_incremental → update()):
// even a pure payment-rotation block, which changes NOTHING in the SML, paid a
// full re-materialize + std::sort + full-set diff + full-cache realloc.
//   * update()             bumps by entries.size()  — it re-sorts and re-diffs
//                          the entire incoming set (cold build / leaf-set change).
//   * apply_value_changes() bumps only by the number of leaves the block
//                          actually mutated (the O(k) delta).
//   * a quiet block bumps NEITHER — the fold engine returns the resident cached
//     root without calling either path.
// Same single-io-thread discipline as the sml_leaf/node_hash counters: plain
// uint64, no atomics.
inline uint64_t& sml_leaves_examined_count()
{
    static uint64_t n = 0;
    return n;
}

class IncrementalSmlMerkle
{
public:
    // A cached leaf: the sort key (proRegTxHash), the SML entry it was built
    // from (for byte-equality-gated reuse), and the cached CalcHash().
    struct Leaf
    {
        uint256                 key;    // proRegTxHash — the merkle sort key
        CSimplifiedMNListEntry  entry;  // gates reuse: unchanged ⇒ reuse hash
        uint256                 hash;   // cached CalcHash()
    };

    // Recompute merkleRootMNList from `entries` (any order), reusing cached
    // leaf hashes for entries whose SML bytes are unchanged and reusing cached
    // internal tree nodes wherever the block did not disturb them.
    //
    // Return value is byte-identical to
    //     CSimplifiedMNList(std::move(copy_of_entries)).CalcMerkleRoot()
    // for every input — see the header invariant.
    uint256 update(std::vector<CSimplifiedMNListEntry> entries)
    {
        // The full path re-sorts and re-diffs the ENTIRE incoming set — the
        // O(n) per-block cost the delta path (apply_value_changes) avoids.
        sml_leaves_examined_count() += entries.size();

        // Same total order the naive path sorts by: dashcore's memcmp over the
        // raw proRegTxHash bytes (little-endian byte order). proRegTxHash is
        // unique per MN, so this is a strict total order → deterministic.
        std::sort(entries.begin(), entries.end(),
            [](const CSimplifiedMNListEntry& a,
               const CSimplifiedMNListEntry& b) {
                return keycmp(a.proRegTxHash, b.proRegTxHash) < 0;
            });

        // Two-pointer merge of the incoming sorted set against the cached
        // sorted leaves. Classify each key as reused / value-changed / added /
        // removed, building the new leaf vector and hashing ONLY new or
        // value-changed entries.
        std::vector<Leaf>   merged;
        std::vector<size_t> value_dirty;   // positions in `merged` re-hashed
                                           // by a same-key VALUE change
        merged.reserve(entries.size());
        bool structural = false;           // leaf SET changed (add/remove)

        size_t i = 0;                      // into sorted `entries`
        size_t j = 0;                      // into cached `m_leaves`
        while (i < entries.size() || j < m_leaves.size()) {
            int c;
            if (i >= entries.size())      c =  1;   // only cached left ⇒ remove
            else if (j >= m_leaves.size()) c = -1;  // only incoming left ⇒ add
            else c = keycmp(entries[i].proRegTxHash, m_leaves[j].key);

            if (c < 0) {
                // Added MN: no cached leaf for this key — must hash.
                Leaf lf;
                lf.key   = entries[i].proRegTxHash;
                lf.entry = entries[i];
                lf.hash  = entries[i].CalcHash();
                merged.push_back(std::move(lf));
                structural = true;
                ++i;
            } else if (c > 0) {
                // Removed MN: cached leaf has no incoming counterpart — drop.
                structural = true;
                ++j;
            } else {
                // Surviving key. Reuse the cached hash iff the SML entry is
                // byte-unchanged (the payment-rotation / PoSe-decay case);
                // otherwise re-hash exactly this one leaf.
                Leaf lf;
                lf.key   = entries[i].proRegTxHash;
                lf.entry = entries[i];
                if (entries[i] == m_leaves[j].entry) {
                    lf.hash = m_leaves[j].hash;         // REUSE — no hashing
                } else {
                    lf.hash = entries[i].CalcHash();    // value changed
                    value_dirty.push_back(merged.size());
                }
                merged.push_back(std::move(lf));
                ++i;
                ++j;
            }
        }

        m_leaves = std::move(merged);

        if (m_leaves.empty()) {
            // CalcMerkleRoot()'s empty convention.
            m_levels.clear();
            m_root  = uint256::ZERO;
            m_valid = true;
            return m_root;
        }

        const bool same_shape =
            m_valid && !structural
            && !m_levels.empty()
            && m_levels[0].size() == m_leaves.size();

        if (same_shape) {
            if (value_dirty.empty()) {
                // Nothing SML-relevant moved (pure payment rotation / decay):
                // the root is definitionally unchanged. Zero hashing.
                return m_root;
            }
            // Patch the changed leaf hashes into level 0, then recompute only
            // the affected root-paths.
            for (size_t idx : value_dirty)
                m_levels[0][idx] = m_leaves[idx].hash;
            recompute_paths(value_dirty);
        } else {
            // First fold, or the leaf SET changed: rebuild the tree from the
            // cached leaf hashes (unchanged leaves still not re-hashed).
            rebuild_tree();
        }
        m_valid = true;
        return m_root;
    }

    // DELTA PATH (task #154). Apply in-place VALUE changes to a known-small set
    // of already-present leaves, reusing the resident sorted leaf cache AND the
    // cached tree — WITHOUT re-materialising, re-sorting, or re-diffing the full
    // ~4900-entry set. `changed` carries the NEW SML entries for exactly the
    // leaves the block mutated in place: same proRegTxHash → same sorted
    // position, value-only fields moved (confirmedHash, netInfo, pubKeyOperator,
    // keyIDVoting, isValid, nType, platform*). The leaf SET must be unchanged;
    // adds / removes (which shift sorted positions) still go through update().
    //
    // Returns the new root, byte-identical to
    //     CSimplifiedMNList(resulting_set).CalcMerkleRoot()
    // by the same structural guarantee update() gives — identical CalcHash(),
    // identical merkle_pair_hash(), identical memcmp leaf order. Returns
    // std::nullopt when the delta cannot be applied safely (cache invalid / no
    // tree / a key is not present ⇒ the set actually changed): the caller then
    // falls back to update() so the self-check root is never approximate.
    std::optional<uint256> apply_value_changes(
        const std::vector<CSimplifiedMNListEntry>& changed)
    {
        if (!m_valid || m_leaves.empty() || m_levels.empty())
            return std::nullopt;
        if (m_levels[0].size() != m_leaves.size())
            return std::nullopt;

        // Only the touched leaves are examined — the O(k) win.
        sml_leaves_examined_count() += changed.size();

        std::vector<size_t> dirty;
        dirty.reserve(changed.size());
        for (const auto& e : changed) {
            // lower_bound over the resident sorted leaf cache by proRegTxHash.
            size_t lo = 0, hi = m_leaves.size();
            while (lo < hi) {
                const size_t mid = lo + (hi - lo) / 2;
                if (keycmp(m_leaves[mid].key, e.proRegTxHash) < 0) lo = mid + 1;
                else                                              hi = mid;
            }
            if (lo >= m_leaves.size()
                || keycmp(m_leaves[lo].key, e.proRegTxHash) != 0) {
                // Key absent ⇒ the leaf SET changed, not just a value. Bail so
                // the caller rebuilds from the full set (fail-safe, never wrong).
                return std::nullopt;
            }
            m_leaves[lo].entry = e;
            m_leaves[lo].hash  = e.CalcHash();     // bumps sml_leaf_hash_count
            m_levels[0][lo]    = m_leaves[lo].hash;
            dirty.push_back(lo);
        }
        if (!dirty.empty())
            recompute_paths(dirty);   // O(k·log n) internal nodes only
        return m_root;
    }

    const uint256& root() const { return m_root; }
    size_t         size() const { return m_leaves.size(); }
    bool           valid() const { return m_valid; }

    // Drop all cached state — forces the next update() to rebuild fully. Used
    // when the fold re-seeds from a snapshot (the held list is replaced
    // wholesale, so the incremental diff base is gone).
    void reset()
    {
        m_leaves.clear();
        m_levels.clear();
        m_root  = uint256::ZERO;
        m_valid = false;
    }

private:
    // dashcore's leaf order: memcmp over the raw 32 bytes.
    static int keycmp(const uint256& a, const uint256& b)
    {
        return std::memcmp(a.data(), b.data(), 32);
    }

    // Full pairwise tree from the cached leaf hashes. Byte-identical to
    // CSimplifiedMNList::compute_merkle_root_local: duplicate-last-on-odd,
    // level by level, via the shared merkle_pair_hash. Populates m_levels
    // (level 0 = leaf hashes, last level = {root}).
    void rebuild_tree()
    {
        m_levels.clear();
        std::vector<uint256> cur;
        cur.reserve(m_leaves.size());
        for (const auto& lf : m_leaves) cur.push_back(lf.hash);
        m_levels.push_back(cur);

        while (cur.size() > 1) {
            const size_t n = cur.size();
            std::vector<uint256> next;
            next.reserve((n + 1) / 2);
            for (size_t k = 0; k < n; k += 2) {
                const uint256& a = cur[k];
                const uint256& b = (k + 1 < n) ? cur[k + 1] : cur[k];
                next.push_back(CSimplifiedMNList::merkle_pair_hash(a, b));
            }
            m_levels.push_back(next);
            cur = std::move(next);
        }
        m_root = m_levels.back()[0];
    }

    // Recompute ONLY the internal nodes on the root-paths of the given (level
    // 0) dirty leaf indices, reusing every other cached node. The tree shape
    // is unchanged (same-shape guarantee), so pairing indices match
    // rebuild_tree exactly — duplicate-last-on-odd included. O(k·log n).
    void recompute_paths(const std::vector<size_t>& dirty_leaf_idx)
    {
        std::set<size_t> dirty(dirty_leaf_idx.begin(), dirty_leaf_idx.end());
        for (size_t L = 0; L + 1 < m_levels.size(); ++L) {
            const size_t n = m_levels[L].size();
            std::set<size_t> parents;
            for (size_t idx : dirty) {
                const size_t p  = idx / 2;
                const size_t li = 2 * p;
                const size_t ri = (2 * p + 1 < n) ? 2 * p + 1 : 2 * p; // dup-last
                m_levels[L + 1][p] =
                    CSimplifiedMNList::merkle_pair_hash(m_levels[L][li],
                                                        m_levels[L][ri]);
                parents.insert(p);
            }
            dirty = std::move(parents);
        }
        m_root = m_levels.back()[0];
    }

    std::vector<Leaf>                  m_leaves;   // sorted by keycmp ascending
    std::vector<std::vector<uint256>>  m_levels;   // [0]=leaves … back()={root}
    uint256                            m_root{uint256::ZERO};
    bool                               m_valid{false};
};

} // namespace vendor
} // namespace coin
} // namespace dash
