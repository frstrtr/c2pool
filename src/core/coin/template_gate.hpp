// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core::coin template gate: the mempool is cleaned for the whole segment a
// template builds on (#2136, #2137 S0).
//
// A template on the tip prices its transactions against the UTXO view, whose
// best block can be behind the tip: when the tip's body arrives while the view
// is short of its parent (a UTXO gap, a fill running, a reorg across a
// sibling), the full-block handler cleans the mempool for the tip at once but
// the blocks between the view's best and the tip are cleaned only when the
// fill connects them. Until then the txs those blocks confirmed are still in
// the pool, priced against the older view and selectable; a template carrying
// one is a block litecoind rejects (bad-txns-inputs-missingorspent).
//
// The gate: every block from the view's best (exclusive) to the tip
// (inclusive), along the tip's own ancestry, ran through the mempool cleanup,
// and the view's best is an ancestor of the tip (a view above the tip or on a
// sibling branch is a reorg in progress). Anything else refuses the template
// (kNotCleanedForAncestor), which the ingress guard HOLDs.
//
// Header-only and pure over the two lookups so the KATs can pin it directly.
// ---------------------------------------------------------------------------

#include <core/uint256.hpp>

#include <cstdint>
#include <optional>

namespace core::coin {

/// Refusal code a template builder puts under kTemplateRefusalKey when the
/// segment gate fails.
inline constexpr const char* kNotCleanedForAncestor = "mempool-not-cleaned-for-ancestor";

/// A block by height and hash.
struct BlockRef {
    uint32_t height{0};
    uint256  hash;
};

enum class SegmentGate {
    Ok,           // every block of (view best, tip] cleaned; the view's best is on the tip's ancestry
    NotCleaned,   // a block of the segment was not cleaned, or the segment is longer than kept
    NotAncestor,  // the view's best is above the tip, on another branch, or its link is missing
};

inline const char* segment_gate_name(SegmentGate g)
{
    switch (g) {
        case SegmentGate::Ok:          return "ok";
        case SegmentGate::NotCleaned:  return "not-cleaned";
        case SegmentGate::NotAncestor: return "view-not-an-ancestor";
    }
    return "unknown";
}

struct SegmentCheck {
    SegmentGate gate{SegmentGate::Ok};
    uint32_t    height{0};  // where it failed: the uncleaned block, or the height the ancestry broke at
    uint256     hash;       // the block at `height` on the tip's ancestry (null when unknown)
    bool ok() const { return gate == SegmentGate::Ok; }
};

/// The segment gate. `cleaned_for(hash)` is the pool's Mempool::cleaned_for;
/// `parent_of(hash)` gives a header's parent hash (nullopt: unknown header).
/// The walk goes down from the tip by parent links (the tip's own ancestry,
/// not the live height index, which may already belong to a newer tip).
/// A segment of more than `max_blocks` blocks fails as NotCleaned without a
/// walk: the pool remembers only that many cleaned blocks, and a view that far
/// behind is a bootstrap.
template <typename CleanedFn, typename ParentFn>
SegmentCheck segment_cleaned(const BlockRef& view_best, const BlockRef& tip,
                             CleanedFn&& cleaned_for, ParentFn&& parent_of,
                             uint32_t max_blocks)
{
    if (view_best.height > tip.height)
        return {SegmentGate::NotAncestor, view_best.height, view_best.hash};
    if (tip.height - view_best.height > max_blocks)
        return {SegmentGate::NotCleaned, tip.height, tip.hash};
    uint256 cur = tip.hash;
    for (uint32_t h = tip.height; h > view_best.height; --h) {
        if (!cleaned_for(cur))
            return {SegmentGate::NotCleaned, h, cur};
        const std::optional<uint256> parent = parent_of(cur);
        if (!parent)
            return {SegmentGate::NotAncestor, h - 1, uint256()};
        cur = *parent;
    }
    if (cur != view_best.hash)
        return {SegmentGate::NotAncestor, view_best.height, cur};
    return {};
}

} // namespace core::coin
