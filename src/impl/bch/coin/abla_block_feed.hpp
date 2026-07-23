// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::coin::AblaBlockFeed -- M5: drives the ABLA size feed from the REAL
// block-connect path. This is the wiring that was missing after M5 slice C:
// AblaTracker.record_block_size() existed but nothing called it; the running
// State was only ever exercised by the out-of-tree roundtrip harness. This
// feed closes that gap by subscribing to the embedded daemon's full_block
// event and folding each best-chain block's actual serialized size into the
// tracker.
//
// WHY HERE (full-block / daemon layer, not the header chain):
//   ABLA advances per block by that block's *actual serialized size*, which
//   the headers-only SPV header_chain structurally does not carry (M4 s3 pin /
//   M5 PINNED acceptance item). The size therefore must be fed as full blocks
//   arrive at the embedded-daemon layer -- exactly where interfaces::Node's
//   full_block event fires (p2p_node block + cmpctblock handlers).
//
// CONTIGUOUS-TIP-ONLY by construction. We resolve each block's height from the
// best-chain HeaderChain index (header sync precedes full-block download in the
// BIP130 flow). A block whose hash is not on the indexed best chain (unsolicited
// block, side branch, or one whose header has not been indexed yet) is skipped:
// we cannot assign it a trustworthy height, so we hand the tracker nothing and
// let its own gap-detect do the rest. The tracker already enforces ordering:
//   height == cursor+1 -> fold (hot path)
//   height <= cursor   -> idempotent ignore (duplicate / replayed old block)
//   height >  cursor+1 -> GAP -> stale -> builder falls back to the 32 MB floor
//                         until reanchor() supplies a fresh known-good State.
// So a reorg or a skipped block can only ever DROP the budget to the safe
// floor, never raise it on bad data. Reanchoring (BCHN pin / explicit) is a
// separate path; until it runs the floor holds -- the never-undercut invariant.
//
// p2pool-merged-v36 SURFACE: NONE. Identical to abla.hpp / abla_tracker.hpp,
// this governs only the LOCAL build-time block-size budget. It never touches
// PoW hash, share format, coinbase commitment, or PPLNS math -- zero interop
// risk.
//
// PER-COIN ISOLATION: everything here is src/impl/bch/coin/ only. The block
// accessor (full_block event), the height source (HeaderChain), and the sink
// (AblaTracker) are all bch-owned. No bitcoin_family/ or src/core block
// primitive is reached for -- size comes from this module's own block.hpp
// Serialize via pack(), height from this module's own header index.
//
// Build-INERT / source-only: header-only, no impl_bch CMake registration
// (bch stays skip-green; don't race ci-steward).
// ---------------------------------------------------------------------------

#include "abla_tracker.hpp"
#include "block.hpp"
#include "header_chain.hpp"     // bch::coin::block_hash(), HeaderChain
#include "node_interface.hpp"   // bch::interfaces::Node (full_block event)

#include <core/events.hpp>      // Event, EventDisposable
#include <core/pack.hpp>        // pack() -> serialized span
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <memory>

namespace bch {
namespace coin {

/// Subscribes to interfaces::Node::full_block and folds each best-chain block's
/// real serialized size into an AblaTracker. Single-threaded use from the
/// daemon's block-processing context is assumed (mirrors how the header chain
/// advances and how AblaTracker documents its own threading contract).
class AblaBlockFeed {
public:
    /// @param tracker  the ABLA size tracker to feed (daemon-owned; must outlive this).
    /// @param chain    best-chain header index, the height source for received blocks.
    AblaBlockFeed(AblaTracker& tracker, const HeaderChain& chain)
        : m_tracker(tracker), m_chain(chain) {}

    AblaBlockFeed(const AblaBlockFeed&) = delete;
    AblaBlockFeed& operator=(const AblaBlockFeed&) = delete;

    /// Wire this feed to a node's full_block event. The returned subscription
    /// is retained internally and torn down on destruction (or detach()).
    /// Call once, after the node and header chain exist.
    void attach(bch::interfaces::Node& node) {
        m_sub = node.full_block.subscribe(
            [this](const BlockType& block) { on_full_block(block); });
    }

    /// Drop the subscription early (idempotent). Destruction does this anyway.
    void detach() {
        if (m_sub) {
            m_sub->dispose();
            m_sub.reset();
        }
    }

    /// Fold one received full block into the ABLA tracker. Public so the
    /// out-of-tree harness can drive it without a live Event/socket; in
    /// production it is invoked only by the full_block subscription.
    void on_full_block(const BlockType& block) {
        // Identity: SHA256d of the 80-byte header (the hash used for inv/getdata
        // and the key the header index stores).
        const uint256 hash = block_hash(static_cast<const BlockHeaderType&>(block));

        // Height source: the best-chain header index. Absent => not on our best
        // chain (yet) => skip and let the tracker's gap-detect handle the
        // resulting discontinuity (=> floor) rather than guess a height.
        const auto entry = m_chain.get_header(hash);
        if (!entry) {
            LOG_DEBUG_COIND << "[EMB-BCH] ABLA feed: block " << hash.GetHex().substr(0, 16)
                            << "... not on indexed best chain -- skipped (gap-detect will floor)";
            return;
        }

        // Size: the block's ACTUAL serialized byte length via this module's own
        // legacy (no-witness) block Serialize. This is the consensus serialized
        // size ABLA folds through NextBlockState.
        const uint64_t serialized_size =
            static_cast<uint64_t>(pack(block).size());

        m_tracker.record_block_size(entry->height, serialized_size);

        LOG_DEBUG_COIND << "[EMB-BCH] ABLA feed: height=" << entry->height
                        << " size=" << serialized_size
                        << " current=" << (m_tracker.is_current(entry->height) ? "yes" : "no")
                        << " budget=" << m_tracker.budget_for_tip(m_tracker.cursor_height());
    }

    bool is_attached() const { return static_cast<bool>(m_sub); }

    ~AblaBlockFeed() { detach(); }

private:
    AblaTracker&       m_tracker;
    const HeaderChain& m_chain;
    std::shared_ptr<EventDisposable> m_sub;
};

} // namespace coin
} // namespace bch