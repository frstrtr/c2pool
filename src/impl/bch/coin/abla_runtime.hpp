#pragma once
// ---------------------------------------------------------------------------
// bch::coin::AblaRuntime -- M5: the CLOSING assembly of the embedded-daemon
// ABLA size loop. The four pieces existed in isolation after slices C/sG:
//   AblaTracker        -- folds each best-chain block size, holds running State
//   AblaBlockFeed      -- subscribes to interfaces::Node::full_block, sinks size
//   EmbeddedCoinNode   -- consumes the tracker for the dynamic build budget
//   full_block event   -- fires from all 3 p2p delivery paths (direct / cmpct /
//                         blocktxn) AFTER the merkle-root accept gate (sG)
// ...but nothing OWNED a tracker, owned a feed, and tied them to a live node +
// EmbeddedCoinNode. This runtime is that owner: one object the embedded-daemon
// front-end (coin::Node) holds, constructed once the HeaderChain exists and
// wired once the node + EmbeddedCoinNode exist. After wire():
//   full_block --> AblaBlockFeed --> AblaTracker --> EmbeddedCoinNode::getwork
//                  --> TemplateBuilder dynamic ABLA budget (else 32 MB floor).
//
// COLD START = floor anchor. Absent a BCHN-pinned {height,State}, we anchor at
// the activation/floor State (limit == the 32 MB floor); folding live sizes
// forward can only RAISE the budget, never undercut the floor -- the
// never-undercut invariant holds from the first block. A later BCHN pin is a
// reanchor() passthrough, no reconstruction.
//
// LIFETIME: m_tracker is declared before m_feed so the feed`s AblaTracker&
// binds to a fully-constructed member, and the tracker outlives both the feed
// subscription and the raw pointer handed to EmbeddedCoinNode. The runtime must
// outlive the node it wired (the daemon owns both for its whole run).
//
// p2pool-merged-v36 SURFACE: NONE. Pure local build-time block-size budget --
// no PoW hash, share format, coinbase commitment, or PPLNS math is touched.
// PER-COIN ISOLATION: src/impl/bch/coin/ only; every type reached is bch-owned.
// Build-INERT / source-only: header-only, no impl_bch CMake registration
// (bch stays skip-green; don`t race ci-steward).
// ---------------------------------------------------------------------------

#include "abla.hpp"              // abla::State (reanchor / pinned-anchor ctor)
#include "abla_tracker.hpp"      // AblaTracker
#include "abla_block_feed.hpp"   // AblaBlockFeed
#include "header_chain.hpp"      // HeaderChain (height source for the feed)
#include "node_interface.hpp"    // bch::interfaces::Node (full_block source)
#include "template_builder.hpp"  // EmbeddedCoinNode (set_abla_tracker sink)

#include <core/log.hpp>

#include <cstdint>

namespace bch {
namespace coin {

/// Owns the ABLA tracker + full_block feed for one embedded daemon instance and
/// wires them to a live node + EmbeddedCoinNode. Single-threaded use from the
/// daemon block-processing context (same contract as AblaTracker / feed).
class AblaRuntime {
public:
    /// Cold-start: anchor at the activation/floor State for `anchor_height`.
    /// Safe default when no BCHN-pinned anchor is available yet.
    AblaRuntime(bool is_testnet, uint32_t anchor_height, const HeaderChain& chain)
        : m_tracker(AblaTracker::floor_anchored(is_testnet, anchor_height)),
          m_feed(m_tracker, chain) {}

    /// BCHN-pinned anchor: start from a known-good {height, State} captured at
    /// daemon start. Lets the live budget track the real consensus limit from
    /// block one instead of climbing from the floor.
    AblaRuntime(bool is_testnet, uint32_t anchor_height, abla::State anchor_state,
                const HeaderChain& chain)
        : m_tracker(is_testnet, anchor_height, anchor_state),
          m_feed(m_tracker, chain) {}

    AblaRuntime(const AblaRuntime&) = delete;
    AblaRuntime& operator=(const AblaRuntime&) = delete;

    /// Close the loop: attach the feed to the node`s full_block event and hand
    /// the tracker to the EmbeddedCoinNode. Call once, after both exist.
    void wire(bch::interfaces::Node& node, EmbeddedCoinNode& embedded) {
        m_feed.attach(node);
        embedded.set_abla_tracker(&m_tracker);
        LOG_INFO << "[EMB-BCH] ABLA runtime wired: full_block -> feed -> tracker"
                 << " -> template builder (anchor_height=" << m_tracker.cursor_height()
                 << ", budget=" << m_tracker.budget_for_tip(m_tracker.cursor_height())
                 << ", " << (m_tracker.is_stale() ? "stale" : "current") << ")";
    }

    /// Re-establish a known-good anchor after a gap/reorg or on a fresh BCHN
    /// pin. Thin passthrough to the tracker; the feed keeps its subscription.
    void reanchor(uint32_t height, abla::State state) {
        m_tracker.reanchor(height, state);
        LOG_INFO << "[EMB-BCH] ABLA runtime reanchored at height=" << height
                 << " budget=" << m_tracker.budget_for_tip(height);
    }

    AblaTracker&       tracker()       { return m_tracker; }
    const AblaTracker& tracker() const { return m_tracker; }
    bool               is_wired() const { return m_feed.is_attached(); }

private:
    AblaTracker   m_tracker;   // declared first: outlives m_feed + the EmbeddedCoinNode pointer
    AblaBlockFeed m_feed;
};

} // namespace coin
} // namespace bch
