// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH daemonless — LIVE tip-tracking controller for the full-history replay
// UTXO fold (PR-C1, --embedded-fold-live).
//
// The replay UTXO fold (replay_utxo_fold.hpp) is a strict left fold of the
// whole chain into a dashd-equivalent coin set, gate-proven byte-equal to
// dashd's `gettxoutsetinfo hash_serialized_2`. Opened alone it is a SNAPSHOT
// frozen at its resume cursor R: a coin unspent at R but spent on-chain in
// (R, tip] would still read UNSPENT, which — if that stale answer priced a
// mempool tx — could select a double-spend of an already-confirmed input and
// lose a block. dashd never has this problem because its CCoinsViewCache is
// kept AT the tip: ConnectBlock applies each connected block (spending inputs,
// adding outputs) and DisconnectBlock undoes on a reorg.
//
// This controller ports exactly those two halves onto the fold so it becomes a
// true tip-tracking view, and adds a fail-closed serving guard:
//
//   * ADVANCE (dashd ConnectBlock): on_block_connected() applies each connected
//     block to the fold in ascending, no-gap order, advancing R toward the tip.
//     It also retains the block body in a bounded ring so the undo half can key
//     the spent-coin restore, exactly like dashd hands DisconnectBlock the block
//     it is undoing.
//
//   * UNDO (dashd DisconnectBlock): handle_reorg() walks the fold cursor down
//     over every orphaned tip block — using the retained body — until the fork
//     point (the first height whose switched-chain hash already matches the
//     fold's block there). A reorg deeper than the retained window fails closed
//     (marks the view stranded) rather than leaving a wrong coin unspent. This
//     mirrors PR-B's MinedCommitmentIndex connect+undo halves.
//
//   * AT-TIP SERVING GUARD (belt-and-suspenders): at_tip() answers true ONLY
//     when the fold is caught up to the serve tip AND its tip block is the one
//     on the served chain at that height. The mempool consults the fold for
//     pricing/viability ONLY when this holds; behind tip (cold start, a gap in
//     the live feed, mid-reorg, or a stranded view) it withholds, which is
//     byte-identical to master's fee-unknown exclusion — never a bad block.
//
// One std::mutex serialises every fold touch (advance / undo / serve-path read)
// so the io-thread block feed and any serve-path reader cannot tear the fold's
// in-memory overlay. Constructed only under --embedded-fold-live; absent, the
// fold is never opened and this class is never instantiated — the fee path and
// pin gate are byte-identical to master.

#include "block.hpp"                 // BlockType / BlockHeaderType
#include "replay_utxo_fold.hpp"      // dash::coin::replay::ReplayUtxoFold

#include <impl/dash/crypto/hash_x11.hpp>

#include <core/coin/utxo.hpp>        // core::coin::Coin / Outpoint
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace dash {
namespace coin {

class FoldLiveController {
public:
    using Coin       = ::core::coin::Coin;
    using Outpoint   = ::core::coin::Outpoint;
    using ReplayFold = ::dash::coin::replay::ReplayUtxoFold;
    // Canonical (served-chain) block hash at a height — supplied by the caller
    // from the header chain. std::nullopt when the height is not indexed.
    using HashAtFn   = std::function<std::optional<uint256>(uint32_t)>;

    explicit FoldLiveController(std::shared_ptr<ReplayFold> fold)
        : m_fold(std::move(fold))
    {
        // Retain at most one undo window of block bodies (bounded, same window
        // the fold keeps its undo records over): a reorg deeper than this is
        // handled fail-closed, not by unbounded body retention.
        if (m_fold) m_body_ring_cap = m_fold->undo_window();
    }

    // ── ADVANCE (dashd ConnectBlock) ───────────────────────────────────────
    // Apply one connected block to the fold, tracking the tip. Idempotent
    // redelivery and out-of-order/gap deliveries are handled by the fold's own
    // strict in-order contract (a gap is REFUSED and the fold simply stays
    // behind tip, which the serving guard treats as "not caught up"). Returns
    // whatever the fold returned (true = advanced or idempotently acked).
    bool on_block_connected(const BlockType& block, uint32_t height)
    {
        std::lock_guard<std::mutex> lk(m_mu);
        if (!m_fold) return false;
        const uint256 hash = block_identity(block);
        const bool ok = m_fold->on_replay_block(height, hash, block);
        // Retain the body only for the height the fold now actually sits at, so
        // the undo half has the exact block it must disconnect.
        if (ok && m_fold->have_cursor() && m_fold->best_height() == height) {
            m_bodies[height] = block;
            prune_bodies_locked();
        }
        return ok;
    }

    // ── UNDO (dashd DisconnectBlock) ───────────────────────────────────────
    // Roll the fold cursor down over the orphaned tail to the fork point.
    // `canonical_hash_at` returns the switched chain's hash at a height. Returns
    // true when the fold tip is consistent with the switched chain afterwards;
    // false (and latches "stranded") when a body outside the retained window
    // would be needed — the serving guard then withholds until a restart /
    // fresh contiguous fold re-establishes chain identity. Never leaves a coin
    // wrongly unspent (fail-closed, the over-withholding direction).
    bool handle_reorg(const HashAtFn& canonical_hash_at)
    {
        std::lock_guard<std::mutex> lk(m_mu);
        if (!m_fold || !m_fold->have_cursor()) return false;
        while (m_fold->best_height() > 0) {
            const uint32_t h = m_fold->best_height();
            const auto want = canonical_hash_at(h);
            if (want && *want == m_fold->best_hash())
                return true;  // fold tip already on the switched chain
            auto it = m_bodies.find(h);
            if (it == m_bodies.end() || !m_fold->disconnect_tip(it->second)) {
                m_reorg_stranded = true;  // fail-closed
                return false;
            }
            m_bodies.erase(it);
        }
        return true;
    }

    // ── AT-TIP SERVING GUARD (remediation B) ───────────────────────────────
    // The fold may feed a pricing/viability decision ONLY when it is caught up
    // to `serve_tip` AND its tip block is the served chain's block at that
    // height. Any other state (behind tip, mid-reorg, stranded) => false.
    bool at_tip(uint32_t serve_tip, const HashAtFn& canonical_hash_at) const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        return at_tip_locked(serve_tip, canonical_hash_at);
    }

    // Serve-path coin lookup, self-guarded by at_tip. Returns true and fills
    // `out` only when the fold is at tip AND holds the coin unspent. This is
    // the function handed to the mempool (fold-input pricing) and, at tip, to
    // the pin gate. Off-tip it returns false, which the mempool reads as
    // fee-unknown (byte-identical to master).
    bool resolve_for_serve(const Outpoint& op, Coin& out,
                           uint32_t serve_tip,
                           const HashAtFn& canonical_hash_at) const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        if (!at_tip_locked(serve_tip, canonical_hash_at)) return false;
        return m_fold->get_coin(op, out) && !out.is_spent();
    }

    std::shared_ptr<ReplayFold> fold() const { return m_fold; }
    bool reorg_stranded() const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_reorg_stranded;
    }
    uint32_t best_height() const
    {
        std::lock_guard<std::mutex> lk(m_mu);
        return (m_fold && m_fold->have_cursor()) ? m_fold->best_height() : 0;
    }

private:
    bool at_tip_locked(uint32_t serve_tip, const HashAtFn& canonical_hash_at) const
    {
        if (!m_fold || !m_fold->have_cursor() || m_reorg_stranded) return false;
        const uint32_t fh = m_fold->best_height();
        if (fh < serve_tip) return false;              // not caught up
        const auto want = canonical_hash_at(fh);
        return want.has_value() && *want == m_fold->best_hash();  // chain identity
    }

    static uint256 block_identity(const BlockType& block)
    {
        auto packed = ::pack(static_cast<const BlockHeaderType&>(block));
        return ::dash::crypto::hash_x11(packed.get_span());
    }

    void prune_bodies_locked()
    {
        // std::map is height-ordered; drop the lowest heights past the cap.
        while (m_bodies.size() > m_body_ring_cap && !m_bodies.empty())
            m_bodies.erase(m_bodies.begin());
    }

    mutable std::mutex             m_mu;
    std::shared_ptr<ReplayFold>    m_fold;
    std::map<uint32_t, BlockType>  m_bodies;             // retained undo bodies
    std::size_t                    m_body_ring_cap = 100;
    bool                           m_reorg_stranded = false;
};

} // namespace coin
} // namespace dash
