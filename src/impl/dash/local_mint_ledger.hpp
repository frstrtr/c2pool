// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// local_mint_ledger.hpp — display-only orphan/sibling gauge for LOCAL mints.
//
// Why this exists: /local_stats reported `orphan 0 / dead 0 / efficiency 1.0`
// on a node that was in fact losing ~76% of the shares it minted to siblings.
// Those numbers come from the sharechain-wide StaleInfo tally, and every share
// this node mints is stamped StaleInfo::none (mint_runloop.hpp) — so a share
// that is minted, broadcast, verified, and then simply LOSES the head race is
// invisible in every existing counter. We were blind to a revenue-sized defect
// for hours because of it.
//
// This ledger closes that hole from the other end: remember the hashes WE
// minted, and once the best chain has grown `settle_depth` shares past one of
// them, ask a single cheap question — is it still an ancestor of the best
// share? If not, it is a sibling/orphan and it earns us nothing.
//
// Strictly display-only:
//   * nothing here is consulted by share validation, mint contents, the
//     coinbase, PPLNS weights, or the won-block path;
//   * StaleInfo stamping is NOT touched (that IS consensus-visible);
//   * the pending set is bounded (kMaxPending) and settle() is O(pending),
//     driven off the existing best-share-changed event — no new timer.
//
// Header-only, fenced to src/impl/dash/, KAT-able with a fake chain.
// ============================================================================

#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

namespace dash::mint {

/// Verdict for one locally minted share, as of the current best chain.
enum class MintVerdict {
    pending,    ///< best chain has not yet grown settle_depth past it
    on_chain,   ///< still an ancestor of (or equal to) the best share
    off_chain,  ///< a sibling/orphan — it lost the head race
    gone        ///< no longer in the tracker (pruned/dropped) — unknowable
};

/// Classify one locally minted share against the current best share.
///
/// Cheap by construction: get_acc_height() is the cached O(1) TrackerView
/// height and get_nth_parent_via_skip() is the O(log n) Bitcoin-Core skip-list
/// walk — the same two primitives the producer walks already use. The caller
/// holds the tracker read guard.
template <typename ChainT>
inline MintVerdict classify_local_mint(ChainT& chain,
                                       const uint256& best_share,
                                       const uint256& minted,
                                       int32_t settle_depth)
{
    if (best_share.IsNull() || minted.IsNull())
        return MintVerdict::pending;
    if (!chain.contains(minted))
        return MintVerdict::gone;          // pruned/dropped before it settled
    if (!chain.contains(best_share))
        return MintVerdict::pending;       // best not (yet) in this view

    const int32_t minted_height = chain.get_acc_height(minted);
    const int32_t best_height   = chain.get_acc_height(best_share);
    if (minted_height <= 0 || best_height <= 0)
        return MintVerdict::pending;       // heights not resolvable yet

    const int32_t depth = best_height - minted_height;
    if (depth < settle_depth)
        return MintVerdict::pending;       // too shallow to call — reorg window

    const uint256 ancestor = chain.get_nth_parent_via_skip(best_share, depth);
    if (ancestor.IsNull())
        return MintVerdict::pending;       // skip-list could not answer
    return (ancestor == minted) ? MintVerdict::on_chain : MintVerdict::off_chain;
}

/// Bounded, thread-safe tally of locally minted shares and their fate.
class LocalMintLedger
{
public:
    /// Best-chain depth a mint must be buried under before we call it. Small
    /// (the DASH sharechain reorgs shallowly) but non-zero so a share that is
    /// merely NEWER than the published best share is never miscounted.
    static constexpr int32_t kSettleDepth = 3;
    /// Hard bound on the un-settled set (a stalled/looping settle can never
    /// grow memory). Oldest entries are dropped and counted as `dropped`.
    static constexpr std::size_t kMaxPending = 512;

    struct Stats {
        uint64_t minted   = 0;   ///< local mints recorded since start
        uint64_t on_chain = 0;   ///< settled: still on the best chain
        uint64_t orphaned = 0;   ///< settled: sibling/orphan (lost the race)
        uint64_t gone     = 0;   ///< settled: left the tracker before verdict
        uint64_t dropped  = 0;   ///< evicted un-settled (pending bound hit)
        uint64_t pending  = 0;   ///< awaiting settle depth
        /// orphaned / (orphaned + on_chain); 0.0 when nothing settled yet.
        double   orphan_rate = 0.0;
    };

    /// Record a share this node just minted onto the sharechain.
    void record_mint(const uint256& hash)
    {
        if (hash.IsNull()) return;
        std::lock_guard<std::mutex> lk(m_mutex);
        ++m_minted;
        m_pending.push_back(hash);
        while (m_pending.size() > kMaxPending) {
            m_pending.pop_front();
            ++m_dropped;
        }
    }

    /// Settle every pending mint the classifier can now call. `classify` is
    /// invoked once per pending entry and must be cheap (see
    /// classify_local_mint). Safe to call as often as the tip moves.
    template <typename ClassifyFn>
    void settle(ClassifyFn classify)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            switch (classify(*it)) {
            case MintVerdict::on_chain:  ++m_on_chain; it = m_pending.erase(it); break;
            case MintVerdict::off_chain: ++m_orphaned; it = m_pending.erase(it); break;
            case MintVerdict::gone:      ++m_gone;     it = m_pending.erase(it); break;
            case MintVerdict::pending:   ++it;                                   break;
            }
        }
    }

    Stats stats() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        Stats s;
        s.minted   = m_minted;
        s.on_chain = m_on_chain;
        s.orphaned = m_orphaned;
        s.gone     = m_gone;
        s.dropped  = m_dropped;
        s.pending  = static_cast<uint64_t>(m_pending.size());
        const uint64_t settled = m_on_chain + m_orphaned;
        if (settled > 0)
            s.orphan_rate = static_cast<double>(m_orphaned) / static_cast<double>(settled);
        return s;
    }

    std::size_t pending_count() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_pending.size();
    }

private:
    mutable std::mutex     m_mutex;
    std::deque<uint256>    m_pending;
    uint64_t m_minted{0};
    uint64_t m_on_chain{0};
    uint64_t m_orphaned{0};
    uint64_t m_gone{0};
    uint64_t m_dropped{0};
};

} // namespace dash::mint
