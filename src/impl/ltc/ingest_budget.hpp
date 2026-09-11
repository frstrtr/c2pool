// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC inbound-share ADMISSION BOUNDS (memory, not consensus).
//
// Why this exists: the LTC pool node self-aborted on rss_limit_mb under an
// ingest storm (contabo 2026-09-09..11). The only bound on the ingest path was
// NodeImpl::MAX_PENDING_ADDS, which caps the number of DEFERRED BATCHES waiting
// for the tracker lock. That cap is (a) downstream of the phase-1 verify-pool
// backlog, which had no bound at all, and (b) a count of batches, not of shares
// or bytes — one batch is one sharereply (up to 1000 shares) or one unsolicited
// `shares` message (bounded only by the 32 MiB socket cap). Both holes let a
// single peer push hundreds of MB of deserialised shares into the process
// before MAX_PENDING_ADDS was ever consulted.
//
// IngestBudget bounds the ingest pipeline in SHARES and BYTES at the point of
// admission (NodeImpl::processing_shares), i.e. BEFORE any scrypt job is posted.
// The reservation is held by the owning HandleSharesData and released by its
// destructor, so it covers the whole life of a batch: verify-pool backlog,
// m_pending_adds queue, and phase 2.
//
// REWARD-SAFETY: this is an admission bound, nothing else. A refused batch is
// indistinguishable, for consensus purposes, from a batch the peer never sent —
// no share is accepted, rejected, re-scored, or paid differently because of it.
// Peers re-advertise their best share on every handshake and every best-change,
// think() recomputes `desired` every cycle, and the ancestor walk re-requests a
// parent it still does not have, so a refused batch is re-offered.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ltc
{

/// Inflight accounting for admitted-but-not-yet-destroyed share batches.
///
/// THREAD MODEL: try_admit() is called ONLY from the io thread
/// (processing_shares is reached from the protocol handlers and from the
/// download_shares reply callback, both io-thread). release() can run on any
/// thread, because the last owning reference to a HandleSharesData may be
/// dropped by a verify-pool worker. That is why the counters are atomics and
/// why try_admit may reserve-then-roll-back: with a single admitter the
/// transient overshoot is invisible to anyone but the rolling-back caller
/// itself, and release() only ever decrements amounts a successful admit
/// reserved, so neither counter can go negative.
class IngestBudget
{
public:
    IngestBudget(std::size_t max_shares, std::size_t max_bytes)
        : m_max_shares(max_shares), m_max_bytes(max_bytes) {}

    /// Reserve n shares / b bytes. Returns false and reserves NOTHING when
    /// either ceiling would be crossed.
    bool try_admit(std::size_t n, std::size_t b)
    {
        const std::size_t shares_after = m_shares.fetch_add(n, std::memory_order_acq_rel) + n;
        const std::size_t bytes_after  = m_bytes.fetch_add(b, std::memory_order_acq_rel) + b;
        if (shares_after <= m_max_shares && bytes_after <= m_max_bytes)
            return true;
        m_shares.fetch_sub(n, std::memory_order_acq_rel);
        m_bytes.fetch_sub(b, std::memory_order_acq_rel);
        return false;
    }

    /// Give back a reservation made by a successful try_admit().
    void release(std::size_t n, std::size_t b)
    {
        if (n) m_shares.fetch_sub(n, std::memory_order_acq_rel);
        if (b) m_bytes.fetch_sub(b, std::memory_order_acq_rel);
    }

    std::size_t shares() const { return m_shares.load(std::memory_order_relaxed); }
    std::size_t bytes()  const { return m_bytes.load(std::memory_order_relaxed); }
    std::size_t max_shares() const { return m_max_shares; }
    std::size_t max_bytes()  const { return m_max_bytes; }

private:
    std::atomic<std::size_t> m_shares{0};
    std::atomic<std::size_t> m_bytes{0};
    std::size_t m_max_shares;
    std::size_t m_max_bytes;
};

/// Depth bound for the recursive ancestor walk in download_shares().
///
/// The walk ("the oldest share in this reply has an unknown parent, so ask for
/// that parent too") had NO termination condition other than reaching a hash we
/// already hold — it would walk to genesis. think() refuses to emit `desired`
/// for anything in the pruning zone (share_tracker.hpp: 2*chain_length+10), but
/// the recursion never consulted that rule, so it fetched shares that
/// clean_tracker Step 3 would drop again as soon as they landed.
///
/// REWARD-SAFETY: the PPLNS window is chain_length; everything deeper than
/// 2*chain_length+10 below a head is what drop-tails removes and what think()
/// already declines to request. Stopping the fetch there cannot change any
/// payout, because such a share can never enter a payout computation.
///
/// `depth` is the number of shares already pulled by THIS walk.
inline bool walk_may_continue(std::uint64_t depth, std::uint64_t chain_length)
{
    return depth < (2 * chain_length + 10);
}

} // namespace ltc
