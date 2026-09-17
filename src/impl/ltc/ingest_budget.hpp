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
// PER-PEER FAIRNESS (issue #1600): the global ceiling above is fair-share blind
// — one peer could accumulate batch after batch until it occupied the entire
// inflight budget and crowded every other peer out of admission.
// try_admit_for_peer()/release_for_peer() additionally track, per source peer,
// the shares+bytes that peer currently holds inflight, and REFUSE a peer that is
// ALREADY holding its PER-PEER slice — a strict SUB-DIVISION of the global
// ceiling (per_peer_max_*, ceil(global/2) here). The check is on CURRENT usage,
// not current+incoming, so a peer's first/only batch is never throttled (a
// single batch is bounded by the p2p wire/socket message cap anyway) while a
// peer that has reached its slice is frozen out until it drains, which is what
// stops it monopolising the pipeline across many batches. The per-peer cap NEVER
// lets the global counters exceed their existing ceiling — the global bound is
// enforced exactly as before; the cap only decides WHICH peer is refused first
// under contention. The peer key is any stable per-peer string (NodeImpl passes
// NetService::to_string()).
//
// REWARD-SAFETY: this is an admission bound, nothing else. A refused batch is
// indistinguishable, for consensus purposes, from a batch the peer never sent —
// no share is accepted, rejected, re-scored, or paid differently because of it.
// Peers re-advertise their best share on every handshake and every best-change,
// think() recomputes `desired` every cycle, and the ancestor walk re-requests a
// parent it still does not have, so a refused batch is re-offered.
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace ltc
{

/// Inflight accounting for admitted-but-not-yet-destroyed share batches.
///
/// THREAD MODEL: try_admit()/try_admit_for_peer() are called ONLY from the io
/// thread (processing_shares is reached from the protocol handlers and from the
/// download_shares reply callback, both io-thread). release()/release_for_peer()
/// can run on any thread, because the last owning reference to a
/// HandleSharesData may be dropped by a verify-pool worker. That is why the
/// global counters are atomics and why try_admit may reserve-then-roll-back:
/// with a single admitter the transient overshoot is invisible to anyone but
/// the rolling-back caller itself, and release() only ever decrements amounts a
/// successful admit reserved, so neither counter can go negative. The per-peer
/// map is additionally guarded by m_peer_mtx because release_for_peer() may run
/// off the io thread concurrently with an io-thread admit. try_admit_for_peer()
/// holds m_peer_mtx across its whole reserve-and-maybe-rollback sequence so its
/// m_peer mutations never race a concurrent release; m_peer_mtx is a leaf lock
/// (no other lock is taken while it is held), so this is deadlock-free.
class IngestBudget
{
public:
    /// Result of a per-peer admission attempt. GlobalFull means the shared
    /// ceiling is the binding constraint (the caller may make room by evicting
    /// the OLDEST inflight shares of ANY peer and retry); PeerCapped means THIS
    /// peer is already holding its fair-share slice (evicting other peers' work
    /// would be a monopoly subsidy, so the caller must refuse WITHOUT evicting).
    enum class AdmitResult { Admitted, GlobalFull, PeerCapped };

    // ── Per-peer cap (#1600) ─────────────────────────────────────────────
    // A single peer may hold at most PER_PEER_BUDGET_NUM/PER_PEER_BUDGET_DEN of
    // the global ceiling inflight at once. Chosen as 1/2: it strictly
    // sub-divides the global bound (so the global ceiling is still the hard
    // memory limit and is never raised), blocks a single-peer monopoly (at
    // least two peers must share the pipeline), yet stays FAR above the working
    // set a legitimate high-hashrate peer holds — a cold-bootstrap download
    // pulls <=1000-share replies from ONE advertiser, self-paced at network RTT
    // (~1000 shares inflight at a time), well under half of the 8192-share
    // ceiling. A tiny fixed cap would throttle exactly that honest case, so the
    // cap is expressed as a fraction of the global budget instead.
    static constexpr std::size_t PER_PEER_BUDGET_NUM = 1;
    static constexpr std::size_t PER_PEER_BUDGET_DEN = 2;

    IngestBudget(std::size_t max_shares, std::size_t max_bytes)
        : m_max_shares(max_shares), m_max_bytes(max_bytes) {}

    /// Reserve n shares / b bytes GLOBALLY (no per-peer accounting). Returns
    /// false and reserves NOTHING when either ceiling would be crossed. Kept for
    /// the global-only callers and the unit tests; the production ingest path
    /// uses try_admit_for_peer().
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

    /// Per-peer admission (#1600). Reserves n shares / b bytes for `peer` iff
    /// BOTH the global ceiling AND this peer's per-peer cap still hold; reserves
    /// NOTHING otherwise. The per-peer cap is checked FIRST so that a PeerCapped
    /// refusal never touches the global counters — the caller can then refuse
    /// without evicting anyone. A GlobalFull refusal has already rolled the
    /// per-peer reservation back, so a later retry (after the caller evicts to
    /// free global headroom) still sees this peer under its cap.
    AdmitResult try_admit_for_peer(std::size_t n, std::size_t b, const std::string& peer)
    {
        const std::size_t pps = per_peer_max_shares();
        const std::size_t ppb = per_peer_max_bytes();
        // Hold m_peer_mtx across the WHOLE sequence — the per-peer check and
        // increment, the global reserve + overflow test, AND the rollback — so
        // the per-peer increment and its possible rollback are ATOMIC with
        // respect to concurrent release_for_peer() calls, which may run on
        // verify-pool worker threads and mutate the SAME m_peer entry. The
        // earlier version released the mutex before the GlobalFull rollback and
        // then called peer_release_locked() unlocked — a data race on m_peer.
        //
        // DEADLOCK-FREE: m_peer_mtx is a LEAF lock. Nothing reached while it is
        // held ever acquires another lock — the global counters are lock-free
        // std::atomics, and peer_release_locked() only touches m_peer. No other
        // code path takes m_peer_mtx and then a second lock, so no lock-ordering
        // cycle exists. Holding the mutex across the atomic reserve is also
        // CORRECT: a concurrent release only ever LOWERS the global counters, so
        // it can never make this overflow test wrongly admit (shares_after is
        // read from THIS call's own fetch_add, not a re-load).
        std::lock_guard<std::mutex> g(m_peer_mtx);
        auto& e = m_peer[peer];
        // Refuse a peer that ALREADY holds its fair-share slice in EITHER
        // dimension. This is deliberately a "current usage" check, not a
        // "current + n" check: a peer's FIRST batch always gets in, so a
        // legitimate large single message is never throttled by the per-peer
        // cap (a single admitted batch is bounded by the p2p wire/socket
        // message cap regardless, and the GLOBAL ceiling below is still the
        // hard memory bound). What the cap stops is a peer ACCUMULATING many
        // batches to crowd others out: once its inflight reaches its slice it
        // is frozen out until it drains, leaving headroom for other peers.
        if (e.shares >= pps || e.bytes >= ppb)
        {
            if (e.shares == 0 && e.bytes == 0) m_peer.erase(peer);
            return AdmitResult::PeerCapped;   // no counter mutated
        }
        e.shares += n;
        e.bytes  += b;

        // Per-peer room granted; now enforce the global ceiling exactly as the
        // global-only path does. On overflow, roll BOTH back (still under lock).
        const std::size_t shares_after = m_shares.fetch_add(n, std::memory_order_acq_rel) + n;
        const std::size_t bytes_after  = m_bytes.fetch_add(b, std::memory_order_acq_rel) + b;
        if (shares_after <= m_max_shares && bytes_after <= m_max_bytes)
            return AdmitResult::Admitted;
        m_shares.fetch_sub(n, std::memory_order_acq_rel);
        m_bytes.fetch_sub(b, std::memory_order_acq_rel);
        peer_release_locked(n, b, peer);   // m_peer_mtx held: contract satisfied
        return AdmitResult::GlobalFull;
    }

    /// Give back a GLOBAL reservation made by a successful try_admit().
    void release(std::size_t n, std::size_t b)
    {
        if (n) m_shares.fetch_sub(n, std::memory_order_acq_rel);
        if (b) m_bytes.fetch_sub(b, std::memory_order_acq_rel);
    }

    /// Give back a reservation made by a successful try_admit_for_peer():
    /// lowers both the global counters and this peer's per-peer counters.
    void release_for_peer(std::size_t n, std::size_t b, const std::string& peer)
    {
        if (n) m_shares.fetch_sub(n, std::memory_order_acq_rel);
        if (b) m_bytes.fetch_sub(b, std::memory_order_acq_rel);
        std::lock_guard<std::mutex> g(m_peer_mtx);
        peer_release_locked(n, b, peer);
    }

    std::size_t shares() const { return m_shares.load(std::memory_order_relaxed); }
    std::size_t bytes()  const { return m_bytes.load(std::memory_order_relaxed); }
    std::size_t max_shares() const { return m_max_shares; }
    std::size_t max_bytes()  const { return m_max_bytes; }

    /// Per-peer ceiling: ceil(global * NUM / DEN), a strict sub-division of the
    /// global ceiling. ceil so a 1-share global budget still admits 1 per peer.
    std::size_t per_peer_max_shares() const
    {
        return (m_max_shares * PER_PEER_BUDGET_NUM + PER_PEER_BUDGET_DEN - 1) / PER_PEER_BUDGET_DEN;
    }
    std::size_t per_peer_max_bytes() const
    {
        return (m_max_bytes * PER_PEER_BUDGET_NUM + PER_PEER_BUDGET_DEN - 1) / PER_PEER_BUDGET_DEN;
    }

    /// Current inflight held by a single peer (0 if none). For telemetry/tests.
    std::size_t peer_shares(const std::string& peer) const
    {
        std::lock_guard<std::mutex> g(m_peer_mtx);
        auto it = m_peer.find(peer);
        return it == m_peer.end() ? 0u : it->second.shares;
    }
    std::size_t peer_bytes(const std::string& peer) const
    {
        std::lock_guard<std::mutex> g(m_peer_mtx);
        auto it = m_peer.find(peer);
        return it == m_peer.end() ? 0u : it->second.bytes;
    }
    /// Number of peers with a non-empty inflight reservation (for tests).
    std::size_t tracked_peers() const
    {
        std::lock_guard<std::mutex> g(m_peer_mtx);
        return m_peer.size();
    }

private:
    struct PeerInflight { std::size_t shares{0}; std::size_t bytes{0}; };

    // Lower `peer`'s per-peer counters by (n,b), clamping at zero, and drop the
    // entry once it reaches zero so the map cannot grow without bound. Caller
    // holds m_peer_mtx.
    void peer_release_locked(std::size_t n, std::size_t b, const std::string& peer)
    {
        auto it = m_peer.find(peer);
        if (it == m_peer.end()) return;
        it->second.shares = (n < it->second.shares) ? it->second.shares - n : 0;
        it->second.bytes  = (b < it->second.bytes)  ? it->second.bytes  - b : 0;
        if (it->second.shares == 0 && it->second.bytes == 0)
            m_peer.erase(it);
    }

    std::atomic<std::size_t> m_shares{0};
    std::atomic<std::size_t> m_bytes{0};
    std::size_t m_max_shares;
    std::size_t m_max_bytes;

    mutable std::mutex m_peer_mtx;
    std::map<std::string, PeerInflight> m_peer;
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
