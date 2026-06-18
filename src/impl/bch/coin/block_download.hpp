#pragma once
// ---------------------------------------------------------------------------
// bch::coin::block_download -- M5 full-block body. Windowed headers-first block
// download, factored out of NodeP2P as a PURE, peer-free state machine so the
// in-flight window policy is unit-testable without a live socket.
//
// THE GAP THIS CLOSES: header_sync.hpp drives the *header* chain forward --
// ContinueSync re-issues getheaders so cold-start IBD walks the whole header
// chain to the peer tip. But those headers' BLOCKS were never getdata'd: only
// the tiny BIP130 tip-announce path (RequestBlocks, <= 3 headers) pulled full
// blocks. So IBD synced 2000-header batches forward indefinitely and never
// downloaded a single block body -- and the embedded daemon's ABLA size feed
// (abla_block_feed.hpp) and the full-block -> mempool reconciliation
// (block_connector.hpp) need REAL block data, not just headers. Cold-start IBD
// could never actually complete.
//
// POLICY (mirrors Bitcoin/BCHN headers-first block download, net_processing):
//   * headers learned during IBD are enqueued in chain order;
//   * at most MAX_BLOCKS_IN_FLIGHT getdata(MSG_BLOCK) are outstanding at once
//     (a bounded window -- never blast the whole 2000-header batch as getdata
//     and stall on a slow peer / unbounded memory);
//   * each arriving block frees one window slot, and the window tops up from
//     the front of the queue (oldest-first), so blocks stream in at the peer's
//     pace until the queue drains.
//
// DEDUPE: a hash already queued, in flight, or already received is never
// re-requested, so an overlapping getheaders locator batch or a re-announce
// cannot double-download.
//
// NOT IN THIS SLICE (deferred per integrator 2026-06-18): in-flight timeout /
// eviction (a block requested but never delivered by a stalling peer). That is
// robustness hardening worth doing only once blocks are actually flowing; this
// slice builds the happy-path window first.
//
// p2pool-merged-v36 SURFACE: NONE -- pure SPV/IBD wire-sync plumbing; no PoW
// hash, share format, coinbase commitment, AuxPoW, or PPLNS math. PER-COIN
// ISOLATION: src/impl/bch/coin/ only; header-only, build-INERT (bch stays
// skip-green).
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <core/uint256.hpp>

namespace bch::coin::block_download {

/// Default cap on outstanding getdata(MSG_BLOCK) requests. 16 matches the
/// Bitcoin/BCHN per-peer MAX_BLOCKS_IN_FLIGHT default -- enough to keep a fast
/// peer's pipe full without unbounded memory on a slow one.
inline constexpr std::size_t DEFAULT_MAX_BLOCKS_IN_FLIGHT = 16;

/// Bounded headers-first block-download window. Peer-free + deterministic:
/// callers feed it learned header hashes (enqueue), drain the requests it wants
/// issued now (next_requests), and report arrivals (on_block_received) which
/// free window slots for the next drain.
class BlockDownloadWindow {
    /// Low-64 of a cryptographic hash is already uniform -- no further mixing.
    struct HashHasher {
        std::size_t operator()(const uint256& h) const { return h.GetLow64(); }
    };

public:
    explicit BlockDownloadWindow(std::size_t max_in_flight = DEFAULT_MAX_BLOCKS_IN_FLIGHT)
        : m_max_in_flight(max_in_flight ? max_in_flight : 1) {}

    /// Enqueue block hashes learned from a headers batch, in chain order.
    /// Skips any hash already queued, in flight, or already received so a
    /// re-announce / overlapping locator batch never double-requests. Returns
    /// the count newly enqueued.
    std::size_t enqueue(const std::vector<uint256>& hashes)
    {
        std::size_t added = 0;
        for (const auto& h : hashes) {
            if (m_known.count(h)) continue;
            m_known.insert(h);
            m_queue.push_back(h);
            ++added;
        }
        return added;
    }

    /// Pop hashes to request now, up to the free window slots
    /// (max_in_flight - in_flight). Marks them in flight. Oldest-first
    /// (chain order) so block bodies are pulled in the order they were learned.
    std::vector<uint256> next_requests(uint64_t now_tick = 0)
    {
        std::vector<uint256> out;
        while (m_in_flight.size() < m_max_in_flight && !m_queue.empty()) {
            uint256 h = m_queue.front();
            m_queue.pop_front();
            m_in_flight.emplace(h, now_tick);
            out.push_back(h);
        }
        return out;
    }

    /// Report an arrived block. Removes it from the in-flight set (freeing a
    /// window slot) and remembers it so a later re-announce is not re-queued.
    /// Returns true iff it was one we actually had in flight (vs. an
    /// unsolicited / already-handled block).
    bool on_block_received(const uint256& h)
    {
        auto it = m_in_flight.find(h);
        if (it == m_in_flight.end()) {
            // Unsolicited or already handled: still remember it so a later
            // headers batch never queues it, but report not-in-flight.
            m_known.insert(h);
            return false;
        }
        m_in_flight.erase(it);
        return true;
    }

    /// Evict in-flight requests that have gone stale -- a block we getdata'd but a
    /// stalling peer never delivered. now_tick and timeout_ticks are in the caller's
    /// monotonic unit (the same unit passed to next_requests()); any request issued
    /// at issue_tick with now_tick - issue_tick >= timeout_ticks is pushed back to
    /// the FRONT of the queue (retry oldest-first, ahead of not-yet-requested hashes)
    /// and dropped from the in-flight set, freeing its window slot. The hash stays in
    /// m_known (still wanted, still deduped). Returns the evicted hashes so the caller
    /// can log / consider peer demotion. A block that arrives after eviction is handled
    /// normally (on_block_received reports it unsolicited, but emit_full_block still
    /// applies it). Deferred from the windowed-download slice (2cc7de44) until block
    /// bodies actually flowed end-to-end.
    std::vector<uint256> expire(uint64_t now_tick, uint64_t timeout_ticks)
    {
        std::vector<uint256> evicted;
        for (auto it = m_in_flight.begin(); it != m_in_flight.end(); ) {
            if (now_tick - it->second >= timeout_ticks) {
                evicted.push_back(it->first);
                it = m_in_flight.erase(it);
            } else {
                ++it;
            }
        }
        // Re-queue the stalled hashes ahead of not-yet-requested ones so a stuck
        // block is retried before fresh tip blocks.
        for (const auto& h : evicted) m_queue.push_front(h);
        return evicted;
    }

    std::size_t in_flight()     const { return m_in_flight.size(); }
    std::size_t queued()        const { return m_queue.size(); }
    std::size_t max_in_flight() const { return m_max_in_flight; }
    /// True when there is window room AND something queued to fill it.
    bool has_capacity() const { return m_in_flight.size() < m_max_in_flight && !m_queue.empty(); }
    /// True when nothing is queued and nothing is outstanding (IBD drained).
    bool idle() const { return m_queue.empty() && m_in_flight.empty(); }

private:
    std::size_t m_max_in_flight;
    std::deque<uint256> m_queue;                            // pending, chain order
    std::unordered_map<uint256, uint64_t, HashHasher> m_in_flight; // hash -> tick getdata issued
    std::unordered_set<uint256, HashHasher> m_known;        // queued ∪ inflight ∪ received
};

} // namespace bch::coin::block_download
