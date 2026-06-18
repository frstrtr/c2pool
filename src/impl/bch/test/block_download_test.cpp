// ---------------------------------------------------------------------------
// bch::coin::block_download::BlockDownloadWindow -- M5 full-block body.
// Pins the windowed headers-first block-download policy that NodeP2P drives
// during cold-start IBD: enqueue learned header hashes, keep at most
// MAX_BLOCKS_IN_FLIGHT getdata(MSG_BLOCK) outstanding, and top the window up
// as blocks arrive. Header-only over coin/block_download.hpp + <core/uint256>;
// no peer, socket, or coin lib.
//
// The behavior under test (the gap this slice closed): before this, IBD walked
// the header chain to the peer tip but never getdata'd a single block body, so
// the ABLA size feed / block-connector had no real block data and cold-start
// IBD could not complete. The window turns the synced header stream into a
// bounded, self-topping-up block download.
//
// p2pool-merged-v36 surface: NONE. per-coin isolation: src/impl/bch/ only.
// ---------------------------------------------------------------------------

#include <cassert>
#include <iostream>
#include <vector>

#include <core/uint256.hpp>

#include "../coin/block_download.hpp"

using bch::coin::block_download::BlockDownloadWindow;
using bch::coin::block_download::DEFAULT_MAX_BLOCKS_IN_FLIGHT;

// Deterministic distinct hashes (no Math.random) -- hash i = uint256(i+1).
static uint256 H(uint64_t i) { return uint256(base_uint<256>(i + 1)); }

static std::vector<uint256> hashes(uint64_t lo, uint64_t hi) {
    std::vector<uint256> v;
    for (uint64_t i = lo; i < hi; ++i) v.push_back(H(i));
    return v;
}

int main()
{
    // ---- Window bounds outstanding getdata at max_in_flight ----------------
    {
        BlockDownloadWindow w(4);
        assert(w.idle());
        // Enqueue a maximal-ish IBD batch of 10 headers.
        assert(w.enqueue(hashes(0, 10)) == 10);
        assert(w.queued() == 10);
        assert(w.has_capacity());

        // First drain requests exactly the window size (4), oldest-first.
        auto req = w.next_requests();
        assert(req.size() == 4);
        assert(req[0] == H(0) && req[3] == H(3));   // chain order preserved
        assert(w.in_flight() == 4);
        assert(w.queued() == 6);

        // Window is full -> a second drain with no arrivals yields nothing.
        assert(w.next_requests().empty());
        assert(w.in_flight() == 4);
    }

    // ---- Arrivals free slots; window tops up oldest-first ------------------
    {
        BlockDownloadWindow w(4);
        w.enqueue(hashes(0, 10));
        w.next_requests();                          // H0..H3 in flight

        // H0 arrives (was in flight) -> frees one slot.
        assert(w.on_block_received(H(0)) == true);
        assert(w.in_flight() == 3);
        auto req = w.next_requests();               // top up by 1
        assert(req.size() == 1 && req[0] == H(4));
        assert(w.in_flight() == 4 && w.queued() == 5);

        // Drain the rest as blocks arrive, in order.
        for (uint64_t i = 1; i < 10; ++i) {
            assert(w.on_block_received(H(i)) == true);
            w.next_requests();
        }
        assert(w.idle());
        assert(w.queued() == 0 && w.in_flight() == 0);
    }

    // ---- Dedupe: re-announce / overlapping locator batch never re-requests --
    {
        BlockDownloadWindow w(8);
        assert(w.enqueue(hashes(0, 5)) == 5);
        // Overlapping batch (3..8): only 5,6,7 are new.
        assert(w.enqueue(hashes(3, 8)) == 3);
        assert(w.queued() == 8);

        auto req = w.next_requests();               // window 8 >= 8 queued
        assert(req.size() == 8);
        // No hash requested twice.
        std::vector<uint256> seen;
        for (auto& h : req) {
            for (auto& s : seen) assert(!(s == h));
            seen.push_back(h);
        }

        // A block we already pulled, re-announced, is not re-queued.
        assert(w.on_block_received(H(2)) == true);
        assert(w.enqueue({H(2)}) == 0);
        assert(w.queued() == 0);
    }

    // ---- Unsolicited block: not in flight, reported false, still remembered --
    {
        BlockDownloadWindow w(4);
        assert(w.on_block_received(H(99)) == false); // never requested
        // ...and remembering it means a later headers batch won't queue it.
        assert(w.enqueue({H(99)}) == 0);
    }

    // ---- Degenerate window (0 -> clamped to 1) still makes progress --------
    {
        BlockDownloadWindow w(0);
        assert(w.max_in_flight() == 1);
        w.enqueue(hashes(0, 3));
        auto req = w.next_requests();
        assert(req.size() == 1 && req[0] == H(0));
        assert(w.next_requests().empty());          // window full at 1
        assert(w.on_block_received(H(0)) == true);
        req = w.next_requests();
        assert(req.size() == 1 && req[0] == H(1));
    }

    // ---- Default window size is the BCHN/Bitcoin per-peer default ----------
    {
        BlockDownloadWindow w;
        assert(w.max_in_flight() == DEFAULT_MAX_BLOCKS_IN_FLIGHT);
        assert(DEFAULT_MAX_BLOCKS_IN_FLIGHT == 16);
    }

    // ---- expire(): stalled in-flight requests are evicted + re-queued ------
    {
        BlockDownloadWindow w(2);
        w.enqueue(hashes(0, 4));                    // [H0 H1 H2 H3]
        auto req = w.next_requests(/*now=*/100);    // H0,H1 issued @100
        assert(req.size() == 2);
        assert(w.in_flight() == 2 && w.queued() == 2);

        // Not yet past the timeout: nothing evicted.
        assert(w.expire(/*now=*/105, /*timeout=*/10).empty());
        assert(w.in_flight() == 2);

        // Past the timeout (110-100 >= 10): both stalled requests evicted,
        // window freed, and they go back to the FRONT of the queue.
        auto evicted = w.expire(/*now=*/110, /*timeout=*/10);
        assert(evicted.size() == 2);
        assert(w.in_flight() == 0);
        assert(w.queued() == 4);                    // H0,H1 re-queued ahead of H2,H3

        // Retried oldest-first: the next window pulls exactly the two stalled
        // hashes (ahead of the never-requested H2/H3).
        auto retry = w.next_requests(/*now=*/200);
        assert(retry.size() == 2);
        std::vector<uint256> rset(retry.begin(), retry.end());
        assert((rset[0] == H(0) || rset[0] == H(1)));
        assert((rset[1] == H(0) || rset[1] == H(1)) && rset[0] != rset[1]);
    }

    // ---- expire(): only the stale request goes, fresh ones stay -----------
    {
        BlockDownloadWindow w(2);
        w.enqueue(hashes(0, 3));                    // [H0 H1 H2]
        w.next_requests(/*now=*/100);               // H0,H1 issued @100
        assert(w.on_block_received(H(1)) == true);  // H1 arrives, frees a slot
        w.next_requests(/*now=*/150);               // H2 issued @150
        // in flight: H0@100, H2@150. timeout 50 at now=155 => only H0 is stale.
        auto evicted = w.expire(/*now=*/155, /*timeout=*/50);
        assert(evicted.size() == 1 && evicted[0] == H(0));
        assert(w.in_flight() == 1);                 // H2 still outstanding

        // A block that arrives AFTER its eviction is reported unsolicited
        // (no longer in flight) -- caller still applies it; window unaffected.
        assert(w.on_block_received(H(0)) == false);
    }

    // ---- tick-driven re-issue cycle: a requeued request gets a FRESH issue
    //      tick on redrain, so it is not immediately re-expired the next tick
    //      (mirrors the NodeP2P expire-timer -> drain_block_window contract) --
    {
        BlockDownloadWindow w(1);
        w.enqueue(hashes(0, 1));                    // [H0]
        auto r0 = w.next_requests(/*now=*/10);      // H0 issued @10
        assert(r0.size() == 1 && r0[0] == H(0));
        // Stall: at now=70 (>= timeout 60) H0 is evicted + requeued to front.
        auto ev = w.expire(/*now=*/70, /*timeout=*/60);
        assert(ev.size() == 1 && ev[0] == H(0));
        assert(w.in_flight() == 0 && w.queued() == 1);
        // Redrain re-issues H0 with a NEW issue tick (=72), not the stale @10.
        auto r1 = w.next_requests(/*now=*/72);
        assert(r1.size() == 1 && r1[0] == H(0));
        // One cadence later it must NOT re-expire (72..77 elapsed 5 < 60),
        // proving the issue tick was refreshed rather than carried over.
        assert(w.expire(/*now=*/77, /*timeout=*/60).empty());
        assert(w.in_flight() == 1);
    }

    std::cout << "bch block_download window: ALL PASS\n";
    return 0;
}
