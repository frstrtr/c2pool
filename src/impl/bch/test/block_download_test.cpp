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

    std::cout << "bch block_download window: ALL PASS\n";
    return 0;
}
