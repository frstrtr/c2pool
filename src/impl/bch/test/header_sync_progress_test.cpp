// ---------------------------------------------------------------------------
// bch::coin::header_sync SYNC-TO-PEER-TIP sequence soak (M5 full-block body).
//
// header_sync_test.cpp pins classify_headers_batch() one batch at a time. But
// the property the embedded daemon actually relies on is COMPOSITIONAL: that
// the per-batch policy, driven in a loop, makes cold-start IBD CONVERGE -- walk
// the whole header chain from the anchor and HALT exactly at the peer tip,
// without (a) stalling mid-chain after one batch, or (b) spinning forever on
// ContinueSync. A single-batch unit test cannot observe either failure mode.
// This fixture drives the real sync loop NodeP2P runs (getheaders -> ingest ->
// classify -> re-issue) as a pure simulation over batch sizes and pins the
// convergence + steady-state-follow claims directly.
//
// Invariants asserted:
//   1. cold-start IBD over a large gap CONVERGES: synced == peer_tip exactly
//      (no overshoot, no header left behind) for both a non-multiple gap and
//      an exact-multiple-of-cap gap.
//   2. the loop TERMINATES: round count is bounded at floor(gap/cap)+1 for
//      every gap -- the exact-multiple case takes one trailing empty/partial
//      round and then halts (never an infinite ContinueSync).
//   3. mid-IBD rounds are all ContinueSync until the final round; the final
//      round is the ONLY non-ContinueSync (the convergence point).
//   4. steady-state follow: once caught up, a BIP130 single-block tip announce
//      drives RequestBlocks (fetch the new block) -- NOT a spurious re-entry
//      into ContinueSync IBD.
//   5. degenerate gaps (0 and 1) behave: empty chain -> immediate Idle in one
//      round; one-header gap -> RequestBlocks (announce) in one round.
//
// Build-INERT / source-only: header-only over coin/header_sync.hpp -- no node,
// socket, RPC, or coin lib (impl_bch stays unregistered; bch = skip-green,
// don't race ci-steward). p2pool-merged-v36 surface: NONE -- pure SPV/IBD wire-
// sync plumbing (no PoW hash, share format, coinbase commitment, AuxPoW, or
// PPLNS math). per-coin isolation: src/impl/bch/coin/ only.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "../coin/header_sync.hpp"

using bch::coin::header_sync::Followup;
using bch::coin::header_sync::classify_headers_batch;
using bch::coin::header_sync::MAX_HEADERS_RESULTS;
using bch::coin::header_sync::DEFAULT_ANNOUNCE_THRESHOLD;

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// Result of driving the headers-first IBD loop against a peer that holds
// `gap` headers beyond our anchor, serving at most `cap` per `headers` message.
struct SyncRun {
    std::uint64_t synced       = 0;  // headers ingested when the loop halted
    std::size_t   rounds       = 0;  // getheaders round-trips taken
    std::size_t   continue_n   = 0;  // rounds that classified ContinueSync
    Followup      final_action = Followup::Idle; // why the loop halted
};

// Mirror of NodeP2P's `headers` follow-up loop: request up to `cap`, ingest the
// batch, classify; ContinueSync re-issues, anything else halts the IBD walk.
// MAX_ROUNDS is a TEST-SIDE runaway guard -- if the policy ever fails to
// converge, we trip it and the bound assertion (inv. 2) catches the bug instead
// of the test hanging.
SyncRun drive_ibd(std::uint64_t gap, std::size_t cap = MAX_HEADERS_RESULTS,
                  std::size_t announce = DEFAULT_ANNOUNCE_THRESHOLD)
{
    SyncRun r;
    const std::size_t MAX_ROUNDS = 1'000'000;
    while (r.rounds < MAX_ROUNDS) {
        ++r.rounds;
        std::uint64_t remaining = gap - r.synced;
        std::size_t batch = (remaining >= cap) ? cap
                                               : static_cast<std::size_t>(remaining);
        r.synced += batch;
        Followup f = classify_headers_batch(batch, announce, cap);
        if (f == Followup::ContinueSync) { ++r.continue_n; continue; }
        r.final_action = f;
        break;
    }
    return r;
}

// --- Fork-convergence soak: drive the IBD loop through choose_continue_locator
// against a peer whose tip sits past a FORK from our latest header. The
// COMPOSITIONAL counterpart to header_sync_test's pure choose_continue_locator
// cases: proves the back-off locator makes the *loop* CONVERGE where the
// degraded single-hash locator STALLS -- the silent-stall failure PR #208 fixed.
// Header-layer "false_evict" analog = headers the peer re-serves that we already
// hold; anchoring at the exact common ancestor keeps that at ZERO.
using bch::coin::header_sync::choose_continue_locator;

// Hash stand-in: main-chain blocks hash to their height; our fork-only blocks
// hash to height + FORK_TAG so the peer (which holds only the main chain) can
// never anchor a fork-only locator entry.
constexpr std::uint64_t FORK_TAG = 1'000'000'000ull;

inline std::uint64_t our_hash(std::uint64_t height, std::uint64_t fork_point) {
    return (height <= fork_point) ? height : height + FORK_TAG;
}
inline bool peer_can_anchor(std::uint64_t hash, std::uint64_t peer_tip) {
    return hash < FORK_TAG && hash <= peer_tip;   // a main-chain hash the peer holds
}

// Mirror of HeaderChain::get_locator_internal (BIP31 back-off): dense head of 11
// consecutive heights from the tip, then the step doubles each entry down to 0.
std::vector<std::uint64_t> make_chain_locator(std::uint64_t tip_height,
                                              std::uint64_t fork_point) {
    std::vector<std::uint64_t> loc;
    std::int64_t step = 1;
    std::int64_t h = static_cast<std::int64_t>(tip_height);
    while (h >= 0) {
        loc.push_back(our_hash(static_cast<std::uint64_t>(h), fork_point));
        if (h == 0) break;
        h -= step;
        if (h < 0) h = 0;
        if (loc.size() > 10) step *= 2;
    }
    return loc;
}

struct ForkRun {
    std::uint64_t synced    = 0;  // highest MAIN-chain height we hold at halt
    std::size_t   reissues  = 0;  // ContinueSync getheaders re-issues
    std::size_t   redundant = 0;  // already-held headers re-served (false_evict analog)
    bool          converged = false;
    bool          stalled   = false;
};

// Drive the headers-first IBD continuation against a forked peer.
//  fork_tip    : height of OUR latest header (on a minority fork above fork_point)
//  fork_point  : last height common to us and the peer (the true common ancestor)
//  peer_tip    : the peer's main-chain tip we must converge to
//  use_provider: true  -> robust HeaderChain back-off locator wired (THE FIX)
//                false -> degraded single-hash fallback (no provider) -> empty chain_locator
ForkRun drive_forked_ibd(std::uint64_t fork_tip, std::uint64_t fork_point,
                         std::uint64_t peer_tip, bool use_provider,
                         std::size_t cap = MAX_HEADERS_RESULTS) {
    ForkRun r;
    std::uint64_t our_tip = fork_tip;          // height of our latest header
    std::uint64_t main_progress = fork_point;  // highest main height we already hold
    const std::size_t MAX_ROUNDS = 100000;     // runaway guard: a real stall trips it
    std::size_t rounds = 0;
    while (rounds < MAX_ROUNDS) {
        ++rounds;
        // Build the continuation locator exactly as NodeP2P now does.
        std::vector<std::uint64_t> chain_loc =
            use_provider ? make_chain_locator(our_tip, fork_point)
                         : std::vector<std::uint64_t>{};      // no provider -> degraded
        std::vector<std::uint64_t> loc =
            choose_continue_locator(chain_loc, our_hash(our_tip, fork_point));

        // Peer anchors at the FIRST (highest) locator entry it holds on its main
        // chain; if none, it returns nothing (the silent stall #208 addressed).
        std::int64_t anchor = -1;
        for (std::uint64_t hh : loc) {
            if (peer_can_anchor(hh, peer_tip)) { anchor = static_cast<std::int64_t>(hh); break; }
        }
        if (anchor < 0) { r.stalled = true; break; }   // cannot anchor -> stall

        std::uint64_t from = static_cast<std::uint64_t>(anchor);
        if (from >= peer_tip) break;                    // nothing new to serve -> caught up
        std::uint64_t want = peer_tip - from;
        std::size_t batch = (want >= cap) ? cap : static_cast<std::size_t>(want);
        std::uint64_t served_to = from + batch;

        // Headers in (from, main_progress] are ones we already hold -> re-served.
        if (from < main_progress)
            r.redundant += static_cast<std::size_t>(std::min(served_to, main_progress) - from);

        our_tip = served_to;                            // now on the peer's main chain
        if (served_to > main_progress) main_progress = served_to;
        r.synced = main_progress;

        Followup f = classify_headers_batch(batch, DEFAULT_ANNOUNCE_THRESHOLD, cap);
        if (f == Followup::ContinueSync) { ++r.reissues; continue; }
        break;                                          // converged / caught up
    }
    r.converged = (r.synced == peer_tip) && !r.stalled;
    return r;
}

} // namespace

int main()
{
    const std::size_t CAP = MAX_HEADERS_RESULTS; // 2000

    // ---- inv. 1 + 2 + 3: non-multiple gap (realistic cold-start anchor) -----
    // 955700 headers ~ a fresh sync to a near-tip BCH peer from the anchor.
    {
        const std::uint64_t gap = 955700;
        SyncRun r = drive_ibd(gap);
        CHECK(r.synced == gap);                       // converged exactly (inv.1)
        const std::size_t expect_rounds = gap / CAP + 1; // 477 full + 1 partial
        CHECK(r.rounds == expect_rounds);             // bounded + terminates (inv.2)
        CHECK(r.continue_n == r.rounds - 1);          // all but last = ContinueSync (inv.3)
        // 955700 % 2000 == 1700, above the announce threshold -> caught-up Idle.
        CHECK(r.final_action == Followup::Idle);
    }

    // ---- inv. 1 + 2: exact-multiple gap takes a trailing round, still halts --
    {
        const std::uint64_t gap = 954000;            // == 477 * 2000, exact multiple
        SyncRun r = drive_ibd(gap);
        CHECK(r.synced == gap);                       // converged exactly
        // 477 maximal ContinueSync rounds, then one remaining==0 (empty) Idle round.
        CHECK(r.rounds == gap / CAP + 1);             // 478, NOT infinite
        CHECK(r.continue_n == gap / CAP);             // exactly the 477 full batches
        CHECK(r.final_action == Followup::Idle);      // empty trailing batch -> Idle
    }

    // ---- inv. 2 (bound holds across many gap shapes) ------------------------
    for (std::uint64_t gap = 0; gap <= 8005; ++gap) {
        SyncRun r = drive_ibd(gap);
        CHECK(r.synced == gap);                       // always converges
        CHECK(r.rounds == gap / CAP + 1);             // always bounded
        CHECK(r.rounds <= 5);                         // <= floor(8005/2000)+1 = 5
    }

    // ---- inv. 4: steady-state follow after caught up ------------------------
    // A single new block announced via BIP130 -> RequestBlocks (fetch it), and
    // crucially NOT ContinueSync (no spurious IBD re-entry on a 1-block tip).
    CHECK(classify_headers_batch(1) == Followup::RequestBlocks);
    {
        SyncRun tip_advance = drive_ibd(/*gap=*/1);
        CHECK(tip_advance.rounds == 1);               // one round, no IBD walk
        CHECK(tip_advance.continue_n == 0);           // never entered ContinueSync
        CHECK(tip_advance.final_action == Followup::RequestBlocks);
    }

    // ---- inv. 5: degenerate gaps --------------------------------------------
    {
        SyncRun empty = drive_ibd(/*gap=*/0);
        CHECK(empty.synced == 0);
        CHECK(empty.rounds == 1);                     // single empty batch
        CHECK(empty.continue_n == 0);
        CHECK(empty.final_action == Followup::Idle);  // nothing arrived -> Idle
    }

    // ---- inv. 6: shallow fork -> back-off locator anchors at the EXACT common
    // ancestor, converges to peer tip, re-walks ZERO already-held headers
    // (false_evict analog == 0). Loop-level proof of PR #208 over a live-shaped
    // cursor (anchor 955700 -> peer tip 955822, the VM300 bchn-bch range).
    {
        const std::uint64_t peer_tip = 955822, fork_point = 955700;
        const std::uint64_t fork_tip = fork_point + 3;   // 3-block minority fork
        ForkRun r = drive_forked_ibd(fork_tip, fork_point, peer_tip, /*use_provider=*/true);
        CHECK(r.converged);                              // reached peer tip (no stall)
        CHECK(r.synced == peer_tip);
        CHECK(r.redundant == 0);                         // anchored at exact ancestor: 0 re-walk
        CHECK(r.reissues == (peer_tip - fork_point - 1) / CAP); // bounded re-issues
        CHECK(!r.stalled);
    }

    // ---- inv. 7: SAME fork, degraded single-hash locator (no provider) STALLS.
    // The peer cannot anchor our lone minority-fork tip -> serves nothing -> IBD
    // never converges. Proves the back-off provider is LOAD-BEARING, not cosmetic:
    // remove it and cold-start IBD across a fork silently hangs (the pre-#208 bug).
    {
        const std::uint64_t peer_tip = 955822, fork_point = 955700;
        const std::uint64_t fork_tip = fork_point + 3;
        ForkRun r = drive_forked_ibd(fork_tip, fork_point, peer_tip, /*use_provider=*/false);
        CHECK(r.stalled);                                // degraded path hangs on the fork
        CHECK(!r.converged);
        CHECK(r.synced < peer_tip);
    }

    // ---- inv. 8: DEEP fork (50 blocks) still converges via back-off, never
    // stalls; the re-walk stays bounded by one batch, not unbounded.
    {
        const std::uint64_t peer_tip = 955822, fork_point = 955700;
        const std::uint64_t fork_tip = fork_point + 50;  // deep minority fork
        ForkRun r = drive_forked_ibd(fork_tip, fork_point, peer_tip, /*use_provider=*/true);
        CHECK(r.converged);
        CHECK(r.synced == peer_tip);
        CHECK(!r.stalled);
        CHECK(r.redundant < CAP);                        // re-walk bounded, finite
    }

    if (failures == 0)
        std::cout << "bch header_sync sync-to-peer-tip soak: ALL PASS\n";
    else
        std::cout << "bch header_sync sync-to-peer-tip soak: " << failures << " FAIL\n";
    return failures == 0 ? 0 : 1;
}
