// SPDX-License-Identifier: AGPL-3.0-or-later
// [L-KR1Z1S] drop-tails KAT — the clean_tracker() Step 3 tail-dropping loop
// (ltc::drop_tails, drop_tails.hpp) driven over a REAL ltc::ShareTracker of
// ~18k shares while a concurrent download walker (pool::download::build_stops,
// the exact call download_shares makes) runs on another thread.
//
// WHY: the experimental kr1z1s node SIGSEGV'd inside drop-tails at
// iter=300 chain_size=18349. The loop used to be inline in clean_tracker, so
// nothing could drive it from a test. Run this target under ASan
// (-fsanitize=address) to catch a use-after-free between the compute-thread
// prune (chain.remove frees the share) and the IO-thread stops walk.
//
// LOCK DISCIPLINE MIRRORED FROM PRODUCTION:
//   - pruner: std::unique_lock on the tracker mutex for the whole drop_tails
//     call (clean_tracker holds the exclusive lock across Steps 1-4).
//   - walker: std::shared_lock(try_to_lock); on failure skip (download_shares
//     abandons the request), on success build_stops under the lock (#1562).
// Set C2POOL_KAT_UNLOCKED_WALKER=1 to run the walker WITHOUT the lock (the
// pre-#1562 shape) — a negative control showing the KAT has teeth under ASan.
// It is never set in CI.
//
// Expected count: one unrooted linear chain of N shares has head height N; each
// iteration drops reverse[tail] (the oldest share) while min head height >=
// 2*CL+10, so a call drops N - (2*CL+9) shares, one per iteration.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/ltc/drop_tails.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <pool/share_download.hpp>

namespace {

uint256 hx(const std::string& tail)
{
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

uint256 share_hash(uint64_t salt, uint64_t i)
{
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%llx",
                  static_cast<unsigned long long>((salt << 32) + 0x1000 + i));
    return hx(buf);
}

// Append `count` shares to the chain whose current tip is `prev` (or start a
// new unrooted segment at missing parent `prev`). Every 3rd share is also put
// in the borrowing `verified` view so drop_tails exercises verified.remove.
uint256 append(ltc::ShareTracker& t, uint256 prev, uint64_t salt, uint64_t first,
               uint64_t count, std::vector<uint256>* verified_hashes)
{
    for (uint64_t i = first; i < first + count; ++i) {
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = share_hash(salt, i);
        sh->m_prev_hash = prev;
        ltc::ShareType st;
        st = sh;
        t.add(st);
        if (i % 3 == 0) {
            t.verified.add(st);
            if (verified_hashes) verified_hashes->push_back(sh->m_hash);
        }
        prev = sh->m_hash;
    }
    return prev;
}

constexpr int32_t kCL = 8640;  // LTC mainnet chain_length -> threshold 17290
constexpr int32_t kKeep = 2 * kCL + 9;

} // namespace

// 18k shares: the first call runs 711 drop iterations (> the 300 the crash
// reached), then 40 growth rounds each add 10 shares and drop 10 more, with the
// walker spinning on its own thread the whole time.
TEST(LtcDropTailsAsanKat, ConcurrentWalkerOver18kShares)
{
    const bool unlocked_walker = std::getenv("C2POOL_KAT_UNLOCKED_WALKER") != nullptr;

    ltc::ShareTracker t;
    std::shared_mutex mtx;
    std::vector<uint256> verified_hashes;
    const uint256 missing_parent = hx("dead0001");
    constexpr uint64_t N0 = 18000;

    uint256 tip;
    {
        std::unique_lock lock(mtx);
        tip = append(t, missing_parent, 1, 0, N0, &verified_hashes);
    }
    ASSERT_EQ(t.chain.size(), N0);

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> walks{0};
    std::thread walker([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            if (unlocked_walker) {
                auto stops = pool::download::build_stops(t.chain);
                (void)stops;
                ++walks;
                continue;
            }
            std::shared_lock lock(mtx, std::try_to_lock);
            if (!lock.owns_lock()) { std::this_thread::yield(); continue; }
            auto stops = pool::download::build_stops(t.chain);
            EXPECT_FALSE(stops.empty());
            ++walks;
        }
    });

    ltc::SupersedeHint hint;  // inactive, as on a converged node
    int total_iters = 0;
    uint64_t next = N0;
    constexpr int kRounds = 40;
    constexpr uint64_t kGrow = 10;
    for (int round = 0; round <= kRounds; ++round) {
        int dropped = 0;
        size_t size_after = 0;
        {
            std::unique_lock lock(mtx);
            if (round > 0) {
                tip = append(t, tip, 1, next, kGrow, &verified_hashes);
                next += kGrow;
            }
            const size_t size_before = t.chain.size();
            dropped = ltc::drop_tails(t.chain, t.verified, kCL, hint);
            size_after = t.chain.size();
            EXPECT_EQ(size_before - size_after, static_cast<size_t>(dropped));
        }
        EXPECT_EQ(dropped, round == 0 ? static_cast<int>(N0 - kKeep)
                                      : static_cast<int>(kGrow)) << "round " << round;
        EXPECT_EQ(size_after, static_cast<size_t>(kKeep)) << "round " << round;
        total_iters += dropped;  // one share per iteration on a linear chain
        // Give the walker a window between prunes, as the 5s timer does.
        for (int k = 0; k < 50; ++k) std::this_thread::yield();
    }
    stop = true;
    walker.join();

    EXPECT_GE(total_iters, 300);
    EXPECT_GT(walks.load(), 0u) << "walker never ran alongside the pruner";

    // The borrowing view must never outlive the owning chain's entries.
    std::unique_lock lock(mtx);
    for (const auto& h : verified_hashes)
        if (t.verified.contains(h))
            EXPECT_TRUE(t.chain.contains(h)) << h.GetHex();
    EXPECT_TRUE(t.chain.contains(tip));
    EXPECT_EQ(t.chain.get_height(tip), kKeep);
}

// A segment below 2*CL+10 is never touched; one above it is trimmed to exactly
// 2*CL+9. Small CL keeps it fast.
TEST(LtcDropTailsAsanKat, ThresholdPerSegment)
{
    ltc::ShareTracker t;
    constexpr int32_t cl = 5;  // threshold 20, keep 19
    const uint256 tip_a = append(t, hx("dead00a"), 2, 0, 35, nullptr);
    const uint256 tip_b = append(t, hx("dead00b"), 3, 0, 19, nullptr);
    ltc::SupersedeHint hint;
    EXPECT_EQ(ltc::drop_tails(t.chain, t.verified, cl, hint), 35 - 19);
    EXPECT_EQ(t.chain.get_height(tip_a), 19);
    EXPECT_EQ(t.chain.get_height(tip_b), 19);
    EXPECT_EQ(t.chain.size(), 38u);
}

// get_tails() is keyed by the MISSING parent hash, i.e. the segment id that
// SupersedeHint carries as target_segment_last. An active hint must exempt the
// whole challenger segment from the trim; once the hint deactivates, normal
// drop-tails resumes and the segment is trimmed to 2*CL+9.
// (Was SupersedeExemptionCurrentlyInert, which pinned the old dead guard
// `chain.contains(tail_hash)` that never matched and trimmed 30 -> 19.)
TEST(LtcDropTailsAsanKat, SupersedeExemptionKeepsChallengerSegment)
{
    ltc::ShareTracker t;
    constexpr int32_t cl = 5;
    const uint256 seg = hx("dead00c");
    const uint256 tip = append(t, seg, 4, 0, 30, nullptr);
    ASSERT_EQ(t.chain.get_last(tip), seg);

    ltc::SupersedeHint hint;
    hint.active = true;
    hint.target_head = tip;
    hint.target_segment_last = t.chain.get_last(tip);
    EXPECT_EQ(ltc::drop_tails(t.chain, t.verified, cl, hint), 0);
    EXPECT_EQ(t.chain.size(), 30u);
    EXPECT_EQ(t.chain.get_height(tip), 30);

    hint.active = false;  // challenger verified to CHAIN_LENGTH -> hint off
    EXPECT_EQ(ltc::drop_tails(t.chain, t.verified, cl, hint), 30 - 19);
    EXPECT_EQ(t.chain.get_height(tip), 19);
}

// Two segments, both above the threshold. The hint names the challenger: it
// survives the trim at full depth while the other segment is trimmed as usual.
TEST(LtcDropTailsAsanKat, ChallengerSurvivesTrimSiblingTrimmed)
{
    ltc::ShareTracker t;
    constexpr int32_t cl = 5;  // threshold 20, keep 19
    const uint256 seg_ch = hx("dead00d");
    const uint256 tip_ch = append(t, seg_ch, 5, 0, 32, nullptr);
    const uint256 tip_other = append(t, hx("dead00e"), 6, 0, 35, nullptr);

    ltc::SupersedeHint hint;
    hint.active = true;
    hint.target_head = tip_ch;
    hint.target_segment_last = seg_ch;
    EXPECT_EQ(ltc::drop_tails(t.chain, t.verified, cl, hint), 35 - 19);
    EXPECT_EQ(t.chain.get_height(tip_ch), 32);
    EXPECT_EQ(t.chain.get_last(tip_ch), seg_ch);
    EXPECT_EQ(t.chain.get_height(tip_other), 19);
    EXPECT_EQ(t.chain.size(), 32u + 19u);
}
