// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH FULL-HISTORY REPLAY — W2 bulk block-fetch lane KATs.
///
/// Pins the properties the replay transport promises
/// (src/impl/dash/coin/replay_bulk_fetch.hpp; design
/// docs/DASH_FULL_HISTORY_REPLAY_MODE.md §4.1/§4.3, WP W2):
///
///   (A) RANGE PARTITIONING — the wanted height span is handed out as
///       contiguous per-peer batches across the pool, per-peer in-flight
///       capped, window-bounded (the §4.3 bounded work-ahead buffer).
///   (B) RE-REQUEST — a timed-out request, a notfound answer, and a departed
///       peer each requeue their heights; the retry rotates AWAY from the
///       peer that failed.
///   (C) IN-ORDER DELIVERY + PRUNE — bodies arriving out of order are
///       delivered to the consumer strictly in height order with no gaps and
///       PRUNED immediately (never persisted); a consumer refusal fails the
///       lane closed.
///   (D) VERIFICATION — a body whose tx set does not fold to its header's
///       committed merkle root is rejected, counted and re-fetched, never
///       delivered.
///   (E) TIP PRIORITY — while a tracked tip body is outstanding (tip_busy),
///       the lane issues NO new bulk getdata.
///   (F) RESUMABILITY — the delivered high-water cursor round-trips its
///       versioned file; a resumed lane verifies the cursor hash against the
///       chain and FAILS CLOSED on mismatch instead of folding a different
///       branch.
///   (G) HEADER BACKFILL — the genesis→anchor walk links+claims batches,
///       joins the fast-start anchor exactly, and fails closed on a join
///       mismatch (the wrong-chain / hostile-peer case).
///   (H) CAPTURE — the optional segment-file cache round-trips records and a
///       torn tail truncates instead of corrupting.
///
/// Everything here is KAT-able without mainnet: the scheduler and lane are
/// pure/seam-injected, and synthetic chains use check_pow=false (X11 PoW on
/// real headers is exercised by the existing header-chain KATs; a live bulk
/// throughput smoke is a soak item, not a unit test — see the PR notes).
///
/// This TU compiles into the EXISTING allowlisted test_dash_p2p_node target
/// (no new test target, no workflow edit — the drift-guard stays green).

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_bulk_fetch.hpp>
#include <impl/dash/coin/header_chain.hpp>   // x11_hash

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

using dash::coin::BlockType;
using dash::coin::BlockHeaderType;
using dash::coin::MutableTransaction;
namespace rp = dash::coin::replay;

namespace {

// ── synthetic chain ───────────────────────────────────────────────────────
//
// Bodies are REAL BlockType objects whose tx set folds to the header's
// committed merkle root (single unique tx per height), so the lane's
// merkle-bind check runs the real code. PoW is not mined — the lane never
// checks PoW itself (the header INDEX it fetches against is PoW-checked by
// HeaderChain/HeaderBackfill, which have their own KATs).
struct SyntheticChain
{
    std::vector<BlockType> blocks;   // index = height
    std::vector<uint256>   hashes;

    explicit SyntheticChain(uint32_t n_heights)
    {
        uint256 prev;   // null
        for (uint32_t h = 0; h < n_heights; ++h)
        {
            BlockType b;
            b.m_version = 1;
            b.m_previous_block = prev;
            b.m_timestamp = 1700000000u + h;
            b.m_bits = 0x1e0fffff;
            b.m_nonce = h;
            MutableTransaction tx;
            tx.locktime = h;              // unique tx per height
            b.m_txs.push_back(tx);
            auto packed_tx = ::pack(b.m_txs[0]);
            b.m_merkle_root = ::Hash(packed_tx.get_span());
            const auto header = static_cast<BlockHeaderType>(b);
            auto packed = ::pack(header);
            const uint256 hash = dash::crypto::hash_x11(packed.get_span());
            blocks.push_back(b);
            hashes.push_back(hash);
            prev = hash;
        }
    }

    std::optional<uint256> hash_at(uint32_t h) const
    {
        if (h >= hashes.size()) return std::nullopt;
        return hashes[h];
    }
};

// ── lane rig: all seams captured, no sockets, no io_context ───────────────
struct LaneRig
{
    SyntheticChain chain;
    rp::CountingReplayConsumer counter;
    std::vector<std::string> peers{"p1:9999", "p2:9999", "p3:9999"};
    bool tip_busy{false};
    bool defer_higher{false};   // MN-checkpoint fold mid-replay (deconflict seam)
    uint32_t chain_height;

    struct SentBatch
    {
        std::string peer;
        std::vector<uint256> hashes;
    };
    std::vector<SentBatch> sent;
    std::vector<std::pair<std::string, uint256>> getheaders_sent;

    std::unique_ptr<rp::BulkFetchLane> lane;

    explicit LaneRig(uint32_t heights, rp::BulkFetchLane::Config cfg,
                     rp::HeaderBackfill* backfill = nullptr,
                     rp::ReplayCursorStore* cursor = nullptr,
                     rp::IReplayBlockConsumer* consumer_override = nullptr)
        : chain(heights), chain_height(heights - 1)
    {
        rp::BulkFetchLane::Seams seams;
        seams.hash_at = [this](uint32_t h) { return chain.hash_at(h); };
        seams.chain_height = [this] { return chain_height; };
        seams.eligible_peers = [this] { return peers; };
        seams.send_getdata = [this](const std::string& peer,
                                    const std::vector<uint256>& hashes) {
            sent.push_back({peer, hashes});
        };
        seams.send_getheaders = [this](const std::string& peer,
                                       const uint256& loc, const uint256&) {
            getheaders_sent.emplace_back(peer, loc);
        };
        seams.tip_busy = [this] { return tip_busy; };
        seams.defer_to_higher_priority = [this] { return defer_higher; };
        lane = std::make_unique<rp::BulkFetchLane>(
            std::move(seams), cfg, backfill,
            consumer_override ? consumer_override
                              : static_cast<rp::IReplayBlockConsumer*>(&counter),
            cursor);
    }

    /// Answer every outstanding sent batch with its real bodies, in the given
    /// (possibly shuffled) order. Returns bodies answered.
    std::size_t answer_all(std::mt19937* shuffle_rng = nullptr)
    {
        std::vector<std::pair<uint256, const BlockType*>> pending;
        for (auto& b : sent)
            for (auto& h : b.hashes)
            {
                auto it = std::find(chain.hashes.begin(), chain.hashes.end(), h);
                if (it == chain.hashes.end())
                {
                    ADD_FAILURE() << "lane requested an unknown hash";
                    continue;
                }
                const auto idx = static_cast<std::size_t>(
                    std::distance(chain.hashes.begin(), it));
                pending.emplace_back(h, &chain.blocks[idx]);
            }
        sent.clear();
        if (shuffle_rng)
            std::shuffle(pending.begin(), pending.end(), *shuffle_rng);
        for (auto& [h, blk] : pending)
            lane->on_block_body(h, *blk);
        return pending.size();
    }
};

std::string temp_path(const char* stem)
{
    static std::mt19937_64 rng{std::random_device{}()};
    return (std::filesystem::temp_directory_path() /
            (std::string(stem) + "-" + std::to_string(rng()))).string();
}

// ═══ (A) range partitioning ═══════════════════════════════════════════════

TEST(DashReplayBulkScheduler, RangePartitionsContiguousRunsAcrossPeers)
{
    SyntheticChain chain(200);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.window = 1000;
    cfg.per_peer_inflight = 32;
    cfg.batch = 8;
    s.configure(cfg);
    s.reset(10);
    s.set_target_end(199);

    const std::vector<std::string> peers{"a", "b", "c"};
    auto plan = s.pump(1000, peers,
                       [&](uint32_t h) { return chain.hash_at(h); }, 0);
    ASSERT_EQ(plan.size(), 3u);

    uint32_t expect = 10;
    std::set<std::string> seen_peers;
    for (const auto& a : plan)
    {
        seen_peers.insert(a.peer);
        // Each peer gets a CONTIGUOUS run of `batch` heights, and the runs
        // tile the span with no gap and no overlap.
        ASSERT_EQ(a.blocks.size(), cfg.batch);
        for (const auto& [h, hash] : a.blocks)
        {
            EXPECT_EQ(h, expect);
            EXPECT_EQ(hash, chain.hashes[h]);
            ++expect;
        }
    }
    EXPECT_EQ(seen_peers.size(), 3u);          // all peers loaded
    EXPECT_EQ(s.inflight_count(), 24u);        // 3 × batch
    EXPECT_EQ(s.next_height(), 34u);

    // Second pump keeps loading up to the per-peer cap, never beyond.
    for (int i = 0; i < 10; ++i)
        s.pump(1001 + i, peers,
               [&](uint32_t h) { return chain.hash_at(h); }, 0);
    for (const auto& [key, t] : s.tallies())
        EXPECT_LE(t.inflight, cfg.per_peer_inflight) << key;
    EXPECT_LE(s.inflight_count(), 3u * cfg.per_peer_inflight);
}

TEST(DashReplayBulkScheduler, WindowBoundsWorkAhead)
{
    SyntheticChain chain(5000);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.window = 100;              // small window
    cfg.per_peer_inflight = 64;
    cfg.batch = 32;
    s.configure(cfg);
    s.reset(0);
    s.set_target_end(4999);

    const std::vector<std::string> peers{"a", "b", "c", "d", "e", "f"};
    for (int i = 0; i < 50; ++i)
        s.pump(1000 + i, peers,
               [&](uint32_t h) { return chain.hash_at(h); }, /*buffered=*/0);
    // Nothing may be requested past delivered + window, regardless of pumps
    // and peer capacity (bounded residency — spec §4.3).
    EXPECT_LE(s.next_height(), 0u + cfg.window + 1);
    EXPECT_LE(s.inflight_count(), cfg.window);
}

// ═══ (B) re-request paths ═════════════════════════════════════════════════

TEST(DashReplayBulkScheduler, TimeoutRequeuesAndRotatesPeer)
{
    SyntheticChain chain(50);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.batch = 4;
    cfg.request_timeout_sec = 30;
    s.configure(cfg);
    s.reset(0);
    s.set_target_end(3);

    auto plan = s.pump(1000, {"a", "b"},
                       [&](uint32_t h) { return chain.hash_at(h); }, 0);
    ASSERT_EQ(plan.size(), 1u);               // 4 heights fit one batch
    const std::string first_peer = plan[0].peer;
    EXPECT_EQ(s.inflight_count(), 4u);

    // Not yet: 29 s.
    s.service(1029, {"a", "b"});
    EXPECT_EQ(s.inflight_count(), 4u);
    EXPECT_EQ(s.timeout_count(), 0u);

    // At 30 s: all four requeued.
    s.service(1030, {"a", "b"});
    EXPECT_EQ(s.inflight_count(), 0u);
    EXPECT_EQ(s.retry_count(), 4u);
    EXPECT_EQ(s.timeout_count(), 4u);

    // The retry avoids the peer that just failed: with two peers the whole
    // batch lands on the OTHER one.
    auto retry_plan = s.pump(1031, {"a", "b"},
                             [&](uint32_t h) { return chain.hash_at(h); }, 0);
    ASSERT_FALSE(retry_plan.empty());
    for (const auto& a : retry_plan)
        for ([[maybe_unused]] const auto& blk : a.blocks)
            EXPECT_NE(a.peer, first_peer);
}

TEST(DashReplayBulkScheduler, NotfoundRequeuesFrontAvoidingPeer)
{
    SyntheticChain chain(50);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.batch = 2;
    s.configure(cfg);
    s.reset(0);
    s.set_target_end(1);

    auto plan = s.pump(1000, {"a", "b"},
                       [&](uint32_t h) { return chain.hash_at(h); }, 0);
    ASSERT_EQ(plan.size(), 1u);
    const std::string asked = plan[0].peer;
    ASSERT_EQ(plan[0].blocks.size(), 2u);

    EXPECT_TRUE(s.on_notfound(plan[0].blocks[0].second));
    EXPECT_EQ(s.notfound_count(), 1u);
    EXPECT_EQ(s.retry_count(), 1u);
    // Unknown hash: not ours.
    EXPECT_FALSE(s.on_notfound(uint256::ONE));

    auto retry = s.pump(1001, {"a", "b"},
                        [&](uint32_t h) { return chain.hash_at(h); }, 0);
    ASSERT_FALSE(retry.empty());
    EXPECT_NE(retry[0].peer, asked);
    EXPECT_EQ(retry[0].blocks[0].first, plan[0].blocks[0].first);
}

TEST(DashReplayBulkScheduler, DepartedPeerRequestsRequeueImmediately)
{
    SyntheticChain chain(50);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.batch = 4;
    cfg.request_timeout_sec = 30;
    s.configure(cfg);
    s.reset(0);
    s.set_target_end(7);

    auto plan = s.pump(1000, {"a", "b"},
                       [&](uint32_t h) { return chain.hash_at(h); }, 0);
    ASSERT_EQ(plan.size(), 2u);
    // Peer "a" churns out ONE second later — its requests must not wait out
    // the 30 s timeout.
    s.service(1001, {"b"});
    EXPECT_EQ(s.retry_count(), 4u);
    EXPECT_EQ(s.inflight_count(), 4u);   // b's requests untouched
}

// ═══ (B2) stall-demotion — dashd BLOCK_STALLING_TIMEOUT parity ═════════════
//
// The live full-history replay measured timeout=753956 against total=1681142
// delivered (a 45% re-request rate) with notfound=0: non-archival peers do not
// DECLINE deep-history getdata, they silently drop it, and one near-dead peer
// (553 blk of 2.52M) kept its slot the whole run because nothing ever demoted
// it. dashd disconnects a peer that stalls the download window; the reward-safe
// analogue here holds a peer that leaves `demote_after` consecutive getdata
// unanswered off FRESH contiguous-range assignment for a cooldown — never
// dropping a height (timed-out heights requeue exactly as before), and clearing
// the moment the peer delivers again.

TEST(DashReplayBulkScheduler, StallDemotionHoldsDeadPeerOffFreshRanges)
{
    SyntheticChain chain(500);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.window = 400;
    cfg.per_peer_inflight = 8;
    cfg.batch = 8;
    cfg.request_timeout_sec = 30;
    cfg.demote_after = 3;
    cfg.demote_cooldown_sec = 60;
    s.configure(cfg);
    s.reset(0);
    s.set_target_end(499);
    auto hashfn = [&](uint32_t h) { return chain.hash_at(h); };

    // One dead peer, two healthy — so a healthy peer has spare capacity for
    // fresh work even while the other absorbs the dead peer's requeued heights.
    const std::vector<std::string> peers{"dead", "live1", "live2"};
    int64_t now = 1000;

    // Round 1: all three peers get a fresh contiguous batch.
    auto plan = s.pump(now, peers, hashfn, 0);
    ASSERT_EQ(plan.size(), 3u);
    EXPECT_EQ(s.demoted_count(now), 0u);
    // The live peers answer every body; "dead" answers none.
    for (const auto& a : plan)
        if (a.peer != "dead")
            for (const auto& [h, hash] : a.blocks) s.on_body(hash, 100);

    // 30 s later dead's whole batch times out in one service pass — enough
    // consecutive unanswered getdata to cross demote_after.
    now += 30;
    s.service(now, peers);
    EXPECT_GE(s.timeout_count(), static_cast<uint64_t>(cfg.demote_after));
    EXPECT_EQ(s.demoted_count(now), 1u);            // exactly "dead"

    // Next pump: "dead" is handed NOTHING — its timed-out heights requeue with
    // avoid="dead" (steered onto a live peer) and it is barred from fresh
    // ranges. All work flows through the live peers, which keep advancing.
    const uint32_t fresh_floor = s.next_height();
    auto plan2 = s.pump(now, peers, hashfn, 0);
    ASSERT_FALSE(plan2.empty());
    for (const auto& a : plan2)
        EXPECT_NE(a.peer, "dead") << "demoted peer must receive no assignment";
    EXPECT_GT(s.next_height(), fresh_floor);        // live kept advancing
}

TEST(DashReplayBulkScheduler, DeliveredBodyClearsDemotionImmediately)
{
    SyntheticChain chain(200);
    rp::BulkBlockScheduler s;
    rp::BulkBlockScheduler::Config cfg;
    cfg.per_peer_inflight = 4;
    cfg.batch = 4;
    cfg.request_timeout_sec = 30;
    cfg.demote_after = 3;
    cfg.demote_cooldown_sec = 600;   // long cooldown — only a delivery can clear
    s.configure(cfg);
    s.reset(0);
    s.set_target_end(199);
    auto hashfn = [&](uint32_t h) { return chain.hash_at(h); };

    const std::vector<std::string> solo{"x"};
    int64_t now = 5000;
    auto plan = s.pump(now, solo, hashfn, 0);        // "x" gets a batch
    ASSERT_EQ(plan.size(), 1u);
    const auto batch = plan[0].blocks;

    now += 30;
    s.service(now, solo);                            // all time out → demoted
    EXPECT_EQ(s.demoted_count(now), 1u);

    // A single delivered body proves the peer is serving again — clears the
    // streak and demotion even though the 600 s cooldown has not elapsed.
    // (Deliver a requeued height by re-pumping first so it is in-flight again;
    // liveness fallback lets the sole demoted peer take fresh work.)
    auto plan2 = s.pump(now, solo, hashfn, 0);
    ASSERT_FALSE(plan2.empty());                     // sole peer ⇒ liveness bypass
    s.on_body(plan2[0].blocks[0].second, 100);
    EXPECT_EQ(s.demoted_count(now), 0u);             // demotion cleared
}

TEST(DashReplayBulkScheduler, StallDemotionCutsTimeoutWallTimeVsBaseline)
{
    // Deterministic before/after "measurement" of the exact throttle the live
    // run measured. One dead peer among four; live peers answer instantly, the
    // dead peer's requests only clear by 30 s timeout. The lane's in-order
    // delivery cursor + bounded work-ahead window are modelled faithfully: the
    // dead peer's contiguous chunk sits at the cursor HEAD, blocks it, the
    // window fills with buffered work-ahead, and the whole fetch waits out a
    // 30 s timeout wave before the cursor can advance. The metric is virtual
    // SECONDS to deliver the entire span in order. Baseline (demote_after=0 ==
    // pre-port behaviour) re-hands the dead peer a fresh contiguous chunk on
    // every rotation, so it re-blocks the cursor and pays a 30 s wave again and
    // again; the port demotes it after one wave and the remainder flows at live
    // speed. Both MUST deliver every height in order (reward-safety: no skip).
    auto run = [](uint32_t demote_after) -> std::pair<int64_t, bool> {
        const uint32_t END = 2999;
        SyntheticChain chain(END + 1);
        rp::BulkBlockScheduler s;
        rp::BulkBlockScheduler::Config cfg;
        cfg.window = 512;             // bounded work-ahead (the §4.3 buffer)
        cfg.per_peer_inflight = 16;
        cfg.batch = 16;
        cfg.request_timeout_sec = 30;
        cfg.demote_after = demote_after;
        cfg.demote_cooldown_sec = 60;
        s.configure(cfg);
        s.reset(0);
        s.set_target_end(END);
        auto hashfn = [&](uint32_t h) { return chain.hash_at(h); };
        const std::vector<std::string> peers{"dead", "l1", "l2", "l3"};

        std::set<uint32_t> received;   // bodies in hand, above the cursor
        int64_t cursor = 0;            // next height the in-order lane needs
        int64_t now = 0;
        int guard = 0;
        while (cursor <= END && guard++ < 2000000)
        {
            // Pump to a fixed point at this instant: a delivered body frees
            // window/inflight, so keep pumping+delivering+draining until the
            // in-order cursor can no longer advance (blocked behind the dead
            // peer's held chunk).
            bool progressed = true;
            while (progressed)
            {
                progressed = false;
                auto plan = s.pump(now, peers, hashfn, received.size());
                for (const auto& a : plan)
                {
                    if (a.peer == "dead") continue;       // never answers
                    for (const auto& [h, hash] : a.blocks)
                    {
                        auto got = s.on_body(hash, 100);
                        if (got) received.insert(*got);
                    }
                }
                // Drain in order, advancing the cursor + the scheduler high-water.
                while (!received.empty() &&
                       *received.begin() == static_cast<uint32_t>(cursor))
                {
                    s.note_delivered(static_cast<uint32_t>(cursor));
                    received.erase(received.begin());
                    ++cursor;
                    progressed = true;
                }
            }
            if (cursor > END) break;
            // Cursor blocked: advance to the next timeout boundary and service
            // (times out the dead peer's held chunk + requeues it to a live one).
            now += cfg.request_timeout_sec;
            s.service(now, peers);
        }
        return {now, cursor == static_cast<int64_t>(END) + 1};
    };

    auto [baseline_secs, baseline_ok] = run(/*demote_after=*/0);
    auto [ported_secs,   ported_ok]   = run(/*demote_after=*/3);

    EXPECT_TRUE(baseline_ok) << "baseline must still deliver every block in order";
    EXPECT_TRUE(ported_ok)   << "port must still deliver every block in order";
    // The port must slash the timeout wall time.
    EXPECT_LT(ported_secs, baseline_secs);
    EXPECT_LT(ported_secs * 3, baseline_secs)
        << "ported=" << ported_secs << "s baseline=" << baseline_secs << "s";
    // Surface the numbers in the test log for the before/after record.
    std::fprintf(stderr,
        "[stall-demote KAT] in-order full-span fetch virtual wall: "
        "baseline=%llds ported=%llds (%.1fx less timeout wall)\n",
        static_cast<long long>(baseline_secs),
        static_cast<long long>(ported_secs),
        baseline_secs > 0 && ported_secs > 0
            ? double(baseline_secs) / double(ported_secs) : 0.0);
}

// ═══ (C) in-order delivery + prune ════════════════════════════════════════

TEST(DashReplayBulkLane, DeliversInOrderAndPrunes)
{
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    cfg.tip_exclusion = 12;
    LaneRig rig(200, cfg);
    rig.lane->scheduler().configure({/*window*/ 1000, /*per_peer*/ 64,
                                     /*batch*/ 16, /*timeout*/ 30});

    // Pump until every wanted height [10, 187] is requested, answering each
    // round SHUFFLED — out-of-order arrival is the normal multi-peer case.
    std::mt19937 rng(1234);
    int64_t now = 1000;
    for (int round = 0; round < 64; ++round)
    {
        rig.lane->tick(now++);
        rig.answer_all(&rng);
        if (rig.lane->delivered() == 187) break;
    }

    EXPECT_EQ(rig.lane->delivered(), 187u);            // tip(199) − exclusion(12)
    EXPECT_EQ(rig.counter.blocks(), 187u - 10u + 1u);
    EXPECT_FALSE(rig.counter.order_violated());        // strict in-order, no gaps
    EXPECT_EQ(rig.counter.last_height(), 187u);
    EXPECT_EQ(rig.lane->buffer_size(), 0u);            // PRUNED — nothing retained
    EXPECT_FALSE(rig.lane->failed());
    EXPECT_GT(rig.lane->total_bytes(), 0u);
}

TEST(DashReplayBulkLane, ConsumerRefusalFailsClosed)
{
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    cfg.tip_exclusion = 12;
    LaneRig rig(100, cfg);
    rig.counter.set_refuse_at(20);   // the W1-fold-refused stand-in

    int64_t now = 1000;
    for (int round = 0; round < 32 && !rig.lane->failed(); ++round)
    {
        rig.lane->tick(now++);
        rig.answer_all();
    }

    EXPECT_TRUE(rig.lane->failed());
    EXPECT_NE(rig.lane->fail_cause().find("consumer-refused"),
              std::string::npos);
    EXPECT_EQ(rig.counter.last_height(), 19u);   // delivered up to the refusal
    // Failed lane issues no further requests.
    rig.sent.clear();
    rig.lane->tick(now + 100);
    EXPECT_TRUE(rig.sent.empty());
}

// ═══ (D) body verification ════════════════════════════════════════════════

TEST(DashReplayBulkLane, CorruptBodyRejectedAndRefetched)
{
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    cfg.tip_exclusion = 12;
    LaneRig rig(100, cfg);
    rig.lane->scheduler().configure({1000, 64, 16, 30});

    rig.lane->tick(1000);
    ASSERT_FALSE(rig.sent.empty());
    // Answer the FIRST requested body with a TAMPERED tx set under the same
    // header (same hash — the header is pinned; the body is not, until the
    // merkle bind runs).
    const uint256 victim = rig.sent[0].hashes[0];
    const auto idx = static_cast<std::size_t>(std::distance(
        rig.chain.hashes.begin(),
        std::find(rig.chain.hashes.begin(), rig.chain.hashes.end(), victim)));
    BlockType tampered = rig.chain.blocks[idx];
    tampered.m_txs.push_back(tampered.m_txs[0]);   // duplicate-tx mutation

    EXPECT_TRUE(rig.lane->on_block_body(victim, tampered));   // consumed…
    EXPECT_EQ(rig.lane->corrupt_bodies(), 1u);                // …and rejected
    EXPECT_EQ(rig.counter.blocks(), 0u);                      // never delivered
    EXPECT_EQ(rig.lane->scheduler().rerequests(), 1u);        // refetch queued

    // The honest body then arrives on the retry and delivery proceeds.
    std::mt19937 rng(7);
    int64_t now = 1001;
    for (int round = 0; round < 64; ++round)
    {
        rig.lane->tick(now++);
        rig.answer_all(&rng);
        if (rig.lane->delivered() == 87) break;
    }
    EXPECT_EQ(rig.lane->delivered(), 87u);
    EXPECT_FALSE(rig.counter.order_violated());
    EXPECT_FALSE(rig.lane->failed());
}

TEST(DashReplayBulkLane, ForeignBodyFallsThroughToTipLane)
{
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    LaneRig rig(100, cfg);
    rig.lane->tick(1000);
    // A body the bulk lane never requested (the tip lane's) must NOT be
    // consumed — false means the client fires full_block as before.
    BlockType foreign;
    foreign.m_version = 1;
    foreign.m_nonce = 0xDEAD1234u;
    MutableTransaction tx;
    tx.locktime = 0xDEAD1234u;
    foreign.m_txs.push_back(tx);
    auto packed_tx = ::pack(foreign.m_txs[0]);
    foreign.m_merkle_root = ::Hash(packed_tx.get_span());
    const auto header = static_cast<BlockHeaderType>(foreign);
    auto packed = ::pack(header);
    const uint256 fhash = dash::crypto::hash_x11(packed.get_span());
    EXPECT_FALSE(rig.lane->on_block_body(fhash, foreign));
}

// ═══ (E) tip priority ═════════════════════════════════════════════════════

TEST(DashReplayBulkLane, TipBusyIssuesNoNewRequests)
{
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    LaneRig rig(100, cfg);

    rig.tip_busy = true;
    rig.lane->tick(1000);
    EXPECT_TRUE(rig.sent.empty());   // STRICT priority: not one bulk getdata

    rig.tip_busy = false;
    rig.lane->tick(1001);
    EXPECT_FALSE(rig.sent.empty());  // released — bulk resumes
}

// DECONFLICT: while the higher-priority MN-checkpoint anchor->tip fold is
// building the payee queue, the bulk lane issues NO body getdata — its fetch
// shares the coin-P2P response demux with the fold's block-body pull, and the
// fold gates the money arm. Released the instant the fold publishes.
TEST(DashReplayBulkLane, DeferHigherPriorityBodyPumpYields)
{
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    LaneRig rig(100, cfg);

    rig.defer_higher = true;         // MN-ckpt fold mid-replay
    rig.lane->tick(1000);
    EXPECT_TRUE(rig.sent.empty())    // not one bulk getdata competes with it
        << "bulk must yield the demux to the MN-checkpoint fold";

    rig.defer_higher = false;        // fold published — bridging_active() false
    rig.lane->tick(1001);
    EXPECT_FALSE(rig.sent.empty());  // released — bulk resumes at full rate
}

// ═══ (F) resumability ═════════════════════════════════════════════════════

TEST(DashReplayCursorStore, RoundTripAndGarbageRejection)
{
    const std::string path = temp_path("c2pool-replay-cursor-kat");
    rp::ReplayCursorStore store(path);
    EXPECT_FALSE(store.load().has_value());   // absent file: no cursor

    rp::ReplayCursorStore::Cursor c;
    c.height = 1234567;
    c.hash.SetHex("00000000000000112233445566778899aabbccddeeff00112233445566778899");
    ASSERT_TRUE(store.store(c));
    auto back = store.load();
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back->height, c.height);
    EXPECT_EQ(back->hash, c.hash);

    // Garbage / wrong version fails LOUD-ignore (nullopt), never a bogus cursor.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "c2pool-replay-cursor v9 1 deadbeef\n";
    }
    EXPECT_FALSE(store.load().has_value());
    std::filesystem::remove(path);
}

TEST(DashReplayBulkLane, ResumesFromVerifiedCursor)
{
    const std::string path = temp_path("c2pool-replay-resume-kat");
    SyntheticChain probe(100);
    {
        rp::ReplayCursorStore store(path);
        rp::ReplayCursorStore::Cursor c;
        c.height = 50;
        c.hash = probe.hashes[50];
        ASSERT_TRUE(store.store(c));
    }
    rp::ReplayCursorStore store(path);
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    cfg.tip_exclusion = 12;
    LaneRig rig(100, cfg, nullptr, &store);
    // Same synthetic chain (seed-deterministic), so the cursor hash matches.
    ASSERT_EQ(rig.chain.hashes[50], probe.hashes[50]);

    EXPECT_EQ(rig.lane->delivered(), 50u);   // resumed, not restarted
    rig.lane->tick(1000);
    ASSERT_FALSE(rig.sent.empty());
    // First fetched height is cursor+1 — nothing below is re-fetched.
    uint32_t min_h = UINT32_MAX;
    for (auto& b : rig.sent)
        for (auto& h : b.hashes)
        {
            auto it = std::find(rig.chain.hashes.begin(),
                                rig.chain.hashes.end(), h);
            min_h = std::min<uint32_t>(min_h, static_cast<uint32_t>(
                std::distance(rig.chain.hashes.begin(), it)));
        }
    EXPECT_EQ(min_h, 51u);
    EXPECT_FALSE(rig.lane->failed());
    std::filesystem::remove(path);
}

TEST(DashReplayBulkLane, CursorHashMismatchFailsClosed)
{
    const std::string path = temp_path("c2pool-replay-mismatch-kat");
    {
        rp::ReplayCursorStore store(path);
        rp::ReplayCursorStore::Cursor c;
        c.height = 50;
        c.hash = uint256::ONE;   // NOT this chain's hash at 50
        ASSERT_TRUE(store.store(c));
    }
    rp::ReplayCursorStore store(path);
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    LaneRig rig(100, cfg, nullptr, &store);

    rig.lane->tick(1000);
    EXPECT_TRUE(rig.lane->failed());
    EXPECT_NE(rig.lane->fail_cause().find("resume-cursor-hash-mismatch"),
              std::string::npos);
    EXPECT_TRUE(rig.sent.empty());   // refused before ONE body was requested
    std::filesystem::remove(path);
}

// ═══ (G) header backfill ══════════════════════════════════════════════════

// Synthetic pre-anchor header chain: linkage is real, PoW checking is
// disabled (check_pow=false — mining X11 in a unit test is not a thing; the
// PoW predicate itself is pinned by the header-chain KATs).
struct BackfillChain
{
    uint256 genesis;
    std::vector<BlockType> headers;   // heights 1..N
    std::vector<uint256> hashes;      // heights 0..N (0 = genesis)

    explicit BackfillChain(uint32_t anchor_height, uint32_t salt = 0)
    {
        genesis.SetHex("000007deadbeef00112233445566778899aabbccddeeff001122334455667788");
        // A salted chain diverges from genesis onward (distinct-chain rigs).
        if (salt != 0)
        {
            unsigned char* gd = genesis.data();
            gd[31] ^= static_cast<unsigned char>(salt);
        }
        hashes.push_back(genesis);
        uint256 prev = genesis;
        for (uint32_t h = 1; h <= anchor_height; ++h)
        {
            BlockType b;
            b.m_version = 2;
            b.m_previous_block = prev;
            b.m_timestamp = 1400000000u + h;
            b.m_bits = 0x1e0fffff;
            b.m_nonce = h * 7u + salt;
            const auto header = static_cast<BlockHeaderType>(b);
            auto packed = ::pack(header);
            const uint256 hash = dash::crypto::hash_x11(packed.get_span());
            headers.push_back(b);
            hashes.push_back(hash);
            prev = hash;
        }
    }

    std::vector<BlockType> batch(uint32_t from_height, uint32_t count) const
    {
        std::vector<BlockType> out;
        for (uint32_t i = 0; i < count && (from_height - 1 + i) < headers.size(); ++i)
            out.push_back(headers[from_height - 1 + i]);
        return out;
    }
};

// DECONFLICT, header leg: the genesis->anchor header-backfill getheaders walk
// ALSO yields while the higher-priority MN-checkpoint fold runs (the cited
// starver — a headers batch is consumed before the tip lane's new_headers, and
// it contends for the same coin-P2P link as the fold's body getdata). Released
// when the fold publishes (defer_higher goes false).
TEST(DashReplayBulkLane, DeferHigherPriorityBackfillGetheadersYields)
{
    const uint32_t ANCHOR = 25;
    BackfillChain bc(ANCHOR);
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    rp::HeaderBackfill bf(bc.genesis, ANCHOR, bc.hashes[ANCHOR], pow_limit,
                          /*db_path=*/"", /*check_pow=*/false);

    rp::BulkFetchLane::Config cfg;
    cfg.start_height = ANCHOR + 1;
    LaneRig rig(100, cfg, &bf);

    rig.defer_higher = true;         // MN-ckpt fold mid-replay
    rig.lane->tick(1000);
    EXPECT_TRUE(rig.getheaders_sent.empty())
        << "the header backfill must not kick getheaders while the fold runs";

    rig.defer_higher = false;        // fold published
    rig.lane->tick(1001);
    EXPECT_FALSE(rig.getheaders_sent.empty())  // released — walk resumes
        << "backfill resumes the instant the fold's priority is released";
}

TEST(DashReplayHeaderBackfill, WalksToAnchorAndJoins)
{
    const uint32_t ANCHOR = 25;
    BackfillChain bc(ANCHOR);
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    rp::HeaderBackfill bf(bc.genesis, ANCHOR, bc.hashes[ANCHOR], pow_limit,
                          /*db_path=*/"", /*check_pow=*/false);

    EXPECT_FALSE(bf.complete());
    EXPECT_EQ(bf.tip_height(), 0u);
    // Pre-join, pre-anchor hashes are NOT an index (a walk in progress is not
    // trustworthy) — only genesis is known.
    EXPECT_FALSE(bf.hash_at(10).has_value());

    // Batches in getheaders-sized chunks; claims() is the demux predicate.
    auto b1 = bc.batch(1, 10);
    EXPECT_TRUE(bf.claims(b1));
    EXPECT_EQ(bf.add_headers(b1), 10);
    EXPECT_EQ(bf.tip_height(), 10u);

    // A batch that does NOT link (the tip lane's) is not claimed.
    BackfillChain other(5, /*salt=*/0x5A);
    EXPECT_FALSE(bf.claims(other.batch(1, 5)));

    // Duplicate re-served batch: claimed (prev is in the recent window) but
    // folds zero headers — no double-count, no corruption.
    EXPECT_TRUE(bf.claims(b1));
    EXPECT_EQ(bf.add_headers(b1), 0);
    EXPECT_EQ(bf.tip_height(), 10u);

    EXPECT_EQ(bf.add_headers(bc.batch(11, 100)), static_cast<int>(ANCHOR - 10));
    EXPECT_TRUE(bf.complete());       // JOINED the anchor
    EXPECT_FALSE(bf.failed());
    // Post-join the whole pre-anchor index is served.
    ASSERT_TRUE(bf.hash_at(10).has_value());
    EXPECT_EQ(*bf.hash_at(10), bc.hashes[10]);
    EXPECT_EQ(*bf.hash_at(ANCHOR), bc.hashes[ANCHOR]);
    EXPECT_FALSE(bf.hash_at(ANCHOR + 1).has_value());
    // A complete walk claims nothing further.
    EXPECT_FALSE(bf.claims(b1));
}

TEST(DashReplayHeaderBackfill, AnchorJoinMismatchFailsClosed)
{
    const uint32_t ANCHOR = 12;
    BackfillChain bc(ANCHOR);
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    // Anchor hash is NOT what this chain produces at the anchor height: the
    // wrong-chain / hostile-peer case.
    rp::HeaderBackfill bf(bc.genesis, ANCHOR, uint256::ONE, pow_limit,
                          "", false);
    bf.add_headers(bc.batch(1, ANCHOR));
    EXPECT_TRUE(bf.failed());
    EXPECT_FALSE(bf.complete());
    EXPECT_NE(bf.fail_cause().find("anchor-join-mismatch"), std::string::npos);
    // A failed walk serves NO index — the lane cannot fetch off it.
    EXPECT_FALSE(bf.hash_at(5).has_value());
}

// Restart-resume (vm905 fold, 2026-08-15): persist_full_chunks() writes
// m_hashes[0] onward, so chunk 0 already carries genesis in slot 0 — while
// the constructor seeds the walker with genesis BEFORE load_persisted().
// Appending the store onto that seed shifted every persisted hash up one
// height, so the JOIN CHECK read height (anchor-1)'s hash at the anchor index
// and a byte-perfect store failed closed with anchor-join-mismatch on EVERY
// restart. This walks past one full CHUNK_SPAN, persists, destroys the
// walker, reloads from the same store, and must resume at the exact chunk
// boundary and still join the anchor. Red on the shifted reload; green when
// the reload rebuilds the walker from the store alone.
TEST(DashReplayHeaderBackfill, RestartResumeRejoinsAnchor)
{
    const uint32_t ANCHOR = rp::HeaderBackfill::CHUNK_SPAN + 2000;   // 12000
    BackfillChain bc(ANCHOR);
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const std::string db_path = testing::TempDir() + "/backfill_resume_kat";
    std::filesystem::remove_all(db_path);

    {   // Run 1: walk past the chunk boundary, join, persist, shut down.
        rp::HeaderBackfill bf(bc.genesis, ANCHOR, bc.hashes[ANCHOR], pow_limit,
                              db_path, /*check_pow=*/false);
        for (uint32_t h = 1; h <= ANCHOR && !bf.complete(); h += 2000)
            bf.add_headers(bc.batch(h, 2000));
        ASSERT_TRUE(bf.complete());
        ASSERT_FALSE(bf.failed());
    }

    // Run 2: a fresh process resumes from the persisted chunks.
    rp::HeaderBackfill bf2(bc.genesis, ANCHOR, bc.hashes[ANCHOR], pow_limit,
                           db_path, /*check_pow=*/false);
    // The resume must NOT fail closed on its own byte-perfect store.
    ASSERT_FALSE(bf2.failed()) << bf2.fail_cause();
    // Only full chunks persist: resume lands exactly at the chunk boundary
    // (height CHUNK_SPAN-1), not one above it (the double-genesis shift).
    EXPECT_EQ(bf2.tip_height(), rp::HeaderBackfill::CHUNK_SPAN - 1);

    // The partial tail re-fetches and the walk joins the anchor again.
    auto tail = bc.batch(rp::HeaderBackfill::CHUNK_SPAN, 2001);
    EXPECT_TRUE(bf2.claims(tail));
    bf2.add_headers(tail);
    ASSERT_TRUE(bf2.complete()) << bf2.fail_cause();
    EXPECT_FALSE(bf2.failed());
    // And the served index is height-exact against the source chain.
    ASSERT_TRUE(bf2.hash_at(rp::HeaderBackfill::CHUNK_SPAN - 1).has_value());
    EXPECT_EQ(*bf2.hash_at(rp::HeaderBackfill::CHUNK_SPAN - 1),
              bc.hashes[rp::HeaderBackfill::CHUNK_SPAN - 1]);
    EXPECT_EQ(*bf2.hash_at(ANCHOR), bc.hashes[ANCHOR]);
    std::filesystem::remove_all(db_path);
}

// ═══ (G.2) header-backfill peer selection: CanServeBlocks + stall-demote ════
//
// THE INCIDENT (2026-08-17, vm905, --coin-rpc removed, dashd ABSENT). The
// genesis→anchor header backfill WEDGED at hdr=0/2513000. The getheaders
// round-robin at maybe_kick_backfill()/on_headers() picked its target BLINDLY
// over eligible_peers(), whose liveness fallback re-admits a pruned /
// NODE_NETWORK_LIMITED peer when the CanServeBlocks-filtered serving set is
// transiently empty (cold start with one limited peer up). That peer SILENTLY
// DROPS the from-genesis getheaders, m_backfill->tip_height() never leaves 0,
// BulkBlockScheduler stays gated on m_backfill->complete(), bodies=0, the fold
// never starts. PR #1273 (df10298d) fixed exactly this class for the BODY
// scheduler (peer_can_serve + BLOCK_STALLING_TIMEOUT demote); the header lane
// was simply not covered.
//
// THE PORT (this PR). The header round-robin now (1) reuses the peer_can_serve
// seam VERBATIM (main_dash → bulk_peer_can_serve: CanServeBlocks + start_height
// coverage + not-demoted) so a non-serving peer is never targeted for a span it
// cannot serve, and (2) stall-demotes a peer that RECEIVED getheaders but did
// not advance the walker within the re-kick window, re-homing the span — with a
// liveness bypass so no header span is ever skipped.
//
// A getheaders-driven rig stands the lane up with no sockets: a "live" server
// answers a getheaders with the next real header batch (driving the walk); a
// non-live peer records the target and DROPS it. `serving` models CanServeBlocks
// (what a peer ADVERTISES); `live` models whether it actually answers — a LIAR
// advertises service but is not live, the case peer_can_serve alone cannot catch
// and only the stall-demote re-homes.
struct HdrLaneRig
{
    BackfillChain bc;
    rp::HeaderBackfill bf;
    rp::CountingReplayConsumer counter;
    std::unique_ptr<rp::BulkFetchLane> lane;

    std::vector<std::string> peers;
    std::set<std::string> serving;      // CanServeBlocks: advertises + covers span
    std::set<std::string> live;         // actually answers getheaders
    bool     wire_can_serve;            // false ⇒ peer_can_serve null (blind lane)
    uint32_t batch_headers;
    int64_t  now{1000};                 // start past backfill_rekick_sec so the first tick kicks

    std::vector<std::string> getheaders_targets;   // every peer a getheaders went to

    HdrLaneRig(uint32_t anchor, std::vector<std::string> peers_,
               std::set<std::string> serving_, std::set<std::string> live_,
               bool can_serve, uint32_t batch, const uint256& pow_limit,
               int64_t demote_cooldown_sec)
        : bc(anchor)
        , bf(bc.genesis, anchor, bc.hashes[anchor], pow_limit,
             /*db_path=*/"", /*check_pow=*/false)
        , peers(std::move(peers_)), serving(std::move(serving_))
        , live(std::move(live_)), wire_can_serve(can_serve), batch_headers(batch)
    {
        rp::BulkFetchLane::Config cfg;
        cfg.start_height = anchor + 1;
        cfg.backfill_rekick_sec = 15;
        cfg.backfill_demote_cooldown_sec = demote_cooldown_sec;

        rp::BulkFetchLane::Seams s;
        s.hash_at = [](uint32_t) -> std::optional<uint256> { return std::nullopt; };
        s.chain_height = [anchor] { return anchor + 1; };
        s.eligible_peers = [this] { return peers; };
        s.send_getdata = [](const std::string&, const std::vector<uint256>&) {};
        s.now_sec = [this] { return now; };
        if (can_serve)
            s.peer_can_serve = [this](const std::string& p, uint32_t) {
                return serving.count(p) != 0;
            };
        s.send_getheaders = [this](const std::string& peer, const uint256&,
                                   const uint256&) {
            getheaders_targets.push_back(peer);
            // A live server answers with the next real header batch (driving the
            // walk, and — via on_headers — self-propelling). A non-live peer
            // (pruned/limited or a liar) drops it: only the target is recorded.
            if (live.count(peer))
            {
                auto b = bc.batch(bf.tip_height() + 1, batch_headers);
                if (!b.empty()) lane->on_headers(peer, b);
            }
        };
        lane = std::make_unique<rp::BulkFetchLane>(
            std::move(s), cfg, &bf,
            static_cast<rp::IReplayBlockConsumer*>(&counter), nullptr);
    }

    // One tick per re-kick window (each tick advances `now` past the re-kick
    // gate so the backstop fires), until complete/failed or max_kicks.
    void drive(int max_kicks)
    {
        for (int k = 0; k < max_kicks && !bf.complete() && !bf.failed(); ++k)
        {
            lane->tick(now);
            now += 16;
        }
    }

    bool targeted(const std::string& p) const
    {
        return std::find(getheaders_targets.begin(), getheaders_targets.end(), p)
               != getheaders_targets.end();
    }
};

// (G.2 RED) The PRE-PORT blind lane (peer_can_serve null AND demote disabled,
// backfill_demote_cooldown_sec=0 — the byte-identical pre-#1273 behaviour)
// round-robins onto the non-serving peer every other kick and WEDGES: within a
// tight kick budget it never reaches the anchor, and it DID target the dead
// peer (the wedge cause).
TEST(DashReplayHeaderBackfillPeerSelect, RedBlindRoundRobinWedgesOnNonServer)
{
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint32_t ANCHOR = 40;   // 8 batches of 5 headers to reach the anchor
    HdrLaneRig rig(ANCHOR, {"limited:1", "full:1"},
                   /*serving=*/{"full:1"}, /*live=*/{"full:1"},
                   /*can_serve=*/false, /*batch=*/5, pow_limit,
                   /*demote_cooldown_sec=*/0);
    rig.drive(/*max_kicks=*/4);
    EXPECT_FALSE(rig.bf.complete())
        << "blind round-robin wastes every other kick on the non-serving peer";
    EXPECT_LT(rig.bf.tip_height(), ANCHOR) << "walker stalls short of the anchor";
    EXPECT_TRUE(rig.targeted("limited:1"))
        << "the blind lane DID target the dead peer — the wedge cause";
}

// (G.2 GREEN, proactive) With peer_can_serve wired the CanServeBlocks filter
// NEVER targets the non-serving peer; the walk self-propels off the one serving
// peer and JOINS the anchor in a single kick.
TEST(DashReplayHeaderBackfillPeerSelect, GreenCanServeFilterCompletesInOneKick)
{
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint32_t ANCHOR = 40;
    HdrLaneRig rig(ANCHOR, {"limited:1", "full:1"},
                   /*serving=*/{"full:1"}, /*live=*/{"full:1"},
                   /*can_serve=*/true, /*batch=*/5, pow_limit,
                   /*demote_cooldown_sec=*/60);
    rig.drive(/*max_kicks=*/1);
    EXPECT_TRUE(rig.bf.complete()) << "filtered lane joins the anchor at once";
    EXPECT_EQ(rig.bf.tip_height(), ANCHOR);
    EXPECT_FALSE(rig.targeted("limited:1"))
        << "CanServeBlocks never targets the non-serving peer";
}

// (G.2 GREEN, reactive) A LIAR advertises full-block service (passes
// CanServeBlocks) but silently drops every getheaders — the case peer_can_serve
// alone cannot catch. The BLOCK_STALLING_TIMEOUT demote must fire: the liar is
// tried once, stalls, is demoted, and the span RE-HOMES to the live server,
// completing. No span is skipped.
TEST(DashReplayHeaderBackfillPeerSelect, GreenStallDemoteReHomesOffLyingPeer)
{
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint32_t ANCHOR = 40;
    HdrLaneRig rig(ANCHOR, {"liar:1", "full:1"},
                   /*serving=*/{"liar:1", "full:1"},   // BOTH advertise service
                   /*live=*/{"full:1"},                // only full actually answers
                   /*can_serve=*/true, /*batch=*/5, pow_limit,
                   /*demote_cooldown_sec=*/60);
    rig.drive(/*max_kicks=*/4);
    EXPECT_TRUE(rig.bf.complete())
        << "stall-demote re-homes the span off the lying peer and completes";
    EXPECT_EQ(rig.bf.tip_height(), ANCHOR);
    EXPECT_TRUE(rig.targeted("liar:1"))
        << "the liar WAS tried once (it advertised service) — then demoted";
}

// (G.2 liveness bypass) BOTH peers advertise service but NEITHER answers. The
// lane must keep re-homing — Pass 2 clears demotions rather than deadlock — so
// it never freezes and never permanently skips a span: both peers keep getting
// retried. It cannot complete (no live server) but it MUST NOT fail/crash.
TEST(DashReplayHeaderBackfillPeerSelect, LivenessBypassNeverDeadlocks)
{
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint32_t ANCHOR = 40;
    HdrLaneRig rig(ANCHOR, {"a:1", "b:1"},
                   /*serving=*/{"a:1", "b:1"}, /*live=*/{},   // nobody answers
                   /*can_serve=*/true, /*batch=*/5, pow_limit,
                   /*demote_cooldown_sec=*/60);
    rig.drive(/*max_kicks=*/10);
    EXPECT_FALSE(rig.bf.complete());   // no live server ⇒ cannot join
    EXPECT_FALSE(rig.bf.failed());     // but never fails/crashes/deadlocks
    EXPECT_TRUE(rig.targeted("a:1"));
    EXPECT_TRUE(rig.targeted("b:1"))
        << "liveness bypass re-homes to BOTH — no span permanently skipped";
    EXPECT_GE(rig.getheaders_targets.size(), 5u)
        << "the lane keeps trying every kick — never wedges silently";
}

// ═══ (H) capture cache ════════════════════════════════════════════════════

TEST(DashReplayBulkCapture, SegmentRoundTripAndTornTail)
{
    const std::string dir = temp_path("c2pool-replay-capture-kat");
    SyntheticChain chain(4);
    {
        rp::BulkCaptureWriter w(dir);
        ASSERT_FALSE(w.failed());
        for (uint32_t h = 1; h < 4; ++h)
        {
            auto packed = ::pack(chain.blocks[h]);
            std::vector<uint8_t> raw(
                reinterpret_cast<const uint8_t*>(packed.data()),
                reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());
            ASSERT_TRUE(w.append(h, chain.hashes[h], raw));
        }
        EXPECT_EQ(w.records(), 3u);
    }
    const std::string seg =
        (std::filesystem::path(dir) / rp::BulkCaptureWriter::segment_name(0))
            .string();
    auto recs = rp::BulkCaptureWriter::read_segment(seg);
    ASSERT_EQ(recs.size(), 3u);
    for (uint32_t h = 1; h < 4; ++h)
    {
        EXPECT_EQ(recs[h - 1].height, h);
        EXPECT_EQ(recs[h - 1].hash, chain.hashes[h]);
        // Byte-exact body round trip: re-fold input == fetched input.
        auto packed = ::pack(chain.blocks[h]);
        ASSERT_EQ(recs[h - 1].bytes.size(), packed.size());
        EXPECT_EQ(0, std::memcmp(recs[h - 1].bytes.data(), packed.data(),
                                 packed.size()));
    }

    // Torn tail (crash mid-append): truncate the last record's payload — the
    // reader returns the intact prefix, never garbage.
    {
        const auto full = std::filesystem::file_size(seg);
        std::filesystem::resize_file(seg, full - 5);
    }
    auto truncated = rp::BulkCaptureWriter::read_segment(seg);
    EXPECT_EQ(truncated.size(), 2u);

    std::filesystem::remove_all(dir);
}

TEST(DashReplayBulkLane, CaptureConsumerDecoratesWithoutChangingDelivery)
{
    const std::string dir = temp_path("c2pool-replay-capture-lane-kat");
    rp::BulkFetchLane::Config cfg;
    cfg.start_height = 10;
    cfg.tip_exclusion = 12;

    rp::CountingReplayConsumer inner;
    rp::CaptureReplayConsumer capture(dir, &inner);
    LaneRig rig(60, cfg, nullptr, nullptr, &capture);

    std::mt19937 rng(99);
    int64_t now = 1000;
    for (int round = 0; round < 32; ++round)
    {
        rig.lane->tick(now++);
        rig.answer_all(&rng);
        if (rig.lane->delivered() == 47) break;
    }
    EXPECT_EQ(rig.lane->delivered(), 47u);
    EXPECT_EQ(inner.blocks(), 47u - 10u + 1u);      // inner verdict untouched
    EXPECT_FALSE(inner.order_violated());
    EXPECT_EQ(capture.writer().records(), inner.blocks());   // every body cached

    std::filesystem::remove_all(dir);
}

// ═══ (I) dashd CanServeBlocks / BLOCK_STALLING_TIMEOUT throughput port ══════
//
// The full-history --replay-bulk run measured timeout=753956 / 1.68M delivered
// (45% re-request) with notfound=0: non-archival peers SILENTLY DROP deep-
// history getdata, and nothing demoted a near-dead peer that kept its 32 slots
// the whole run, so the in-order delivery cursor head-of-line-blocked behind
// each hole for the flat 30 s timeout. This ports dashd net_processing's two
// halves — the proactive CanServeBlocks service-bit/coverage filter (WHO may
// be handed a range) and the reactive BLOCK_STALLING_TIMEOUT demote (WHEN a
// non-server is re-eligible) — plus the event-driven refill that lifts the
// ~1/s tick pump ceiling. All THROUGHPUT-ONLY: no height is ever skipped.

// (I.1) CanServeBlocks: a fresh contiguous range is handed ONLY to a peer that
// advertises it can serve the height; a height no eligible peer covers still
// goes out (liveness — never freeze the head-of-line block).
TEST(DashReplayBulkScheduler, CanServeBlocksSteersRangesToArchivalPeers)
{
    SyntheticChain chain(200);
    rp::BulkBlockScheduler::Config cfg;
    cfg.window = 1000; cfg.per_peer_inflight = 32; cfg.batch = 8;

    rp::BulkBlockScheduler s;
    s.configure(cfg); s.reset(10); s.set_target_end(199);
    const std::vector<std::string> peers{"full", "pruned"};
    // "pruned" advertises no history for this deep band; "full" covers all.
    auto only_full = [](const std::string& p, uint32_t) { return p == "full"; };
    auto plan = s.pump(1000, peers,
                       [&](uint32_t h) { return chain.hash_at(h); }, 0,
                       only_full);
    ASSERT_EQ(plan.size(), 1u);                 // pruned got nothing
    EXPECT_EQ(plan[0].peer, "full");
    EXPECT_EQ(plan[0].blocks.size(), cfg.batch);
    for (const auto& [h, hash] : plan[0].blocks) EXPECT_EQ(hash, chain.hashes[h]);

    // Liveness: when NO peer can serve a height, the filter degrades to a
    // preference and the assignment still issues (no block is ever orphaned).
    rp::BulkBlockScheduler s2;
    s2.configure(cfg); s2.reset(10); s2.set_target_end(199);
    auto none = [](const std::string&, uint32_t) { return false; };
    auto plan2 = s2.pump(1000, peers,
                         [&](uint32_t h) { return chain.hash_at(h); }, 0, none);
    std::size_t total = 0;
    for (const auto& a : plan2) total += a.blocks.size();
    EXPECT_GT(total, 0u) << "bypass: a height no peer covers must still go out";
}

// (I.2a) Stall-demote: `demote_after` consecutive timeouts hold a dead peer OFF
// fresh ranges while a healthy peer remains; its retries steer to the healthy
// peer. (I.2b) A delivered body clears the streak and the demotion at once.
TEST(DashReplayBulkScheduler, StallDemoteHoldsDeadPeerOffFreshRanges)
{
    SyntheticChain chain(500);
    rp::BulkBlockScheduler::Config cfg;
    cfg.window = 1000; cfg.per_peer_inflight = 8; cfg.batch = 8;
    cfg.request_timeout_sec = 30; cfg.demote_after = 3; cfg.demote_cooldown_sec = 60;

    rp::BulkBlockScheduler s;
    s.configure(cfg); s.reset(0); s.set_target_end(499);
    auto hs = [&](uint32_t h) { return chain.hash_at(h); };
    const std::vector<std::string> peers{"good", "dead"};

    // rr order: good←[0..7], dead←[8..15].
    s.pump(1000, peers, hs, 0);
    for (uint32_t h = 0; h < 8; ++h) s.on_body(chain.hashes[h], 100);  // good serves

    EXPECT_EQ(s.demoted_count(1040), 0u);
    s.service(1040, peers);              // dead's 8..15 time out (streak 8 ≥ 3)
    EXPECT_GE(s.demoted_count(1040), 1u) << "dead demoted after the stall wave";

    auto plan = s.pump(1041, peers, hs, 0);
    for (const auto& a : plan)
        EXPECT_NE(a.peer, "dead")
            << "a demoted peer gets neither fresh ranges nor its own retries";

    // (I.2b) sole-peer bypass keeps the fetch live AND a delivered body clears
    // the demotion the instant the peer proves it is serving again.
    rp::BulkBlockScheduler s2;
    s2.configure(cfg); s2.reset(0); s2.set_target_end(99);
    const std::vector<std::string> solo{"dead"};
    s2.pump(1000, solo, hs, 0);          // dead←[0..7]
    s2.service(1040, solo);              // all 8 time out → demoted
    EXPECT_EQ(s2.demoted_count(1040), 1u);
    s2.pump(1041, solo, hs, 0);          // liveness bypass re-feeds sole peer
    s2.on_body(chain.hashes[0], 100);    // a body arrives at last
    EXPECT_EQ(s2.demoted_count(1041), 0u) << "delivered body clears the demotion";
}

// ── stall-band throughput sim ──────────────────────────────────────────────
// One archival "good" peer answers instantly; one "dead" peer silently drops
// every getdata (the measured notfound=0 condition). The lane runs on a 1 s
// tick; run() returns the virtual seconds to deliver the whole span in order.
struct StallSim
{
    SyntheticChain chain;
    rp::CountingReplayConsumer counter;
    std::unique_ptr<rp::BulkFetchLane> lane;
    std::vector<std::string> peers{"good:1", "dead:1"};
    struct Out { std::string peer; uint256 hash; int64_t at; };
    std::vector<Out> outstanding;
    int64_t timeout;
    int64_t now{0};

    StallSim(uint32_t heights, uint32_t demote_after, int64_t req_timeout)
        : chain(heights), timeout(req_timeout)
    {
        rp::BulkFetchLane::Config cfg;
        cfg.start_height = 0; cfg.tip_exclusion = 0;
        rp::BulkFetchLane::Seams s;
        s.hash_at = [this](uint32_t h) { return chain.hash_at(h); };
        s.chain_height = [this] {
            return static_cast<uint32_t>(chain.hashes.size() - 1);
        };
        s.eligible_peers = [this] { return peers; };
        s.send_getdata = [this](const std::string& p,
                                const std::vector<uint256>& hh) {
            for (const auto& h : hh) outstanding.push_back({p, h, now});
        };
        s.send_getheaders = [](const std::string&, const uint256&,
                               const uint256&) {};
        s.tip_busy = [] { return false; };
        s.defer_to_higher_priority = [] { return false; };
        lane = std::make_unique<rp::BulkFetchLane>(
            std::move(s), cfg, nullptr, &counter, nullptr);
        rp::BulkBlockScheduler::Config sc;
        sc.window = 512; sc.per_peer_inflight = 32; sc.batch = 8;
        sc.request_timeout_sec = req_timeout;
        sc.demote_after = demote_after; sc.demote_cooldown_sec = 60;
        lane->scheduler().configure(sc);
    }

    const BlockType* body_for(const uint256& h)
    {
        auto it = std::find(chain.hashes.begin(), chain.hashes.end(), h);
        return it == chain.hashes.end()
                   ? nullptr
                   : &chain.blocks[std::distance(chain.hashes.begin(), it)];
    }

    // Deliver in order; return {seconds, timeouts}. seconds=-1 ⇒ never finished.
    std::pair<int64_t, uint64_t> run(uint32_t target)
    {
        const int64_t cap = 200000;
        for (now = 1; now <= cap; ++now)
        {
            lane->tick(now);
            auto batch = outstanding; outstanding.clear();
            for (auto& e : batch)
            {
                if (e.peer == "good:1")
                {
                    if (const BlockType* b = body_for(e.hash))
                        lane->on_block_body(e.hash, *b);   // instant serve
                }
                else if (now - e.at >= timeout)
                {
                    /* dead request timed out — scheduler already requeued it */
                }
                else outstanding.push_back(e);             // still waiting
            }
            if (lane->delivered() >= target)
                return {now, lane->scheduler().timeout_count()};
        }
        return {-1, lane->scheduler().timeout_count()};
    }
};

// (I.3) THE THROUGHPUT PROOF. Same dead-peer topology, in-order full span:
// demote_after=0 (pre-port) vs demote_after=3 (ported). The port must deliver
// every block in order in BOTH cases (never skips a height) while cutting the
// timeout wall — the stall-band rate rises.
TEST(DashReplayBulkScheduler, StallBandThroughputRisesWithDemotePort)
{
    const uint32_t H = 600;
    StallSim baseline(H, /*demote_after=*/0, /*timeout=*/30);   // pre-port
    StallSim ported  (H, /*demote_after=*/3, /*timeout=*/30);   // dashd parity

    auto [b_secs, b_to] = baseline.run(H - 1);
    auto [p_secs, p_to] = ported.run(H - 1);

    // Correctness FIRST: both deliver the whole span, strictly in order.
    EXPECT_EQ(baseline.lane->delivered(), H - 1);
    EXPECT_EQ(ported.lane->delivered(),   H - 1);
    EXPECT_FALSE(baseline.counter.order_violated());
    EXPECT_FALSE(ported.counter.order_violated());
    ASSERT_GT(b_secs, 0);
    ASSERT_GT(p_secs, 0);

    const double b_rate = double(H) / double(b_secs);
    const double p_rate = double(H) / double(p_secs);
    std::printf("[STALL-BAND] pre-port: %lld s, %llu timeouts, %.2f blk/s | "
                "ported: %lld s, %llu timeouts, %.2f blk/s | rate x%.2f\n",
                (long long)b_secs, (unsigned long long)b_to, b_rate,
                (long long)p_secs, (unsigned long long)p_to, p_rate,
                p_rate / b_rate);

    // The port cuts re-requests and raises the delivered-in-order rate.
    EXPECT_LT(p_to, b_to)   << "ported issues strictly fewer re-requests";
    EXPECT_LT(p_secs, b_secs) << "ported clears the span sooner (rate rises)";
}

// (I.4) Event-driven refill: with the clock seam armed, a delivered body hands
// its freed slot fresh work IMMEDIATELY (no wait for the next tick); without
// it, the lane issues nothing new until the tick — the ~1/s pump ceiling.
struct RefillRig
{
    SyntheticChain chain;
    rp::CountingReplayConsumer counter;
    std::vector<std::pair<std::string, std::vector<uint256>>> sent;
    std::unique_ptr<rp::BulkFetchLane> lane;
    int64_t clock{1000};

    RefillRig(uint32_t heights, bool arm_event) : chain(heights)
    {
        rp::BulkFetchLane::Config cfg;
        cfg.start_height = 0; cfg.tip_exclusion = 0;
        rp::BulkFetchLane::Seams s;
        s.hash_at = [this](uint32_t h) { return chain.hash_at(h); };
        s.chain_height = [this] {
            return static_cast<uint32_t>(chain.hashes.size() - 1);
        };
        s.eligible_peers = [] { return std::vector<std::string>{"p:1"}; };
        s.send_getdata = [this](const std::string& p,
                                const std::vector<uint256>& h) {
            sent.emplace_back(p, h);
        };
        s.send_getheaders = [](const std::string&, const uint256&,
                               const uint256&) {};
        s.tip_busy = [] { return false; };
        s.defer_to_higher_priority = [] { return false; };
        if (arm_event) s.now_sec = [this] { return clock; };
        lane = std::make_unique<rp::BulkFetchLane>(
            std::move(s), cfg, nullptr, &counter, nullptr);
        rp::BulkBlockScheduler::Config sc;
        sc.window = 1000; sc.per_peer_inflight = 32; sc.batch = 8;
        sc.request_timeout_sec = 30;
        lane->scheduler().configure(sc);
    }

    void deliver_sent()
    {
        auto batch = sent; sent.clear();
        for (auto& [p, hs] : batch)
            for (auto& h : hs)
            {
                auto it = std::find(chain.hashes.begin(), chain.hashes.end(), h);
                if (it != chain.hashes.end())
                    lane->on_block_body(
                        h, chain.blocks[std::distance(chain.hashes.begin(), it)]);
            }
    }
};

TEST(DashReplayBulkLane, EventDrivenRefillLiftsPerTickCeiling)
{
    RefillRig armed(500, /*arm_event=*/true);
    RefillRig tickonly(500, /*arm_event=*/false);

    armed.lane->tick(1000);
    tickonly.lane->tick(1000);
    const std::size_t primed = armed.sent.size();
    ASSERT_GT(primed, 0u);
    ASSERT_EQ(primed, tickonly.sent.size());   // identical priming

    // Answer the primed bodies WITHOUT a second tick.
    armed.deliver_sent();
    tickonly.deliver_sent();

    EXPECT_GT(armed.sent.size(), 0u)
        << "armed lane refills on each delivered body (no tick needed)";
    EXPECT_EQ(tickonly.sent.size(), 0u)
        << "tick-only lane issues nothing until the next tick (the ceiling)";
    // Both still deliver in order — throughput-only, nothing skipped.
    EXPECT_FALSE(armed.counter.order_violated());
}

} // namespace
