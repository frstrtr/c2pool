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

} // namespace
