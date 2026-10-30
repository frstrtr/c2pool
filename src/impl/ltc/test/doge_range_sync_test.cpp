// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// doge::coin::RangeSync and the anchored HashSchedule (rides share_test,
// DESIGN-ANCHORS §4): ranges of 2,000 headers between anchors, stored only
// when exact, in any order, from many peers at once; the sequential sync is
// the fallback.
//   - ExactRangesCompleteInAnyOrder, OnlyAnExactRangeIsStored
//   - ATricklingPeerDeliversNothingAndTheRangeMovesOn (V4-M1 against the
//     ranges), APoisonIsNeverStoredSoNothingIsEverCut
//   - TimeoutReasksAnotherPeerAndCools, ThreeTimeoutsExclude, InFlightIsBounded
//   - ResumesFromTheBitmap, ImportsASequentialPrefix (holes, a wrong record,
//     records above a cut frontier)
//   - WrongAnchorFallsBackToSequential,
//     AnchorsForAnOlderCheckpointCoverThePrefixThenTheTailIsSequential,
//     AbsentAnchorsUseTheSequentialSync, AnchorDumpRoundTrips
//   - RangeAnswersNeverTouchHeaderAsks (the headers routing)
//   - UnsolicitedWrongEndAnswersCannotRefuseTheAnchors,
//     AWrongAnchorWithTwoPeersStillFallsBack, InFlightNeverExceedsGlobalUnderManyPeers
//     (VERIFY5)
//   - ALimitedLinkStrikesNoPeer (the in-flight budget follows the delivery
//     rate), ADeliveryForgivesAStrike
//   - BuiltinAnchorsAreDogeMainnet (the generated .inc, when present)
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <cstdint>
#include <deque>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <impl/doge/coin/hash_schedule.hpp>
#include <impl/doge/coin/header_sync.hpp>
#include <impl/doge/coin/range_sync.hpp>
#include <impl/doge/coin/schedule_anchors.hpp>
#include <impl/doge/coin/schedule_dispatch.hpp>
#include <impl/ltc/coin/block.hpp>

namespace {

using doge::coin::HashSchedule;
using doge::coin::HashScheduleSync;
using doge::coin::RangeSync;
using doge::coin::ScheduleAnchors;
using Feed = HashSchedule::Feed;
using Mode = RangeSync::Mode;
using Answer = RangeSync::Answer;
using ltc::coin::BlockHeaderType;
using Clock = RangeSync::Clock;
constexpr uint32_t STEP = ScheduleAnchors::STEP;

struct TempStore {
    std::filesystem::path dir;
    std::unique_ptr<core::LevelDBStore> db;
    TempStore()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("doge_range_sync_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
        db = std::make_unique<core::LevelDBStore>(dir.string(), core::LevelDBOptions{});
        EXPECT_TRUE(db->open());
    }
    ~TempStore()
    {
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

uint256 hash_of(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }

uint256 genesis_hash()
{
    uint256 g;
    g.SetHex("1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691");
    return g;
}

/// A chain of `n` headers on genesis; headers[h - 1] is height h.
struct Chain {
    std::vector<BlockHeaderType> headers;
    std::vector<uint256> hashes;
    std::map<uint256, uint32_t> height_of;
    explicit Chain(uint32_t n, uint32_t salt = 0)
    {
        hashes.push_back(genesis_hash());
        height_of[hashes.back()] = 0;
        for (uint32_t h = 1; h <= n; ++h) {
            BlockHeaderType b;
            b.m_version = 0x00620104;
            b.m_previous_block = hashes.back();
            b.m_merkle_root.SetHex(std::to_string(1000 + h));
            b.m_timestamp = 1400000000 + h * 60;
            b.m_bits = 0x1e0ffff0;
            b.m_nonce = h + salt;
            headers.push_back(b);
            hashes.push_back(hash_of(b));
            height_of[hashes.back()] = h;
        }
    }
    std::vector<BlockHeaderType> slice(uint32_t from, uint32_t to) const
    {
        return {headers.begin() + (from - 1), headers.begin() + to};
    }
    ScheduleAnchors anchors(uint32_t up_to) const
    {
        ScheduleAnchors a;
        for (uint32_t h = 0; h <= up_to; h += STEP)
            a.hashes.push_back(hashes[h]);
        return a;
    }
    /// An honest peer's answer: from the first locator entry it knows (from
    /// genesis when none), up to 2,000 headers or the stop hash.
    std::vector<BlockHeaderType> answer(const std::vector<uint256>& locator, const uint256& stop) const
    {
        uint32_t from = 0;
        for (const auto& l : locator) {
            auto it = height_of.find(l);
            if (it != height_of.end()) {
                from = it->second;
                break;
            }
        }
        uint32_t to = std::min<uint32_t>(from + STEP, static_cast<uint32_t>(headers.size()));
        auto st = height_of.find(stop);
        if (st != height_of.end() && st->second > from)
            to = std::min(to, st->second);
        return slice(from + 1, to);
    }
    /// STEP linked fakes starting at `from_h`'s parent, ending elsewhere.
    std::vector<BlockHeaderType> fake_range(uint32_t range) const
    {
        std::vector<BlockHeaderType> out = slice(STEP * range + 1, STEP * (range + 1));
        uint256 prev = hashes[STEP * range];
        for (auto& b : out) {
            b.m_previous_block = prev;
            b.m_nonce += 77777;
            prev = hash_of(b);
        }
        return out;
    }
};

Clock::time_point t0() { return Clock::time_point{} + std::chrono::hours(1); }

std::unique_ptr<HashSchedule> open_schedule(TempStore& s, const Chain& c, uint32_t cp)
{
    auto sched = std::make_unique<HashSchedule>(*s.db, cp, c.hashes[cp], genesis_hash());
    sched->load();
    return sched;
}

/// Run the sequential sync to completion with honest answers.
void complete_sequentially(HashSchedule& sched, HashScheduleSync& sync, const Chain& c, Clock::time_point& t)
{
    for (int i = 0; i < 200 && !sched.complete(); ++i) {
        t += HashScheduleSync::STALL + std::chrono::seconds(1);
        const auto a = sync.due(t);
        if (!a)
            continue;
        sync.asked("seq", t);
        std::optional<HashScheduleSync::Ask> next;
        sync.on_headers("seq", c.answer(a->locator, uint256()), t, next);
        while (next && !sched.complete()) {
            sync.asked("seq", t);
            auto loc = next->locator;
            next.reset();
            sync.on_headers("seq", c.answer(loc, uint256()), t, next);
        }
    }
}

} // namespace

// 20 ranges from four peers, answered out of order: the schedule completes,
// the prefix is proven and hash_at serves every height.
TEST(DogeRangeSync, ExactRangesCompleteInAnyOrder)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(CP));
    ASSERT_EQ(rs.mode(), Mode::Anchored);
    const std::vector<std::string> peers{"a", "b", "c", "d"};
    auto t = t0();
    for (int round = 0; round < 10 && rs.mode() == Mode::Anchored; ++round) {
        auto reqs = rs.tick(peers, t);
        for (auto it = reqs.rbegin(); it != reqs.rend(); ++it)
            rs.on_headers(it->peer, c.answer(it->locator, it->stop), t);
        t += std::chrono::seconds(1);
    }
    EXPECT_EQ(rs.mode(), Mode::Complete);
    EXPECT_TRUE(sched->complete());
    for (uint32_t h : {0u, 1u, 1999u, 2000u, 2001u, 12345u, CP - 1, CP})
        EXPECT_EQ(sched->hash_at(h), c.hashes[h]) << "h=" << h;
    EXPECT_GE(rs.stats(t).peers_used, 3u);
}

// Only an exact range is stored: short, long, broken, wrong end and wrong
// start store nothing. Only the peer a range is in flight to is judged: a
// short, long or broken answer is what the AuxPoW parser can make of an
// honest answer (live, 19:34Z), so it costs that peer a strike and the range
// is asked again; a wrong end (2,000 linked headers ending elsewhere)
// excludes it at once. From a peer not asked, any of them is not ours (it
// falls through to the header chain) and costs, excludes or votes nothing
// (VERIFY5 S1); three strikes exclude.
TEST(DogeRangeSync, OnlyAnExactRangeIsStored)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(CP));
    auto t = t0();
    ASSERT_EQ(rs.tick({"a"}, t).size(), 2u) << "ranges 0 and 1, the starting budget";
    const uint32_t r = 1, lo = STEP * r + 1, hi = STEP * (r + 1);
    EXPECT_EQ(rs.on_headers("a", c.slice(lo, hi - 1), t), Answer::Ignored) << "short";
    EXPECT_EQ(rs.inflight_of("a"), 1u) << "the short answer ended the request: asked again";
    EXPECT_EQ(rs.on_headers("b", c.slice(lo, hi + 1), t), Answer::NotOurs) << "long, not asked";
    auto broken = c.slice(lo, hi);
    broken[500].m_previous_block = c.hashes[9];
    EXPECT_EQ(rs.on_headers("c", broken, t), Answer::NotOurs) << "broken, not asked";
    EXPECT_EQ(rs.on_headers("d", c.fake_range(r), t), Answer::NotOurs) << "wrong end, not asked";
    EXPECT_EQ(rs.on_headers("e", c.slice(lo + 1, hi + 1), t), Answer::NotOurs) << "wrong start";
    EXPECT_EQ(sched->ranges_done(), 0u);
    EXPECT_FALSE(sched->range_done(r));
    EXPECT_TRUE(sched->stored_hash(lo).IsNull()) << "a record was written from a non-exact answer";
    EXPECT_FALSE(rs.excluded("a"));
    EXPECT_FALSE(rs.excluded("b"));
    EXPECT_FALSE(rs.excluded("c"));
    EXPECT_FALSE(rs.excluded("d")) << "an unasked wrong end excluded its sender";
    EXPECT_FALSE(rs.excluded("e"));
    EXPECT_EQ(rs.stats(t).short_parses, 1u);
    EXPECT_EQ(rs.stats(t).bad_parses, 0u);
    EXPECT_EQ(rs.on_headers("d", c.slice(lo, hi), t), Answer::Stored) << "an exact answer, from anyone";
    EXPECT_TRUE(sched->range_done(r));
    EXPECT_EQ(sched->stored_hash(lo), c.hashes[lo]);
    EXPECT_EQ(rs.on_headers("a", c.slice(lo, hi), t), Answer::NotOurs) << "a copy of a stored range";
    const uint32_t w = 0;  // in flight to a
    EXPECT_EQ(rs.on_headers("a", c.fake_range(w), t), Answer::Excluded) << "wrong end, asked";
    EXPECT_TRUE(rs.excluded("a"));
    EXPECT_EQ(rs.stats(t).bad_parses, 1u);
    EXPECT_EQ(rs.inflight_of("a"), 0u) << "an excluded peer's ranges go back to the window";

    // Three bad answers to its own requests exclude a peer (no cooldown
    // here, so it is asked again at once).
    TempStore s2;
    auto sched2 = open_schedule(s2, c, CP);
    RangeSync::Config cfg2;
    cfg2.peer_cooldown = std::chrono::seconds(0);
    RangeSync rs2(*sched2, c.anchors(CP), cfg2);
    Answer last = Answer::Ignored;
    for (int k = 0; k < 3; ++k) {
        const auto reqs = rs2.tick({"x"}, t + std::chrono::seconds(k));
        ASSERT_FALSE(reqs.empty());
        const uint32_t q = reqs.front().range;
        auto b = c.slice(STEP * q + 1, STEP * (q + 1));
        b[7].m_previous_block = c.hashes[3];
        last = rs2.on_headers("x", b, t + std::chrono::seconds(k));
    }
    EXPECT_EQ(last, Answer::Excluded);
    EXPECT_TRUE(rs2.excluded("x"));
    EXPECT_EQ(sched2->ranges_done(), 0u);
}

// V4-M1 against the ranges: a peer answers its ranges with one-header
// messages every 29 s, for two hours if it can. Nothing of it is stored;
// each short answer ends the request (the range goes to another peer) and
// costs a strike that cools it for 10 minutes; three strikes exclude it; the
// schedule completes from the honest (slow) peer.
TEST(DogeRangeSync, ATricklingPeerDeliversNothingAndTheRangeMovesOn)
{
    constexpr uint32_t CP = 40 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync::Config cfg;
    cfg.window = 4;
    cfg.per_peer = 1;
    cfg.global = 2;
    RangeSync rs(*sched, c.anchors(CP), cfg);
    const std::vector<std::string> peers{"t", "h"};
    std::map<uint32_t, std::pair<Clock::time_point, RangeSync::Request>> h_due;
    std::map<uint32_t, RangeSync::Request> t_ranges;
    std::vector<Clock::time_point> t_asked;
    auto t = t0();
    const auto start = t;
    for (int sec = 0; sec < 7200 && rs.mode() == Mode::Anchored; ++sec) {
        t = start + std::chrono::seconds(sec);
        for (const auto& r : rs.tick(peers, t)) {
            if (r.peer == "t") {
                t_ranges[r.range] = r;
                t_asked.push_back(t);
            } else {
                h_due[r.range] = {t + std::chrono::seconds(55), r};
            }
        }
        for (auto it = h_due.begin(); it != h_due.end();) {
            if (it->second.first <= t) {
                rs.on_headers("h", c.answer(it->second.second.locator, it->second.second.stop), t);
                it = h_due.erase(it);
            } else {
                ++it;
            }
        }
        if (rs.inflight_of("t") == 0)
            t_ranges.clear();
        if (sec % 29 == 0)
            for (const auto& [range, req] : t_ranges)
                EXPECT_NE(rs.on_headers("t", {c.headers[STEP * range]}, t), Answer::Stored);
    }
    EXPECT_EQ(rs.mode(), Mode::Complete) << "the trickler held the schedule";
    EXPECT_TRUE(sched->complete());
    EXPECT_TRUE(rs.excluded("t")) << "three strikes did not exclude the trickler";
    EXPECT_GE(rs.stats(t).short_parses, 3u);
    ASSERT_EQ(t_asked.size(), 3u) << "asked once per strike";
    EXPECT_GE(t_asked[1] - t_asked[0], cfg.peer_cooldown) << "not cooled";
    EXPECT_GE(t_asked[2] - t_asked[1], cfg.peer_cooldown) << "not cooled";
    EXPECT_LT(t - start, std::chrono::hours(1));
}

// A peer we asked answers with a linking fake range: excluded, nothing
// stored, nothing ever cut (the sequential sync's truncations stay 0).
TEST(DogeRangeSync, APoisonIsNeverStoredSoNothingIsEverCut)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(CP));
    HashScheduleSync seq(*sched);
    auto t = t0();
    const auto reqs = rs.tick({"p", "h"}, t);
    uint32_t poisoned = UINT32_MAX;
    for (const auto& r : reqs) {
        if (r.peer == "p" && poisoned == UINT32_MAX) {
            poisoned = r.range;
            EXPECT_EQ(rs.on_headers("p", c.fake_range(r.range), t), Answer::Excluded);
            EXPECT_TRUE(sched->stored_hash(STEP * r.range + 1).IsNull()) << "a poisoned record was written";
        } else if (r.peer == "h") {
            rs.on_headers("h", c.answer(r.locator, r.stop), t);
        }
    }
    ASSERT_NE(poisoned, UINT32_MAX);
    EXPECT_TRUE(rs.excluded("p"));
    for (int round = 0; round < 20 && rs.mode() == Mode::Anchored; ++round) {
        t += std::chrono::seconds(1);
        for (const auto& r : rs.tick({"p", "h"}, t)) {
            EXPECT_NE(r.peer, "p") << "an excluded peer was asked";
            rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
        }
    }
    EXPECT_TRUE(sched->complete());
    EXPECT_EQ(sched->hash_at(STEP * poisoned + 1), c.hashes[STEP * poisoned + 1]);
    EXPECT_EQ(seq.truncations(), 0u);
}

// A silent peer's range goes to another peer at 60 s; the silent peer is
// cooled for 10 minutes, then asked again.
TEST(DogeRangeSync, TimeoutReasksAnotherPeerAndCools)
{
    constexpr uint32_t CP = 40 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync::Config cfg;
    cfg.window = 2;
    cfg.per_peer = 1;
    cfg.global = 2;
    RangeSync rs(*sched, c.anchors(CP), cfg);
    const std::vector<std::string> peers{"a", "b"};
    std::map<uint32_t, std::pair<Clock::time_point, RangeSync::Request>> b_due;
    std::vector<std::pair<Clock::time_point, uint32_t>> a_asked;
    uint32_t a_first = UINT32_MAX;
    bool reasked_to_b = false;
    const auto start = t0();
    for (int sec = 0; sec < 900 && rs.mode() == Mode::Anchored; ++sec) {
        const auto t = start + std::chrono::seconds(sec);
        for (const auto& r : rs.tick(peers, t)) {
            if (r.peer == "a") {
                a_asked.emplace_back(t, r.range);
                if (a_first == UINT32_MAX)
                    a_first = r.range;
            } else {
                if (r.range == a_first)
                    reasked_to_b = true;
                b_due[r.range] = {t + std::chrono::seconds(30), r};
            }
        }
        for (auto it = b_due.begin(); it != b_due.end();) {
            if (it->second.first <= t) {
                rs.on_headers("b", c.answer(it->second.second.locator, it->second.second.stop), t);
                it = b_due.erase(it);
            } else {
                ++it;
            }
        }
    }
    ASSERT_GE(a_asked.size(), 2u);
    EXPECT_TRUE(reasked_to_b) << "the silent peer's range was not asked of another peer";
    EXPECT_GE(a_asked[1].first - a_asked[0].first, cfg.request_timeout + cfg.peer_cooldown)
        << "asked again while cooling";
    EXPECT_LT(a_asked[1].first - a_asked[0].first, cfg.request_timeout + cfg.peer_cooldown + std::chrono::seconds(5))
        << "not asked again after its cooldown";
    EXPECT_FALSE(rs.excluded("a"));
}

// Three strikes exclude a peer: never asked again, its answers ignored.
TEST(DogeRangeSync, ThreeTimeoutsExclude)
{
    constexpr uint32_t CP = 40 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync::Config cfg;
    cfg.window = 2;
    cfg.per_peer = 1;
    cfg.global = 2;
    cfg.peer_cooldown = std::chrono::seconds(60);
    RangeSync rs(*sched, c.anchors(CP), cfg);
    const std::vector<std::string> peers{"a", "b"};
    std::map<uint32_t, std::pair<Clock::time_point, RangeSync::Request>> b_due;
    int a_asks = 0, a_asks_after = 0;
    const auto start = t0();
    for (int sec = 0; sec < 1200 && rs.mode() == Mode::Anchored; ++sec) {
        const auto t = start + std::chrono::seconds(sec);
        const bool was_excluded = rs.excluded("a");
        for (const auto& r : rs.tick(peers, t)) {
            if (r.peer == "a") {
                ++a_asks;
                if (was_excluded)
                    ++a_asks_after;
            } else {
                b_due[r.range] = {t + std::chrono::seconds(30), r};
            }
        }
        for (auto it = b_due.begin(); it != b_due.end();) {
            if (it->second.first <= t) {
                rs.on_headers("b", c.answer(it->second.second.locator, it->second.second.stop), t);
                it = b_due.erase(it);
            } else {
                ++it;
            }
        }
    }
    EXPECT_TRUE(rs.excluded("a"));
    EXPECT_EQ(a_asks, 3) << "asked once per strike";
    EXPECT_EQ(a_asks_after, 0) << "an excluded peer was asked";
    const uint32_t undone = sched->first_undone_range();
    if (undone < 40) {
        RangeSync::Request any{undone, "a", {c.hashes[STEP * undone]}, c.hashes[STEP * (undone + 1)]};
        EXPECT_EQ(rs.on_headers("a", c.answer(any.locator, any.stop), start), Answer::NotOurs)
            << "an excluded peer's answer is nobody's request";
    }
}

// In flight: never more than per_peer per peer nor global in all, every
// range inside the window; a silent peer does not starve the schedule.
TEST(DogeRangeSync, InFlightIsBounded)
{
    const RangeSync::Config d;
    EXPECT_EQ(d.window, 64u);
    EXPECT_EQ(d.per_peer, 8u);
    EXPECT_EQ(d.global, 48u);
    EXPECT_EQ(d.request_timeout, std::chrono::seconds(60));
    EXPECT_EQ(d.peer_cooldown, std::chrono::seconds(600));
    constexpr uint32_t CP = 40 * STEP;
    const Chain c(CP);
    {
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync::Config cfg;
        cfg.window = 8;
        cfg.per_peer = 2;
        cfg.global = 6;
        RangeSync rs(*sched, c.anchors(CP), cfg);
        std::vector<std::string> peers;
        for (int i = 0; i < 10; ++i)
            peers.push_back("p" + std::to_string(i));
        // A fast start (answers at once) grows the budget to the global bound.
        auto t = t0();
        for (int sec = 0; sec < 4; ++sec) {
            t = t0() + std::chrono::seconds(sec);
            const auto reqs = rs.tick(peers, t);
            if (sec == 0)
                EXPECT_EQ(reqs.size(), 2u) << "the starting budget";
            for (const auto& r : reqs)
                rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
        }
        t += std::chrono::seconds(1);
        // Now nobody answers: in flight fills up to the bounds.
        const uint32_t first = sched->first_undone_range();
        const auto reqs = rs.tick(peers, t);
        EXPECT_EQ(rs.stats(t).budget, 6u) << "the budget did not grow to GLOBAL on a fast link";
        EXPECT_EQ(reqs.size(), 6u);
        std::map<std::string, int> per;
        for (const auto& r : reqs) {
            EXPECT_LT(r.range, first + 8u) << "outside the window";
            ++per[r.peer];
        }
        for (const auto& [p, n] : per)
            EXPECT_LE(n, 2) << p;
        EXPECT_TRUE(rs.tick(peers, t + std::chrono::seconds(1)).empty()) << "global bound";
        EXPECT_EQ(rs.stats(t).inflight, 6u);
    }
    {
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync::Config cfg;
        cfg.window = 8;
        cfg.per_peer = 2;
        cfg.global = 6;
        RangeSync rs(*sched, c.anchors(CP), cfg);
        const std::vector<std::string> peers{"slow", "f1", "f2"};
        auto t = t0();
        for (int sec = 0; sec < 300 && rs.mode() == Mode::Anchored; ++sec) {
            t = t0() + std::chrono::seconds(sec);
            for (const auto& r : rs.tick(peers, t))
                if (r.peer != "slow")
                    rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
        }
        EXPECT_EQ(rs.mode(), Mode::Complete) << "a silent peer starved the schedule";
        EXPECT_LE(t - t0(), std::chrono::seconds(120));
    }
}

// A restart with half the ranges stored asks only the rest; every stored
// range's records are there (the bit and the records are one batch).
TEST(DogeRangeSync, ResumesFromTheBitmap)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    {
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, c.anchors(CP));
        for (uint32_t r = 0; r < 20; r += 2)
            ASSERT_EQ(sched->store_range(r, c.slice(STEP * r + 1, STEP * (r + 1))), HashSchedule::RangeFeed::Stored);
    }
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(CP));
    EXPECT_EQ(sched->ranges_done(), 10u);
    EXPECT_EQ(sched->frontier_height(), STEP) << "the contiguous prefix";
    for (uint32_t r = 0; r < 20; ++r) {
        EXPECT_EQ(sched->range_done(r), r % 2 == 0);
        if (r % 2 == 0)
            for (uint32_t h : {STEP * r + 1, STEP * r + 1000, STEP * (r + 1)})
                if (h < CP)
                    EXPECT_EQ(sched->stored_hash(h), c.hashes[h]) << "a stored range without its records, h=" << h;
    }
    std::vector<std::string> peers;
    for (int i = 0; i < 4; ++i)
        peers.push_back("p" + std::to_string(i));
    std::set<uint32_t> asked;
    for (int round = 0; round < 10 && rs.mode() == Mode::Anchored; ++round) {
        for (const auto& r : rs.tick(peers, t0() + std::chrono::seconds(round))) {
            EXPECT_EQ(r.range % 2, 1u) << "a stored range asked again";
            asked.insert(r.range);
            rs.on_headers(r.peer, c.answer(r.locator, r.stop), t0());
        }
    }
    EXPECT_EQ(asked.size(), 10u) << "the ten missing ranges, each once";
    EXPECT_TRUE(sched->complete());
}

// A DB written by the sequential sync (and cut back, with a hole and a wrong
// record above the cut): a range whose 2,000 records link from its anchor to
// the next is imported; one with a hole, a wrong record, or partial is not.
TEST(DogeRangeSync, ImportsASequentialPrefix)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    {
        auto sched = open_schedule(s, c, CP);
        ASSERT_EQ(sched->feed(c.slice(1, 9000)), Feed::Extended);
        ASSERT_TRUE(sched->truncate(1000));  // the live cut: records above stay
        ASSERT_EQ(sched->frontier_height(), 1000u);
    }
    auto key = [](uint32_t h) {
        std::string k(5, '\0');
        k[0] = 'H';
        k[1] = static_cast<char>((h >> 24) & 0xFF);
        k[2] = static_cast<char>((h >> 16) & 0xFF);
        k[3] = static_cast<char>((h >> 8) & 0xFF);
        k[4] = static_cast<char>(h & 0xFF);
        return k;
    };
    ASSERT_TRUE(s.db->remove(key(2500)));  // a hole in range 1
    std::vector<uint8_t> wrong(64, 0x5a);     // a wrong record ending range 2
    std::memcpy(wrong.data() + 32, c.hashes[5999].data(), 32);
    ASSERT_TRUE(s.db->put(key(6000), wrong));
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(CP));
    EXPECT_TRUE(sched->range_done(0));
    EXPECT_FALSE(sched->range_done(1)) << "a range with a hole was imported";
    EXPECT_FALSE(sched->range_done(2)) << "a range ending at a wrong record was imported";
    EXPECT_TRUE(sched->range_done(3)) << "an intact range above the cut frontier was not imported";
    EXPECT_FALSE(sched->range_done(4)) << "a partial range was imported";
    EXPECT_EQ(sched->ranges_done(), 2u);
    EXPECT_EQ(sched->frontier_height(), STEP);
    for (int round = 0; round < 10 && rs.mode() == Mode::Anchored; ++round)
        for (const auto& r : rs.tick({"a", "b"}, t0() + std::chrono::seconds(round)))
            rs.on_headers(r.peer, c.answer(r.locator, r.stop), t0());
    EXPECT_TRUE(sched->complete());
    EXPECT_EQ(sched->hash_at(6000), c.hashes[6000]);
    EXPECT_EQ(sched->hash_at(2500), c.hashes[2500]);
}

// A wrong anchor (a_5): three asked peers agree the range ending there ends
// elsewhere: the anchors are refused, the sequential sync completes from the
// delivered prefix into the checkpoint; the delivered ranges are kept. The
// refusal holds for the process only: the next start tries the anchors
// again (VERIFY5 S1).
TEST(DogeRangeSync, WrongAnchorFallsBackToSequential)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    auto anchors = c.anchors(CP);
    anchors.hashes[5].SetHex("00000000000000000000000000000000000000000000000000000000000000ff");
    RangeSync rs(*sched, anchors);
    std::vector<std::string> peers;
    for (int i = 0; i < 6; ++i)
        peers.push_back("p" + std::to_string(i));
    auto t = t0();
    for (int sec = 0; sec < 600 && rs.mode() == Mode::Anchored; ++sec) {
        t = t0() + std::chrono::seconds(sec);
        for (const auto& r : rs.tick(peers, t))
            rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
    }
    ASSERT_EQ(rs.mode(), Mode::SequentialFallback);
    EXPECT_EQ(rs.floor(), 4 * STEP) << "the contiguous prefix: ranges 0..3";
    EXPECT_TRUE(sched->range_done(10)) << "a delivered range above the wrong anchor";
    {
        RangeSync again(*sched, anchors);
        EXPECT_EQ(again.mode(), Mode::Anchored) << "the refusal is per process: the next start tries the anchors";
    }
    HashScheduleSync seq(*sched);
    seq.set_floor(rs.floor());
    complete_sequentially(*sched, seq, c, t);
    EXPECT_TRUE(sched->complete());
    EXPECT_EQ(sched->hash_at(STEP * 5), c.hashes[STEP * 5]);
    EXPECT_EQ(seq.truncations(), 0u);
}

// Anchors for an older checkpoint (20,000; configured 23,500): the ranges
// cover the prefix, then the sequential sync fetches the tail.
TEST(DogeRangeSync, AnchorsForAnOlderCheckpointCoverThePrefixThenTheTailIsSequential)
{
    constexpr uint32_t CP = 23500;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(10 * STEP));
    ASSERT_EQ(rs.mode(), Mode::Anchored);
    auto t = t0();
    for (int round = 0; round < 10 && rs.mode() == Mode::Anchored; ++round)
        for (const auto& r : rs.tick({"a", "b"}, t + std::chrono::seconds(round)))
            rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
    ASSERT_EQ(rs.mode(), Mode::Tail);
    EXPECT_TRUE(rs.sequential());
    EXPECT_EQ(sched->frontier_height(), 10 * STEP);
    EXPECT_FALSE(sched->complete());
    HashScheduleSync seq(*sched);
    seq.set_floor(rs.floor());
    complete_sequentially(*sched, seq, c, t);
    EXPECT_TRUE(sched->complete());
    EXPECT_EQ(sched->hash_at(21000), c.hashes[21000]);
    EXPECT_EQ(sched->hash_at(19999), c.hashes[19999]);
}

// No anchors (a build without the .inc, a list whose digest does not match,
// anchors for another genesis or above the checkpoint): the sequential sync,
// as before.
TEST(DogeRangeSync, AbsentAnchorsUseTheSequentialSync)
{
    constexpr uint32_t CP = 10 * STEP;
    const Chain c(CP);
    {
        auto lines = c.anchors(CP).to_lines();
        lines[3] = "digest " + std::string(64, '0');
        std::string err;
        EXPECT_FALSE(ScheduleAnchors::parse(lines, &err).has_value());
        EXPECT_EQ(err, "digest mismatch");
    }
    {
        const Chain other(CP, 5);  // another chain from the same genesis
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, other.anchors(CP));
        EXPECT_EQ(rs.mode(), Mode::SequentialFallback) << "anchors ending at another checkpoint hash";
    }
    {
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, c.anchors(CP));  // the same checkpoint: usable
        EXPECT_EQ(rs.mode(), Mode::Anchored);
    }
    {
        const Chain longer(CP + STEP);
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, longer.anchors(CP + STEP));
        EXPECT_EQ(rs.mode(), Mode::SequentialFallback) << "anchors above the checkpoint";
    }
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, ScheduleAnchors{});
    EXPECT_EQ(rs.mode(), Mode::SequentialFallback);
    EXPECT_TRUE(rs.sequential());
    EXPECT_TRUE(rs.tick({"a"}, t0()).empty());
    EXPECT_EQ(rs.on_headers("a", c.slice(1, STEP), t0()), Answer::NotOurs);
    HashScheduleSync seq(*sched);
    auto t = t0();
    complete_sequentially(*sched, seq, c, t);
    EXPECT_TRUE(sched->complete());
}

// The dump: a complete schedule's anchors written as the .inc and read back
// give the same list and digest; an incomplete schedule is refused.
TEST(DogeRangeSync, AnchorDumpRoundTrips)
{
    constexpr uint32_t CP = 5 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    std::string err;
    EXPECT_FALSE(doge::coin::anchors_from_schedule(*sched, &err).has_value());
    EXPECT_NE(err.find("not complete"), std::string::npos);
    ASSERT_EQ(sched->feed(c.slice(1, CP)), Feed::Complete);
    const auto a = doge::coin::anchors_from_schedule(*sched, &err);
    ASSERT_TRUE(a.has_value()) << err;
    EXPECT_EQ(a->hashes, c.anchors(CP).hashes);
    const std::string inc = a->to_inc({"test header"});
    std::vector<std::string> lines;
    size_t pos = 0;
    while ((pos = inc.find('"', pos)) != std::string::npos) {
        const size_t end = inc.find('"', pos + 1);
        lines.push_back(inc.substr(pos + 1, end - pos - 1));
        pos = end + 1;
    }
    const auto back = ScheduleAnchors::parse(lines, &err);
    ASSERT_TRUE(back.has_value()) << err;
    EXPECT_EQ(back->hashes, a->hashes);
    EXPECT_EQ(back->digest(), a->digest());
    EXPECT_EQ(back->checkpoint_height(), CP);
    EXPECT_EQ(back->checkpoint_hash(), c.hashes[CP]);
}

// The headers routing: a range answer from a peer with a header-chain
// getheaders outstanding does not answer it; a header-chain answer (above
// the checkpoint) is not taken for a range and answers it; a sequential
// schedule answer does not answer it either.
TEST(DogeRangeSync, RangeAnswersNeverTouchHeaderAsks)
{
    using Taken = doge::coin::HeadersRoute::Taken;
    constexpr uint32_t CP = 10 * STEP;
    const Chain c(CP);
    const auto t = t0();
    {
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, c.anchors(CP));
        doge::coin::HeaderAsks asks;
        asks.sent("p", t);
        const auto reqs = rs.tick({"p"}, t);
        ASSERT_FALSE(reqs.empty());
        auto route = doge::coin::route_headers(&rs, nullptr, sched.get(), asks, "p",
                                               c.answer(reqs[0].locator, reqs[0].stop), t);
        EXPECT_EQ(route.taken, Taken::Range);
        EXPECT_EQ(route.range, Answer::Stored);
        EXPECT_TRUE(asks.outstanding("p", t)) << "a range answer answered the header chain's getheaders";
        // Headers above the checkpoint (the header chain's): not a range.
        const Chain tip(CP + 3);
        const auto above = tip.slice(CP + 1, CP + 3);
        route = doge::coin::route_headers(&rs, nullptr, sched.get(), asks, "p", above, t);
        EXPECT_EQ(route.taken, Taken::HeaderChain);
        EXPECT_FALSE(asks.outstanding("p", t));
    }
    {
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, ScheduleAnchors{});
        HashScheduleSync seq(*sched);
        doge::coin::HeaderAsks asks;
        asks.sent("q", t);
        ASSERT_TRUE(seq.due(t).has_value());
        seq.asked("q", t);
        const auto route = doge::coin::route_headers(&rs, &seq, sched.get(), asks, "q", c.slice(1, STEP), t);
        EXPECT_EQ(route.taken, Taken::Schedule);
        EXPECT_EQ(route.feed, Feed::Extended);
        EXPECT_TRUE(asks.outstanding("q", t)) << "a schedule answer answered the header chain's getheaders";
    }
}

// The anchors compiled in (when the build carries the generated .inc): they
// parse (digest, heights, checkpoint line) and run from DOGE mainnet's genesis
// to the built-in header checkpoint 6,160,000.
TEST(DogeRangeSync, BuiltinAnchorsAreDogeMainnet)
{
    const auto& a = ScheduleAnchors::builtin();
    if (doge::coin::DOGE_SCHEDULE_ANCHOR_LINE_COUNT == 0) {
        EXPECT_TRUE(a.empty()) << "no .inc in this build: no anchors";
        return;
    }
    ASSERT_FALSE(a.empty()) << "the generated .inc does not parse";
    EXPECT_EQ(a.hashes.front(), genesis_hash());
    EXPECT_EQ(a.checkpoint_height(), 6160000u);
    uint256 cp;
    cp.SetHex("51efd04daebddba43ae403662098524d99abf3edad3bddc3ea7b2938c6799939");
    EXPECT_EQ(a.checkpoint_hash(), cp);
    EXPECT_EQ(a.hashes.size(), 3081u);
}

// ---------------------------------------------------------------------------
// VERIFY5 (ee4c882f0): unasked WrongEnd answers refused the anchors for good
// (S1); a wrong anchor with two peers stalled (S2). The verifier's probes.
// ---------------------------------------------------------------------------

// VERIFY5 S1 (the verifier's probe V5-P3, kept as the KAT): a WrongEnd
// answer is 2,000 linked headers from an anchor's child ending elsewhere: no
// PoW, no ask needed. Answers from peers never asked for the range cannot
// refuse the anchors, and nothing is persisted that a restart would obey. On
// ee4c882f0 three unsolicited fakes from three peers switched the schedule
// to the sequential fallback for good.
TEST(DogeRangeSync, UnsolicitedWrongEndAnswersCannotRefuseTheAnchors)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    const auto anchors = c.anchors(CP);
    RangeSync rs(*sched, anchors);
    ASSERT_EQ(rs.mode(), Mode::Anchored);
    auto t = t0();
    // Only "h" is ever asked.
    const auto reqs = rs.tick({"h"}, t);
    ASSERT_FALSE(reqs.empty());
    const uint32_t r = 15;  // not in flight to anyone (h holds 0..7)
    for (const auto& q : reqs)
        ASSERT_NE(q.range, r);
    for (int i = 0; i < 3; ++i) {
        const std::string sybil = "sybil" + std::to_string(i);
        const auto a = rs.on_headers(sybil, c.fake_range(r), t);
        std::cout << "  " << sybil << " unsolicited wrong-end answer: "
                  << (a == Answer::Excluded ? "Excluded" : a == Answer::Ignored ? "Ignored" : "other")
                  << " mode=" << RangeSync::mode_name(rs.mode()) << "\n";
    }
    EXPECT_EQ(rs.mode(), Mode::Anchored) << "three unsolicited fakes refused the anchors";
    EXPECT_FALSE(rs.sequential());
    // And across a restart:
    RangeSync again(*sched, anchors);
    EXPECT_EQ(again.mode(), Mode::Anchored) << "the refusal was persisted: the anchors are never tried again";
}

// VERIFY5 S2 (the verifier's probe V5-P5, kept as the KAT): a wrong anchor
// with fewer than VOTES peers connected: every peer is excluded on its honest
// answer to the range, the votes never reach three. The schedule still
// reaches the fallback (every connected peer excluded for 5 minutes). On
// ee4c882f0 both peers were excluded and no request went out again.
TEST(DogeRangeSync, AWrongAnchorWithTwoPeersStillFallsBack)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    auto anchors = c.anchors(CP);
    anchors.hashes[5].SetHex("00000000000000000000000000000000000000000000000000000000000000ff");
    RangeSync rs(*sched, anchors);
    const std::vector<std::string> peers{"p0", "p1"};
    auto t = t0();
    size_t last_reqs = 0;
    for (int sec = 0; sec < 1200 && rs.mode() == Mode::Anchored; ++sec) {
        t = t0() + std::chrono::seconds(sec);
        const auto reqs = rs.tick(peers, t);
        last_reqs = reqs.size();
        for (const auto& r : reqs)
            rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
    }
    std::cout << "  mode=" << RangeSync::mode_name(rs.mode()) << " excluded(p0)=" << rs.excluded("p0")
              << " excluded(p1)=" << rs.excluded("p1") << " ranges_done=" << sched->ranges_done()
              << " last tick requests=" << last_reqs << "\n";
    EXPECT_NE(rs.mode(), Mode::Anchored) << "two honest peers, one wrong anchor: stuck in anchored mode with every peer excluded";
}

// The verifier's probe V5-P6, kept as a pin: the in-flight map never exceeds
// GLOBAL, nor a peer PER_PEER, with many peers connected.
TEST(DogeRangeSync, InFlightNeverExceedsGlobalUnderManyPeers)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync rs(*sched, c.anchors(CP));
    std::vector<std::string> peers;
    for (int i = 0; i < 64; ++i)
        peers.push_back("p" + std::to_string(i));
    auto t = t0();
    const auto reqs = rs.tick(peers, t);
    EXPECT_LE(reqs.size(), 48u);
    EXPECT_LE(rs.stats(t).inflight, 48u);
    for (const auto& p : peers)
        EXPECT_LE(rs.inflight_of(p), 8u);
}

// The live fresh-node run beside a block IBD: the schedule's share of the
// link was ~0.5 MB/s, an AuxPoW range ~1.6 MB, and 48 ranges in flight were
// minutes of queue: every honest peer missed its 60 s and took strikes (17
// in 5 minutes). Eighteen honest peers behind one link that delivers a range
// every 4 s, in order: the in-flight budget follows the delivery rate, no
// peer is struck or excluded, and the schedule completes.
TEST(DogeRangeSync, ALimitedLinkStrikesNoPeer)
{
    constexpr uint32_t CP = 100 * STEP;
    const Chain c(CP);
    // One range every 4 s (the first live minutes), then a starved link: one
    // every 20 s (the live run during its own accrual bootstrap, ~3 a minute).
    for (const int every : {4, 20}) {
        TempStore s;
        auto sched = open_schedule(s, c, CP);
        RangeSync rs(*sched, c.anchors(CP));
        std::vector<std::string> peers;
        for (int i = 0; i < 18; ++i)
            peers.push_back("p" + std::to_string(i));
        std::deque<RangeSync::Request> link;  // answered in the order asked, one every `every` s
        auto t = t0();
        int sec = 0;
        for (; sec < 120 * every + 600 && rs.mode() == Mode::Anchored; ++sec) {
            t = t0() + std::chrono::seconds(sec);
            for (const auto& r : rs.tick(peers, t))
                link.push_back(r);
            if (sec % every == every - 1 && !link.empty()) {
                const auto r = link.front();
                link.pop_front();
                rs.on_headers(r.peer, c.answer(r.locator, r.stop), t);
            }
        }
        const auto st = rs.stats(t);
        EXPECT_EQ(st.strikes, 0u) << "a range every " << every << " s: honest peers struck because our own "
                                  << "link was full (" << st.timeouts << " range timeouts)";
        EXPECT_EQ(st.excluded, 0u);
        EXPECT_EQ(rs.mode(), Mode::Complete)
            << "a range every " << every << " s: ranges_done=" << st.ranges_done << " after " << sec << " s";
    }
}

// A peer struck while the link was full delivers afterwards: the delivery
// forgives the strike, so two more timeouts do not exclude it. A peer that
// never delivers is excluded on its third strike (ThreeTimeoutsExclude).
TEST(DogeRangeSync, ADeliveryForgivesAStrike)
{
    constexpr uint32_t CP = 20 * STEP;
    const Chain c(CP);
    TempStore s;
    auto sched = open_schedule(s, c, CP);
    RangeSync::Config cfg;
    cfg.window = 1;
    cfg.per_peer = 1;
    cfg.global = 1;
    cfg.peer_cooldown = std::chrono::seconds(60);
    RangeSync rs(*sched, c.anchors(CP), cfg);
    auto t = t0();
    int asked = 0, struck_silent = 0;
    bool delivered = false;
    for (int sec = 0; sec < 900; ++sec) {
        t = t0() + std::chrono::seconds(sec);
        for (const auto& r : rs.tick({"a"}, t)) {
            ++asked;
            if (asked == 2) {  // the second ask is answered: the link is back
                EXPECT_EQ(rs.on_headers("a", c.answer(r.locator, r.stop), t), Answer::Stored);
                delivered = true;
            } else {
                ++struck_silent;  // the others time out
            }
        }
        if (struck_silent >= 3 && delivered)
            break;
    }
    ASSERT_TRUE(delivered);
    ASSERT_GE(struck_silent, 3);
    t += cfg.request_timeout + std::chrono::seconds(1);
    rs.tick({"a"}, t);  // the last silent ask times out
    EXPECT_FALSE(rs.excluded("a")) << "three strikes, one forgiven by a delivery: excluded anyway";
}
