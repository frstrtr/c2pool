// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT: pre-anchor header-backfill PARALLEL GETHEADERS WINDOW (extends the #1263
// cold-arm header-backfill lane; base PR #1278).
//
// PROVEN DIAGNOSIS (wf wx0agv6hk): the self-derive cold start walked genesis ->
// anchor headers on a SINGLE in-flight getheaders. A peer that received the
// getheaders but never answered stalled the WHOLE walk until the ~15 s re-kick
// timer fired and demoted it — dashd never serializes header fetch on one peer
// (it keeps a download window across peers, event-refills on each arrival, and
// DISCONNECTS a staller rather than leaving a zombie session). This KAT drives
// the real BulkFetchLane header lane against a scripted peer set and proves,
// RED (legacy config) -> GREEN (ported config), the three behaviours:
//
//   A. PARALLEL WINDOW  — GREEN keeps >1 getheaders span in flight across peers
//                         from a cold tip; RED (window=1) is single-inflight.
//   B. EVENT REFILL     — a delivered headers batch immediately issues the next
//                         span (no tick / no timer wait).
//   C. STALL DISCONNECT — a peer silent past the stalling window is
//                         disconnected+redialed (GREEN); RED never disconnects.
//   D. SERIALIZATION    — with one dead peer in the pool, RED pays at least a
//                         full stall window of zero progress (single-inflight
//                         wedge) while GREEN routes around it and completes in
//                         fewer ticks than one stall window. Both complete
//                         (liveness: never a true deadlock).
//
// The lane is REWARD-SAFE by construction and this KAT does not touch that: the
// synthetic chain is prev-hash linked and the join check still pins the anchor;
// only header-fetch peer selection + timing is exercised.

#include <impl/dash/coin/replay_bulk_fetch.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace rp = dash::coin::replay;
using dash::coin::BlockType;
using dash::coin::BlockHeaderType;

static int g_failures = 0;
#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::cout << "  FAIL: " << (msg) << "\n";                           \
            ++g_failures;                                                       \
        } else {                                                                \
            std::cout << "  ok:   " << (msg) << "\n";                           \
        }                                                                       \
    } while (0)

// Hash a header exactly as HeaderBackfill::add_headers does (header slice only).
static uint256 header_hash(const BlockType& b)
{
    BlockHeaderType hdr = static_cast<BlockHeaderType>(b);
    auto packed = ::pack(hdr);
    return dash::crypto::hash_x11(packed.get_span());
}

// A scripted coin-P2P network for the header lane. good peers answer getheaders
// (after a fixed latency); non-good peers swallow them (the silent-stall case).
struct Net
{
    std::vector<BlockType> chain;          // chain[0..anchor]
    std::vector<uint256>   hashes;         // hashes[h] = header_hash(chain[h])
    std::map<uint256, uint32_t> h2h;       // hash -> height
    uint32_t anchor = 0;
    uint32_t batch  = 6;
    int64_t  latency = 1;                  // ticks between ask and answer

    std::set<std::string> good;            // peers that answer
    std::set<std::string> eligible;        // peers CoinClient would offer

    int64_t clock = 0;

    struct Sent { std::string peer; uint256 locator; int64_t at; };
    std::vector<Sent> pending;             // asked, not yet delivered

    uint64_t send_count = 0;
    std::vector<std::string> tick_peers;   // getheaders targets since last reset
    std::vector<std::string> disconnected; // disconnect_and_redial calls
    std::string redial_peer;               // replacement dialed on a disconnect

    void build(uint32_t n, uint32_t batch_)
    {
        anchor = n; batch = batch_;
        chain.clear(); hashes.clear(); h2h.clear();
        uint256 prev;   // genesis prev = null
        for (uint32_t i = 0; i <= n; ++i)
        {
            BlockType b;
            b.SetNull();
            b.m_version = 1;
            b.m_previous_block = prev;
            b.m_timestamp = 1000000 + i;
            b.m_bits = 0x1e0ffff0;         // nonzero (not consulted: check_pow off)
            b.m_nonce = i;
            b.m_merkle_root.SetNull();
            b.m_merkle_root.data()[0] = static_cast<unsigned char>(i & 0xFF);
            b.m_merkle_root.data()[1] = static_cast<unsigned char>((i >> 8) & 0xFF);
            uint256 h = header_hash(b);
            chain.push_back(b);
            hashes.push_back(h);
            h2h[h] = i;
            prev = h;
        }
    }

    std::vector<std::string> eligible_vec() const
    {
        return std::vector<std::string>(eligible.begin(), eligible.end());
    }

    // Deliver every pending response whose peer still answers and whose latency
    // has elapsed. Returns the batches to the lane (which may re-arm the window
    // via the event-driven refill inside on_headers).
    template <typename Lane>
    void deliver(Lane& lane)
    {
        std::vector<Sent> ready;
        for (auto it = pending.begin(); it != pending.end(); )
        {
            const bool answers = good.count(it->peer) && eligible.count(it->peer);
            if (answers && (clock - it->at) >= latency)
            {
                ready.push_back(*it);
                it = pending.erase(it);
            }
            else ++it;
        }
        for (const auto& s : ready)
        {
            auto hit = h2h.find(s.locator);
            if (hit == h2h.end()) continue;
            const uint32_t H = hit->second;
            if (H >= anchor) continue;
            std::vector<BlockType> b;
            for (uint32_t k = H + 1; k <= std::min<uint32_t>(H + batch, anchor); ++k)
                b.push_back(chain[k]);
            if (!b.empty()) lane.on_headers(s.peer, b);
        }
    }
};

// Build a BulkFetchLane wired to the scripted Net + a fresh HeaderBackfill.
struct Rig
{
    Net net;
    uint256 pow_limit;
    std::unique_ptr<rp::HeaderBackfill> backfill;
    std::unique_ptr<rp::CountingReplayConsumer> consumer;
    std::unique_ptr<rp::BulkFetchLane> lane;

    void make(uint32_t chain_n, uint32_t batch, uint32_t window,
              int64_t stall_disconnect_sec)
    {
        net.build(chain_n, batch);
        pow_limit = uint256::ZERO;
        for (int i = 0; i < 32; ++i) pow_limit.data()[i] = 0xFF;

        backfill = std::make_unique<rp::HeaderBackfill>(
            net.hashes[0], net.anchor, net.hashes[net.anchor], pow_limit,
            /*db_path=*/"", /*check_pow=*/false);
        consumer = std::make_unique<rp::CountingReplayConsumer>();

        rp::BulkFetchLane::Seams s;
        Net* n = &net;
        s.hash_at      = [](uint32_t) -> std::optional<uint256> { return std::nullopt; };
        s.chain_height = [n]() { return n->anchor; };
        s.eligible_peers = [n]() { return n->eligible_vec(); };
        s.send_getdata = [](const std::string&, const std::vector<uint256>&) {};
        s.send_getheaders = [n](const std::string& peer, const uint256& loc,
                                const uint256&) {
            ++n->send_count;
            n->tick_peers.push_back(peer);
            n->pending.push_back(Net::Sent{ peer, loc, n->clock });
        };
        s.tip_busy = []() { return false; };
        s.peer_can_serve = [](const std::string&, uint32_t) { return true; };
        s.now_sec = [n]() { return n->clock; };
        s.disconnect_and_redial = [n](const std::string& peer) {
            n->disconnected.push_back(peer);
            n->eligible.erase(peer);
            if (!n->redial_peer.empty())
            {
                n->eligible.insert(n->redial_peer);
                n->good.insert(n->redial_peer);
            }
        };

        rp::BulkFetchLane::Config cfg;
        cfg.start_height = net.anchor + 1;   // body scheduler idle; header lane is the subject
        cfg.tip_exclusion = 0;
        cfg.backfill_rekick_sec = 15;
        cfg.backfill_demote_cooldown_sec = 60;
        cfg.backfill_getheaders_window = window;
        cfg.backfill_stall_disconnect_sec = stall_disconnect_sec;

        lane = std::make_unique<rp::BulkFetchLane>(
            std::move(s), cfg, backfill.get(), consumer.get(), /*cursor=*/nullptr);
    }

    // One simulated second: advance clock, tick the lane, deliver answers.
    void step()
    {
        ++net.clock;
        lane->tick(net.clock);
        net.deliver(*lane);
    }

    // Run until the backfill joins the anchor or the tick budget is spent.
    // Returns the tick count at completion (or budget+1 if it never completed).
    int run(int budget)
    {
        for (int t = 1; t <= budget; ++t)
        {
            step();
            if (backfill->complete()) return t;
        }
        return budget + 1;
    }
};

static void scenario_A_window()
{
    std::cout << "[A] parallel getheaders window (cold tip)\n";
    // GREEN: 3 eligible peers, window 3 — expect 3 concurrent spans.
    {
        Rig r;
        r.make(/*chain*/60, /*batch*/6, /*window*/3, /*disc*/15);
        r.net.good = {"g1", "g2", "g3"};
        r.net.eligible = {"g1", "g2", "g3"};
        r.net.tick_peers.clear();
        ++r.net.clock;
        r.lane->tick(r.net.clock);         // NO delivery: measure the cold fan
        std::set<std::string> distinct(r.net.tick_peers.begin(),
                                       r.net.tick_peers.end());
        CHECK(distinct.size() == 3,
              "GREEN window=3 issues 3 concurrent getheaders (got " +
                  std::to_string(distinct.size()) + ")");
    }
    // RED: same pool, window 1 — single-inflight.
    {
        Rig r;
        r.make(60, 6, /*window*/1, /*disc*/0);
        r.net.good = {"g1", "g2", "g3"};
        r.net.eligible = {"g1", "g2", "g3"};
        r.net.tick_peers.clear();
        ++r.net.clock;
        r.lane->tick(r.net.clock);
        std::set<std::string> distinct(r.net.tick_peers.begin(),
                                       r.net.tick_peers.end());
        CHECK(distinct.size() == 1,
              "RED window=1 is single-inflight (got " +
                  std::to_string(distinct.size()) + ")");
    }
}

static void scenario_B_event_refill()
{
    std::cout << "[B] event-driven refill (no timer wait)\n";
    Rig r;
    r.make(60, 6, /*window*/2, /*disc*/15);
    r.net.good = {"g1", "g2"};
    r.net.eligible = {"g1", "g2"};
    r.net.latency = 0;                     // answer available immediately
    ++r.net.clock;
    r.lane->tick(r.net.clock);             // cold fan issues up to 2 spans
    const uint64_t sends_before = r.net.send_count;
    const uint32_t tip_before = r.backfill->tip_height();
    // Deliver ONE response — WITHOUT another tick. The event-driven refill must
    // issue the next span from inside on_headers.
    // Deliver just g1's pending span.
    for (auto it = r.net.pending.begin(); it != r.net.pending.end(); ++it)
    {
        if (it->peer != "g1") continue;
        uint32_t H = r.net.h2h[it->locator];
        std::vector<BlockType> b;
        for (uint32_t k = H + 1; k <= std::min<uint32_t>(H + r.net.batch, r.net.anchor); ++k)
            b.push_back(r.net.chain[k]);
        r.net.pending.erase(it);
        r.lane->on_headers("g1", b);
        break;
    }
    CHECK(r.backfill->tip_height() > tip_before,
          "delivered batch advanced the walk");
    CHECK(r.net.send_count > sends_before,
          "on_headers issued the next span immediately (event refill, no tick)");
}

static void scenario_C_stall_disconnect()
{
    std::cout << "[C] stall disconnect + redial\n";
    Rig r;
    r.make(/*chain*/100, /*batch*/5, /*window*/2, /*disc*/15);
    r.net.good = {"g1"};                   // g1 answers, bad swallows
    r.net.eligible = {"g1", "bad"};
    r.net.latency = 1;
    r.net.redial_peer = "g3";              // the redial brings a fresh serving peer
    int done = r.run(400);
    CHECK(done <= 400, "backfill completed despite a permanently-silent peer");
    bool bad_dropped = false, g1_dropped = false;
    for (const auto& p : r.net.disconnected)
    {
        if (p == "bad") bad_dropped = true;
        if (p == "g1") g1_dropped = true;
    }
    CHECK(bad_dropped, "silent peer was DISCONNECT+REDIALed (BLOCK_STALLING_TIMEOUT)");
    CHECK(!g1_dropped, "the answering peer was NOT disconnected");
    CHECK(r.backfill->tip_height() == r.net.anchor,
          "walk reached the anchor (join pinned)");
}

static void scenario_C_red_no_disconnect()
{
    std::cout << "[C-RED] disconnect disabled -> demote-only, no disconnect seam call\n";
    Rig r;
    r.make(100, 5, /*window*/2, /*disc*/0);   // disconnect OFF
    r.net.good = {"g1"};
    r.net.eligible = {"g1", "bad"};
    r.net.latency = 1;
    int done = r.run(400);
    CHECK(done <= 400, "RED still completes via demote-only re-home (liveness)");
    CHECK(r.net.disconnected.empty(),
          "RED never called disconnect_and_redial (demote-only fallback)");
}

static void scenario_D_serialization()
{
    std::cout << "[D] single-inflight serialization vs parallel window\n";
    const uint32_t CHAIN = 30, BATCH = 10;   // 3 spans
    // GREEN: window 3, one dead peer in the pool. Must route around it and
    // finish in FEWER ticks than a single stall window (15).
    int green_ticks;
    {
        Rig r;
        r.make(CHAIN, BATCH, /*window*/3, /*disc*/15);
        r.net.good = {"g1", "g2"};
        r.net.eligible = {"g1", "bad", "g2"};
        r.net.latency = 1;
        green_ticks = r.run(400);
        CHECK(r.backfill->complete(), "GREEN completed");
    }
    // RED: window 1, SAME pool. Single-inflight lands on the dead peer and pays
    // a full stall window (>=15 ticks) of zero progress before re-homing.
    int red_ticks;
    {
        Rig r;
        r.make(CHAIN, BATCH, /*window*/1, /*disc*/0);
        r.net.good = {"g1", "g2"};
        r.net.eligible = {"g1", "bad", "g2"};
        r.net.latency = 1;
        red_ticks = r.run(400);
        CHECK(r.backfill->complete(), "RED eventually completed (no true deadlock)");
    }
    std::cout << "  green_ticks=" << green_ticks
              << " red_ticks=" << red_ticks << "\n";
    CHECK(green_ticks < 15,
          "GREEN finished inside one stall window (never serialized on the dead peer)");
    CHECK(red_ticks >= 15,
          "RED paid at least one full stall window (single-inflight wedge)");
    CHECK(red_ticks > green_ticks,
          "parallel window is strictly faster than single-inflight");
}

int main()
{
    std::cout << "=== dash header-backfill parallel-window KAT ===\n";
    scenario_A_window();
    scenario_B_event_refill();
    scenario_C_stall_disconnect();
    scenario_C_red_no_disconnect();
    scenario_D_serialization();
    std::cout << (g_failures == 0 ? "ALL PASS\n" : "FAILURES\n");
    return g_failures == 0 ? 0 : 1;
}
