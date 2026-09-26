// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_restart_kat -- DROPS-RESTART (flip-1 multinode robustness).
//
// Three defects the RAIN-BACKFILL-2 restart runs measured on a 3-node regtest:
//
//   R1  THE prev_lane WALK DECIDED ON TRANSIENT FAILURES. A predecessor whose
//       decode failed WITH a reason (lane-root-unknown: the restarted node's
//       ring had not reached the block's root yet) was memoised "not lane", and
//       a chain row that was not readable ended the walk as "no lane block
//       below" (lo = 0). The restarted node skipped canonical lane blocks and
//       composed h over a different range than its peers. Fix: only
//       bytes-read-and-no-lane-tag is a deterministic "not lane"; a tagged
//       block is a lane block; an unreadable row or unreadable bytes HOLD
//       (nullopt) and nothing is memoised.
//   R2  THE WINNER'S CARRIED DELTA LIVED ONLY IN MEMORY. A winner restarted
//       with its own win pending never sent it, and every node waited for it
//       forever. Fix: the carried-delta journal (DropsCarryStore: own wins,
//       carried frames written BEFORE they are sent or booked, booked deltas)
//       survives the restart, and ANY node that holds a carried frame serves it
//       on request (FB_GETWON, gate ON only), so a lost message or a dead winner
//       does not stall booking.
//   R3  A RESTART RE-DROVE PENDING FOUNDS THROUGH THE PRE-DROPS PATH (price
//       INVALID, empty local delta) and forked owed_digest. Fix: the journalled
//       booked delta is re-booked by block id; the shell HOLDs a booking while
//       DROPS is not live.
//
// RED on the base (c3fd4b55: no DropsCarryStore / walk / FB_GETWON; the base
// branches below run the base's own logic and the checks fail); GREEN on the
// fix. The relay section needs a flip-1 build (a flip-0 decoder refuses
// FB_BLOCK_WON v0x02 by construction) and is SKIPPED at flip 0.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif
#ifndef V37_XMR_SRC_DIR
#define V37_XMR_SRC_DIR ""
#endif

using namespace gap2test;
using namespace std::chrono_literals;
namespace dx = ::c2pool::v37n::xmr::drops;
using COH = dx::ChainOrderedHarvest;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;

static std::string slurp(const std::string& p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}

// ── R1 model: a 3-node chain, heights 1..130, lane blocks = tagged coinbases ──
// truth (a synced node): lane blocks at 60, 105, 110, 115; 120 carries NO tag.
struct Obs { bool bytes_read = true; bool is_lane = false; bool has_tag = false; std::string why; };
static std::string bid_at(std::uint64_t h) { char b[65]; std::snprintf(b, sizeof b, "%064llx", (unsigned long long)(0xb10c0000ULL + h)); return b; }
static std::uint64_t h_of(const std::string& bid) { return std::strtoull(bid.c_str(), nullptr, 16) - 0xb10c0000ULL; }
static bool tagged(std::uint64_t h) { return h == 60 || h == 105 || h == 110 || h == 115; }
// A RESTARTED node: its ring does not hold 115's root yet (decode fails WITH a
// reason, is_lane false, tag present); 118's bytes are not readable on the
// first read (transient fetch failure).
struct Restarted {
    std::map<std::uint64_t, int> reads;
    std::set<std::uint64_t> rows_missing;
    bool ring_caught_up = false;
    Obs observe(std::uint64_t h) {
        Obs o;
        const int n = reads[h]++;
        if (h == 118 && n == 0) { o.bytes_read = false; return o; }
        o.has_tag = tagged(h);
        o.is_lane = o.has_tag && (h != 115 || ring_caught_up);
        if (o.has_tag && !o.is_lane) o.why = "lane-root-unknown: root not in the candidate ring";
        else if (!o.has_tag) o.why = "not-lane: no 03-21-00 tag";
        return o;
    }
    std::optional<std::string> row(std::uint64_t h) { if (rows_missing.count(h)) return std::nullopt; return bid_at(h); }
};
static std::optional<std::uint64_t> truth_prev(std::uint64_t h) {
    for (std::uint64_t x = h; x-- > 1;) if (tagged(x)) return x;
    return COH::kNoPrevLane;
}
// The walk under test. Fix: COH::walk_prev_lane + probe_of. Base: the shell's
// RAIN-BACKFILL-2 lambda body, verbatim in logic.
static std::optional<std::uint64_t> walk(Restarted& n, std::uint64_t h, std::map<std::string, bool>& memo) {
#if defined(C2POOL_XMR_DROPS_RESTART)
    return COH::walk_prev_lane(h, 1024, [&](std::uint64_t x) { return n.row(x); },
        [&](const std::string& b) { const Obs o = n.observe(h_of(b)); return COH::probe_of(o.bytes_read, o.is_lane, o.has_tag); }, memo);
#else
    for (std::uint64_t x = h; x-- > 1 && h - x <= 1024;) {
        const auto b = n.row(x);
        if (!b) break;
        auto it = memo.find(*b);
        if (it == memo.end()) {
            const Obs o = n.observe(x);
            const bool ok = o.bytes_read && o.is_lane;
            if (!ok && !o.is_lane && (o.bytes_read ? o.why : std::string()).empty()) return std::nullopt;
            it = memo.emplace(*b, o.is_lane).first;
        }
        if (it->second) return x;
    }
    return COH::kNoPrevLane;
#endif
}
static std::string show(std::optional<std::uint64_t> v) { return v ? std::to_string(*v) : std::string("HOLD"); }

// ── R2 relay harness (real loopback TCP) ────────────────────────────────────
struct RNode {
    std::string name;
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    std::vector<BlockWon> got;
    RNode(std::string n, RelayOptions ro) : name(std::move(n)) {
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [](const std::string&) {});
    }
    ~RNode() { relay->stop(); }
    void pump() { for (auto& [b, p] : relay->drain_block_won()) { (void)p; got.push_back(b); } }
};
static RelayOptions opts(bool listen, std::vector<u16> dial, u64 floor_diff) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = floor_diff;
    return o;
}
template <class F>
static bool wait_for(F cond, std::vector<RNode*> pump, std::chrono::milliseconds limit = 10000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
static BlockWon carried_win(u8 seed, u64 h) {
    BlockWon b;
    b.chain_id = kChain; b.bid = b32_of(seed); b.h_b = h; b.cut_next_pos = 5; b.cut_spine_digest = b32_of(seed + 1);
    b.reward = 35174273644664ULL; b.payout_emitted = true; b.owed_digest_at_win = b32_of(seed + 2);
    BlockWon::Drops d; d.delta[b32_of(0x21)] = 1234567; d.delta[b32_of(0x22)] = -1234567; d.enrollment_digest = b32_of(0x23);
    b.drops = d;
    return b;
}

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_restart_kat (DROPS-RESTART %s, v0x02 decoder %s) ==\n",
#if defined(C2POOL_XMR_DROPS_RESTART)
                "present",
#else
                "ABSENT: base logic",
#endif
                kBlockWonDropsLive ? "ON (flip 1)" : "OFF (flip 0)");

    // ── R1 the prev_lane walk: transient failures HOLD, never decide ────────
    {
        Restarted n; std::map<std::string, bool> memo;
        const auto a = walk(n, 121, memo);   // 120 not lane, 119 not lane, 118 unreadable (first read)
        std::printf("    R1a walk(121) first read: %s (truth %s); memo holds 118: %d\n", show(a).c_str(), show(truth_prev(121)).c_str(),
                    (int)memo.count(bid_at(118)));
        C(!a.has_value(), "R1a ★ unreadable bytes of a predecessor HOLD the walk (nullopt), never a decision");
        C(memo.count(bid_at(118)) == 0, "R1a ★ nothing is memoised for a block whose bytes were not read");
        const auto b = walk(n, 121, memo);   // 118 readable now; 115: tag present, root not in this node's ring yet
        std::printf("    R1b walk(121) again: %s (truth %s); memo 115 = %s\n", show(b).c_str(), show(truth_prev(121)).c_str(),
                    memo.count(bid_at(115)) ? (memo[bid_at(115)] ? "lane" : "NOT-LANE") : "-");
        C(b == truth_prev(121), "R1b ★ a TAGGED block whose root this restarted node cannot match yet is still the lane predecessor (115)");
        n.ring_caught_up = true;
        C(walk(n, 117, memo) == truth_prev(117), "R1c the memo never holds a ring-dependent 'not lane' (walk(117) = 115 after catch-up)");
        Restarted m; m.rows_missing.insert(108); std::map<std::string, bool> memo2;
        const auto c = walk(m, 109, memo2);
        std::printf("    R1d walk(109) with the chain row at 108 unreadable: %s (base answered 'no lane below' -> lo=0)\n", show(c).c_str());
        C(!c.has_value(), "R1d ★ an unreadable chain row HOLDs (nullopt), never 'no lane block below' (lo = 0)");
        Restarted k; std::map<std::string, bool> memo3;
        C(walk(k, 59, memo3) == COH::kNoPrevLane, "R1e walking to height 1 with every block read and untagged is the deterministic 'none below'");
        C(walk(k, 104, memo3) == 60, "R1f a readable chain finds the nearest tagged block (60)");
#if defined(C2POOL_XMR_DROPS_RESTART)
        C(COH::probe_of(false, false, false) == COH::LaneProbe::Undecidable &&
          COH::probe_of(true, false, true) == COH::LaneProbe::Lane &&
          COH::probe_of(true, true, true) == COH::LaneProbe::Lane &&
          COH::probe_of(true, false, false) == COH::LaneProbe::NotLane,
          "R1g probe_of: unread=UNDECIDABLE, tag=LANE (matched or not), read+untagged=NOT-LANE");
#else
        C(false, "R1g probe_of (base: absent)");
#endif
    }

    // ── R2a the carried-delta journal survives a restart ────────────────────
    {
#if defined(C2POOL_XMR_DROPS_RESTART)
        const std::string path = "/tmp/v37_xmr_drops_restart_kat." + std::to_string(::getpid()) + ".journal";
        std::remove(path.c_str());
        const BlockWon own = [] { BlockWon b = carried_win(0x31, 151); b.drops.reset(); return b; }();
        const BlockWon won = carried_win(0x41, 152);
        const std::string own_bid(64, 'a'), won_bid(64, 'b'), redo_bid(64, 'c');
        std::map<::v37::bytes32, long long> d1 = won.drops->delta, d2;
        {
            dx::DropsCarryStore s(path);
            C(s.put_own(own_bid, encode_block_won(own)), "R2a winner journals its own win at registration (W, fsync)");
            C(s.put_frame(won_bid, encode_block_won(won)), "R2a winner journals its composed v0x02 frame BEFORE sending it (F)");
            C(s.put_booked(won_bid, d1) && s.put_booked(redo_bid, d2) && s.put_booked(redo_bid, d1),
              "R2a booked deltas journalled before booking (B; last record wins)");
        }
        { std::FILE* f = std::fopen(path.c_str(), "a"); std::fputs("B cccc", f); std::fclose(f); }   // torn tail (crash mid-append)
        dx::DropsCarryStore r(path);
        const auto l = r.load();
        std::printf("    R2a reloaded own=%zu frames=%zu booked=%zu malformed=%zu\n", l.own, l.frames, l.booked, l.malformed);
        C(l.own == 1 && l.frames == 1 && l.booked == 3 && l.malformed == 1, "R2a reload: 1 own, 1 frame, 3 booked records, the torn tail ignored");
        C(r.own().count(own_bid) && r.own().at(own_bid) == encode_block_won(own), "R2a ★ the own win (no delta yet) survives the restart byte-exact");
        C(r.frames().count(won_bid) && r.frames().at(won_bid) == encode_block_won(won), "R2a ★ the carried frame survives the restart byte-exact");
        C(r.booked(won_bid) == d1 && r.booked(redo_bid) == d1 && !r.booked(own_bid), "R2a ★ booked deltas by bid (a re-drive books exactly these)");
        std::remove(path.c_str());
#else
        C(false, "R2a the carried delta survives a restart (base: own_won lives only in memory)");
#endif
    }

    // ── R2b a non-winner serves the carried frame on request ────────────────
    if (!kBlockWonDropsLive) {
        std::printf("    R2b SKIPPED: flip-0 build (the v0x02 decoder is OFF by construction)\n");
#if defined(C2POOL_XMR_DROPS_RESTART)
        RNode Z("Z", opts(false, {}, 0));
        C(Z.relay->want_block_won(b32_of(1)) == 0, "R2b flip 0 (drops_floor_diff 0): want_block_won sends nothing");
#endif
    } else {
        std::string why;
        auto W = std::make_unique<RNode>("W", opts(true, {}, kFloorDiff));
        C(W->relay->start(why), "R2b W (the winner) listens " + why);
        RNode B("B", opts(true, {W->relay->listen_port()}, kFloorDiff));
        C(B.relay->start(why), "R2b B dials W " + why);
        RNode Cn("C", opts(false, {B.relay->listen_port()}, kFloorDiff));
        C(Cn.relay->start(why), "R2b C dials B only " + why);
        C(wait_for([&] { return W->relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 2 && Cn.relay->ready_peers().size() == 1; },
                   {W.get(), &B, &Cn}), "R2b HELLO: W-B-C up");
        const BlockWon won = carried_win(0x51, 151);
        W->relay->broadcast_block_won(won);
        C(wait_for([&] { return !B.got.empty() && !Cn.got.empty(); }, {W.get(), &B, &Cn}), "R2b the v0x02 frame floods W -> B -> C");
        Cn.got.clear();   // C LOST it (restart before it could keep the delta / a dropped message)
        W.reset();        // the winner is gone
        C(wait_for([&] { return B.relay->ready_peers().size() == 1; }, {&B, &Cn}), "R2b the winner is down; B-C still up");
#if defined(C2POOL_XMR_DROPS_RESTART)
        const std::size_t asked = Cn.relay->want_block_won(won.bid);
        const bool back = wait_for([&] { return !Cn.got.empty(); }, {&B, &Cn});
        std::printf("    R2b C asked %zu peer(s); B served=%llu; C solicited_rx=%llu\n", asked,
                    (unsigned long long)B.relay->stats().won_served.load(), (unsigned long long)Cn.relay->stats().won_solicited_rx.load());
        C(asked == 1 && back, "R2b ★ C gets the carried frame back from B (a NON-winner) with the winner down");
        C(back && Cn.got.front().bid == won.bid && Cn.got.front().drops && Cn.got.front().drops->delta == won.drops->delta &&
          Cn.got.front().owed_digest_at_win == won.owed_digest_at_win,
          "R2b ★ the served frame is the winner's, byte for byte (delta + commitment fields for the booking check)");
        C(B.relay->stats().won_served.load() == 1, "R2b B counted one FB_GETWON served");
        const std::size_t asked2 = Cn.relay->want_block_won(b32_of(0x77));
        std::this_thread::sleep_for(300ms); Cn.pump(); B.pump();
        C(asked2 == 1 && B.relay->stats().won_unknown.load() == 1 && Cn.got.size() == 1, "R2b an unknown bid is not answered (counted), nothing delivered");
#else
        const bool back = wait_for([&] { return !Cn.got.empty(); }, {&B, &Cn}, 2000ms);
        C(back, "R2b C gets the carried frame back from a non-winner (base: no FB_GETWON, the bid is deduped for good)");
#endif
    }

    // ── R3 no pre-DROPS booking at flip 1; the re-drive books the journal ───
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        const std::string nd = slurp(std::string(V37_XMR_SRC_DIR) + "/xmr_node.hpp");
        C(!sh.empty() && !nd.empty(), "R3 sources readable");
        const auto bk = sh.find("fo.book_from_chain_ex = [&]");
        const auto hold = sh.find("DROPS not live yet (flip 1: no pre-DROPS booking)");
        const auto fetch = sh.find("fetch_decode(bid, bk, why, &chain_blob, &cand_superseded)");
        C(bk != std::string::npos && hold != std::string::npos && fetch != std::string::npos && bk < hold && hold < fetch,
          "R3 ★ book_from_chain_ex HOLDs (relay-repair family) while DROPS is not live, before anything is decoded or booked");
        const auto seam = sh.find("node.set_drops_booked_fn(");
        const auto reseed = sh.find("fc.reseed_after_bring_up()");
        C(seam != std::string::npos && reseed != std::string::npos && seam < reseed,
          "R3 ★ the journal is loaded and handed to the node BEFORE the boot re-drive of pending FOUNDs");
        C(nd.find("carried = m_drops_booked(fb.bid);") != std::string::npos,
          "R3 ★ XmrNode re-drives a pending FOUND with the journalled booked delta (never a fresh local composition)");
        const auto jb = sh.find("drops_store->put_booked(bid,");
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
        const auto sc = sh.find("drops->set_carried(lane.carry.delta)");   // DROPS-ENROL-LANE: the lane composition is booked
#else
        const auto sc = sh.find("drops->set_carried(wit->second.drops->delta)");
#endif
        C(jb != std::string::npos && sc != std::string::npos && jb < sc, "R3 the booked delta is journalled BEFORE the node books it");
        const auto jf = sh.find("if (drops_store) drops_store->put_frame(bid, relay::encode_block_won(bw));");
        const auto bc = sh.find("relay_node->broadcast_block_won(bw);", jf == std::string::npos ? 0 : jf);
        C(jf != std::string::npos && bc != std::string::npos && jf < bc, "R2 the winner's composed frame is journalled BEFORE it is broadcast (write-ahead)");
        C(sh.find("if (drops && bw.drops) {") != std::string::npos, "R3 a carried delta received before DROPS is live is kept (not dropped)");
        const auto scr = sh.find("fo.book_scratch = [&]");
#if defined(C2POOL_XMR_DROPS_LANE_ENROL)
        const auto scc = sh.find("if (!drops_take_carry(h, bid, bk, why, false, lane)) return false;");   // DROPS-ENROL-LANE
#else
        const auto scc = sh.find("if (drops && !drops_take_carry(h, bid, bk, why, false)) return false;");
#endif
        const auto cdp = sh.find("converge-decode: h=%llu");
        C(scr != std::string::npos && scc != std::string::npos && cdp != std::string::npos && scr < scc && scc < cdp,
          "R3 ★ the D2 scratch re-derivation (minority converge) books the carried delta too, never a pre-DROPS local composition");
        C(sh.find("drops_lane_memo[bid] = bk.is_lane || bk.has_onchain_root;") != std::string::npos,
          "R1 the booking memoises only the bytes' lane tag, never the ring-dependent root match");
    }
    return C.done("v37_xmr_drops_restart_kat");
}
