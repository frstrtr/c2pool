// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_writeahead_kat -- DROPS WRITE-AHEAD (flip-1 restart robustness).
//
// DROPS-RESTART journalled an own win (W) in the FOUND callback, i.e. AFTER the
// block was published. A winner that dies between the publish and that
// callback leaves no record: after its restart it does not know the block is
// its own win, never composes the carried delta, and every node waits for
// "the winner's carried DROPS delta" for good (FB_GETWON finds no holder).
//
// Fix: the exact network gate journals the block (P <bid> <h>) BEFORE it is
// published; at the block's booking a P without a W is our win all the same
// and is composed once, exactly like a registered win.
//
//   WA1  the P record survives a crash (no W ever written) and the booking
//        decision "our win, compose it" answers yes; after the frame (F) it
//        answers no (composed once).
//   WA2  the gate appends P from the stratum listener thread while the main
//        thread appends F / B: every record reloads, none torn.
//   WA3  the restarted winner composes and carries the delta; the waiting
//        peers (which asked FB_GETWON and got nothing) receive it. On the base
//        nothing is composed: the peers stall. Flip 1 only (v0x02 decoder).
//   WA4  source pins: P is written in the gate BEFORE the publish arm is
//        called; the booking composes a P-only win before the carried-delta
//        decision; the hook is installed only when the journal exists (flip 1).
//
// RED on the base (DROPS-RESTART on master: no P record, the checks run the
// base's decision and fail); GREEN on the fix.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
using namespace std::chrono_literals;
namespace dx = ::c2pool::v37n::xmr::drops;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;

static std::string slurp(const std::string& p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}
static std::string hex64(const bytes32& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (u8 x : b) { s.push_back(d[x >> 4]); s.push_back(d[x & 15]); }
    return s;
}
// The booking's decision for a lane block after a restart: is it OUR win whose
// carried delta is still to be composed? Fix: DropsCarryStore::own_to_compose
// (W or P, no F). Base: the reload only knows W records (written in the FOUND
// callback, after the publish).
static bool our_win_to_compose(const dx::DropsCarryStore& s, const std::string& bid) {
#if defined(C2POOL_XMR_DROPS_WRITEAHEAD)
    return s.own_to_compose(bid);
#else
    return s.own().count(bid) != 0 && !s.has_frame(bid);
#endif
}
static BlockWon carried_win(u8 seed, u64 h, std::size_t rows = 2) {
    BlockWon b;
    b.chain_id = kChain; b.bid = b32_of(seed); b.h_b = h; b.cut_next_pos = 5; b.cut_spine_digest = b32_of(seed + 1);
    b.reward = 35174273644664ULL; b.payout_emitted = true; b.owed_digest_at_win = b32_of(seed + 2);
    BlockWon::Drops d;
    for (std::size_t i = 0; i < rows; ++i) {
        bytes32 k = b32_of(0x21); k[1] = static_cast<u8>(i); k[2] = static_cast<u8>(i >> 8);
        d.delta[k] = (i % 2 ? -1 : 1) * static_cast<long long>(1000 + i);
    }
    d.enrollment_digest = b32_of(0x23);
    b.drops = d;
    return b;
}

// ── WA3 relay harness (real loopback TCP) ───────────────────────────────────
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

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_writeahead_kat (WRITE-AHEAD %s, v0x02 decoder %s) ==\n",
#if defined(C2POOL_XMR_DROPS_WRITEAHEAD)
                "present",
#else
                "ABSENT: base logic",
#endif
                kBlockWonDropsLive ? "ON (flip 1)" : "OFF (flip 0)");
    const std::string jdir = "/tmp/v37_xmr_drops_writeahead_kat." + std::to_string(::getpid());
    const BlockWon won = carried_win(0x61, 151);
    const std::string bid = hex64(won.bid);

    // ── WA1 the own block survives a crash between publish and the FOUND callback ──
    {
        const std::string path = jdir + ".wa1.journal";
        std::remove(path.c_str());
        {
            dx::DropsCarryStore s(path);   // the winner, before the crash
#if defined(C2POOL_XMR_DROPS_WRITEAHEAD)
            C(s.put_published(bid, won.h_b), "WA1 the gate journals our block BEFORE it is published (P, fsync)");
#endif
            // ... published ... CRASH: the FOUND callback (W) never runs
        }
        dx::DropsCarryStore r(path);
        const auto l = r.load();
        const bool compose = our_win_to_compose(r, bid);
        std::printf("    WA1 reloaded own=%zu frames=%zu booked=%zu malformed=%zu -> our win to compose: %s\n",
                    l.own, l.frames, l.booked, l.malformed, compose ? "YES" : "NO (nobody composes the carried delta: stall)");
        C(l.own == 0 && l.malformed == 0, "WA1 the crash left no W record (the window this closes)");
        C(compose, "WA1 ★ after the restart the booking knows the block is OUR win and composes its carried delta");
#if defined(C2POOL_XMR_DROPS_WRITEAHEAD)
        C(l.published == 1 && r.published(bid) && !r.published(std::string(64, 'e')), "WA1 the P record reloads by block id");
        C(r.put_frame(bid, encode_block_won(won)) && !r.own_to_compose(bid), "WA1 once composed (F), never composed again");
        dx::DropsCarryStore r2(path);
        r2.load();
        C(!r2.own_to_compose(bid) && r2.has_frame(bid), "WA1 ... and that survives a second restart (P + F -> re-offer F, no second composition)");
#endif
        std::remove(path.c_str());
    }

    // ── WA2 the gate thread and the main thread append concurrently ─────────
    {
#if defined(C2POOL_XMR_DROPS_WRITEAHEAD)
        const std::string path = jdir + ".wa2.journal";
        std::remove(path.c_str());
        constexpr int kN = 300;
        {
            dx::DropsCarryStore s(path);
            std::atomic<bool> go{false};
            std::thread gate([&] {
                while (!go.load()) std::this_thread::yield();
                for (int i = 0; i < kN; ++i) { char b[65]; std::snprintf(b, sizeof b, "%064x", 0x1000 + i); s.put_published(b, 200 + i); }
            });
            const BlockWon big = carried_win(0x71, 300, 120);   // a > 8 KB line
            const auto frame = encode_block_won(big);
            go = true;
            for (int i = 0; i < kN; ++i) { char b[65]; std::snprintf(b, sizeof b, "%064x", 0x9000 + i); s.put_frame(b, frame); }
            gate.join();
            C(s.write_failures() == 0 && s.published_size() == static_cast<std::size_t>(kN), "WA2 no write failure; every P held");
        }
        dx::DropsCarryStore r(path);
        const auto l = r.load();
        std::printf("    WA2 reloaded published=%zu frames=%zu malformed=%zu\n", l.published, l.frames, l.malformed);
        C(l.published == static_cast<std::size_t>(kN) && l.frames == static_cast<std::size_t>(kN) && l.malformed == 0,
          "WA2 ★ P from the listener thread + F from the main thread: every record reloads, none interleaved or torn");
        std::remove(path.c_str());
#else
        C(false, "WA2 concurrent pre-publish journal (base: absent)");
#endif
    }

    // ── WA3 the restarted winner carries the delta; the waiting peers get it ──
    if (!kBlockWonDropsLive) {
        std::printf("    WA3 SKIPPED: flip-0 build (the v0x02 decoder is OFF by construction)\n");
    } else {
        std::string why;
        RNode W("W", opts(true, {}, kFloorDiff));          // the winner, just restarted
        C(W.relay->start(why), "WA3 W (restarted winner) listens " + why);
        RNode B("B", opts(true, {W.relay->listen_port()}, kFloorDiff));
        C(B.relay->start(why), "WA3 B dials W " + why);
        RNode Cn("C", opts(false, {B.relay->listen_port()}, kFloorDiff));
        C(Cn.relay->start(why), "WA3 C dials B " + why);
        C(wait_for([&] { return W.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 2 && Cn.relay->ready_peers().size() == 1; },
                   {&W, &B, &Cn}), "WA3 HELLO: W-B-C up");
        // B and C are booking h=151 and wait for the winner's carried delta: they ask.
        const std::size_t ab = B.relay->want_block_won(won.bid), ac = Cn.relay->want_block_won(won.bid);
        std::this_thread::sleep_for(300ms); B.pump(); Cn.pump();
        C(ab >= 1 && ac >= 1 && B.got.empty() && Cn.got.empty(), "WA3 the peers asked (FB_GETWON) and nobody holds the frame yet");
        // The restarted winner books h=151 from the chain: the journal decides whether it composes.
        const std::string path = jdir + ".wa3.journal";
        std::remove(path.c_str());
        {
            dx::DropsCarryStore pre(path);
#if defined(C2POOL_XMR_DROPS_WRITEAHEAD)
            pre.put_published(bid, won.h_b);   // written in the gate before the crash
#endif
        }
        dx::DropsCarryStore j(path);
        j.load();
        std::size_t sent = 0;
        if (our_win_to_compose(j, bid)) {
            j.put_frame(bid, encode_block_won(won));   // write-ahead of the composed frame, then carry it
            sent = W.relay->broadcast_block_won(won);
        }
        const bool got = wait_for([&] { return !B.got.empty() && !Cn.got.empty(); }, {&W, &B, &Cn}, 3000ms);
        std::printf("    WA3 winner composed+sent to %zu peer(s); B got %zu, C got %zu frame(s)%s\n", sent, B.got.size(), Cn.got.size(),
                    got ? "" : " -> STALL: every node keeps awaiting the winner's carried DROPS delta");
        C(got, "WA3 ★ the restarted winner's carried delta reaches every waiting peer (no stall)");
        C(got && B.got.front().bid == won.bid && Cn.got.front().drops && Cn.got.front().drops->delta == won.drops->delta,
          "WA3 the delivered frame is the winner's composed delta, byte for byte");
        std::remove(path.c_str());
    }

    // ── WA4 source pins ─────────────────────────────────────────────────────
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), "WA4 shell source readable");
        const auto gate = sh.find("class GatedShareSinkT final");
        const auto pre = sh.find("if (m_pre_publish) m_pre_publish(tj.blob, tj.height);");
        const auto pub = sh.find("m_inner.submit_network_block(template_id, nonce, extra_nonce);", gate == std::string::npos ? 0 : gate);
        C(gate != std::string::npos && pre != std::string::npos && pub != std::string::npos && gate < pre && pre < pub,
          "WA4 ★ the exact network gate journals the block BEFORE the publish arm is called");
        C(sh.find("if (hooks.pre_publish) sink.set_pre_publish(hooks.pre_publish);") != std::string::npos,
          "WA4 serve_and_run installs the pre-publish hook on the gate");
        const auto hk = sh.find("if (drops_store)   // ★ DROPS WRITE-AHEAD");
        const auto hs = sh.find("hooks.pre_publish = [&]");
        const auto hp = sh.find("drops_store->put_published(b, h);");
        C(hk != std::string::npos && hs != std::string::npos && hp != std::string::npos && hk < hs && hs < hp,
          "WA4 the hook exists only when the journal does (flip 1): flip 0 publishes exactly as master");
        const auto bk = sh.find("fo.book_from_chain_ex = [&]");
        const auto dec = sh.find("drops_store->own_to_compose(bid)");
        const auto cmp = sh.find("relay_node->broadcast_block_won(bw);", dec == std::string::npos ? 0 : dec);
        const auto tk = sh.find("if (!drops_take_carry(h, bid, bk, why, true)) return false;");
        C(bk != std::string::npos && dec != std::string::npos && cmp != std::string::npos && tk != std::string::npos &&
          bk < dec && dec < cmp && cmp < tk,
          "WA4 ★ the booking composes a P-only own win (once) before the carried-delta decision");
        const auto bf = sh.find("auto bridge_found = [&]()");
        const auto kn = sh.find("TEST knob: CRASH after publish", bf == std::string::npos ? 0 : bf);
        const auto fq = sh.find("found_q.push(std::move(e));", bf == std::string::npos ? 0 : bf);
        C(bf != std::string::npos && kn != std::string::npos && fq != std::string::npos && bf < kn && kn < fq,
          "WA4 the rig's --test-crash-after-publish point sits after the publish and before the FOUND event is queued");
    }
    return C.done("v37_xmr_drops_writeahead_kat");
}
