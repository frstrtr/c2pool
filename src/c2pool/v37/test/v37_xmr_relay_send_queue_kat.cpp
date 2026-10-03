// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_relay_send_queue_kat -- RELAY-SEND-QUEUE (capstone attempt 6 false
// start): large FB_BLOCK_WON v0x03 frames re-offered on HELLO from the READER
// thread deadlocked both ends of a link.
//
// THE DEFECT. on_hello -> reoffer_won_to re-sent every kept won frame (up to
// 64 x ~512 KiB) synchronously from that link's reader thread, holding the
// connection's write lock for the whole blocking send (SO_SNDTIMEO 10 s). Both
// ends did it at once, so neither read: both sends filled the other side's
// receive buffer, timed out, the link was hard-dropped and redialed, the new
// HELLO re-offered again -- and every other sender (verify flood, maintenance
// PING, stratum share path) queued on that lock the whole time.
//
//   S1  two relay nodes over loopback TCP, each holding kFrames carried v0x03
//       won frames of 16384 ids (524613 B) the other lacks; they HELLO. While
//       the mutual re-offer runs, A floods a small won frame from another
//       thread. Base: the small send blocks (>= seconds), the link times out
//       and redials (HELLO count climbs), frames do not all arrive. Fix: 0
//       slow drops / 0 redials, every frame delivered both ways, the small
//       send returns at once and arrives in < 1 s.
//   S2  forced re-HELLO of the same two processes after delivery: the fix
//       re-offers NOTHING (each node provably holds every bid: received from
//       it, or PONG-confirmed after our copy) -- no 16 MiB re-flood per HELLO.
//   S3  the per-peer send queue stays bounded (high-water mark measured).
// ===========================================================================
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>

using namespace gap2test;
using namespace std::chrono_literals;
using SClock = std::chrono::steady_clock;
using ::c2pool::v37n::kMaxCarrierFrame;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr int kFrames = 32;   // per node: 32 x 524613 B = 16.8 MB each way

struct RNode {
    std::string name;
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    std::set<bytes32> got;
    SClock::time_point small_at{};
    bytes32 small_bid{};
    RNode(std::string n, RelayOptions ro) : name(std::move(n)) {
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [](const std::string&) {});
    }
    ~RNode() { relay->stop(); }
    void pump() {
        for (auto& [b, p] : relay->drain_block_won()) {
            (void)p;
            if (b.bid == small_bid && small_at == SClock::time_point{}) small_at = SClock::now();
            got.insert(b.bid);
        }
    }
};
static RelayOptions opts(bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = kFloorDiff;
    o.keepalive_ms = 300;   // PINGs flow during the test (the fix's delivery proof rides on PONG)
    return o;
}
template <class F>
static bool wait_for(F cond, std::vector<RNode*> pump, std::chrono::milliseconds limit) {
    const auto dl = SClock::now() + limit;
    while (SClock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(10ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
// A carried v0x03 frame at the set cap: 16384 strictly ascending ids.
static BlockWon big_win(u8 seed, u64 h) {
    BlockWon b;
    b.chain_id = kChain; b.bid = b32_of(seed); b.h_b = h; b.cut_next_pos = 5; b.cut_spine_digest = b32_of(seed + 1);
    b.reward = 35174273644664ULL; b.payout_emitted = true; b.owed_digest_at_win = b32_of(seed + 2);
    BlockWon::Drops d; d.delta[b32_of(0x21)] = 1234567; d.delta[b32_of(0x22)] = -1234567; d.enrollment_digest = b32_of(0x23);
    std::vector<bytes32> ids(kBlockWonSetMaxIds);
    for (std::size_t i = 0; i < ids.size(); ++i) {
        bytes32 id{};
        id[0] = static_cast<u8>(i >> 24); id[1] = static_cast<u8>(i >> 16); id[2] = static_cast<u8>(i >> 8); id[3] = static_cast<u8>(i);
        id[31] = seed;
        ids[i] = id;
    }
    d.set = std::move(ids);
    b.drops = d;
    return b;
}
static BlockWon small_win(u8 seed, u64 h) {   // a v0x01 frame (127 B)
    BlockWon b;
    b.chain_id = kChain; b.bid = b32_of(seed); b.h_b = h; b.cut_next_pos = 6; b.cut_spine_digest = b32_of(seed + 1);
    b.reward = 1; b.owed_digest_at_win = b32_of(seed + 2);
    return b;
}
static long long ms_since(SClock::time_point t0, SClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t - t0).count();
}
static unsigned long long field(const std::string& s, const char* key) {   // "key=<n>" out of describe_sendq()
    const auto k = s.find(key);
    return k == std::string::npos ? ~0ULL : std::strtoull(s.c_str() + k + std::strlen(key), nullptr, 10);
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_send_queue_kat (RELAY-SEND-QUEUE %s, v0x03 decoder %s) ==\n",
#if defined(C2POOL_XMR_RELAY_SEND_QUEUE)
                "present",
#else
                "ABSENT: base send path",
#endif
                kBlockWonDropsLive ? "ON (flip 1)" : "OFF (flip 0)");
    C(kBlockWonDropsLive, "S0 built as the XMR product (flip 1: the carried v0x03 frame decodes)");
    if (!kBlockWonDropsLive) return C.done("v37_xmr_relay_send_queue_kat");

    std::vector<std::vector<u8>> fa, fb;
    for (int i = 0; i < kFrames; ++i) {
        fa.push_back(encode_block_won(big_win(static_cast<u8>(1 + i), 1000 + i)));
        fb.push_back(encode_block_won(big_win(static_cast<u8>(101 + i), 2000 + i)));
    }
    std::printf("    frame bytes=%zu x %d per node (%zu B each way)\n", fa[0].size(), kFrames, fa[0].size() * kFrames);
    C(fa[0].size() > 512 * 1024 && fa[0].size() < kMaxCarrierFrame, "S0 each carried frame is > 512 KiB (16384 ids) and under the 1 MiB ceiling");

    std::string why;
    RNode A("A", opts(true, {}));
    C(A.relay->start(why), "S1 A listens " + why);
    for (const auto& f : fa) A.relay->adopt_won_frame(f);
    RNode B("B", opts(false, {A.relay->listen_port()}));
    for (const auto& f : fb) B.relay->adopt_won_frame(f);
    const auto t_start = SClock::now();
    C(B.relay->start(why), "S1 B dials A " + why);
    const bool up = wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, {}, 5000ms);
    C(up, "S1 HELLO A<->B (both re-offer their 32 frames now)");
    std::this_thread::sleep_for(100ms);   // the mutual re-offer is in flight

    // A concurrent small sender (the stratum / verify-flood path in the daemon).
    const BlockWon sw = small_win(200, 3000);
    B.small_bid = sw.bid;
    const auto t0 = SClock::now();
    const std::size_t n_small = A.relay->broadcast_block_won(sw);
    const auto t1 = SClock::now();
    const long long call_ms = ms_since(t0, t1);

    std::set<bytes32> want_b, want_a;
    for (int i = 0; i < kFrames; ++i) { want_b.insert(b32_of(static_cast<u8>(1 + i))); want_a.insert(b32_of(static_cast<u8>(101 + i))); }
    auto all = [](const std::set<bytes32>& got, const std::set<bytes32>& want) {
        for (const auto& w : want) if (!got.count(w)) return false;
        return true;
    };
    const bool delivered = wait_for([&] { return all(B.got, want_b) && all(A.got, want_a) && B.small_at != SClock::time_point{}; },
                                    {&A, &B}, 30000ms);
    const auto t_done = SClock::now();
    std::size_t gb = 0, ga = 0;
    for (const auto& w : want_b) gb += B.got.count(w);
    for (const auto& w : want_a) ga += A.got.count(w);
    const long long arrive_ms = B.small_at == SClock::time_point{} ? -1 : ms_since(t0, B.small_at);
    const auto helloA = A.relay->stats().hello_ok.load(), helloB = B.relay->stats().hello_ok.load();
    std::printf("    S1 METRIC small_send_call_ms=%lld small_send_peers=%zu small_arrive_ms=%lld | delivered A->B %zu/%d B->A %zu/%d in %lld ms"
                " | hello_ok A=%llu B=%llu\n",
                call_ms, n_small, arrive_ms, gb, kFrames, ga, kFrames, ms_since(t_start, t_done),
                (unsigned long long)helloA, (unsigned long long)helloB);
    C(call_ms < 1000, "S1 ★ a concurrent small send never blocks behind the re-offer (call < 1 s)");
    C(arrive_ms >= 0 && arrive_ms < 1000, "S1 ★ ... and reaches the peer in < 1 s");
    C(delivered, "S1 ★ every re-offered frame is delivered, both directions");
    C(helloA == 1 && helloB == 1, "S1 ★ no send timeout -> no hard drop -> no redial (one HELLO per side)");

    // ── S2 forced re-HELLO of the same processes: nothing the peer holds is re-sent ──
    {
#if defined(C2POOL_XMR_RELAY_SEND_QUEUE)
        // Give the PONG proof a moment (keepalive 300 ms); the base has no such proof.
        wait_for([&] {
            return A.relay->stats().won_held_confirmed.load() >= static_cast<u64>(kFrames) &&
                   B.relay->stats().won_held_confirmed.load() >= static_cast<u64>(kFrames);
        }, {&A, &B}, 5000ms);
#else
        std::this_thread::sleep_for(1000ms);
#endif
        const u64 ra0 = A.relay->stats().won_reoffered.load(), rb0 = B.relay->stats().won_reoffered.load();
        const u64 ha0 = A.relay->stats().hello_ok.load();
        const auto peers = A.relay->ready_peers();
        if (!peers.empty()) A.relay->drop_peer(peers.front());
        const bool back = wait_for([&] {
            return A.relay->stats().hello_ok.load() > ha0 && A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1;
        }, {&A, &B}, 20000ms);
        std::this_thread::sleep_for(1500ms);   // any re-offer would be queued by now
        A.pump(); B.pump();
        const u64 ra = A.relay->stats().won_reoffered.load() - ra0, rb = B.relay->stats().won_reoffered.load() - rb0;
        std::printf("    S2 METRIC re-HELLO back=%d re-offered after re-HELLO A=%llu B=%llu frames\n",
                    (int)back, (unsigned long long)ra, (unsigned long long)rb);
#if defined(C2POOL_XMR_RELAY_SEND_QUEUE)
        std::printf("    S2 METRIC skipped A=%llu B=%llu, PONG-confirmed A=%llu B=%llu\n",
                    (unsigned long long)A.relay->stats().won_reoffer_skipped.load(), (unsigned long long)B.relay->stats().won_reoffer_skipped.load(),
                    (unsigned long long)A.relay->stats().won_held_confirmed.load(), (unsigned long long)B.relay->stats().won_held_confirmed.load());
#endif
        C(back, "S2 the link comes back after a forced drop (re-HELLO)");
        C(ra == 0 && rb == 0, "S2 ★ the re-HELLO re-offers NOTHING the peer node provably holds (no 16 MiB re-flood per HELLO)");
    }

    // ── S3 the per-peer send queue is bounded ────────────────────────────────
#if defined(C2POOL_XMR_RELAY_SEND_QUEUE)
    {
        const std::string sa = A.relay->describe_sendq(), sb = B.relay->describe_sendq();
        std::printf("    S3 METRIC A %s\n    S3 METRIC B %s\n", sa.c_str(), sb.c_str());
        const auto bound = field(sa, "bound=");
        C(field(sa, "hwm=") <= bound && field(sb, "hwm=") <= bound, "S3 ★ per-peer queued bytes never exceed the bound");
        C(field(sa, "hwm=") <= (std::size_t{1} << 20) + 2 * kMaxCarrierFrame &&
          field(sb, "hwm=") <= (std::size_t{1} << 20) + 2 * kMaxCarrierFrame,
          "S3 ★ the paged re-offer keeps a peer's queue near one page (not 16 MiB)");
        C(field(sa, "full_drops=") == 0 && field(sb, "full_drops=") == 0 && field(sa, "slow_drops=") == 0 &&
          field(sb, "slow_drops=") == 0, "S3 0 queue-full drops, 0 send-timeout drops");
    }
#else
    C(false, "S3 the per-peer send queue is bounded (base: no queue, the sender blocks instead)");
#endif
    return C.done("v37_xmr_relay_send_queue_kat");
}
