// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_relay_send_queue_kat -- RELAY-SEND-QUEUE on the Path B relay node:
// the HELLO re-offer of a full pending set goes through the per-link send
// queue, never a blocking send.
//
//   S1  two Path B relay nodes over loopback TCP, each holding a full pending
//       set (P-09 receipts on a tip it has moved past) the other lacks; they
//       HELLO and both re-offer every pending receipt (FB_RECEIPTS v3). While
//       the mutual re-offer runs, A mines a carrier (a small flood from another
//       thread): the call returns at once and the frame reaches B in < 1 s;
//       every re-offered frame is delivered, both directions; no send timeout,
//       no hard drop, no redial (one HELLO per side).
//   S3  the per-link send queue stays bounded (high-water mark measured), with
//       0 queue-full drops and 0 send-timeout drops.
// ===========================================================================
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;
using SClock = std::chrono::steady_clock;

static long long ms_since(SClock::time_point t0, SClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t - t0).count();
}

static pb::PathbRelayOptions opts(bool listen, std::vector<u16> dial) {
    pb::PathbRelayOptions o = Rig::opts(listen, dial);
    o.keepalive_ms = 300;   // PINGs flow during the test
    return o;
}

// The first arrival time of each small frame by the id it carries: an FC_CARRIER (its carrier) or an FB_RECEIPTS of
// one body (that receipt).
struct SmallArrivals {
    std::mutex m;
    std::map<pb::Hash32, SClock::time_point> at;
    pb::RelayBuffers buf;
    void tap(const std::vector<u8>& f) {
        if (f.empty() || f.size() < pb::kFrameHeaderBytes) return;
        std::optional<pb::Hash32> id;
        if (f[0] == pb::kOpFcCarrier) {
            pb::CarrierBodyV3 c;
            if (pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                           pb::CarrierLimits{buf.receipt, pb::kRuledLaneParams.r_max}, c) == pb::WireError::None)
                id = pb::receipt_id(c.own);
        } else if (f[0] == pb::kOpFbReceipts && f.size() > pb::kFrameHeaderBytes && f[pb::kFrameHeaderBytes] == 1) {
            pb::ReceiptBodyV3 r;
            if (pb::decode_receipt_body_v3(f.data() + pb::kFrameHeaderBytes + 1, f.size() - pb::kFrameHeaderBytes - 1,
                                           pb::receipt_limits(buf), r) == pb::WireError::None)
                id = pb::receipt_id(r);
        }
        if (!id) return;
        std::lock_guard<std::mutex> lk(m);
        at.emplace(*id, SClock::now());
    }
    std::optional<SClock::time_point> of(const pb::Hash32& id) {
        std::lock_guard<std::mutex> lk(m);
        const auto it = at.find(id);
        if (it == at.end()) return std::nullopt;
        return it->second;
    }
};

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_send_queue_kat ==\n");
    Rig rig;
    const std::size_t K = static_cast<std::size_t>(pb::relay_horizons(pb::kRuledLaneParams).pending_cap);   // P-09
    // each node: K shares of one job at position 0, then a carrier at position 1: K pending receipts it holds alone
    auto pend = [&](RNode& n, std::size_t payee, std::uint32_t en, std::uint32_t nonce0) {
        const std::optional<pb::PathbJob> j = rig.job(n, payee, en);
        if (!j || rig.mine(n, payee, nonce0 - 1).action != pb::NodeAction::Placed) return std::size_t{0};
        std::size_t k = 0;
        for (std::uint32_t i = 0; i < K; ++i) k += rig.share(n, *j, nonce0 + i).action == pb::NodeAction::Pending ? 1 : 0;
        return k;
    };
    SmallArrivals arrivals;   // before B: B's reader threads use it until B stops
    const auto t_pend = SClock::now();
    auto A = rig.make("A", opts(true, {}), /*launch=*/true);
    const std::size_t pa = pend(*A, 1, 0xA1, 0x10000000u);
    std::string why;
    C(A->start(why), "S1 A listens " + why);
    auto B = rig.make("B", opts(false, {A->port()}), /*launch=*/true);
    const std::size_t pb_ = pend(*B, 2, 0xB2, 0x20000000u);
    arrivals.buf = B->node->config().buffers;
    B->links.set_tap([&](std::uint64_t, const std::vector<u8>& f) { arrivals.tap(f); });
    const std::vector<pb::ReceiptBodyV3> one{A->r().with_node([](pb::PathbNode& n) { return n.pending().all().front()->body; })};
    const std::size_t body = pb::encode_fb_receipts(0, one, pb::kRuledLaneParams).value_or(std::vector<u8>{}).size();
    std::printf("    pending A=%zu B=%zu (P-09 = %zu) in %lld ms; a one-body frame %zu B; ~%zu B each way\n", pa, pb_, K,
                ms_since(t_pend, SClock::now()), body, body * K);
    std::printf("    receipt buffer (P-10) %llu B: P-09 x P-10 = %llu B; per-link send queue %zu B\n",
                (unsigned long long)arrivals.buf.receipt, (unsigned long long)(arrivals.buf.receipt * K),
                pb::PathbRelayOptions{}.send_queue_bytes);
    C(pa == K && pb_ == K, "S1 each node holds a full pending set the other lacks (" + std::to_string(K) + " receipts)");

    const auto tj = SClock::now();
    const std::optional<pb::PathbJob> jsmall = rig.job(*A, 3, 0x30);
    std::printf("    a job on A with its full pending set: %lld ms\n", ms_since(tj, SClock::now()));
    if (!jsmall) {
        C(false, "S1 A builds a job on its best tip");
        return C.done("v37_xmr_relay_send_queue_kat");
    }
    const auto t_start = SClock::now();
    C(B->start(why), "S1 B dials A " + why);
    const bool up = wait_until([&] { return A->r().ready_peers().size() == 1 && B->r().ready_peers().size() == 1; }, 5000ms, 10ms);
    C(up, "S1 HELLO A<->B (both re-offer their pending sets now)");
    std::this_thread::sleep_for(100ms);   // the mutual re-offer is in flight

    // A concurrent small sender: A's share of a job made before the HELLO, flooded as one frame (the stratum /
    // verify-flood path in the daemon).
    const auto t0 = SClock::now();
    const pb::NodeEventResult shared = rig.share(*A, *jsmall, 0x30000000u);
    const auto t1 = SClock::now();
    const long long call_ms = ms_since(t0, t1);
    const pb::Hash32 small = pb::receipt_id(body_of(*jsmall, 0x30000000u));

    const bool delivered = wait_until([&] {
        return A->st().reoffer_frames.load() > 0 && B->st().reoffer_frames.load() > 0 &&
               B->links.frames(pb::kOpFbReceipts) >= A->st().reoffer_frames.load() &&
               A->links.frames(pb::kOpFbReceipts) >= B->st().reoffer_frames.load() && arrivals.of(small).has_value();
    }, 30000ms, 10ms);
    const auto t_done = SClock::now();
    const std::optional<SClock::time_point> at = arrivals.of(small);
    const long long arrive_ms = at ? ms_since(t0, *at) : -1;
    const auto helloA = A->st().hello_ok.load(), helloB = B->st().hello_ok.load();
    std::printf("    S1 METRIC small_send_call_ms=%lld small_arrive_ms=%lld | re-offered A->B %llu (B got %llu) B->A %llu "
                "(A got %llu) frames in %lld ms | hello_ok A=%llu B=%llu\n",
                call_ms, arrive_ms, (unsigned long long)A->st().reoffer_frames.load(),
                (unsigned long long)B->links.frames(pb::kOpFbReceipts), (unsigned long long)B->st().reoffer_frames.load(),
                (unsigned long long)A->links.frames(pb::kOpFbReceipts), ms_since(t_start, t_done),
                (unsigned long long)helloA, (unsigned long long)helloB);
    C((shared.action == pb::NodeAction::Placed || shared.action == pb::NodeAction::Pending) && call_ms < 1000,
      "S1 a concurrent small send never blocks behind the re-offer (call < 1 s)");
    C(arrive_ms >= 0 && arrive_ms < 1000, "S1 ... and reaches the peer in < 1 s");
    C(delivered, "S1 every re-offered frame is delivered, both directions");
    C(helloA == 1 && helloB == 1, "S1 no send timeout -> no hard drop -> no redial (one HELLO per side)");

    // ── S3 the per-link send queue is bounded ────────────────────────────────
    {
        auto& na = A->links.net();
        auto& nb = B->links.net();
        std::printf("    S3 METRIC A hwm=%zu bound=%zu full_drops=%llu slow_drops=%llu | B hwm=%zu bound=%zu full_drops=%llu "
                    "slow_drops=%llu\n",
                    na.queued_bytes_hwm(), na.send_queue_limit(), (unsigned long long)na.peers_dropped_queue_full(),
                    (unsigned long long)na.peers_dropped_slow(), nb.queued_bytes_hwm(), nb.send_queue_limit(),
                    (unsigned long long)nb.peers_dropped_queue_full(), (unsigned long long)nb.peers_dropped_slow());
        C(na.queued_bytes_hwm() <= na.send_queue_limit() && nb.queued_bytes_hwm() <= nb.send_queue_limit(),
          "S3 per-link queued bytes never exceed the bound");
        C(na.peers_dropped_queue_full() == 0 && nb.peers_dropped_queue_full() == 0 && na.peers_dropped_slow() == 0 &&
          nb.peers_dropped_slow() == 0, "S3 0 queue-full drops, 0 send-timeout drops");
    }
    return C.done("v37_xmr_relay_send_queue_kat");
}
