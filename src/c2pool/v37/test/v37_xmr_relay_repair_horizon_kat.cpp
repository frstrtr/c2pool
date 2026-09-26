// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_relay_repair_horizon_kat -- REPAIR-HORIZON (stagenet capstone 09-26)
//
// The capstone hold: after a relay stall the lane orders of the two sides
// differ (by design, xmr_receipt_ingest.hpp) and the non-winner side needs the
// relay repair of the winner's cut (P, spine). The repair always asked the
// order [0, P); a peer's frame vault keeps only the last horizon_positions
// (8640) positions and answers BELOW_HORIZON, the refused peer was set aside,
// and once the lane was longer than the horizon EVERY peer refused: the repair
// was Exhausted forever and every cross-side block HELD
//   ("idle: every ready peer tried (N), none serves an order reaching this
//    spine", repair order_ok=0, peer_fail growing; capstone P=11796 > 8640).
//
// Harness = the multinode KAT's TNode: a real XmrRelayNode + FrameVault +
// SupplyService over loopback TCP, the real canonical XmrReceiptIngest, a real
// V37Engine lane; fake RandomX only. A tiny vault horizon stands in for 8640.
//
//   H1 CONTROL  lane shorter than the horizon: the repair is Ready from [0, P)
//               and its replay reproduces the winner's spine (unchanged).
//   H2 CAPSTONE lane longer than the horizon, the divergent suffix inside it:
//               base = Exhausted (the capstone status); fix = a BELOW_HORIZON
//               answer raises the start to the peer's lowest_retained a0, the
//               prefix probe agrees, the repair is READY with [a0, P), and OUR
//               first a0 pushes + the served suffix replay to the winner's
//               spine -- the block books.
//   H3 DEEP     the divergence lies BELOW the only peer's horizon: never
//               Ready (the digest gate cannot be met from any peer), and the
//               fix names it -- repair_deep_divergence() + a DEEP-DIVERGENCE
//               status (the base only says "none serves").
//   H4 OPEN BIN receipts minted into a bin that stays OPEN across the stall
//               (older than --relay-reoffer-seconds, not pushed, so outside
//               the GETORDER backfill too) are re-offered on reconnect: both
//               sides close that bin with the SAME set -> equal lane digests,
//               0 late (base: the peer's receipts are never delivered).
//   H5 CHAIN    after the H2 repair the lanes grow on (orders never re-converge)
//               until the divergence is BELOW the peer's horizon; the next two
//               cross-side cuts are repaired from the SHADOW (the last
//               reconstructed winner-side order, xmr_repair_replay.hpp) as the
//               prefix -- the fix keeps working past one horizon of growth.
// The replay is the daemon's own RepairReplayer (relay_view), so the KAT runs
// the code that books. RED on the base (H2..H5), GREEN on the fix.
// ===========================================================================
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/v37_engine.hpp>
#if __has_include(<c2pool/v37/xmr/relay/xmr_repair_replay.hpp>)
#include <c2pool/v37/xmr/relay/xmr_repair_replay.hpp>
#define KAT_HAVE_REPLAYER 1
#endif

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

// Feature detection, so this KAT BUILDS on the base and fails there by value.
template <class N> static u64 repair_a0_of(N& n, u64 P, const bytes32& s) {
    if constexpr (requires { n.repair_a0(P, s); }) return n.repair_a0(P, s); else return 0;
}
template <class N> static bool deep_of(N& n, u64 P, const bytes32& s, u64* a0) {
    if constexpr (requires { n.repair_deep_divergence(P, s, a0); }) return n.repair_deep_divergence(P, s, a0); else return false;
}
template <class S> static u64 rearm_of(const S& s) {
    if constexpr (requires { s.repair_horizon_rearm; }) return s.repair_horizon_rearm.load(); else return 0;
}
template <class S> static u64 reoffer_unpushed_of(const S& s) {
    if constexpr (requires { s.reoffer_unpushed; }) return s.reoffer_unpushed.load(); else return 0;
}

struct TNode {
    std::string name;
    ChainView chain;
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    std::map<u64, bytes32> dig_at;                          // our lane digest after each push position
    std::vector<std::pair<::v37::ScriptRef, u64>> feed;     // our own lane pushes (main_v37_xmr's feed_log)
    u64 template_height = 0;
#ifdef KAT_HAVE_REPLAYER
    std::unique_ptr<RepairReplayer> rep;
#endif
    TNode(std::string n, RelayOptions ro) : name(std::move(n)) {
#ifdef KAT_HAVE_REPLAYER
        rep = std::make_unique<RepairReplayer>(2 * (ro.vault.horizon_positions ? ro.vault.horizon_positions : 8640));
#endif
        engine = std::make_unique<c2pool::v37n::V37Engine>(4096);
        engine->start();
        engine->submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(kChain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [](const std::string&) {});
        XmrReceiptIngest::Options io; io.chain = kChain; io.order = XmrReceiptIngest::Order::Canonical; io.bin_lag = 1; io.grace_ms = 0;
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dig) {
                ::v37::PayoutDescriptor d; d.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(kChain, d, w, 0)).get().applied()) return false;
                feed.emplace_back(payee, w);
                auto s = engine->snapshot(kChain);
                next_after = s->next_pos; dig = s->digest; dig_at[next_after] = dig;
                return true;
            },
            [this](const Admitted& a, u64 pos, u32 n_pushes, u64 next_after, const bytes32& dig) {
                relay->on_pushed(a.id, pos, n_pushes, a.raw, next_after, dig);
            });
    }
    ~TNode() { relay->stop(); engine->stop(); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    void pump() { for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a)); ingest->tick(template_height); }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
};

static RelayOptions opts(bool listen, std::vector<u16> dial, u64 horizon, u32 reoffer_s = 60) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.reoffer_seconds = reoffer_s;
    o.hello_timeout_ms = 3000;
    o.vault.horizon_positions = horizon;
    return o;
}
template <class F>
static bool wait_for(F cond, std::vector<TNode*> pump, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
static Admitted own(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, kChain, kShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    return a;
}

// The daemon's relay_view replay (main_v37_xmr.cpp): the served ids [a0, P)
// from the verified cache after OUR first a0 pushes (or the shadow's) --
// RepairReplayer on the fix; a plain own-prefix replay where it does not exist.
// Returns 0 = no view, 1 = own/full, 2 = shadow.
static int replay_reaches(TNode& Y, u64 P, const bytes32& spine, u64 a0, const std::vector<bytes32>& ids) {
    std::vector<std::pair<::v37::ScriptRef, u64>> served;
    for (const auto& id : ids) {
        ::v37::ScriptRef ref;
        if (!Y.relay->cached(id, &ref)) return 0;
        served.emplace_back(ref, kReceiptWeight);
    }
#ifdef KAT_HAVE_REPLAYER
    RepairReplayer::Base used = RepairReplayer::kNone;
    auto view = Y.rep->replay(kChain, ::v37::LaneParams{}, P, spine, a0, Y.feed, served, &used);
    if (!view) return 0;
    Y.relay->note_alt_digests(Y.rep->shadow_digests());
    return used == RepairReplayer::kShadow ? 2 : 1;
#else
    if (a0 > Y.feed.size()) return 0;
    c2pool::v37n::V37Engine scratch; scratch.start();
    scratch.submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
    auto push = [&](const std::pair<::v37::ScriptRef, u64>& p) {
        ::v37::PayoutDescriptor d; d.pay = p.first;
        scratch.submit_tracked(::v37::LaneRecord::push(kChain, d, p.second, 0)).get();
    };
    for (u64 i = 0; i < a0; ++i) push(Y.feed[i]);
    for (const auto& p : served) push(p);
    bool mism = false;
    auto view = scratch.settlement_view_by_cut(kChain, P, spine, &mism);
    scratch.stop();
    return view ? 1 : 0;
#endif
}

struct Outcome { int st = -1; u64 a0 = 0; bool replay_ok = false; int base = 0; bool deep = false; u64 deep_a0 = 0; std::string status; };

static Outcome run_repair(TNode& X, TNode& Y, u64 P, const bytes32& spine, std::chrono::milliseconds limit) {
    Outcome out;
    std::vector<TNode*> xy{&X, &Y};
    std::vector<bytes32> ids;
    XmrRelayNode::RepairState st = XmrRelayNode::RepairState::Pending;
    const bool ready = wait_for([&] {
        st = Y.relay->repair_poll(P, spine, 0, &ids);
        return st == XmrRelayNode::RepairState::Ready; }, xy, limit);
    out.st = ready ? 1 : (st == XmrRelayNode::RepairState::Exhausted ? 0 : 2);
    out.status = Y.relay->repair_status(P, spine);
    const auto& ys = Y.relay->stats();
    out.deep = deep_of(*Y.relay, P, spine, &out.deep_a0);
    if (ready) {
        out.a0 = repair_a0_of(*Y.relay, P, spine);
        out.base = replay_reaches(Y, P, spine, out.a0, ids);
        out.replay_ok = out.base != 0;
    }
    std::printf("   Y repair: %s a0=%llu ids=%zu replay=%s | %s | start=%llu order_ok=%llu spine_mis=%llu peer_fail=%llu ready=%llu rearm=%llu deep=%s\n",
                out.st == 1 ? "READY" : out.st == 0 ? "EXHAUSTED" : "PENDING", (unsigned long long)out.a0, ids.size(),
                ready ? (out.base == 2 ? "reproduces the spine (SHADOW prefix)" : out.replay_ok ? "reproduces the spine" : "DOES NOT reproduce") : "-", out.status.c_str(),
                (unsigned long long)ys.repair_started.load(), (unsigned long long)ys.repair_order_ok.load(),
                (unsigned long long)ys.repair_spine_mismatch.load(), (unsigned long long)ys.repair_peer_fail.load(),
                (unsigned long long)ys.repair_ready.load(), (unsigned long long)rearm_of(ys), out.deep ? "YES" : "no");
    return out;
}

static std::string vault_line(TNode& X, u64 a, u64 P) {
    const auto o = X.relay->vault().serve_order(kChain, a, P, 4096);
    const char* s = o.status == c2pool::v37n::VaultOrderStatus::OK ? "OK" : o.status == c2pool::v37n::VaultOrderStatus::BELOW_HORIZON ? "BELOW_HORIZON" : "other";
    return "serve_order[" + std::to_string(a) + "," + std::to_string(P) + ")=" + s + " ids=" + std::to_string(o.ids.size()) +
           " lowest_retained=" + std::to_string(o.lowest_retained);
}

int main() {
    Checker C;
    std::string why;
    std::printf("== v37_xmr_relay_repair_horizon_kat ==\n");

    // ── H1 / H2: the capstone shape, below and above the vault horizon ──────
    for (const u64 H : {u64{8640}, u64{8}}) {
        const bool trig = H < 100;
        const std::string tag = trig ? "H2" : "H1";
        const u32 N0 = 12, seed = trig ? 60 : 40;
        std::printf("-- %s: vault horizon %llu, common prefix %u, stall 3 vs 2 receipts\n", tag.c_str(), (unsigned long long)H, N0);
        TNode X("X", opts(true, {}, H));
        C(X.relay->start(why), tag + " X starts " + why);
        TNode Y("Y", opts(false, {X.relay->listen_port()}, H));
        C(Y.relay->start(why), tag + " Y starts, dials X " + why);
        std::vector<TNode*> xy{&X, &Y};
        C(wait_for([&] { return X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1; }, xy), tag + " X-Y up");
        std::vector<bytes32> prev(8);
        for (int i = 0; i < 8; ++i) prev[i] = b32_of(static_cast<u8>(seed + i));
        const ::v37::ScriptRef pX = payee_of("X"), pY = payee_of("Y");
        for (auto* n : xy) { for (int i = 0; i < 8; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }
        const SynthBlock b100 = make_block(100, prev[0], seed, nullptr, 2, 14);
        for (u32 k = 0; k < N0; ++k) X.relay->submit_own(own(b100, 1000 + k, pX));
        C(wait_for([&] { return X.relay->cache_size() == N0 && Y.relay->cache_size() == N0; }, xy), tag + " bin 100 flooded to both");
        for (auto* n : xy) n->template_height = 101;
        C(wait_for([&] { return X.next_pos() == N0 && Y.next_pos() == N0; }, xy), tag + " bin 100 closed on both (12 pushes)");
        Y.relay->set_dialing(false);
        C(wait_for([&] { return Y.relay->ready_peers().empty() && X.relay->ready_peers().empty(); }, xy, 8000ms), tag + " relay stall");
        const SynthBlock b101x = make_block(101, prev[1], seed + 1, nullptr, 2, 15);
        const SynthBlock b101y = make_block(101, prev[1], seed + 2, nullptr, 2, 16);
        for (u32 k = 0; k < 3; ++k) X.relay->submit_own(own(b101x, 2000 + k, pX));
        for (u32 k = 0; k < 2; ++k) Y.relay->submit_own(own(b101y, 3000 + k, pY));
        for (auto* n : xy) n->template_height = 102;
        C(wait_for([&] { return X.next_pos() == N0 + 3 && Y.next_pos() == N0 + 2; }, xy), tag + " both close bin 101 without the other's receipts");
        const u64 P = X.next_pos();
        const bytes32 spineX = X.dig_at[P];   // the winner's on-chain cut (P, spine)
        Y.relay->set_dialing(true);
        C(wait_for([&] { return X.next_pos() == N0 + 5 && Y.next_pos() == N0 + 5; }, xy, 20000ms), tag + " heal: the other side's receipts arrive late (tail)");
        const bool y_has = Y.relay->digest_at(P) && *Y.relay->digest_at(P) == spineX;
        C(!y_has, tag + " Y's own order does not reach X's spine at P=" + std::to_string(P) + " (Y needs the relay repair)");
        std::printf("   X vault: %s | %s\n", vault_line(X, 0, P).c_str(), vault_line(X, N0, P).c_str());
        const Outcome o = run_repair(X, Y, P, spineX, 12000ms);
        if (!trig) {
            C(o.st == 1 && o.a0 == 0 && o.replay_ok, "H1 CONTROL lane < horizon: repair READY from [0,P) and the replay reproduces X's spine");
        } else {
            const u64 lowX = X.relay->vault().lowest_position();
            C(o.st == 1, "H2 CAPSTONE lane (17) > horizon (8): the repair is READY (base: Exhausted -- 'none serves an order reaching this spine')");
            C(o.a0 > 0 && o.a0 <= lowX && o.a0 <= N0,
              "H2 the order was served from the peer's horizon a0=" + std::to_string(o.a0) + " (X lowest_retained " + std::to_string(lowX) +
              "), at or below the divergence position " + std::to_string(N0));
            C(o.replay_ok, "H2 OUR first a0 pushes + the served [a0,P) replay to X's spine: the cross-side block books");
            C(rearm_of(Y.relay->stats()) >= 1, "H2 the BELOW_HORIZON answer re-armed the repair (repair_horizon_rearm >= 1) instead of setting X aside");
            C(!o.deep, "H2 no DEEP-DIVERGENCE (the divergence is inside X's horizon)");
            // ── H5: the lanes grow past one horizon beyond the divergence; the
            // next cross-side cuts chain from the shadow ─────────────────────
            u64 P_prev = P;
            for (int link = 0; link < 2; ++link) {
                const std::string t5 = "H5." + std::to_string(link + 1);
                const SynthBlock bl = make_block(102 + link, prev[2 + link], seed + 10 + link, nullptr, 2, 17 + link);
                const std::size_t c0 = X.relay->cache_size();
                for (u32 k = 0; k < 6; ++k) X.relay->submit_own(own(bl, 5000 + 100 * link + k, pX));
                C(wait_for([&] { return X.relay->cache_size() == c0 + 6 && Y.relay->cache_size() == c0 + 6; }, xy), t5 + " 6 more receipts flooded to both");
                for (auto* n : xy) n->template_height = 103 + link;
                const u64 want = P_prev + (link == 0 ? 2 : 0) + 6;
                C(wait_for([&] { return X.next_pos() == want && Y.next_pos() == want; }, xy), t5 + " both push them (lane " + std::to_string(want) + ")");
                const u64 P2 = X.next_pos();
                const bytes32 spine2 = X.dig_at[P2];
                const u64 low2 = X.relay->vault().lowest_position();
                std::printf("   %s X cut P=%llu, X lowest_retained=%llu (divergence at %u is %s the horizon)\n", t5.c_str(),
                            (unsigned long long)P2, (unsigned long long)low2, N0, low2 > N0 ? "BELOW" : "inside");
                const Outcome o2 = run_repair(X, Y, P2, spine2, 12000ms);
                C(low2 > N0, t5 + " the divergence (position 12) is below X's horizon (lowest_retained " + std::to_string(low2) + ")");
                C(o2.st == 1 && o2.base == 2 && o2.a0 > N0,
                  t5 + " READY from a0=" + std::to_string(o2.a0) + " and the replay reaches X's spine only from the SHADOW prefix (own order diverged below a0)");
                C(!o2.deep, t5 + " no DEEP-DIVERGENCE: the probe accepted the shadow's digest at a0");
                P_prev = P2;
            }
        }
        X.relay->set_dialing(false); Y.relay->set_dialing(false);
    }

    // ── H3: divergence BELOW the only peer's horizon -> loud, never Ready ──
    {
        std::printf("-- H3: divergence at position 4, then 14 common pushes; vault horizon 8\n");
        const u64 H = 8;
        TNode X("X", opts(true, {}, H));
        C(X.relay->start(why), "H3 X starts " + why);
        TNode Y("Y", opts(false, {X.relay->listen_port()}, H));
        C(Y.relay->start(why), "H3 Y starts " + why);
        std::vector<TNode*> xy{&X, &Y};
        C(wait_for([&] { return X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1; }, xy), "H3 X-Y up");
        std::vector<bytes32> prev(8);
        for (int i = 0; i < 8; ++i) prev[i] = b32_of(static_cast<u8>(90 + i));
        const ::v37::ScriptRef pX = payee_of("X"), pY = payee_of("Y");
        for (auto* n : xy) { for (int i = 0; i < 8; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }
        const SynthBlock b100 = make_block(100, prev[0], 90, nullptr, 2, 14);
        for (u32 k = 0; k < 4; ++k) X.relay->submit_own(own(b100, 1000 + k, pX));
        C(wait_for([&] { return X.relay->cache_size() == 4 && Y.relay->cache_size() == 4; }, xy), "H3 bin 100 flooded");
        for (auto* n : xy) n->template_height = 101;
        C(wait_for([&] { return X.next_pos() == 4 && Y.next_pos() == 4; }, xy), "H3 bin 100 closed on both");
        Y.relay->set_dialing(false);
        C(wait_for([&] { return Y.relay->ready_peers().empty() && X.relay->ready_peers().empty(); }, xy, 8000ms), "H3 relay stall");
        const SynthBlock b101x = make_block(101, prev[1], 91, nullptr, 2, 15);
        const SynthBlock b101y = make_block(101, prev[1], 92, nullptr, 2, 16);
        for (u32 k = 0; k < 3; ++k) X.relay->submit_own(own(b101x, 2000 + k, pX));
        for (u32 k = 0; k < 2; ++k) Y.relay->submit_own(own(b101y, 3000 + k, pY));
        for (auto* n : xy) n->template_height = 102;
        C(wait_for([&] { return X.next_pos() == 7 && Y.next_pos() == 6; }, xy), "H3 both close bin 101 alone");
        Y.relay->set_dialing(true);
        C(wait_for([&] { return X.next_pos() == 9 && Y.next_pos() == 9; }, xy, 20000ms), "H3 heal (late tails; orders differ from position 4)");
        const SynthBlock b102 = make_block(102, prev[2], 93, nullptr, 2, 17);
        for (u32 k = 0; k < 14; ++k) X.relay->submit_own(own(b102, 4000 + k, pX));
        C(wait_for([&] { return X.relay->cache_size() == 23 && Y.relay->cache_size() == 23; }, xy), "H3 bin 102 flooded");
        for (auto* n : xy) n->template_height = 103;
        C(wait_for([&] { return X.next_pos() == 23 && Y.next_pos() == 23; }, xy), "H3 bin 102 closed on both (23 pushes)");
        const u64 P = X.next_pos();
        const bytes32 spineX = X.dig_at[P];
        std::printf("   X vault: %s\n", vault_line(X, 0, P).c_str());
        const Outcome o = run_repair(X, Y, P, spineX, 6000ms);
        C(o.st != 1, "H3 never Ready: no peer retains the divergent positions (the digest gate cannot be met)");
        C(o.deep && o.deep_a0 > 4, "H3 the fix NAMES it: repair_deep_divergence() with a0=" + std::to_string(o.deep_a0) +
                                   " > the divergence position 4 (base: a silent 'none serves')");
        C(o.status.find("DEEP-DIVERGENCE") != std::string::npos, "H3 the repair status carries DEEP-DIVERGENCE (the daemon alarms on it)");
        X.relay->set_dialing(false); Y.relay->set_dialing(false);
    }

    // ── H4: a bin OPEN across the stall is re-offered on reconnect ───────────
    {
        std::printf("-- H4: bin 101 stays open across a stall longer than --relay-reoffer-seconds (1 s)\n");
        TNode X("X", opts(true, {}, 8640, 1));
        C(X.relay->start(why), "H4 X starts " + why);
        TNode Y("Y", opts(false, {X.relay->listen_port()}, 8640, 1));
        C(Y.relay->start(why), "H4 Y starts " + why);
        std::vector<TNode*> xy{&X, &Y};
        C(wait_for([&] { return X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1; }, xy), "H4 X-Y up");
        std::vector<bytes32> prev(8);
        for (int i = 0; i < 8; ++i) prev[i] = b32_of(static_cast<u8>(120 + i));
        const ::v37::ScriptRef pX = payee_of("X"), pY = payee_of("Y");
        for (auto* n : xy) { for (int i = 0; i < 8; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }
        const SynthBlock b100 = make_block(100, prev[0], 120, nullptr, 2, 14);
        for (u32 k = 0; k < 3; ++k) X.relay->submit_own(own(b100, 1000 + k, pX));
        C(wait_for([&] { return X.relay->cache_size() == 3 && Y.relay->cache_size() == 3; }, xy), "H4 bin 100 flooded");
        for (auto* n : xy) n->template_height = 101;
        C(wait_for([&] { return X.next_pos() == 3 && Y.next_pos() == 3; }, xy), "H4 bin 100 closed on both");
        Y.relay->set_dialing(false);
        C(wait_for([&] { return Y.relay->ready_peers().empty() && X.relay->ready_peers().empty(); }, xy, 8000ms), "H4 relay stall");
        const SynthBlock b101x = make_block(101, prev[1], 121, nullptr, 2, 15);
        const SynthBlock b101y = make_block(101, prev[1], 122, nullptr, 2, 16);
        for (u32 k = 0; k < 3; ++k) X.relay->submit_own(own(b101x, 2000 + k, pX));
        for (u32 k = 0; k < 2; ++k) Y.relay->submit_own(own(b101y, 3000 + k, pY));
        wait_for([] { return false; }, xy, 2500ms);   // the stall outlasts the 1 s re-offer window; bin 101 stays OPEN (template 101)
        const u64 ro0 = reoffer_unpushed_of(X.relay->stats()) + reoffer_unpushed_of(Y.relay->stats());
        Y.relay->set_dialing(true);
        const bool both = wait_for([&] { return X.relay->cache_size() == 8 && Y.relay->cache_size() == 8; }, xy, 8000ms);
        const u64 ro = reoffer_unpushed_of(X.relay->stats()) + reoffer_unpushed_of(Y.relay->stats()) - ro0;
        std::printf("   after reconnect: X cache=%zu Y cache=%zu (want 8 each) reoffer_unpushed=%llu\n",
                    X.relay->cache_size(), Y.relay->cache_size(), (unsigned long long)ro);
        C(both, "H4 the open bin's receipts are re-offered on reconnect: both caches hold all 8 before bin 101 closes");
        for (auto* n : xy) n->template_height = 102;
        const bool closed = wait_for([&] { return X.next_pos() == 8 && Y.next_pos() == 8; }, xy, 5000ms);
        const u64 lateX = X.ingest->stats().late, lateY = Y.ingest->stats().late;
        const bool same = X.dig_at.count(8) && Y.dig_at.count(8) && X.dig_at[8] == Y.dig_at[8];
        std::printf("   bin 101 closed: X next_pos=%llu Y next_pos=%llu late X=%llu Y=%llu digest@8 %s\n",
                    (unsigned long long)X.next_pos(), (unsigned long long)Y.next_pos(), (unsigned long long)lateX,
                    (unsigned long long)lateY, same ? "EQUAL" : "DIFFER/absent");
        C(closed && same && lateX == 0 && lateY == 0,
          "H4 both close bin 101 with the SAME 5 receipts: equal lane digests, 0 late (base: X's receipts never reach Y)");
        C(ro >= 5, "H4 reoffer_unpushed counted the " + std::to_string(ro) + " unpushed receipts re-offered (>= 5)");
        X.relay->set_dialing(false); Y.relay->set_dialing(false);
    }
    return C.done("v37_xmr_relay_repair_horizon_kat");
}
