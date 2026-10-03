// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_multinode_kat -- GAP-2 stage 1, KATs 3/4/5 in one harness.
//
// Three in-process XmrRelayNode instances over REAL loopback TCP
// (CarrierPeerNode), each with its own V37Engine lane + XmrReceiptIngest, in a
// LINE topology  A <- B <- C  (B dials A, C dials B) so a receipt minted at A
// reaches C only by B's re-flood. RandomX is a counting fake (the real RandomX
// path is xmr_receipt_bind_v2_kat B4): PoW = 0 for every blob except nonce
// 0xDEADBEEF, whose PoW is 2^256-1 (below any share_diff >= 2).
//
//   M1  HELLO gate: a node with another share_diff is REFUSED with the reason;
//       it never becomes a ready peer
//   M2  flood + dedup: receipts minted at A and at C are admitted exactly once
//       per node, RandomX-verified exactly once per foreign receipt, never at
//       the minter, and reach the far end through the middle node
//   M3  canonical order: A and B (canonical) publish byte-identical lane
//       digests for the same receipt set, whatever the arrival order
//   M4  backfill: C drops off, A mints more, C comes back -> GETORDER/GETFRAMES
//       from B (B's re-offer is OFF) brings every missed receipt, each one
//       re-verified (solicited credit), none twice
//   M5  repair: C runs arrival order (its lane digest differs); the relay repair
//       fetches the winner-side order over [0,P) from a peer whose digest at P
//       is A's spine, and a scratch replay of it reproduces A's digest at P
//       byte-for-byte; a spine nobody holds never becomes Ready
//   M6  DoS: a raw peer that passes HELLO is (a) kept after an unknown 0x4f
//       frame and a Family-A 0x02 frame (counted), (b) charged a structural
//       strike -- and NO RandomX evaluation -- for a tampered receipt, (c)
//       BANNED and disconnected after one confirmed invalid PoW
//   M7  refused ORDER: a peer whose frame vault has evicted lane position 0
//       answers GETORDER [0,P) with BELOW_HORIZON. The relay never takes the
//       empty refused order for progress. REPAIR-HORIZON (capstone 09-26)
//       changed what follows: the refusal carries the peer's lowest_retained
//       a0, so the repair RE-ASKS that peer from a0 instead of setting it aside
//       (setting it aside made every repair of a lane longer than the vault
//       horizon Exhausted forever): exactly THREE GETORDERs reach it -- [0,P)
//       refused, the zero-length prefix probe [a0,a0) (its digest at a0 equals
//       ours), and the suffix [a0,P) -- and, since this spine is one X never
//       held, the suffix fails the spine check at P: X is set aside, the repair
//       is Exhausted and never Ready, and no further GETORDER follows.
//   M8  HOLD-ROUND-2 (B5): 200 shares the verdict classifies AHEAD (lane-prefix
//       skew): bans=0, refused=0, the peer stays; parked bounded per peer (64
//       kept, the oldest dropped without a strike); re-judged CANONICAL and
//       admitted once the share state advances. (red on the base: -1 -> bans)
//   M9  HOLD-ROUND-2 V4: the AHEAD park bound is per sender NODE (a reconnect
//       keeps one budget: 32 held, not 64) and the cap evicts the heaviest
//       node's oldest (the honest finder keeps 40/40, the flooder 56/64).
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/v37_engine.hpp>

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr std::uint32_t kBadNonce = 0xDEADBEEF;

struct TNode {
    std::string name;
    ChainView chain;
    std::atomic<u64> rx_calls{0};
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    std::vector<std::pair<::v37::ScriptRef, u64>> lane_log;
    u64 template_height = 0;
    std::vector<std::string> logs;
    std::mutex log_mtx;

    TNode(std::string n, RelayOptions ro, XmrReceiptIngest::Order order) : name(std::move(n)) {
        engine = std::make_unique<c2pool::v37n::V37Engine>(4096);
        engine->start();
        engine->submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [this](const std::vector<u8>& blob, const bytes32&, bytes32& pow) {
                ++rx_calls;
                u32 nonce = 0;
                ::v37::xmr::HashingBlob hb; hb.bytes = blob;
                ::v37::xmr::verify::ParsedBlob pb;
                if (::v37::xmr::verify::parse_hashing_blob(hb, pb))
                    for (int i = 0; i < 4; ++i) nonce |= static_cast<u32>(blob[pb.header_len - 4 + i]) << (8 * i);
                if (nonce == kBadNonce) pow.fill(0xff); else pow.fill(0);
                return true;
            },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(kChain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(log_mtx); logs.push_back(l); });
        XmrReceiptIngest::Options io; io.chain = kChain; io.order = order; io.bin_lag = 1; io.grace_ms = 0;
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dig) {
                ::v37::PayoutDescriptor d; d.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(kChain, d, w, 0)).get().applied()) return false;
                lane_log.emplace_back(payee, w);
                auto s = engine->snapshot(kChain);
                next_after = s->next_pos; dig = s->digest;
                return true;
            },
            [this](const Admitted& a, u64 pos, u32 n_pushes, u64 next_after, const bytes32& dig) {
                relay->on_pushed(a.id, pos, n_pushes, a.raw, next_after, dig);
            });
    }
    ~TNode() { relay->stop(); engine->stop(); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    void pump() {
        for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a));
        ingest->tick(template_height);
    }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
    bytes32 digest() { auto s = engine->snapshot(kChain); return s ? s->digest : bytes32{}; }
    void dump_logs() { std::lock_guard<std::mutex> lk(log_mtx); for (auto& l : logs) std::printf("    [%s] %s\n", name.c_str(), l.c_str()); logs.clear(); }
};

static RelayOptions opts(bool listen, std::vector<u16> dial, u32 reoffer = 60, u64 share_diff = kShareDiff) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = share_diff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, share_diff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.reoffer_seconds = reoffer;
    o.hello_timeout_ms = 3000;
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

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_multinode_kat ==\n");
    const ::v37::ScriptRef pA = payee_of("A"), pB = payee_of("B"), pC = payee_of("C");

    TNode A("A", opts(true, {}), XmrReceiptIngest::Order::Canonical);
    std::string why;
    C(A.relay->start(why), "A starts (listen ephemeral) " + why);
    const u16 portA = A.relay->listen_port();
    TNode B("B", opts(true, {portA}, /*reoffer=*/0), XmrReceiptIngest::Order::Canonical);
    C(B.relay->start(why), "B starts, dials A " + why);
    const u16 portB = B.relay->listen_port();
    TNode Cn("C", opts(true, {portB}), XmrReceiptIngest::Order::Arrival);
    C(Cn.relay->start(why), "C starts, dials B " + why);
    std::vector<TNode*> all{&A, &B, &Cn};

    C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 2 && Cn.relay->ready_peers().size() == 1; }, all),
      "HELLO: line A-B-C up (A:1 B:2 C:1 ready peers)");

    // ── M1 HELLO refusal ────────────────────────────────────────────────────
    {
        TNode D("D", opts(false, {portA}, 60, kShareDiff + 1), XmrReceiptIngest::Order::Canonical);
        C(D.relay->start(why), "M1 D (share_diff 1001) starts, dials A");
        const u64 rej0 = A.relay->stats().hello_rejected.load();
        C(wait_for([&] { return A.relay->stats().hello_rejected.load() > rej0; }, {&A, &D}, 5000ms),
          "M1 A REFUSES D's HELLO: " + A.relay->last_reject());
        std::this_thread::sleep_for(300ms);
        C(D.relay->ready_peers().empty() && A.relay->ready_peers().size() == 1, "M1 D never becomes a ready peer; A keeps B");
        D.relay->set_dialing(false);
    }

    // chain context for bins 100..103 on every node
    std::vector<bytes32> prev(8);
    for (int i = 0; i < 8; ++i) prev[i] = b32_of(static_cast<u8>(100 + i));
    for (auto* n : all) { for (int i = 0; i < 4; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }

    // SHARE-VERDICT HEIGHT: B's share verdict records the coinbase height the
    // relay hands it. Every M2 receipt is mined on prev[0], whose ChainView
    // context is the NEW block's height 100 (note_bin(prev[0], 100), as the
    // template and the chain feed note it), so the verdict must see 100, not
    // 101: a wrong height rebuilds every honest share as non-canonical.
    std::mutex vh_mtx; std::vector<u64> verdict_heights;
    B.relay->set_share_verdict([&](const FbReceipt&, const ::v37::xmr::verify::ParsedBlob&, u64 cb_h, std::string&) {
        std::lock_guard<std::mutex> lk(vh_mtx); verdict_heights.push_back(cb_h); return 1;
    });

    // ── M2 flood + dedup ────────────────────────────────────────────────────
    const SynthBlock blkA = make_block(100, prev[0], 1, nullptr, 3, 10);
    const SynthBlock blkC = make_block(100, prev[0], 2, nullptr, 3, 11);
    std::vector<Admitted> minted;
    for (std::uint32_t k = 0; k < 4; ++k) minted.push_back(own(blkA, 10 + k, pA));
    for (std::uint32_t k = 0; k < 3; ++k) minted.push_back(own(blkC, 20 + k, pC));
    for (int k = 0; k < 4; ++k) A.relay->submit_own(minted[k]);
    for (int k = 4; k < 7; ++k) Cn.relay->submit_own(minted[k]);
    A.relay->submit_own(minted[0]);   // a duplicate own submit
    C(wait_for([&] { return A.relay->cache_size() == 7 && B.relay->cache_size() == 7 && Cn.relay->cache_size() == 7; }, all),
      "M2 all 7 receipts reach all three nodes (C<-B<-A and A<-B<-C through the middle)");
    C(A.relay->stats().admitted_own.load() == 4 && A.relay->stats().admitted_foreign.load() == 3, "M2 A: 4 own + 3 foreign admitted, once each");
    C(B.relay->stats().admitted_foreign.load() == 7 && B.relay->stats().admitted_own.load() == 0, "M2 B: 7 foreign admitted, once each");
    C(Cn.relay->stats().admitted_own.load() == 3 && Cn.relay->stats().admitted_foreign.load() == 4, "M2 C: 3 own + 4 foreign admitted, once each");
    {
        std::lock_guard<std::mutex> lk(vh_mtx);
        bool all100 = verdict_heights.size() == 7;
        for (u64 h : verdict_heights) all100 = all100 && h == 100;
        C(all100, "M2 the share verdict gets the coinbase height of the mined block (100) for all 7 receipts, got " +
                  std::to_string(verdict_heights.size()) + (verdict_heights.empty() ? "" : " first " + std::to_string(verdict_heights[0])));
    }
    C(A.rx_calls.load() == 3 && B.rx_calls.load() == 7 && Cn.rx_calls.load() == 4,
      "M2 RandomX ran once per FOREIGN receipt per node (A 3, B 7, C 4), never at the minter");
    C(A.relay->stats().dup.load() >= 1, "M2 the duplicate own submit was deduped");

    // ── M3 canonical order ──────────────────────────────────────────────────
    for (auto* n : all) n->template_height = 101;
    C(wait_for([&] { return A.next_pos() == 7 && B.next_pos() == 7 && Cn.next_pos() == 7; }, all),
      "M3 bin 100 closed: every lane holds 7 receipt pushes");
    C(A.digest() == B.digest(), "M3 canonical A and B: byte-identical lane digests (" + hex(A.digest()).substr(0, 16) + ")");
    const u64 P = A.next_pos();
    const bytes32 spineA = A.digest();
    std::printf("    C (arrival order) digest %s %s A's\n", hex(Cn.digest()).substr(0, 16).c_str(), Cn.digest() == spineA ? "==" : "!=");

    // ── M4 backfill ─────────────────────────────────────────────────────────
    Cn.relay->set_dialing(false);
    C(wait_for([&] { return Cn.relay->ready_peers().empty() && B.relay->ready_peers().size() == 1; }, all, 5000ms), "M4 C dropped off the network");
    const SynthBlock blkA2 = make_block(101, prev[1], 3, nullptr, 2, 12);
    for (std::uint32_t k = 0; k < 5; ++k) A.relay->submit_own(own(blkA2, 30 + k, pA));
    for (auto* n : all) n->template_height = 102;
    C(wait_for([&] { return B.next_pos() == 12 && A.next_pos() == 12; }, all), "M4 A and B push 5 more (bin 101); C is offline");
    C(Cn.relay->cache_size() == 7, "M4 C has none of them");
    const u64 sol0 = Cn.relay->stats().admitted_solicited.load();
    Cn.relay->set_dialing(true);
    C(wait_for([&] { return Cn.relay->cache_size() == 12 && Cn.next_pos() == 12; }, all, 20000ms),
      "M4 C reconnects and backfills all 5 over GETORDER/GETFRAMES");
    C(Cn.relay->stats().admitted_solicited.load() - sol0 == 5 && Cn.relay->stats().backfill_ids_asked.load() >= 5,
      "M4 the 5 arrived as SOLICITED frames (B's re-offer is off), each re-verified once");
    C(Cn.rx_calls.load() == 4 + 5, "M4 C RandomX-verified exactly the 5 missing receipts (no double work)");
    C(A.digest() == B.digest(), "M4 A and B still agree after bin 101");

    // ── M5 repair (C's arrival order vs the canonical spine) ────────────────
    {
        std::vector<bytes32> ids;
        XmrRelayNode::RepairState st = XmrRelayNode::RepairState::Pending;
        const bool ok = wait_for([&] { st = Cn.relay->repair_poll(P, spineA, 0, &ids); return st == XmrRelayNode::RepairState::Ready; }, all);
        C(ok && ids.size() == P, "M5 repair of (P=" + std::to_string(P) + ", A's spine) Ready via B: " + std::to_string(ids.size()) + " ids");
        c2pool::v37n::V37Engine scratch; scratch.start();
        scratch.submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
        bool all_cached = true;
        for (const auto& id : ids) {
            ::v37::ScriptRef ref;
            if (!Cn.relay->cached(id, &ref)) { all_cached = false; break; }
            ::v37::PayoutDescriptor d; d.pay = ref;
            scratch.submit_tracked(::v37::LaneRecord::push(kChain, d, kReceiptWeight, 0)).get();
        }
        bool mism = false;
        auto view = scratch.settlement_view_by_cut(kChain, P, spineA, &mism);
        scratch.stop();
        C(all_cached && view != nullptr, "M5 scratch replay of the served order reproduces A's digest at P byte-for-byte");
        bytes32 nobody = spineA; nobody[0] ^= 0x5a;
        const u64 mis0 = Cn.relay->stats().repair_spine_mismatch.load();
        std::this_thread::sleep_for(50ms);
        const bool never = !wait_for([&] { return Cn.relay->repair_poll(P, nobody, 0, nullptr) == XmrRelayNode::RepairState::Ready; }, all, 2500ms);
        C(never && Cn.relay->stats().repair_spine_mismatch.load() > mis0,
          "M5 a spine no peer holds is NEVER Ready (the serving peer's digest at P is checked; spine mismatches counted)");
    }

    // ── M6 DoS ──────────────────────────────────────────────────────────────
    {
        c2pool::v37n::CarrierPeerNode evil;
        std::atomic<PeerId> epid{0};
        std::atomic<bool> dropped{false};
        evil.set_on_peer_event([&](PeerId p, bool up) { if (up) epid = p; else dropped = true; });
        std::atomic<int> hellos{0};
        evil.set_inbound_from([&](PeerId, const std::vector<u8>& f) { if (!f.empty() && f[0] == FB_HELLO) ++hellos; });
        const PeerId pid = evil.add_peer_id("127.0.0.1", portB);
        C(pid != 0, "M6 raw peer E connects to B");
        const std::size_t before = B.relay->ready_peers().size();
        Hello h = B.relay->our_hello(); h.node_nonce ^= 0x12345; h.lane_next_pos = 0;
        evil.send_to(pid, encode_hello(h));
        C(wait_for([&] { return B.relay->ready_peers().size() == before + 1 && hellos.load() >= 1; }, all, 5000ms), "M6 E passes HELLO at B");
        const auto& s = B.relay->stats();
        const u64 unk0 = s.fb_unknown.load(), fa0 = s.fa_ignored.load();
        evil.send_to(pid, std::vector<u8>{0x4f, 1, 2, 3});
        evil.send_to(pid, std::vector<u8>{0x02, 0, 0, 0, 0});
        C(wait_for([&] { return s.fb_unknown.load() > unk0 && s.fa_ignored.load() > fa0; }, all, 3000ms) && !dropped.load(),
          "M6 unknown 0x4f and Family-A 0x02 frames: counted, socket KEPT");
        // a structurally tampered receipt: identity no longer matches the payee
        B.note_bin(prev[2], 102);
        const SynthBlock blkE = make_block(102, prev[2], 4, nullptr, 1, 13);
        Admitted bad = own(blkE, 40, pB);
        bad.r.side.identity[0] ^= 1; bad.r.receipt.info_digest = side_digest_v2(bad.r.side);
        const auto rawbad = encode_fb_receipt(bad.r);
        const u64 st0 = s.structural.load(), rx0 = B.rx_calls.load();
        evil.send_to(pid, encode_receipts_frame(kChain, {&rawbad}));
        C(wait_for([&] { return s.structural.load() > st0; }, all, 3000ms) && B.rx_calls.load() == rx0 && !dropped.load(),
          "M6 tampered receipt: structural strike, ZERO RandomX evaluations, peer kept");
        // one confirmed invalid PoW -> ban
        Admitted inv = own(blkE, kBadNonce, pB);
        const auto rawinv = encode_fb_receipt(inv.r);
        evil.send_to(pid, encode_receipts_frame(kChain, {&rawinv}));
        C(wait_for([&] { return s.bans.load() >= 1 && dropped.load(); }, all, 5000ms),
          "M6 invalid PoW (RandomX below share_diff, confirmed by re-hash): BANNED + disconnected");
        C(s.rx_invalid.load() >= 1 && !B.relay->known(inv.id), "M6 the invalid receipt was never admitted");
        evil.stop();
    }

    // ── M7 a refused (BELOW_HORIZON) ORDER is re-asked from the peer's horizon ──
    {
        RelayOptions xo = opts(true, {});
        xo.vault.horizon_positions = 2;           // X keeps only its newest positions
        TNode X("X", xo, XmrReceiptIngest::Order::Canonical);
        C(X.relay->start(why), "M7 X starts (vault horizon 2 positions) " + why);
        TNode Y("Y", opts(false, {X.relay->listen_port()}), XmrReceiptIngest::Order::Canonical);
        C(Y.relay->start(why), "M7 Y starts, dials X " + why);
        std::vector<TNode*> xy{&X, &Y};
        C(wait_for([&] { return X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1; }, xy),
          "M7 X-Y up");
        for (auto* n : xy) { for (int i = 0; i < 4; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }
        const SynthBlock blkX = make_block(100, prev[0], 5, nullptr, 2, 14);
        for (std::uint32_t k = 0; k < 6; ++k) X.relay->submit_own(own(blkX, 50 + k, pA));
        for (auto* n : xy) n->template_height = 101;
        C(wait_for([&] { return X.next_pos() == 6 && Y.next_pos() == 6; }, xy), "M7 X and Y both push 6 receipts");
        const u64 PX = X.next_pos();
        bytes32 spineX = X.digest(); spineX[1] ^= 0x33;   // a cut Y does not hold: Y must repair it from X
        const auto& ys = Y.relay->stats();
        const u64 fail0 = ys.repair_peer_fail.load();
        const u64 mis0 = ys.repair_spine_mismatch.load();
        const u64 ord0 = Y.relay->requester()->stats().orders_requested;
        XmrRelayNode::RepairState st = XmrRelayNode::RepairState::Pending;
        const bool exhausted = wait_for([&] {
            st = Y.relay->repair_poll(PX, spineX, 0, nullptr);
            return st == XmrRelayNode::RepairState::Exhausted; }, xy, 8000ms);
        const u64 fails = ys.repair_peer_fail.load() - fail0;
        const u64 orders = Y.relay->requester()->stats().orders_requested - ord0;
        std::this_thread::sleep_for(300ms);
        for (int i = 0; i < 10; ++i) { (void)Y.relay->repair_poll(PX, spineX, 0, nullptr); X.pump(); Y.pump(); std::this_thread::sleep_for(20ms); }
        const u64 orders_after = Y.relay->requester()->stats().orders_requested - ord0;
        const u64 lowX = X.relay->vault().lowest_position();
        C(exhausted, "M7 the repair of a spine X never held ends Exhausted (every ready peer tried)");
        C(fails >= 1 && ys.repair_ready.load() == 0 && ys.repair_order_ok.load() == 0,
          "M7 the BELOW_HORIZON answer is a failed ask (repair_peer_fail +" + std::to_string(fails) + "), never an order, never Ready");
        C(ys.repair_horizon_rearm.load() == 1 && ys.repair_prefix_ok.load() == 1 && ys.repair_spine_mismatch.load() - mis0 == 1,
          "M7 REPAIR-HORIZON: the refusal re-armed the repair from X's lowest_retained (" + std::to_string(lowX) +
          "), the prefix probe matched, the suffix order failed the spine check at P (rearm=" +
          std::to_string(ys.repair_horizon_rearm.load()) + " prefix_ok=" + std::to_string(ys.repair_prefix_ok.load()) + ")");
        C(orders == 3 && orders_after == 3,
          "M7 X was asked exactly three times -- [0,P) refused, probe [a0,a0), suffix [a0,P) (" + std::to_string(orders) +
          ", then " + std::to_string(orders_after) + " after more polls): the empty refused order is not taken for progress");
        X.relay->set_dialing(false); Y.relay->set_dialing(false);
    }

    // ── M8 (HOLD-ROUND-2 B5): a lane-prefix-SKEW verdict is never a strike ──
    // Stagenet attempt 7: every finder share the receivers judged on their older
    // lane prefix was -1 -> a strike -> the finder banned every ~3 s (86350 bans
    // on A). The share verdict now classifies those AHEAD (v37_xmr_share_verdict_kat
    // S13 B1); the relay parks them (bounded per peer), never strikes, and
    // re-judges them when the node's share state advances.
    {
        RelayOptions qo = opts(true, {});
#if defined(C2POOL_XMR_SHARE_VERDICT_SKEW)
        qo.share_ahead_per_peer = 64;
#endif
        TNode Q("Q", qo, XmrReceiptIngest::Order::Canonical);
        C(Q.relay->start(why), "M8 Q starts " + why);
        TNode P("P", opts(false, {Q.relay->listen_port()}), XmrReceiptIngest::Order::Canonical);
        C(P.relay->start(why), "M8 P (the finder) starts, dials Q " + why);
        std::vector<TNode*> pq{&P, &Q};
        C(wait_for([&] { return P.relay->ready_peers().size() == 1 && Q.relay->ready_peers().size() == 1; }, pq), "M8 P-Q up");
        std::atomic<bool> advanced{false};
        std::atomic<u64> judged{0};
        Q.relay->set_share_verdict([&](const FbReceipt&, const ::v37::xmr::verify::ParsedBlob&, u64, std::string& w) {
            ++judged;
            if (advanced.load()) return 1;
            w = "ahead: the take is the drain Delta at dh 4 (a lane block not booked here)";
#if defined(C2POOL_XMR_SHARE_VERDICT_SKEW)
            return kShareVerdictAhead;
#else
            return -1;   // the base verdict for that share (S13 B1: under-take)
#endif
        });
        const bytes32 prevM = b32_of(0x77);
        for (auto* n : pq) { n->note_bin(prevM, 105); n->template_height = 105; }
        const SynthBlock blkM = make_block(105, prevM, 6, nullptr, 3, 15);
        for (std::uint32_t k = 0; k < 200; ++k) P.relay->submit_own(own(blkM, 1000 + k, pA));
        const auto& qs = Q.relay->stats();
        C(wait_for([&] { return judged.load() >= 200 || qs.bans.load() >= 1; }, pq, 15000ms), "M8 Q judged P's 200 shares");
        std::this_thread::sleep_for(300ms);
#if defined(C2POOL_XMR_SHARE_VERDICT_SKEW)
        const u64 ahead = qs.share_skew_ahead.load(), evicted = qs.share_ahead_evicted.load();
        const std::size_t now_ahead = Q.relay->share_ahead_size();
#else
        const u64 ahead = 0, evicted = 0; const std::size_t now_ahead = 0;
#endif
        C(qs.bans.load() == 0 && qs.share_refused.load() == 0 && Q.relay->ready_peers().size() == 1,
          "M8 200 AHEAD shares: bans=0, refused=0, P stays connected (base: -1 -> strikes -> bans=" + std::to_string(qs.bans.load()) +
          " refused=" + std::to_string(qs.share_refused.load()) + ")");
        C(ahead == 200 && now_ahead == 64 && evicted == 136 && Q.relay->cache_size() == 0,
          "M8 parked AHEAD, bounded per peer: ahead=" + std::to_string(ahead) + " held=" + std::to_string(now_ahead) +
          " evicted=" + std::to_string(evicted) + " (64 kept, the oldest 136 dropped without a strike), none admitted yet");
        advanced = true;   // the node booked the finder's lane block: share_publish -> notify
#if defined(C2POOL_XMR_SHARE_VERDICT_SKEW)
        Q.relay->notify_share_state_advanced();
#endif
        const bool admitted64 = wait_for([&] { return Q.relay->cache_size() == 64; }, pq, 20000ms);
        C(admitted64 && qs.bans.load() == 0,
          "M8 the state advances: the 64 parked shares are re-judged CANONICAL and admitted (cache=" +
          std::to_string(Q.relay->cache_size()) + "), still bans=" + std::to_string(qs.bans.load()));
        P.relay->set_dialing(false);
    }

    // ── M9 (HOLD-ROUND-2 V4): the AHEAD park bound is per sender NODE ──────
    // VERIFY V4: the bound was keyed by the connection and the cap evicted the
    // global oldest. (a) a finder that reconnects keeps ONE budget: 32 parked,
    // a reconnect, 32 more -> 32 held (its own oldest go), not 64. (b) at the
    // cap the heaviest node's oldest entry goes first: H parks 32, X 64, H 8
    // more at cap 96 -> X loses 8, H keeps all 40 (the global oldest were H's).
    {
        RelayOptions qo = opts(true, {});
        qo.share_ahead_per_peer = 32;
        TNode Q("Q9", qo, XmrReceiptIngest::Order::Canonical);
        C(Q.relay->start(why), "M9a Q starts " + why);
        TNode P("P9", opts(false, {Q.relay->listen_port()}), XmrReceiptIngest::Order::Canonical);
        C(P.relay->start(why), "M9a P starts, dials Q " + why);
        std::vector<TNode*> pq{&P, &Q};
        C(wait_for([&] { return P.relay->ready_peers().size() == 1 && Q.relay->ready_peers().size() == 1; }, pq), "M9a P-Q up");
        std::atomic<bool> advanced{false};
        std::atomic<u64> judged{0};
        Q.relay->set_share_verdict([&](const FbReceipt&, const ::v37::xmr::verify::ParsedBlob&, u64, std::string& w) {
            ++judged;
            if (advanced.load()) return 1;
            w = "ahead: the take is the drain Delta at dh 4 (a lane block not booked here)";
            return kShareVerdictAhead;
        });
        const bytes32 prev9 = b32_of(0x79);
        for (auto* n : pq) { n->note_bin(prev9, 106); n->template_height = 106; }
        const SynthBlock blk9 = make_block(106, prev9, 6, nullptr, 3, 15);
        std::vector<Admitted> sent;
        for (std::uint32_t k = 0; k < 64; ++k) sent.push_back(own(blk9, 3000 + k, pA));
        for (std::uint32_t k = 0; k < 32; ++k) P.relay->submit_own(sent[k]);
        C(wait_for([&] { return judged.load() >= 32; }, pq), "M9a Q judged P's first 32 (parked AHEAD)");
        std::this_thread::sleep_for(200ms);
        const PeerId first = Q.relay->ready_peers().front();
        P.relay->set_dialing(false);
        C(wait_for([&] { return Q.relay->ready_peers().empty(); }, pq, 5000ms), "M9a P drops off");
        P.relay->set_dialing(true);
        C(wait_for([&] { return Q.relay->ready_peers().size() == 1 && P.relay->ready_peers().size() == 1; }, pq, 20000ms) &&
          Q.relay->ready_peers().front() != first, "M9a P reconnects (a new connection id on Q)");
        for (std::uint32_t k = 32; k < 64; ++k) P.relay->submit_own(sent[k]);
        C(wait_for([&] { return judged.load() >= 64; }, pq), "M9a Q judged P's next 32");
        std::this_thread::sleep_for(300ms);
        const auto& qs = Q.relay->stats();
        C(Q.relay->share_ahead_size() == 32 && qs.share_ahead_evicted.load() == 32 && qs.bans.load() == 0,
          "M9a one budget per NODE across a reconnect: held=" + std::to_string(Q.relay->share_ahead_size()) + " evicted=" +
          std::to_string(qs.share_ahead_evicted.load()) + " (cc97146361: 64 held, 0 evicted -- the bound restarted per connection)");
        advanced = true;
        Q.relay->notify_share_state_advanced();
        C(wait_for([&] { return Q.relay->cache_size() == 32; }, pq, 20000ms), "M9a the 32 held re-judge CANONICAL");
        std::size_t newest = 0;
        for (std::uint32_t k = 32; k < 64; ++k) { ::v37::ScriptRef py; u64 bn = 0; std::vector<u8> raw; if (Q.relay->cached_share(sent[k].id, py, bn, raw)) ++newest; }
        C(newest == 32, "M9a the node's NEWEST 32 are the ones kept (" + std::to_string(newest) + ")");
        P.relay->set_dialing(false);
    }
    {
        RelayOptions qo = opts(true, {});
        qo.share_ahead_per_peer = 64; qo.share_ahead_max = 96;
        TNode Q("Q9b", qo, XmrReceiptIngest::Order::Canonical);
        C(Q.relay->start(why), "M9b Q starts " + why);
        TNode H("H9", opts(false, {Q.relay->listen_port()}), XmrReceiptIngest::Order::Canonical);
        TNode X("X9", opts(false, {Q.relay->listen_port()}), XmrReceiptIngest::Order::Canonical);
        C(H.relay->start(why) && X.relay->start(why), "M9b H (honest finder) and X (flooder) dial Q " + why);
        std::vector<TNode*> hxq{&H, &X, &Q};
        C(wait_for([&] { return Q.relay->ready_peers().size() == 2; }, hxq), "M9b H-Q and X-Q up");
        std::atomic<bool> advanced{false};
        std::atomic<u64> judged{0};
        Q.relay->set_share_verdict([&](const FbReceipt&, const ::v37::xmr::verify::ParsedBlob&, u64, std::string& w) {
            ++judged;
            if (advanced.load()) return 1;
            w = "ahead: the take is the drain Delta at dh 4 (a lane block not booked here)";
            return kShareVerdictAhead;
        });
        const bytes32 prevb = b32_of(0x7a);
        for (auto* n : hxq) { n->note_bin(prevb, 107); n->template_height = 107; }
        const SynthBlock blkb = make_block(107, prevb, 6, nullptr, 3, 15);
        std::vector<Admitted> hs, xs;
        for (std::uint32_t k = 0; k < 40; ++k) hs.push_back(own(blkb, 4000 + k, pA));
        for (std::uint32_t k = 0; k < 64; ++k) xs.push_back(own(blkb, 5000 + k, pB));
        for (std::uint32_t k = 0; k < 32; ++k) H.relay->submit_own(hs[k]);
        C(wait_for([&] { return judged.load() >= 32; }, hxq), "M9b H's 32 parked first (the global oldest)");
        std::this_thread::sleep_for(200ms);
        for (std::uint32_t k = 0; k < 64; ++k) X.relay->submit_own(xs[k]);
        C(wait_for([&] { return judged.load() >= 96; }, hxq), "M9b X's 64 parked (the cap 96 reached)");
        std::this_thread::sleep_for(200ms);
        for (std::uint32_t k = 32; k < 40; ++k) H.relay->submit_own(hs[k]);
        C(wait_for([&] { return judged.load() >= 104; }, hxq), "M9b H's 8 more judged at the cap");
        std::this_thread::sleep_for(300ms);
        advanced = true;
        Q.relay->notify_share_state_advanced();
        const bool ok96 = wait_for([&] { return Q.relay->cache_size() == 96; }, hxq, 20000ms);
        C(ok96, "M9b the 96 held re-judge CANONICAL (" + std::to_string(Q.relay->cache_size()) + ")");
        auto held = [&](const std::vector<Admitted>& v) {
            std::size_t n = 0;
            for (const auto& a : v) { ::v37::ScriptRef py; u64 bn = 0; std::vector<u8> raw; if (Q.relay->cached_share(a.id, py, bn, raw)) ++n; }
            return n;
        };
        const std::size_t nh = held(hs), nx = held(xs);
        C(nh == 40 && nx == 56 && Q.relay->stats().bans.load() == 0,
          "M9b at the cap the HEAVIEST node's oldest go: H kept " + std::to_string(nh) + "/40, X " + std::to_string(nx) +
          "/64 (cc97146361: H 32, X 64 -- the global oldest were the honest finder's)");
        H.relay->set_dialing(false); X.relay->set_dialing(false);
    }

    for (auto* n : all) n->dump_logs();
    std::printf("    A %s\n    B %s\n    C %s\n", A.relay->describe().c_str(), B.relay->describe().c_str(), Cn.relay->describe().c_str());
    return C.done("v37_xmr_relay_multinode_kat");
}
