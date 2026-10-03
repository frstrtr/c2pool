// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_admission_relay_kat -- RULES RATCHET R1, RECEIPT ADMISSION (F1-F3,
// operator ruling 2026-10-03), the relay side, over REAL loopback TCP.
//
// A receipt enters the verified cache, the lane order or the raindrop store
// only on share verdict 1, however it arrived. The relay's real share verdict
// (relay::share_verdict on a ShareStateStore) is installed on the receiving
// nodes; the sending node T holds, in its own lane, honest receipts (whose
// verdict is 1 on the receivers) and receipts whose 0x03 root commits no state
// the receivers hold (verdict 0 without the committed history; FOREIGN with it).
//
//   R1 (REVIEW K1)  HELLO backfill: V joins after T minted; GETORDER/GETFRAMES
//      bring every id as a SOLICITED copy. Past the solicited patience the
//      unheld-root receipts are not in V's cache or lane (trusted = 0); the
//      honest ones are. With the committed history they are refused FOREIGN,
//      kept in the refused memo, no strike.             (base: trusted, admitted)
//   R2 (REVIEW K2)  the same through the raindrop inventory (DROPINV, DROPS on):
//      not in V's raindrop store, nothing drained to the harvest. (base: held)
//   R3 (REVIEW K3)  the repair answer of a won block's cut that covers them:
//      the repair completes (each id admitted or refused here), the order
//      reaches the committed spine, the peer is set aside, every ready peer is
//      tried -> still PENDING: the cut stays HELD (review 2026-10-04 D1/D2: a
//      served order never decides a cut; EMPTY-CUT is reserved).
//                                         (base: every id cached -> anchored)
//   R4 (REVIEW K4)  a solicited AHEAD / UNBASED verdict is never admitted: parked
//      and re-judged on share-state advances; UNBASED expires.
//                                                     (base: trusted, admitted)
//   R5 (F3-K8)      the refused memo is a cache: a node that never saw the
//      receipts (a restart) fetches the bytes, reaches the same verdict and
//      keeps the same served order PENDING (HELD).        (base: no memo)
//   R6 (review 2026-10-04, O7) a relay under the admission rule with no share
//      verdict installed refuses to start.   (base: starts, receipts unchecked)
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <set>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/xmr/relay/xmr_share_verdict.hpp>
#include <c2pool/v37/v37_engine.hpp>
#if __has_include(<c2pool/v37/xmr/xmr_cut_admission.hpp>)
#include <c2pool/v37/xmr/xmr_cut_admission.hpp>
#endif

using namespace gap2test;
using namespace std::chrono_literals;
namespace rl = c2pool::v37n::xmr::relay;
namespace rc = c2pool::v37n::xmr::recompute;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr std::uint32_t kDropNonce = 0x40000000u;

// One relay node with its own lane (the GAP-2 multinode rig) and an optional
// share verdict. Fake RandomX: nonce >= kDropNonce -> a raindrop (above the
// drops floor, below share_diff), anything else -> a share.
struct TNode {
    std::string name;
    ChainView chain;
    std::atomic<u64> rx_calls{0};
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    u64 template_height = 0;
    std::vector<bytes32> drained;
    std::vector<std::string> logs;
    std::mutex log_mtx;
    TNode(std::string n, RelayOptions ro) : name(std::move(n)) {
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
                pow.fill(0);
                if (nonce >= kDropNonce) pow[31] = 0x02;
                return true;
            },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(kChain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(log_mtx); logs.push_back(l); });
        XmrReceiptIngest::Options io; io.chain = kChain; io.order = XmrReceiptIngest::Order::Canonical; io.bin_lag = 1; io.grace_ms = 0;
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dig) {
                ::v37::PayoutDescriptor d; d.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(kChain, d, w, 0)).get().applied()) return false;
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
        for (auto& a : relay->drain_drops()) drained.push_back(a.id);
        ingest->tick(template_height);
    }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
    bytes32 digest() { auto s = engine->snapshot(kChain); return s ? s->digest : bytes32{}; }
};

static RelayOptions opts(bool listen, std::vector<u16> dial, bool drops = false) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.reoffer_seconds = 0;   // nothing re-offered on connect: a joiner gets T's receipts ONLY as solicited copies
    o.hello_timeout_ms = 3000;
    o.unresolved_patience_ms = 800;
    o.solicited_unresolved_patience_ms = 1200;   // short: the base trusts a solicited undecided copy past it
    if (drops) o.drops_floor_diff = kFloorDiff;
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
static void settle(std::vector<TNode*> pump, std::chrono::milliseconds d) { (void)wait_for([] { return false; }, std::move(pump), d); }

static Admitted mint(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee, bool drop = false) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, kChain, kShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    if (drop) { a.pow.fill(0); a.pow[31] = 0x02; }
    return a;
}
static bytes32 root_of(const FbReceipt& r) {
    const auto x = rc::mm_root_of(r.receipt.coinbase_opening.tx_extra);
    return x ? *x : bytes32{};
}

// The committed history of a node whose canonical states are not the unheld
// root (cursor past every builder cut used here; warm).
#if defined(C2POOL_XMR_RECEIPT_ADMISSION)
static std::shared_ptr<rl::CommittedHistory> foreign_history() {
    auto h = std::make_shared<rl::CommittedHistory>();
    rl::CommittedHistory::Entry e; e.digest = b32_of(0xD0); e.root = b32_of(0xD1); e.since = 10;
    h->entries.push_back(e);
    h->cursor = 1000; h->d_conf = 2; h->max_root_age = 8; h->warm = true;
    return h;
}
#endif

// The share verdict a receiver installs: the honest root is canonical here
// (its state is held), anything else goes through the REAL relay verdict on
// `store` (empty: the root is not held).
static XmrRelayNode::VerdictFn verdict_with(std::shared_ptr<rl::ShareStateStore> store, bytes32 honest_root,
                                            std::shared_ptr<std::atomic<u64>> calls, std::set<bytes32>* judged = nullptr,
                                            std::mutex* jm = nullptr) {
    return [store, honest_root, calls, judged, jm](const FbReceipt& r, const ::v37::xmr::verify::ParsedBlob& pb, u64 h, std::string& w) {
        ++*calls;
        if (judged && jm) { std::lock_guard<std::mutex> lk(*jm); judged->insert(receipt_id(r)); }
        if (root_of(r) == honest_root) return 1;
        return rl::share_verdict(*store, r, pb, h, w);
    };
}

int main() {
    Checker C;
    std::printf("== v37_xmr_admission_relay_kat ==\n");
    const ::v37::ScriptRef pH = payee_of("honest"), pW = payee_of("weight-key");
    std::string why;
    const bytes32 prev0 = b32_of(0x30);
    const SynthBlock blkH = make_block(100, prev0, 1, nullptr, 3, 10);   // the honest template (its root is held by the receivers)
    const SynthBlock blkX = make_block(100, prev0, 2, nullptr, 3, 50);   // the other template: its root commits no state they hold
    const bytes32 rootH = b32_of(static_cast<u8>(10 + 23)), rootX = b32_of(static_cast<u8>(50 + 23));
    std::vector<Admitted> hon, thf;
    for (std::uint32_t k = 0; k < 3; ++k) hon.push_back(mint(blkH, 10 + k, pH));
    for (std::uint32_t k = 0; k < 2; ++k) thf.push_back(mint(blkX, 20 + k, pW));
    C(root_of(hon[0].r) == rootH && root_of(thf[0].r) == rootX && rootH != rootX, "the two templates commit two different 0x03 roots");

    // T: the sender. Its own lane holds the 3 honest + 2 other receipts of bin 100.
    TNode T("T", opts(true, {}));
    C(T.relay->start(why), "T starts " + why);
    const u16 portT = T.relay->listen_port();
    T.note_bin(prev0, 100); T.template_height = 100;
    for (auto& a : hon) T.relay->submit_own(a);
    for (auto& a : thf) T.relay->submit_own(a);
    T.template_height = 101;
    C(wait_for([&] { return T.next_pos() == 5; }, {&T}), "T's lane holds the 5 receipts of bin 100 (bin closed)");
    const u64 P = T.next_pos();
    const bytes32 spineT = T.digest();

    auto cached_n = [](TNode& n, const std::vector<Admitted>& v) { std::size_t c = 0; for (const auto& a : v) if (n.relay->cached(a.id)) ++c; return c; };

    // ── R1 (REVIEW K1): the HELLO backfill ────────────────────────────────
    auto store1 = std::make_shared<rl::ShareStateStore>();
    auto calls1 = std::make_shared<std::atomic<u64>>(0);
    TNode V1("V1", opts(false, {portT}));
    V1.relay->set_share_verdict(verdict_with(store1, rootH, calls1));
    V1.note_bin(prev0, 100); V1.template_height = 101;
    C(V1.relay->start(why), "R1 V1 (no committed history) starts, dials T " + why);
    C(wait_for([&] { return cached_n(V1, hon) == 3; }, {&T, &V1}), "R1 V1 backfills T's order: the 3 honest receipts are admitted (verdict 1)");
    settle({&T, &V1}, 4000ms);   // well past the solicited patience (1.2 s)
    const auto& s1 = V1.relay->stats();
    C(cached_n(V1, thf) == 0, "R1 the 2 receipts whose root is not held are NOT in V1's cache past the solicited patience (cached " +
                               std::to_string(cached_n(V1, thf)) + "; base: trusted and admitted)");
    C(s1.share_undecided_trusted.load() == 0, "R1 share_undecided_trusted == 0 (" + std::to_string(s1.share_undecided_trusted.load()) + ")");
    C(V1.next_pos() == 3, "R1 V1's lane excludes them: 3 pushes, not 5 (" + std::to_string(V1.next_pos()) + ")");
    C(s1.bans.load() == 0 && V1.relay->ready_peers().size() == 1, "R1 no strike, no ban: T stays connected");
#if defined(C2POOL_XMR_RECEIPT_ADMISSION)
    C(s1.share_undecided_waiting.load() >= 2, "R1 they wait for a share-state advance (waiting=" + std::to_string(s1.share_undecided_waiting.load()) + ")");
#endif

    //    R1b: with the committed history the same receipts are decided FOREIGN
    auto store1b = std::make_shared<rl::ShareStateStore>();
#if defined(C2POOL_XMR_RECEIPT_ADMISSION)
    store1b->set_history(foreign_history());
#endif
    auto calls1b = std::make_shared<std::atomic<u64>>(0);
    TNode V1b("V1b", opts(false, {portT}));
    V1b.relay->set_share_verdict(verdict_with(store1b, rootH, calls1b));
    V1b.note_bin(prev0, 100); V1b.template_height = 101;
    C(V1b.relay->start(why), "R1b V1b (committed history) starts, dials T " + why);
    C(wait_for([&] { return cached_n(V1b, hon) == 3; }, {&T, &V1b}), "R1b V1b admits the 3 honest receipts");
    settle({&T, &V1b}, 3000ms);
    const auto& s1b = V1b.relay->stats();
    C(cached_n(V1b, thf) == 0 && V1b.next_pos() == 3, "R1b the 2 others are not admitted (lane " + std::to_string(V1b.next_pos()) + ")");
#if defined(C2POOL_XMR_RECEIPT_ADMISSION)
    {
        XmrRelayNode::RefusedRec rr;
        const bool memo = V1b.relay->refused(thf[0].id, &rr) && V1b.relay->refused(thf[1].id);
        C(memo && s1b.share_foreign.load() == 2 && rr.payee == pW && rr.bin == 100,
          "R1b decided FOREIGN (committed test) and kept in the refused memo with payee + bin (foreign=" +
          std::to_string(s1b.share_foreign.load()) + ", reason: " + rr.reason.substr(0, 90) + ")");
    }
#else
    C(false, "R1b no committed receipt test / refused memo on the base");
#endif
    C(s1b.bans.load() == 0 && s1b.share_undecided_trusted.load() == 0, "R1b no strike for a FOREIGN receipt, nothing trusted");

    // ── R3 (REVIEW K3): the repair answer of T's won cut (P=5, spine_T) ────
    {
        const u64 v1b_calls0 = calls1b->load();   // F3-K8: the memo answers the refused ids (no verdict re-run)
        std::vector<bytes32> ids;
        XmrRelayNode::RepairState st = XmrRelayNode::RepairState::Pending;
        const bool ready = wait_for([&] { st = V1b.relay->repair_poll(P, spineT, 0, &ids); return st == XmrRelayNode::RepairState::Ready; },
                                    {&T, &V1b}, 10000ms);
        std::size_t adm = 0, refd = 0;
        c2pool::v37n::V37Engine scratch; scratch.start();
        scratch.submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
#if defined(C2POOL_XMR_EMPTY_CUT)
        namespace cutadm = c2pool::v37n::xmr::cutadm;
        cutadm::OrderInput in;
#endif
        for (const auto& id : ids) {
            ::v37::ScriptRef ref;
            bool have = V1b.relay->cached(id, &ref);
            if (have) ++adm;
#if defined(C2POOL_XMR_EMPTY_CUT)
            XmrRelayNode::RefusedRec rr;
            if (!have && V1b.relay->refused(id, &rr)) { ref = rr.payee; have = true; ++refd; in.receipts.push_back(cutadm::Served::Refused); }
            else in.receipts.push_back(have ? cutadm::Served::Admitted : cutadm::Served::Missing);
#endif
            if (!have) continue;
            ::v37::PayoutDescriptor d; d.pay = ref;
            scratch.submit_tracked(::v37::LaneRecord::push(kChain, d, kReceiptWeight, 0)).get();
        }
        bool mism = false;
        const bool spine_ok = scratch.settlement_view_by_cut(kChain, P, spineT, &mism) != nullptr;
        scratch.stop();
        C(ready && ids.size() == P, "R3 the repair of T's cut completes on V1b (" + std::to_string(ids.size()) + " ids)");
        C(!(ready && adm == P), "R3 the cut is NOT reproducible from admitted receipts alone (admitted " + std::to_string(adm) + "/" +
                                 std::to_string(P) + "; base: all " + std::to_string(P) + " cached -> the cut is anchored with them)");
#if defined(C2POOL_XMR_EMPTY_CUT)
        in.spine_reproduced = spine_ok;
        std::string w1;
        const auto v1 = cutadm::classify_served_order(in, &w1);
        C(adm == 3 && refd == 2 && spine_ok && v1 == cutadm::OrderVerdict::Pending,
          "R3 3 admitted + 2 refused, the order reaches T's spine: first a REFUSED VARIANT, other peers to ask (" + w1 + ")");
        V1b.relay->repair_set_aside(P, spineT);
        const bool exh = wait_for([&] { return V1b.relay->repair_poll(P, spineT, 0, nullptr) == XmrRelayNode::RepairState::Exhausted; }, {&T, &V1b}, 4000ms);
        in.every_peer_tried = exh;
        std::string w2;
        const auto v2 = cutadm::classify_served_order(in, &w2);
        // review 2026-10-04 (D1/D2): a served order never decides a cut -- the
        // refused variant keeps the cut HELD even once every ready peer was tried
        C(exh && v2 == cutadm::OrderVerdict::Pending, "R3 T set aside, every ready peer tried (Exhausted): still PENDING, the cut HELD (" + w2 + ")");
        {
            const auto held = cutadm::classify_own_cut(true, true, false, "cut-pending: " + w2);
            C(held == cutadm::OwnCut::Pending, std::string("R3 the booking: ") + cutadm::to_string(held) + " (HELD, no EMPTY-CUT from a served order)");
        }
        // the RESERVED EMPTY-CUT branch, reachable only from a cut-bad reason no served order produces
        const std::string bad_why = std::string(cutadm::kCutBadPrefix) + " (reserved)";
        const auto own = cutadm::classify_own_cut(true, true, false, bad_why);
        {
            ::c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = P; cc.spine_digest = spineT;
            const auto bc = cutadm::booking_cut(own, true, cc);
            C(own == cutadm::OwnCut::EmptyCut && !bc, std::string("R3 the booking: ") + cutadm::to_string(own) + ", no cut passed (the anchor stays)");
            const auto off = cutadm::classify_own_cut(true, false, false, bad_why);
            C(off == cutadm::OwnCut::Pending, "R3 with the empty_cut rule off the same cut is HELD (the pre-R1 outcome)");
        }
        C(calls1b->load() == v1b_calls0, "R3 / F3-K8 V1b's refused memo answered the refused ids: no verdict re-run for the repair (" +
                                         std::to_string(calls1b->load() - v1b_calls0) + " calls)");
#else
        (void)spine_ok;
        C(false, "R3 no EMPTY-CUT decision on the base");
#endif
    }

    // ── R5 (F3-K8): the refused memo is a cache ───────────────────────────
    {
#if defined(C2POOL_XMR_EMPTY_CUT)
        namespace cutadm = c2pool::v37n::xmr::cutadm;
        auto store5 = std::make_shared<rl::ShareStateStore>();
        store5->set_history(foreign_history());
        auto calls5 = std::make_shared<std::atomic<u64>>(0);
        std::set<bytes32> judged5; std::mutex jm5;
        TNode V5("V5", opts(false, {portT}));
        V5.relay->set_share_verdict(verdict_with(store5, rootH, calls5, &judged5, &jm5));
        V5.note_bin(prev0, 100); V5.template_height = 101;
        C(V5.relay->start(why), "R5 V5 (a fresh node: no memo) starts, dials T " + why);
        std::vector<bytes32> ids;
        const bool ready = wait_for([&] { return V5.relay->repair_poll(P, spineT, 0, &ids) == XmrRelayNode::RepairState::Ready; }, {&T, &V5}, 10000ms);
        cutadm::OrderInput in5;
        for (const auto& id : ids)
            in5.receipts.push_back(V5.relay->cached(id) ? cutadm::Served::Admitted
                                   : V5.relay->refused(id) ? cutadm::Served::Refused : cutadm::Served::Missing);
        in5.spine_reproduced = true;   // the same served order (ids) as R3: the same pushes reach the same spine
        V5.relay->repair_set_aside(P, spineT);
        in5.every_peer_tried = wait_for([&] { return V5.relay->repair_poll(P, spineT, 0, nullptr) == XmrRelayNode::RepairState::Exhausted; }, {&T, &V5}, 4000ms);
        const auto v5 = cutadm::classify_served_order(in5);
        bool refetched = false;
        { std::lock_guard<std::mutex> lk(jm5); refetched = judged5.count(thf[0].id) && judged5.count(thf[1].id); }
        C(ready && refetched && v5 == cutadm::OrderVerdict::Pending,
          "R5 V5 fetched and judged the refused receipts itself (no memo) and keeps the same served order PENDING (HELD), as V1b did from its memo");
        V5.relay->set_dialing(false);
#else
        C(false, "R5 no refused memo on the base");
#endif
    }

    // ── R4 (REVIEW K4): a solicited AHEAD / UNBASED verdict is never admitted ─
    for (const int code : {kShareVerdictAhead, kShareVerdictUnbased}) {
        const std::string tag = code == kShareVerdictAhead ? "AHEAD" : "UNBASED";
        TNode V4("V4-" + tag, opts(false, {portT}));
        std::atomic<u64> judged{0};
        V4.relay->set_share_verdict([&, code](const FbReceipt& r, const ::v37::xmr::verify::ParsedBlob&, u64, std::string& w) {
            ++judged;
            if (root_of(r) == rootH) return 1;
            w = "skew (stub): a state this node holds, another lane prefix";
            return code;
        });
        V4.note_bin(prev0, 100); V4.template_height = 101;
        C(V4.relay->start(why), "R4 V4 (" + tag + " stub) starts, dials T " + why);
        C(wait_for([&] { return cached_n(V4, hon) == 3; }, {&T, &V4}), "R4 " + tag + ": the 3 honest receipts admitted");
        settle({&T, &V4}, 2500ms);
        for (int r = 0; r < 6; ++r) { V4.relay->notify_share_state_advanced(); settle({&T, &V4}, 300ms); }
        C(cached_n(V4, thf) == 0 && V4.next_pos() == 3 && V4.relay->stats().share_undecided_trusted.load() == 0,
          "R4 solicited " + tag + " copies: never admitted after 6 share-state advances (cached " + std::to_string(cached_n(V4, thf)) +
          ", lane " + std::to_string(V4.next_pos()) + "; base: mapped to 0 and trusted)");
        C(V4.relay->stats().bans.load() == 0, "R4 " + tag + ": never a strike");
        V4.relay->set_dialing(false);
    }

    // ── R2 (REVIEW K2): the raindrop inventory (DROPINV, DROPS on) ─────────
    {
        TNode T2("T2", opts(true, {}, true));
        C(T2.relay->start(why), "R2 T2 (DROPS on) starts " + why);
        const bytes32 prevD = b32_of(0x31);
        const SynthBlock blkD = make_block(200, prevD, 3, nullptr, 3, 60);   // its root commits no state the receivers hold
        T2.note_bin(prevD, 200);
        std::vector<Admitted> drops;
        for (std::uint32_t k = 0; k < 4; ++k) drops.push_back(mint(blkD, kDropNonce + k, pW, true));
        for (auto& a : drops) T2.relay->submit_own_drop(a);
        for (const bool with_hist : {false, true}) {
            auto store2 = std::make_shared<rl::ShareStateStore>();
#if defined(C2POOL_XMR_RECEIPT_ADMISSION)
            if (with_hist) store2->set_history(foreign_history());
#endif
            auto calls2 = std::make_shared<std::atomic<u64>>(0);
            TNode V2(with_hist ? "V2h" : "V2", opts(false, {T2.relay->listen_port()}, true));
            V2.relay->set_share_verdict(verdict_with(store2, rootH, calls2));
            V2.note_bin(prevD, 200);
            C(V2.relay->start(why), std::string("R2 V2") + (with_hist ? " (committed history)" : "") + " joins " + why);
            (void)wait_for([&] { return V2.relay->drops_sync(200, 201).complete && calls2->load() >= 4; }, {&T2, &V2}, 6000ms);
            settle({&T2, &V2}, 2500ms);
            (void)V2.relay->drops_sync(200, 201);
            settle({&T2, &V2}, 500ms);
            const auto held = V2.relay->drops_held(200, 201);
            std::size_t in = 0;
            for (const auto& a : drops) if (std::find(held.begin(), held.end(), a.id) != held.end()) ++in;
            C(calls2->load() >= 4, std::string("R2 V2") + (with_hist ? "h" : "") + " fetched and judged T2's raindrops (" + std::to_string(calls2->load()) + " verdicts)");
            C(in == 0 && V2.drained.empty(), std::string("R2 V2") + (with_hist ? "h" : "") + ": none of them in the raindrop store or the harvest (held " +
                                             std::to_string(in) + "/4, drained " + std::to_string(V2.drained.size()) + "; base: trusted and admitted)");
            V2.relay->set_dialing(false);
        }
        T2.relay->set_dialing(false);
    }

    // ── R6 (review 2026-10-04, O7): no start without the share verdict ────
    {
#if defined(C2POOL_XMR_VERDICT_REQUIRED)
        RelayOptions o6 = opts(false, {});
        o6.require_share_verdict = true;
        TNode V6("V6", o6);
        std::string w6;
        const bool started = V6.relay->start(w6);
        C(!started && !w6.empty(), "R6 the admission rule on and no share verdict installed: the relay refuses to start (" + w6 + ")");
        TNode V6b("V6b", o6);
        V6b.relay->set_share_verdict([](const FbReceipt&, const ::v37::xmr::verify::ParsedBlob&, u64, std::string&) { return 1; });
        std::string w6b;
        C(V6b.relay->start(w6b), "R6 (control) with the verdict installed it starts " + w6b);
        V6b.relay->set_dialing(false);
#else
        C(false, "R6 the base starts a relay with no share verdict under the admission rule (every receipt unchecked)");
#endif
    }

    V1.relay->set_dialing(false); V1b.relay->set_dialing(false);
    std::printf("    T  %s\n    V1 %s\n    V1b %s\n", T.relay->describe_shares().c_str(), V1.relay->describe_shares().c_str(),
                V1b.relay->describe_shares().c_str());
    return C.done("v37_xmr_admission_relay_kat");
}
