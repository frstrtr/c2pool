// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_empty_cut_kat -- RULES RATCHET R1, RECEIPT ADMISSION, F3: the
// EMPTY-CUT rule (operator ruling 2026-10-03), at the booking.
//
// A canonical lane block B whose own credit cut is DECIDED bad (the
// winner-side order reaches the committed spine and carries a receipt every
// node refuses under the committed receipt test, and no ready peer serves the
// spine without it) books its money as decided with NO cut: its FINALIZE
// leaves the anchor where it is. Undecided cuts stay HELD.
//
// THE RIG (real code at every seam): lane orders and the views at their cuts
// on real V37Engine lanes; each node's REAL FinalizeConnect + XmrNode ledger
// (anchor_cut + empty_cut rules) booking through a callback that decides the
// own cut with xmr_cut_admission.hpp, the receipt status from the committed
// receipt test (relay::committed_root_test); the DROPS harvest range from
// ChainOrderedHarvest::walk_prev_lane / range_with.
//
//   REVIEW 2026-10-04 (D1/D2): a served order never decides a cut. A cut whose
//   served order carries a refused receipt keeps its peer set aside and stays
//   HELD on every node; the EMPTY-CUT booking branch is RESERVED (E7 pins the
//   branch itself). E1-E4 are re-pinned to that rule:
//   E1 a cut B that carries the refused receipt t: HELD on all three nodes, no
//      node books it, none anchors B's cut; the honest anchor view at C would
//      credit r1..r6 and pay t's key 0.     (ed4712059: B booked EMPTY-CUT)
//   E2 (F3-K2) the finder <= solo: the anchor in force after B and the next
//      three honest anchors credit the key t paid 0 piconero.
//   E3 no decision past the bound: B HELD (held_now 1), never booked.
//                                         (ed4712059: decided bad and booked)
//   E4 one outcome whatever the arrival tick or a restart: the three nodes hold
//      B alike, one owed_digest.          (ed4712059: booked EMPTY-CUT)
//   E5 (F3-K6) withheld stays held, loudly: an order no peer serves is HELD,
//      withheld_cut_held 1, refused 0.                   (base: no counter)
//   E6 (F3-K7) the DROPS range is carried: the next decided block's harvest
//      range reaches back over the EMPTY-CUT block and harvests its raindrops.
//   E7 (F3-K9) money independent of the cut: credit, payout, balances and the
//      lane height equal a decided-valid booking at the same anchor; only V37A
//      (the anchor) differs. (The RESERVED branch, driven directly.)
//   E8 (review 2026-10-04, O2) a REAL restart: an XmrNode reopened on the same
//      store rebuilds, from its boot replay, every share state of each digest
//      within the span, each a frozen ledger at exactly its (digest, seq), the
//      live state last; published, each digest is held complete.
//                                         (ed4712059: nothing rebuilt)
// ---------------------------------------------------------------------------
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "c2pool/v37/v37_engine.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_drops_wiring.hpp"
#include "c2pool/v37/xmr/relay/xmr_share_verdict.hpp"
#if __has_include("c2pool/v37/xmr/xmr_cut_admission.hpp")
#include "c2pool/v37/xmr/xmr_cut_admission.hpp"
#endif

namespace o2 = c2pool::v37n::xmr::o2;
namespace st = c2pool::v37n::settle;
namespace rl = c2pool::v37n::xmr::relay;
namespace dx = c2pool::v37n::xmr::drops;
using Amounts = std::map<::v37::bytes32, long long>;

namespace {

int g_fail = 0, g_checks = 0;
void check(const std::string& name, bool ok, const std::string& detail = {}) {
    ++g_checks; if (!ok) ++g_fail;
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.empty() ? "" : "  -- ", detail.c_str());
    std::fflush(stdout);
}
std::string hx6(const ::v37::bytes32& d) { static const char* x = "0123456789abcdef"; std::string s; for (int i = 0; i < 6; ++i) { s += x[d[i] >> 4]; s += x[d[i] & 15]; } return s; }

constexpr std::uint32_t kChain = 7;
constexpr std::uint64_t kDconf = 3, kRetryBound = 30;
constexpr std::uint64_t kHB = 5, kHC = 7;   // B (the finder's block), C (the next honest block)
constexpr long long kR = 600000000000ll;

::v37::ScriptRef ref_of(std::uint8_t k) {
    ::v37::ScriptRef r; r.kind = ::v37::ScriptKind::P2WPKH; r.payload.assign(20, k); return r;
}
// a lane order on a real engine: the digest + view at P
struct Order {
    c2pool::v37n::V37Engine eng{4096};
    Order() { eng.start(); eng.submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get(); }
    ~Order() { eng.stop(); }
    void push(const ::v37::ScriptRef& p) { ::v37::PayoutDescriptor d; d.pay = p; eng.submit_tracked(::v37::LaneRecord::push(kChain, d, 65535, 0)).get(); }
    std::uint64_t P() { auto s = eng.snapshot(kChain); return s ? s->next_pos : 0; }
    ::v37::bytes32 spine() { auto s = eng.snapshot(kChain); return s ? s->digest : ::v37::bytes32{}; }
    std::shared_ptr<const c2pool::v37n::SettlementView> view(std::uint64_t P, const ::v37::bytes32& sp) {
        bool m = false; return eng.settlement_view_by_cut(kChain, P, sp, &m);
    }
};
// pay-now credit of the payee `pay` at an anchor view: split_reward(R, project(view))
long long paid_at(Order& o, std::uint64_t P, const ::v37::bytes32& sp, const ::v37::ScriptRef& pay) {
    auto v = o.view(P, sp);
    if (!v) return -1;
    const auto ps = st::project(*v);
    const auto amt = st::split_reward(static_cast<std::uint64_t>(kR), ps);
    long long s = 0;
    for (std::size_t i = 0; i < ps.size(); ++i) if (ps[i].pay == pay) s += static_cast<long long>(amt[i]);
    return s;
}
::v37::bytes32 key_of(std::uint8_t k) { ::v37::bytes32 b{}; b[0] = 0xE7; b[1] = k; return b; }   // ledger keys (E7)

// The served order of B's cut as one node sees it. `t_status`: the refused
// receipt t, judged by the committed receipt test on the node's history.
struct Served {
    bool available = true;         // false: no connected peer serves the order (withheld)
    int  t_verdict = -1;           // committed_root_test of t on this node
    std::uint64_t ready_at = 1;    // the attempt the order (and its receipts) arrive at
};

// One node: XmrNode + FinalizeConnect, the booking callback for B and C.
struct Outcome {
    std::uint64_t attempts_b = 0, booked_b = 0, refused = 0, held_max = 0, held_end = 0, withheld = 0, cursor = 0;
    bool anchored = false; st::AnchorCut anchor{}; ::v37::bytes32 digest{};
    bool b_cut_none = false;
    bool anchored_after_b = false; st::AnchorCut anchor_after_b{};   // the anchor in force after FINALIZE(B), before FINALIZE(C)
};
Outcome run_node(const std::filesystem::path& tmp, const std::string& name, const Served& sv,
                 const st::AnchorCut& cutB, const st::AnchorCut& cutC, std::uint64_t ticks) {
    using namespace c2pool::v37n::xmr;
    Outcome out;
    XmrNodeConfig c; c.network = MoneroNetwork::Stagenet; c.lane_chain = kChain; c.d_conf = kDconf;
    c.ledger_anchor_cut = true;
#if defined(C2POOL_XMR_EMPTY_CUT)
    c.ledger_empty_cut = true;
#endif
    c.settle_db_path = (tmp / ("store-" + name)).string();
    std::filesystem::create_directories(c.settle_db_path);
    o2::FinalizeConnectOptions o;
    o.out = nullptr; o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
    o.retry_bound = kRetryBound; o.held_retry_every = 1;
    c2pool::xmr::node::MockMonerodTransport mock;
    XmrNode node(c, mock, &smoke::test_point_check);
    try { node.bring_up(); } catch (const std::exception& e) { check("bring_up " + name, false, e.what()); return out; }
    const ::v37::bytes32 pay = smoke::key_of(0xC3);
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string&, o2::FinalizeConnectOptions::ChainBooking& bk) {
        if (h != kHB && h != kHC) { bk.why = "not-lane: test"; return false; }
        bk.payout.clear(); bk.payout[pay] = kR; bk.payout_decoded = true; bk.total_pico = static_cast<std::uint64_t>(kR);
        bk.credit.clear(); bk.credit[pay] = kR;   // the money: decided at the anchor (the same for B and C)
        if (h == kHC) { bk.cut = cutC; return true; }
        ++out.attempts_b;
        if (!sv.available) { bk.why = "cut-pending: relay repair of P=6 spine=x (withheld: no connected peer serves that order yet; retry)"; return false; }
        if (out.attempts_b < sv.ready_at) { bk.why = "cut-pending: relay repair of P=6 spine=x in flight (fetching the winner-side order + missing receipts)"; return false; }
#if defined(C2POOL_XMR_EMPTY_CUT)
        namespace cutadm = c2pool::v37n::xmr::cutadm;
        cutadm::OrderInput in;
        for (int i = 0; i < 5; ++i) in.receipts.push_back(cutadm::Served::Admitted);
        in.receipts.push_back(sv.t_verdict < 0 ? cutadm::Served::Refused : sv.t_verdict == 1 ? cutadm::Served::Admitted : cutadm::Served::Missing);
        in.spine_reproduced = true; in.every_peer_tried = true;
        std::string w;
        const auto ov = cutadm::classify_served_order(in, &w);
        const std::string why = ov == cutadm::OrderVerdict::Bad ? std::string(cutadm::kCutBadPrefix) + " " + w
                              : ov == cutadm::OrderVerdict::Valid ? std::string() : "cut-pending: " + w;
        const auto own = cutadm::classify_own_cut(true, node.ledger().rules().empty_cut, ov == cutadm::OrderVerdict::Valid, why);
        if (own == cutadm::OwnCut::Pending) { bk.why = why.rfind("cut-pending:", 0) == 0 ? why : "cut-pending: " + why; return false; }
        ::c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = cutB.next_pos; cc.spine_digest = cutB.spine;
        bk.cut = cutadm::booking_cut(own, true, cc);
        out.b_cut_none = !bk.cut;
        ++out.booked_b;
        return true;
#else
        // the base: a refused receipt is forgotten, the repair never completes
        // ("a repaired receipt left the verified cache"); an undecided one (0)
        // is trusted past its patience and the cut is anchored with it
        if (sv.t_verdict < 0) { bk.why = "cut-pending: a repaired receipt left the verified cache (retry)"; return false; }
        bk.cut = cutB; ++out.booked_b;
        return true;
#endif
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, c, q, o);
    for (std::uint64_t h = 1; h <= 4; ++h) smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    (void)fc.tick();
    // rows to kHB + kDconf first: FINALIZE(B) runs, FINALIZE(C) cannot yet (the anchor in force between them)
    for (std::uint64_t h = 5; h <= kHB + kDconf; ++h) smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    for (std::uint64_t i = 0; i < ticks; ++i) { (void)fc.tick(); out.held_max = std::max<std::uint64_t>(out.held_max, fc.stats().held_now); }
    if (const auto a = node.ledger().anchor_cut()) { out.anchored_after_b = true; out.anchor_after_b = *a; }
    for (std::uint64_t h = kHB + kDconf + 1; h <= 14; ++h) smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    for (std::uint64_t i = 0; i < 40; ++i) { (void)fc.tick(); out.held_max = std::max<std::uint64_t>(out.held_max, fc.stats().held_now); }
    out.refused = fc.stats().refused; out.held_end = fc.stats().held_now;
#if defined(C2POOL_XMR_EMPTY_CUT)
    out.withheld = fc.stats().withheld_cut_held;
#endif
    out.cursor = node.finalize_driver().cursor_height();
    if (const auto a = node.ledger().anchor_cut()) { out.anchored = true; out.anchor = *a; }
    out.digest = node.ledger().owed_digest();
    (void)fc.drain_before_stop();
    return out;
}

void run(const std::filesystem::path& tmp) {
    // the lanes: every honest node holds r1..r5 then r6; the finder X's order holds r1..r5 then t
    std::vector<::v37::ScriptRef> r; for (std::uint8_t k = 1; k <= 6; ++k) r.push_back(ref_of(static_cast<std::uint8_t>(0x10 + k)));
    const ::v37::ScriptRef T = ref_of(0x66);   // the key the refused receipt t pays
    Order honest, finder;
    for (int i = 0; i < 5; ++i) { honest.push(r[i]); finder.push(r[i]); }
    finder.push(T);
    honest.push(r[5]);
    st::AnchorCut cutB; cutB.next_pos = finder.P(); cutB.spine = finder.spine();
    st::AnchorCut cutC; cutC.next_pos = honest.P(); cutC.spine = honest.spine();
    check("lanes: B's cut (6, finder spine) and C's cut (6, honest spine) differ only in t vs r6",
          cutB.next_pos == 6 && cutC.next_pos == 6 && !(cutB.spine == cutC.spine));

    // t's verdict: on the fix every node decides it by the committed receipt test
    // on its (boot-seeded) history; on the base a synced node holding t's state
    // refuses it (-1) and a node restarted since (the state not held) answers 0
    int t_verdict = -1, t_verdict_restarted = 0;
#if defined(C2POOL_XMR_RECEIPT_ADMISSION)
    {
        rl::CommittedHistory h; h.d_conf = 60; h.max_root_age = 240; h.warm = true; h.cursor = 3000;
        rl::CommittedHistory::Entry e; e.digest[0] = 1; e.root[0] = 2; e.since = 100; h.entries.push_back(e);
        ::v37::bytes32 troot{}; troot[0] = 0x77;   // t's 0x03 root: no state of the history
        std::string w;
        t_verdict = rl::committed_root_test(h, troot, 2000, &w);
        t_verdict_restarted = t_verdict;   // the history is boot-seeded: the restart changes nothing
        check("t's root under the committed test: decided not admissible (-1) once the cursor passed its builder cut", t_verdict == -1, w);
    }
#else
    check("no committed receipt test on the base: t's unheld root is 0 (undecided, then trusted)", false);
#endif

    // ── E1 / E2 / E4 : three nodes ─────────────────────────────────────────
    Served s1; s1.t_verdict = t_verdict; s1.ready_at = 5;
    Served s2; s2.t_verdict = t_verdict; s2.ready_at = kRetryBound + 500;   // 500 ticks past the bound
    Served s3; s3.t_verdict = t_verdict_restarted; s3.ready_at = 1;         // the restarted node
    const auto n1 = run_node(tmp, "n1", s1, cutB, cutC, 80);
    const auto n2 = run_node(tmp, "n2", s2, cutB, cutC, 620);
    const auto n3 = run_node(tmp, "n3", s3, cutB, cutC, 80);
    std::printf("  n1: booked_b=%llu attempts=%llu cut_none=%d anchored=%d P=%llu digest=%s cursor=%llu\n",
                (unsigned long long)n1.booked_b, (unsigned long long)n1.attempts_b, (int)n1.b_cut_none, (int)n1.anchored,
                (unsigned long long)n1.anchor.next_pos, hx6(n1.digest).c_str(), (unsigned long long)n1.cursor);
    std::printf("  n2: booked_b=%llu attempts=%llu held_max=%llu | n3: booked_b=%llu\n", (unsigned long long)n2.booked_b,
                (unsigned long long)n2.attempts_b, (unsigned long long)n2.held_max, (unsigned long long)n3.booked_b);
    check("E1 B (its served order carries the refused t) is HELD on all three nodes: never booked, none refused",
          n1.booked_b == 0 && n2.booked_b == 0 && n3.booked_b == 0 && n1.held_end == 1 && n2.held_end == 1 && n3.held_end == 1 &&
          n1.refused == 0 && n2.refused == 0 && n3.refused == 0,
          "booked " + std::to_string(n1.booked_b) + "/" + std::to_string(n2.booked_b) + "/" + std::to_string(n3.booked_b) +
          " held " + std::to_string(n1.held_end) + "/" + std::to_string(n2.held_end) + "/" + std::to_string(n3.held_end));
    check("E1 no node anchors B's cut (the cut with t)",
          !(n1.anchored && n1.anchor.spine == cutB.spine) && !(n2.anchored && n2.anchor.spine == cutB.spine) &&
          !(n3.anchored && n3.anchor.spine == cutB.spine));
    {
        long long sum_r = 0; bool all_paid = true;
        for (int i = 0; i < 6; ++i) { const long long p = paid_at(honest, cutC.next_pos, cutC.spine, r[static_cast<std::size_t>(i)]); sum_r += p; all_paid = all_paid && p > 0; }
        const long long pt = paid_at(honest, cutC.next_pos, cutC.spine, T);
        check("E1 (REVIEW K5) the anchor view credits r1..r6 (each > 0) and pays t's key 0", all_paid && pt == 0,
              "r1..r6 " + std::to_string(sum_r) + ", t " + std::to_string(pt));
        const long long pt_b = paid_at(finder, cutB.next_pos, cutB.spine, T);
        check("E1 (control) had B's cut been anchored, t's key would be paid " + std::to_string(pt_b), pt_b > 0);
    }
    check("E4 one outcome on all three (arrival tick and restart do not matter): B HELD alike, one owed_digest, one cursor",
          n1.digest == n2.digest && n2.digest == n3.digest && n1.anchored == n2.anchored && n2.anchored == n3.anchored &&
          n1.cursor == n2.cursor && n2.cursor == n3.cursor,
          hx6(n1.digest) + " / " + hx6(n2.digest) + " / " + hx6(n3.digest));
    // E2: the anchor in force right after FINALIZE(B), then three more honest anchors: t's key paid 0 at each
    {
        long long t_total = 0;
        for (const auto* n : {&n1, &n2, &n3}) {
            if (!n->anchored_after_b) continue;   // no anchor: the view credits nobody
            Order& o = (n->anchor_after_b.spine == cutB.spine) ? finder : honest;
            t_total += paid_at(o, n->anchor_after_b.next_pos, n->anchor_after_b.spine, T);
        }
        for (int k = 0; k < 3; ++k) {
            honest.push(r[static_cast<std::size_t>(k)]);
            t_total += paid_at(honest, honest.P(), honest.spine(), T);
        }
        check("E2 (F3-K2) the anchor in force after FINALIZE(B) and three honest anchors after it credit t's key exactly 0 piconero (the finder <= solo)", t_total == 0,
              std::to_string(t_total));
    }

    // ── E3 (F3-K3): the decided-bad cut releases the gate within one held retry ─
    {
        Served sv; sv.t_verdict = t_verdict; sv.ready_at = kRetryBound + 10;
        const auto n = run_node(tmp, "k3", sv, cutB, cutC, 80);
        check("E3 past the bound B is HELD (held_now 1) and never booked: a served order with a refused receipt decides nothing",
              n.held_max == 1 && n.held_end == 1 && n.booked_b == 0 && n.refused == 0,
              "held_max " + std::to_string(n.held_max) + " held_end " + std::to_string(n.held_end) + " booked " + std::to_string(n.booked_b));
    }
    // ── E5 (F3-K6): withheld stays held, loudly ────────────────────────────
    {
        Served sv; sv.available = false; sv.t_verdict = t_verdict;
        const auto n = run_node(tmp, "k6", sv, cutB, cutC, 80);
        check("E5 (F3-K6) an order no peer serves: HELD (held_now 1), withheld_cut_held 1, refused 0, no booking",
              n.held_end == 1 && n.withheld == 1 && n.refused == 0 && n.booked_b == 0,
              "held " + std::to_string(n.held_end) + " withheld " + std::to_string(n.withheld));
    }

    // ── E6 (F3-K7): the DROPS harvest range is carried over an EMPTY-CUT block ─
    {
#if defined(C2POOL_XMR_DROPS_EMPTY_CUT_SKIP)
        using COH = dx::ChainOrderedHarvest;
        COH h(1, 0, kDconf);
        // lane blocks at 10 (composed), 20 (EMPTY-CUT), 30 (the next decided block)
        const std::set<std::uint64_t> lane = {10, 20, 30};
        const std::set<std::string> empty_cut = {"blk-20"};
        std::map<std::string, bool> memo;
        auto row = [](std::uint64_t x) -> std::optional<std::string> { return "blk-" + std::to_string(x); };
        auto probe = [&](const std::string& b) {
            const std::uint64_t x = std::stoull(b.substr(4));
            return COH::probe_of(true, lane.count(x) != 0, false, empty_cut.count(b) != 0);
        };
        const auto pl = COH::walk_prev_lane(30, 64, row, probe, memo);
        const auto rg = h.range_with(30, pl);
        ::v37::bytes32 who{}; who[0] = 0x42;
        for (std::uint64_t iv = 7; iv < 27; ++iv) { ::v37::bytes32 nh{}; nh[0] = static_cast<std::uint8_t>(iv); h.observe_drop(who, iv, nh); }
        std::size_t in_b = 0;
        if (rg) for (std::uint64_t iv = 7; iv < 17; ++iv) if (iv >= rg->first && iv < rg->second) ++in_b;
        check("E6 (F3-K7) prev_lane(30) skips the EMPTY-CUT block 20 -> 10; C's range [7, 27) covers B's [7, 17): its 10 raindrop bins harvested",
              pl && *pl == 10 && rg && rg->first == 7 && rg->second == 27 && in_b == 10,
              pl ? "prev_lane " + std::to_string(*pl) : std::string("undecidable"));
        std::map<std::string, bool> memo2;
        auto probe_plain = [&](const std::string& b) { const std::uint64_t x = std::stoull(b.substr(4)); return COH::probe_of(true, lane.count(x) != 0, false); };
        const auto pl2 = COH::walk_prev_lane(30, 64, row, probe_plain, memo2);
        check("E6 (control) without the skip prev_lane(30) = 20 and B's raindrops [7, 17) are in no range", pl2 && *pl2 == 20);
#else
        check("E6 (F3-K7) no EMPTY-CUT skip in the DROPS prev_lane walk on the base", false);
#endif
    }

    // ── E7 (F3-K9): money independent of the cut ───────────────────────────
    {
#if defined(C2POOL_XMR_EMPTY_CUT)
        namespace cutadm = c2pool::v37n::xmr::cutadm;
        st::OwedLedgerRules R; R.anchor_cut = true; R.empty_cut = true; R.lane_height = true; R.decay_from_gross = true;
        st::OwedLedger Lv(kChain, R), Le(kChain, R);
        const ::v37::bytes32 a = key_of(1), b = key_of(2);
        for (auto* L : {&Lv, &Le}) {
            L->on_block_found("seed", Amounts{{a, 5000000000ll}, {b, 7000000000ll}}, {});
            L->on_block_finalized("seed", 3);
        }
        ::c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = cutB.next_pos; cc.spine_digest = cutB.spine;
        const auto cv = cutadm::booking_cut(cutadm::OwnCut::Valid, true, cc), ce = cutadm::booking_cut(cutadm::OwnCut::EmptyCut, true, cc);
        st::LaneFound lf; lf.height = kHB; lf.gross = {a, b};
        const Amounts credit{{a, 100000000000ll}, {b, 200000000000ll}}, payout{{a, 90000000000ll}, {b, 190000000000ll}};
        Lv.on_block_found("B", credit, payout, cv, nullptr, &lf);
        Le.on_block_found("B", credit, payout, ce, nullptr, &lf);
        Lv.on_block_finalized("B", kHB + kDconf); Le.on_block_finalized("B", kHB + kDconf);
        const auto ov = Lv.effective_owed_all(), oe = Le.effective_owed_all();
        check("E7 (F3-K9) credit, payout and every balance equal a decided-valid booking at the same anchor; the lane height too",
              ov == oe && Lv.prev_lane_height() == Le.prev_lane_height() && Lv.prev_lane_height() == kHB);
        check("E7 only the anchor (V37A) differs: valid -> B's cut, EMPTY-CUT -> none (the anchor stays)",
              Lv.anchor_cut() && Lv.anchor_cut()->spine == cutB.spine && !Le.anchor_cut() && Lv.owed_digest() != Le.owed_digest());
#else
        check("E7 (F3-K9) no EMPTY-CUT booking on the base (a decided-bad cut never books)", false);
#endif
    }

    // ── E8 (review O2): a REAL restart rebuilds the share states ──────────
    {
        Served sv; sv.t_verdict = 1; sv.ready_at = 1;   // B and C book: FOUND / FINALIZE events in the store
        const auto live = run_node(tmp, "k8", sv, cutB, cutC, 80);
        check("E8 the first run books B and C (the store holds their events)", live.booked_b == 1 && live.cursor >= kHC);
        using namespace c2pool::v37n::xmr;
        XmrNodeConfig c; c.network = MoneroNetwork::Stagenet; c.lane_chain = kChain; c.d_conf = kDconf;
        c.ledger_anchor_cut = true;
#if defined(C2POOL_XMR_EMPTY_CUT)
        c.ledger_empty_cut = true;
#endif
        c.settle_db_path = (tmp / "store-k8").string();
        c2pool::xmr::node::MockMonerodTransport mock;
        XmrNode node(c, mock, &smoke::test_point_check);
#if defined(C2POOL_XMR_BOOT_SHARE_STATES)
        node.set_boot_share_span(1000);
#endif
        try { node.bring_up(); } catch (const std::exception& e) { check("E8 restart bring_up", false, e.what()); return; }
        check("E8 the restarted node replays to the same owed_digest", node.ledger().owed_digest() == live.digest);
        auto store = std::make_shared<rl::ShareStateStore>();
        std::size_t n_states = 0, digests = 0, exact = 0;
        ::v37::bytes32 last{}; std::uint64_t last_seq = 0;
#if defined(C2POOL_XMR_BOOT_SHARE_STATES)
        {
            std::vector<std::shared_ptr<rl::ShareStateEntry>> es;
            std::set<::v37::bytes32> ds;
            for (const auto& b : node.boot_share_states()) {
                auto e = std::make_shared<rl::ShareStateEntry>();
                e->digest = b.digest; e->ledger_seq = b.ledger_seq; e->since = b.since; e->ledger = b.ledger;
                if (b.ledger && b.ledger->owed_digest() == b.digest && b.ledger->ledger_seq() == b.ledger_seq) ++exact;
                ds.insert(b.digest);
                es.push_back(e);
                last = b.digest; last_seq = b.ledger_seq;
            }
            n_states = es.size(); digests = ds.size();
            rl::put_boot_states(*store, es, node.finalize_driver().cursor_height(), 0);
        }
#else
        {   // ed4712059: the restarted node publishes its live state only, from_birth = (seq == 0)
            auto e = std::make_shared<rl::ShareStateEntry>();
            e->digest = node.ledger().owed_digest(); e->ledger_seq = node.ledger().ledger_seq();
            e->from_birth = e->ledger_seq == 0;
            store->put(e);
        }
#endif
        std::printf("  E8: %zu state(s) rebuilt over %zu digest(s), %zu exact; last seq %llu (live seq %llu)\n", n_states, digests, exact,
                    (unsigned long long)last_seq, (unsigned long long)node.ledger().ledger_seq());
        check("E8 every share state of the boot replay rebuilt: >= 2 digests, each copy at exactly its (digest, seq), the live state last",
              n_states >= 2 && digests >= 2 && exact == n_states && last == node.ledger().owed_digest() && last_seq == node.ledger().ledger_seq());
        bool all_complete = digests >= 2;
#if defined(C2POOL_XMR_BOOT_SHARE_STATES)
        for (const auto& b : node.boot_share_states()) all_complete = all_complete && store->complete(b.digest);
#else
        all_complete = false;
#endif
        check("E8 published, every rebuilt digest (the live one and those before the restart) is held complete", all_complete);
#if defined(C2POOL_XMR_BOOT_SHARE_STATES)
        node.clear_boot_share_states();
#endif
    }
}

}  // namespace

int main() {
    std::printf("== v37_xmr_empty_cut_kat (R1 receipt admission, F3: EMPTY-CUT) ==\n");
    const std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-ecut-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    run(tmp);
    std::filesystem::remove_all(tmp);
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
