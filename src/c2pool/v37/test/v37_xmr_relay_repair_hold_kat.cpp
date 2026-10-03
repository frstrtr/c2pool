// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_relay_repair_hold_kat.cpp   (RC-HOLD)
//
// A local timeout must never decide booking. Under same-height races a node's
// GAP-2 relay repair of the winner's cut ("cut-pending: relay repair of P=..
// N/M receipts missing (N in verify)") could outlast the booking retry bound;
// relay_repair_stall_timeout then REFUSED that CANONICAL lane block. Each racing
// node refused a different set of heights, so the finalized subsets and
// owed_digest diverged for good (race20 fix-2/fix-3: lane_root_refused cascade,
// split in all pairs). RC-HOLD: an undecided relay repair past the bound is
// HELD (keeps the R4 gate, keeps repairing, loud counter); only a DECIDED
// mismatch is refused.
//
//   H1  a relay repair still in flight past the retry bound is HELD: not
//       refused, no liability, the R4 gate holds the cursor.        (red pre-fix)
//   H2  when the repair completes the held block books, settles, and the
//       cursor walks to the frontier.                               (red pre-fix)
//   H3  two nodes, same chain: X's repair completes at attempt 3, Y's only at
//       attempt 40 (> bound 30). Both book the block; finalized sets and
//       owed_digest are byte-identical.                             (red pre-fix)
//   H4  the rest of the relay-repair family at the bound ("a repaired receipt
//       left the verified cache", "the repaired order did not reproduce the
//       winner's spine" -- a serving PEER set aside) is HELD too.   (red pre-fix)
//   D1  DECIDED mismatch on the first attempt (receipts all present + verified,
//       the reconstructed lane digest differs: "credit-cut MISMATCH ...") is
//       REFUSED at once: gate released, liability recorded.         (as pre-fix)
//   D2  a relay repair HELD past the bound that then completes into a DECIDED
//       mismatch is REFUSED (not held forever): gate released, the cursor walks,
//       nothing held.                                                (as pre-fix)
//   D3  a HELD relay repair whose block then decodes lane-root-refused (synced,
//       root matches nothing) is refused-not-credited, hold cleared. (as pre-fix)
//   N1  (inverted by HOLD-ROUND-2 A) a NON-relay cut-pending past the bound
//       is HELD too; the pre-fix release (booking_stall_timeout, refused) was
//       the attempt-7 split.                                         (red pre-fix)
//   K1  ★ DROPS-RETAIN (L3): "drops set of h=.. has N/M pinned raindrop(s)
//       not held" past the bound is HELD (stall=0 refused=0), books when the
//       members arrive; two nodes completing the set at attempts 3 and 45
//       (bound 30) book the same block, identical owed_digest. (red pre-fix)
//   K1b the same for "drops set of h=.. not carried yet" (FB_GETWON and the
//       scratch-lineage variant).                                   (red pre-fix)
//   A1  ★ HOLD-ROUND-2 (A): the attempt-7 reason "drops lane prefix of P=..:
//       the served order is the SUFFIX .." past the bound is HELD
//       (booking_stall_alarm=1, refused=0), books when the data arrives; two
//       nodes resolving at attempts 3 and 45 hold identical owed_digest. (red)
//   A2  table: every cut-pending reason of DESIGN §2.1 (and the fetch / root-
//       unknown holds) HELD past the bound; every DECIDED reason (§2.2) refused
//       on attempt 1.                                     (red pre-fix: 15 rows)
//   A3  the liveness cost, pinned: a HELD block at h passes main's booking-point
//       gate for T=h only, never above; released on booking. (red pre-fix:
//       the block is refused at the bound and the gate released)
//
// Network-free, RandomX-free (monerod STUB + the injected test point-check
// backend, the v37_xmr_cba_native_booking_kat shape). Nonzero exit on failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_recon_ring.hpp"

namespace o2 = c2pool::v37n::xmr::o2;

namespace {

int g_fail = 0;
void check(const char* name, bool ok, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    if (!ok) ++g_fail;
}

constexpr long long kReward = 600000000000ll;
const std::string kRepairWhy =
    "cut-pending: relay repair of P=173 spine=0123456789ab in flight (fetching the winner-side order + missing receipts) "
    "[fetching: 3/40 receipts missing (3 in verify, 0 to re-ask; order from peer 2, refetches=0, last progress 4s ago)]";
const std::string kRepairExhaustedWhy =
    "cut-pending: relay repair of P=173 spine=0123456789ab (no connected peer serves that order yet; retry) "
    "[idle: every ready peer tried (2), none serves an order reaching this spine]";
const std::string kReceiptLeftWhy = "cut-pending: a repaired receipt left the verified cache (retry)";
const std::string kOrderRejectedWhy =
    "cut-pending: the repaired order did not reproduce the winner's spine at P=173 (serving peer set aside; asking another)";
const std::string kDecidedMismatchWhy =
    "credit-cut MISMATCH after replay: prefix P=173 reconstructs a DIFFERENT lane digest (fail-closed: a real fork, not an eviction)";

// A lane block at height 5 whose booking outcome is scripted per attempt.
using Script = std::function<std::string(std::uint64_t attempt)>;   // "" = book OK, else the failure reason

struct Rig {
    c2pool::v37n::xmr::XmrNodeConfig c;
    o2::FinalizeConnectOptions o;
    c2pool::xmr::node::MockMonerodTransport mock;
    std::unique_ptr<c2pool::v37n::xmr::XmrNode> node;
    o2::FoundBlockQueue q;
    std::unique_ptr<o2::FinalizeConnect> fc;
    std::uint64_t attempts = 0, booked = 0;
    std::string bid5;
    ::v37::bytes32 payee = c2pool::v37n::xmr::smoke::key_of(0xC3);
    bool ok = false;

    Rig(const std::filesystem::path& tmp, const std::string& name, Script script) {
        using namespace c2pool::v37n::xmr;
        c.network = MoneroNetwork::Stagenet;
        c.lane_chain = 7;
        c.d_conf = 3;
        c.settle_db_path = (tmp / ("store-" + name)).string();
        std::filesystem::create_directories(c.settle_db_path);
        o.out = nullptr;
        o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
        o.retry_bound = 30; o.held_retry_every = 5;
        node = std::make_unique<XmrNode>(c, mock, &smoke::test_point_check);
        try { node->bring_up(); } catch (const std::exception& e) { check("bring_up", false, e.what()); return; }
        bid5 = hex_of(smoke::blk_id(5));
        o.book_from_chain_ex = [this, script](std::uint64_t h, const std::string&, o2::FinalizeConnectOptions::ChainBooking& bk) {
            if (h != 5) { bk.why = "not-lane: test"; return false; }
            const std::string why = script(++attempts);
            bk.payout.clear(); bk.payout[payee] = kReward; bk.payout_decoded = true; bk.total_pico = kReward;
            if (!why.empty()) { bk.why = why; return false; }
            // booked: the cut's credit to the payee; the coinbase pays no owed balance
            // (payout {}), so a booked-vs-refused difference shows in owed_digest
            bk.credit.clear(); bk.credit[payee] = kReward; bk.payout.clear();
            ++booked;
            return true;
        };
        fc = std::make_unique<o2::FinalizeConnect>(*node, c, q, o);
        ok = true;
    }
    void chain(std::uint64_t from, std::uint64_t to) {
        using namespace c2pool::v37n::xmr;
        for (std::uint64_t h = from; h <= to; ++h)
            smoke::apply_row(*node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    }
    void ticks(int n) { for (int i = 0; i < n; ++i) (void)fc->tick(); }
    std::uint64_t cursor() const { return node->finalize_driver().cursor_height(); }
    const o2::FinalizeConnect::Stats& st() const { return fc->stats(); }
    std::string brief() const {
        return "attempts=" + std::to_string(attempts) + " refused=" + std::to_string(st().refused) +
               " held_now=" + std::to_string(st().held_now) + " stall=" + std::to_string(st().booking_stall_timeout) +
               " relay_stall=" + std::to_string(st().relay_repair_stall_timeout) +
               " liability=" + std::to_string(st().liability_blocks) + " cursor=" + std::to_string(cursor());
    }
};

// ── H1/H2: one node, the repair completes only at attempt 60 (bound 30) ──
void hold_then_book(const std::filesystem::path& tmp) {
    std::printf("-- H1/H2: an undecided relay repair past the bound is HELD, then books --\n");
    bool repaired = false;
    Rig r(tmp, "h1", [&](std::uint64_t n) { return repaired ? std::string() : (n % 2 ? kRepairWhy : kRepairExhaustedWhy); });
    if (!r.ok) return;
    r.chain(1, 4); r.ticks(1);
    r.chain(5, 10);
    r.ticks(60);   // 60 ticks: well past retry_bound 30
    check("H1 relay repair in flight past the retry bound is HELD: refused=0, no liability, held_now=1, R4 gate holds cursor at 1",
          r.attempts > 30 && r.st().refused == 0 && r.st().liability_blocks == 0 && r.st().booking_stall_timeout == 0 &&
          r.st().held_now == 1 && r.fc->held().count(r.bid5) && r.cursor() == 1 && !r.node->ledger().is_settled(r.bid5),
          r.brief());
    repaired = true;
    r.ticks(12);
    check("H2 the repair completes -> the held block books, settles, hold resolved, cursor walks to the frontier (7)",
          r.booked == 1 && r.st().refused == 0 && r.st().held_now == 0 && r.st().held_resolved == 1 &&
          r.node->ledger().is_settled(r.bid5) && r.cursor() == 7,
          r.brief());
    (void)r.fc->drain_before_stop();
}

// ── H3: two nodes whose repairs complete at different attempts ──
void two_nodes_converge(const std::filesystem::path& tmp) {
    std::printf("-- H3: two racing nodes, fast vs slow repair: identical finalized set + owed_digest --\n");
    Rig x(tmp, "h3x", [](std::uint64_t n) { return n >= 3 ? std::string() : kRepairWhy; });
    Rig y(tmp, "h3y", [](std::uint64_t n) { return n >= 40 ? std::string() : kRepairWhy; });
    if (!x.ok || !y.ok) return;
    for (Rig* r : {&x, &y}) { r->chain(1, 4); r->ticks(1); r->chain(5, 10); }
    for (int i = 0; i < 120; ++i) { x.ticks(1); y.ticks(1); }
    const bool same_digest = x.node->ledger().owed_digest() == y.node->ledger().owed_digest();
    check("H3 both nodes book + settle h=5 (X at attempt 3, Y at attempt >= 40 > bound): same cursor, byte-identical owed_digest, 0 refused",
          x.node->ledger().is_settled(x.bid5) && y.node->ledger().is_settled(y.bid5) && x.cursor() == 7 && y.cursor() == 7 &&
          same_digest && x.st().refused == 0 && y.st().refused == 0,
          "X{" + x.brief() + "} Y{" + y.brief() + "} digest_equal=" + (same_digest ? "yes" : "NO"));
    (void)x.fc->drain_before_stop(); (void)y.fc->drain_before_stop();
}

// ── H4: the rest of the relay-repair family ──
void repair_family(const std::filesystem::path& tmp) {
    std::printf("-- H4: every relay-repair cut-pending reason is undecided --\n");
    const std::vector<std::pair<const char*, std::string>> whys = {{"receipt-left-cache", kReceiptLeftWhy},
                                                                   {"order-rejected", kOrderRejectedWhy}};
    for (const auto& [tag, why] : whys) {
        Rig r(tmp, std::string("h4-") + tag, [w = why](std::uint64_t) { return w; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        const std::string name = std::string("H4 '") + tag + "' past the bound is HELD, not refused";
        check(name.c_str(), r.st().refused == 0 && r.st().liability_blocks == 0 && r.st().held_now == 1 && r.cursor() == 1, r.brief());
        (void)r.fc->drain_before_stop();
    }
}

// ── D1-D3 / N1: decided outcomes are still refused ──
void decided_refused(const std::filesystem::path& tmp) {
    std::printf("-- D1-D3/N1: a DECIDED mismatch is refused exactly as before --\n");
    {
        Rig r(tmp, "d1", [](std::uint64_t) { return kDecidedMismatchWhy; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(3);
        check("D1 decided mismatch (receipts present + verified, reconstructed digest differs) on attempt 1: REFUSED at once, "
              "1 attempt, liability recorded, gate released (cursor 7), nothing held",
              r.attempts == 1 && r.st().refused == 1 && r.st().liability_blocks == 1 && r.st().held_now == 0 &&
              r.booked == 0 && !r.node->ledger().is_settled(r.bid5) && r.cursor() == 7,
              r.brief());
        (void)r.fc->drain_before_stop();
    }
    {
        bool decided = false;
        Rig r(tmp, "d2", [&](std::uint64_t) { return decided ? kDecidedMismatchWhy : kRepairWhy; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        decided = true;   // the repair completes: every receipt verified, the reconstruction differs
        r.ticks(12);
        check("D2 a relay repair past the bound that then completes into a DECIDED mismatch is REFUSED (not held forever): "
              "refused=1, held_now=0, liability recorded, gate released (cursor 7)",
              r.st().refused == 1 && r.st().held_now == 0 && r.st().liability_blocks == 1 && r.booked == 0 &&
              !r.node->ledger().is_settled(r.bid5) && r.cursor() == 7,
              r.brief());
        (void)r.fc->drain_before_stop();
    }
    {
        bool decided = false;
        const std::string refused = "lane-root-refused:" + std::string(64, 'e') + ":no candidate digest (test)";
        Rig r(tmp, "d3", [&](std::uint64_t) { return decided ? refused : kRepairWhy; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        decided = true;
        r.ticks(12);
        check("D3 a held relay repair that then decodes lane-root-refused is refused-not-credited, hold cleared, gate released",
              r.st().refused_not_credited == 1 && r.st().held_now == 0 && r.booked == 0 && r.cursor() == 7,
              r.brief() + " rnc=" + std::to_string(r.st().refused_not_credited));
        (void)r.fc->drain_before_stop();
    }
    {
        // ★ HOLD-ROUND-2 (A): N1's assertion WAS the bug (a non-relay cut-pending
        // refused at the bound). Inverted: "our lane tip T < P" past the bound is
        // HELD like every other cut-pending reason; A1-A3 below are the full pins.
        Rig r(tmp, "n1", [](std::uint64_t) { return std::string("cut-pending: our lane tip 3 < P=9 (receiver behind the winner's cut; retry)"); });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        check("N1 (inverted by HOLD-ROUND-2 A) a non-relay cut-pending past the bound is HELD: stall_timeout=0, refused=0, held_now=1, cursor 1 "
              "(base: booking_stall_timeout=1 refused=1)",
              r.st().booking_stall_timeout == 0 && r.st().refused == 0 && r.st().liability_blocks == 0 &&
              r.st().held_now == 1 && r.cursor() == 1,
              r.brief());
        (void)r.fc->drain_before_stop();
    }
}

// ── K1/K1b (DROPS-RETAIN L3): the DROPS-SET-PIN holds are undecided too ──
// Stagenet attempt 6 (h=2220425): receivers missing 6 and 4 of the winner's
// 16384 pinned raindrops retried 600 times, then booking_stall_timeout REFUSED
// the block into node-local liability while the winner booked it -- an
// owed-ledger split at its FINALIZE. N1 above keeps its non-relay reason.
const std::string kPinnedNotHeldWhy =
    "cut-pending: drops set of h=5 has 3/10 pinned raindrop(s) not held (fetching by id)";
const std::string kSetNotCarriedWhy =
    "cut-pending: drops set of h=5 not carried yet (the winner's FB_BLOCK_WON v0x03; FB_GETWON asked of 0 peer(s))";
const std::string kSetNotCarriedScratchWhy = "cut-pending: drops set of h=5 not carried yet (scratch lineage)";

void drops_set_hold(const std::filesystem::path& tmp) {
    std::printf("-- K1/K1b: a pinned raindrop not held / a set not carried yet past the bound is HELD, then books --\n");
    const std::vector<std::pair<std::string, std::string>> whys = {{"K1 pinned-not-held", kPinnedNotHeldWhy},
                                                                   {"K1b set-not-carried", kSetNotCarriedWhy},
                                                                   {"K1b set-not-carried-scratch", kSetNotCarriedScratchWhy}};
    int k = 0;
    for (const auto& [tag, why] : whys) {
        bool arrived = false;
        Rig r(tmp, "k1-" + std::to_string(k++), [&arrived, w = why](std::uint64_t) { return arrived ? std::string() : w; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        const std::string held = tag + ": past the retry bound (60 attempts > 30) the block is HELD: stall=0 refused=0 "
                                 "liability=0 held=1 relay_repair_held=1, the R4 gate holds the cursor at 1 (base: stall=1 refused=1)";
        check(held.c_str(), r.attempts > 30 && r.st().booking_stall_timeout == 0 && r.st().refused == 0 &&
                            r.st().liability_blocks == 0 && r.st().held_now == 1 && r.st().relay_repair_held == 1 &&
                            r.fc->held().count(r.bid5) && r.cursor() == 1 && !r.node->ledger().is_settled(r.bid5),
              r.brief());
        arrived = true;   // the members (or the set) arrive: the composition completes
        r.ticks(12);
        const std::string booked = tag + ": on arrival the held block books + settles, the hold resolves, the cursor walks to 7";
        check(booked.c_str(), r.booked == 1 && r.st().refused == 0 && r.st().held_now == 0 &&
                              r.st().relay_repair_held_resolved == 1 && r.node->ledger().is_settled(r.bid5) && r.cursor() == 7,
              r.brief());
        (void)r.fc->drain_before_stop();
    }
    // the attempt-6 shape on two nodes: X completes the set at attempt 3, Y only at attempt 45 (> bound 30)
    Rig x(tmp, "k1-x", [](std::uint64_t n) { return n >= 3 ? std::string() : kPinnedNotHeldWhy; });
    Rig y(tmp, "k1-y", [](std::uint64_t n) { return n >= 45 ? std::string() : kPinnedNotHeldWhy; });
    if (!x.ok || !y.ok) return;
    for (Rig* r : {&x, &y}) { r->chain(1, 4); r->ticks(1); r->chain(5, 10); }
    for (int i = 0; i < 120; ++i) { x.ticks(1); y.ticks(1); }
    const bool same = x.node->ledger().owed_digest() == y.node->ledger().owed_digest();
    check("K1 two nodes, set completed at attempt 3 vs 45 (> bound): both book h=5, byte-identical owed_digest, 0 refused, 0 liability "
          "(base: Y refuses into liability -> owed_digest split)",
          x.node->ledger().is_settled(x.bid5) && y.node->ledger().is_settled(y.bid5) && same && x.st().refused == 0 &&
          y.st().refused == 0 && y.st().liability_blocks == 0 && x.cursor() == 7 && y.cursor() == 7,
          "X{" + x.brief() + "} Y{" + y.brief() + "} digest_equal=" + (same ? "yes" : "NO"));
    (void)x.fc->drain_before_stop(); (void)y.fc->drain_before_stop();
}

// ── HOLD-ROUND-2 (A): EVERY cut-pending reason is UNDECIDED -> HELD ──
// Stagenet attempt 7 (h=2220689, binary b261fb1a5): receivers A and C held B's
// block on "drops lane prefix of P=2356: the served order is the SUFFIX ..."; the
// reason was not in the relay-repair list, so at retry 601 both REFUSED it into
// node-local liability while B booked and finalized it: an owed_digest split.
const std::string kSuffixWhy =
    "cut-pending: drops lane prefix of P=2356: the served order is the SUFFIX [225,2356) and our [0,225) is not the "
    "order the spine verified (shadow base without a DROPS record, or the settlement replay is pending) -- HOLD, never "
    "composed from a suffix";

std::uint64_t stall_alarm_of(const Rig& r) {
#ifdef C2POOL_XMR_HOLD_ROUND2_UNDECIDED
    return r.st().booking_stall_alarm;
#else
    return 0;   // base: no alarm counter; the bound REFUSES (booking_stall_timeout)
#endif
}

void undecided_suffix_hold(const std::filesystem::path& tmp) {
    std::printf("-- A1: the attempt-7 SUFFIX reason past the bound is HELD, then books; two nodes converge --\n");
    bool arrived = false;
    Rig r(tmp, "a1", [&](std::uint64_t) { return arrived ? std::string() : kSuffixWhy; });
    if (!r.ok) return;
    r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
    check("A1 SUFFIX reason past the retry bound (60 attempts > 30): HELD, booking_stall_alarm=1, stall_timeout=0, refused=0, "
          "liability=0, R4 gate holds the cursor at 1 (base: refused=1 liability=1 -- the attempt-7 split)",
          r.attempts > 30 && r.st().held_now == 1 && stall_alarm_of(r) == 1 && r.st().booking_stall_timeout == 0 &&
          r.st().refused == 0 && r.st().liability_blocks == 0 && r.cursor() == 1 && !r.node->ledger().is_settled(r.bid5),
          r.brief() + " stall_alarm=" + std::to_string(stall_alarm_of(r)));
    arrived = true;   // the order / its base arrives: the prefix composes
    r.ticks(12);
    check("A1 the data arrives -> booked=1, held_resolved=1, settled, cursor 7",
          r.booked == 1 && r.st().refused == 0 && r.st().held_now == 0 && r.st().held_resolved == 1 &&
          r.node->ledger().is_settled(r.bid5) && r.cursor() == 7,
          r.brief());
    (void)r.fc->drain_before_stop();
    Rig x(tmp, "a1-x", [](std::uint64_t n) { return n >= 3 ? std::string() : kSuffixWhy; });
    Rig y(tmp, "a1-y", [](std::uint64_t n) { return n >= 45 ? std::string() : kSuffixWhy; });
    if (!x.ok || !y.ok) return;
    for (Rig* q : {&x, &y}) { q->chain(1, 4); q->ticks(1); q->chain(5, 10); }
    for (int i = 0; i < 120; ++i) { x.ticks(1); y.ticks(1); }
    const bool same = x.node->ledger().owed_digest() == y.node->ledger().owed_digest();
    check("A1 two nodes, the SUFFIX resolves at attempt 3 vs 45 (> bound): both book h=5, byte-identical owed_digest, 0 refused, "
          "0 liability (base: Y refuses into liability -> owed_digest split)",
          x.node->ledger().is_settled(x.bid5) && y.node->ledger().is_settled(y.bid5) && same && x.st().refused == 0 &&
          y.st().refused == 0 && y.st().liability_blocks == 0 && x.cursor() == 7 && y.cursor() == 7,
          "X{" + x.brief() + "} Y{" + y.brief() + "} digest_equal=" + (same ? "yes" : "NO"));
    (void)x.fc->drain_before_stop(); (void)y.fc->drain_before_stop();
}

// A2: the table of every reason a booking can stay undecided (DESIGN §2.1, the
// producers in main_v37_xmr.cpp) and every DECIDED reason (§2.2).
void undecided_table(const std::filesystem::path& tmp) {
    std::printf("-- A2: every cut-pending reason HELD past the bound; every DECIDED reason refused on attempt 1 --\n");
    const std::string sp = "cut-pending: ";
    const std::vector<std::pair<const char*, std::string>> undecided = {
        {"#1 replay log behind", sp + "replay log has 120 records < P=173 (receiver behind the winner's cut; retry)"},
        {"#2 replay no matching cut", sp + "replay reached P=173 but published no matching cut (retry)"},
        {"#3 relay repair in flight", kRepairWhy},
        {"#3b relay repair no peer", kRepairExhaustedWhy},
        {"#4 served but replay short", sp + "relay repair of P=173 served [40,173) but our replay log has only 30 pushes (retry)"},
        {"#5 served order repeats", sp + "the served order at P=173 repeats receipt 0123456789ab (serving peer set aside; asking another)"},
        {"#6 receipt left cache", kReceiptLeftWhy},
        {"#6b receipt left cache (prefix)", sp + "a repaired receipt left the verified cache (drops lane prefix; retry)"},
        {"#7 origin bin", sp + "the origin bin of a repaired receipt is not resolvable yet (retry)"},
        {"#7b origin bin (prefix)", sp + "the origin bin of a repaired receipt is not resolvable yet (drops lane prefix; retry)"},
        {"#8 composed order breaks", sp + "the composed order at P=173 breaks the canonical order: rank 4 > rank 3 (own tail 2, partial; serving peer set aside; asking another)"},
        {"#9 order did not reproduce", kOrderRejectedWhy},
        {"#10 CUT-FLOOR wait", sp + "CUT-FLOOR wait: the lower chain block 0123456789ab h=4 is undecided (its committed cut may raise the floor under P=173)"},
        {"#11 lane tip behind", sp + "our lane tip 3 < P=9 (receiver behind the winner's cut; retry)"},
        {"#12 prefix not derivable", sp + "drops lane prefix [0,173) not derivable (own lane log has a gap at 40)"},
        {"#13 prefix awaiting order", sp + "relay repair of P=173: drops lane prefix awaiting the winner-side order (own order: gap at 40)"},
        {"#14 SUFFIX (attempt 7)", kSuffixWhy},
        {"#15 prefix not derivable yet", sp + "drops lane prefix of P=173 not derivable yet: replay pending"},
        {"#16 range below undecidable", sp + "drops range below h=5 undecidable (canonical predecessor not readable yet)"},
        {"#17 prefix covers < P", sp + "drops lane prefix covers 100 positions < P=173"},
        {"#18 pinned not held", kPinnedNotHeldWhy},
        {"#19 recompute view", sp + "recompute: the view at P=173 is not readable yet"},
        {"#20 recompute undecidable", sp + "lane-prefix skew: the take equals the drain Delta at dh 4, ours is 14"},
        {"#21 DROPS not live", sp + "relay repair of P=-: DROPS not live yet (flip 1: no pre-DROPS booking)"},
        {"#22 ledger not bound", sp + "settlement ledger not bound yet (boot)"},
        {"#23 backfill below", sp + "drops backfill of intervals below h=5 undecidable (the canonical predecessor lane block is not readable yet)"},
        {"#23b backfill incomplete", sp + "drops backfill of intervals [2,5) incomplete (2/2 peer(s) unconfirmed, 0 raindrop(s) missing)"},
        {"#24 set not carried", kSetNotCarriedWhy},
        {"#24b set not carried (scratch)", kSetNotCarriedScratchWhy},
        {"#25 no scratch ring", sp + "no scratch ring (internal)"},
        {"#26 REJOIN-PAYEE pend", sp + "the view at P=173 is not readable yet [payee resolution: output 2 maps to no known payee -- the payees of the block's own credit cut P=173]"},
        {"#27 get_block", "get_block(0123456789ab): connection refused"},
        {"#27b native-hold", "native-hold: the native chain index does not hold the block body"},
        {"#27c does not parse", "coinbase blob does not parse"},
        {"#28 lane-root-unknown", "lane-root-unknown: the ring is not at the winner's state yet"},
    };
    int k = 0;
    for (const auto& [tag, why] : undecided) {
        Rig r(tmp, "a2u-" + std::to_string(k++), [w = why](std::uint64_t) { return w; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        const std::string name = std::string("A2 UNDECIDED ") + tag + ": HELD past the bound (refused=0, liability=0, held_now=1, cursor 1)";
        check(name.c_str(), r.attempts > 1 && r.st().refused == 0 && r.st().refused_not_credited == 0 &&
                            r.st().liability_blocks == 0 && r.st().held_now == 1 && r.cursor() == 1 &&
                            !r.node->ledger().is_settled(r.bid5),
              r.brief());
        (void)r.fc->drain_before_stop();
    }
    const std::vector<std::pair<const char*, std::string>> decided = {
        {"lane-root-refused", "lane-root-refused:" + std::string(64, 'e') + ":no candidate digest (test)"},
        {"not-lane", "not-lane: no v37 settlement ledger bound (option A)"},
        {"txin_gen height", "coinbase txin_gen height 4 != chain height 5"},
        {"no credit cut", "no on-chain credit cut (0x02 V37C tail) -- E_b unreproducible (fail-closed)"},
        {"cut-floor-refused", "cut-floor-refused: P=173 is below the floor 180 committed at h=4"},
        {"credit-cut MISMATCH (replay)", kDecidedMismatchWhy},
        {"credit-cut MISMATCH (published)", "credit-cut MISMATCH: we published P=173 with a DIFFERENT lane digest (fail-closed: different records in the same prefix)"},
        {"fold_eb REFUSED", "fold_eb REFUSED at the on-chain cut (geometry not ratified)"},
    };
    for (const auto& [tag, why] : decided) {
        Rig r(tmp, "a2d-" + std::to_string(k++), [w = why](std::uint64_t) { return w; });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(3);
        const bool is_root_refused = std::string(tag) == "lane-root-refused", is_not_lane = std::string(tag) == "not-lane";
        const bool outcome = is_root_refused ? r.st().refused_not_credited == 1
                           : is_not_lane     ? r.st().refused == 0
                                             : (r.st().refused == 1 && r.st().liability_blocks == 1);
        const std::string name = std::string("A2 DECIDED ") + tag + ": decided on attempt 1 (no hold, gate released, cursor 7)";
        check(name.c_str(), r.attempts == 1 && outcome && r.st().held_now == 0 && r.booked == 0 &&
                            !r.node->ledger().is_settled(r.bid5) && r.cursor() == 7,
              r.brief() + " rnc=" + std::to_string(r.st().refused_not_credited));
        (void)r.fc->drain_before_stop();
    }
}

// A3: the liveness cost, pinned. A HELD block at h keeps the finalize cursor at
// builder_cut(h) = h-1-D_conf, so main's BOOKING-POINT GATE (provider ready_gate:
// cursor == builder_cut(T)) builds a template for T = h at most -- never above.
void hold_gates_template(const std::filesystem::path& tmp) {
    std::printf("-- A3: a HELD block at h gates every template above h; released on booking --\n");
    namespace recon = c2pool::v37n::xmr::recon;
    bool arrived = false;
    Rig r(tmp, "a3", [&](std::uint64_t) { return arrived ? std::string() : kSuffixWhy; });
    if (!r.ok) return;
    r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
    auto gate = [&](std::uint64_t T) { return r.cursor() == recon::builder_cut(T, r.c.d_conf); };
    check("A3 held at h=5: the booking-point gate passes T=5 only; T=6..11 held (the node mines nothing above the held height)",
          r.st().held_now == 1 && gate(5) && !gate(6) && !gate(11), r.brief());
    arrived = true;
    r.ticks(12);
    check("A3 booked: the gate releases up to the tip's next height (T=11 passes)", r.st().held_now == 0 && gate(11), r.brief());
    (void)r.fc->drain_before_stop();
}

} // namespace

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-rc-hold-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_relay_repair_hold_kat ==\n");
    hold_then_book(tmp);
    two_nodes_converge(tmp);
    repair_family(tmp);
    decided_refused(tmp);
    drops_set_hold(tmp);   // ★ DROPS-RETAIN (L3)
    undecided_suffix_hold(tmp);   // ★ HOLD-ROUND-2 (A)
    undecided_table(tmp);
    hold_gates_template(tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
