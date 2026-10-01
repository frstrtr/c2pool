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
//   N1  a NON-relay cut-pending past the bound keeps its pre-RC-HOLD release
//       (booking_stall_timeout, refused): the change is narrow.     (as pre-fix)
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
        Rig r(tmp, "n1", [](std::uint64_t) { return std::string("cut-pending: our lane tip 3 < P=9 (receiver behind the winner's cut; retry)"); });
        if (!r.ok) return;
        r.chain(1, 4); r.ticks(1); r.chain(5, 10); r.ticks(60);
        check("N1 a NON-relay cut-pending past the bound keeps its release (booking_stall_timeout=1, refused=1, relay_repair_stall=0)",
              r.st().booking_stall_timeout == 1 && r.st().refused == 1 && r.st().relay_repair_stall_timeout == 0 &&
              r.st().held_now == 0 && r.cursor() == 7,
              r.brief());
        (void)r.fc->drain_before_stop();
    }
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
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
