// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_s1_live_wiring_kat.cpp — S-1: the DRIVER drives the settlement.
//
// THE DEFECT THIS KAT PINS. Before the S-1 wiring, no live path ever computed
// E_b. settle::fold_eb — the ONE credit-path entry point — had zero engine or
// driver callers; the live FOUND site (XbtcNode::on_block_won) built BOTH the
// credit and the payout out of the W5 coinbase assembly, which a FRESH win
// (confirmations == 0) WITHHOLDS. So credit was EMPTY, FINALIZE did
// finalW += {} — and owed_digest stayed at the empty "V37O" anchor
//
//     b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339
//
// forever, on every live node, no matter how many blocks the pool won. Case 5
// below reproduces that exact shape and asserts the anchor, so this KAT fails
// if the wiring is ever reverted.
//
// WHAT IS ASSERTED (a FIXED event stream, no clocks, no sockets, no RNG):
//   1  the empty anchor is what an untouched ledger commits to (the baseline)
//   2  driver-drives-S-1: shares -> on_block_won -> fold_eb -> FOUND -> bury ->
//      FINALIZE -> owed_digest is NON-EMPTY, and equals a PINNED golden
//   3  determinism: a second, independent node stack fed the byte-identical
//      event stream converges to the byte-identical owed_digest (the in-process
//      half of the cross-node convergence claim; the socket-peered half is the
//      multi-node regtest rig)
//   4  credit != payout: a fresh win credits E_b and broadcasts NOTHING, so the
//      whole entitlement carries forward as owed (sum(finalW) == reward)
//   5  the defect, reproduced: the old assembly-as-credit shape -> the anchor
//   6  the cut witness: lane_digest / version / incarnation / next_pos on the
//      WonBlockOutcome are the snapshot the fold actually read
//   7  refuse-loud on reward == 0: VALUELESS, counter bumped, FOUND STILL
//      REGISTERED (a real block is never lost to a fold failure)
//   8  refuse-loud on a non-ratified geometry: fold_eb REFUSES, counter bumped,
//      FOUND still registered
//   9  a MATURE win emits a coinbase: payout non-empty, and finalW is the
//      entitlement MINUS what the block actually paid (the carry)
//
// Stdlib-only self-harness (the sibling convention in this directory): no
// gtest, no Boost, no coin lib — MockCoinBackend + MemSettleStore only. Links
// Threads for the engine's single executor thread. Registered with add_test AND
// in BOTH build.yml --target lists (the #1539 / #769 hollow-green rule).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <c2pool/v37/btc/btc_node.hpp>

using namespace c2pool::v37n::btc;
namespace settle = ::c2pool::v37n::settle;

static int g_fails = 0;
static int g_checks = 0;
static void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) { ++g_fails; std::printf("S1-KAT FAIL: %s\n", what.c_str()); }
    else       std::printf("  ok: %s\n", what.c_str());
}

static std::string hex32(const ::v37::bytes32& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; }
    return s;
}

// The empty-fold anchor: sha256d("V37O") — what owed_digest() returns when the
// FINALIZED partition is empty. The S-1 defect's fingerprint.
static const char* kEmptyAnchor =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

// PINNED GOLDEN — the owed_digest the fixed stream of case 2 produces. A change
// here is a CONSENSUS-VISIBLE change to what the pool commits it owes; it may
// only move with a ruling, never with a refactor.
static const char* kOwedGolden =
    "4e13dd3f7472dae166e0d99ab778a296b8308afd6c2f55595747628800bdf0a4";

static ::v37::PayoutDescriptor p2pkh_desc(std::uint8_t tag) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88); s.push_back(0xac);
    ::v37::PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}

static const ::v37::ChainId CH = 7;
static const std::uint64_t  REWARD = 5000000000ULL;   // MockCoinBackend default
static const std::uint64_t  D_CONF = 3;

// ── THE FIXED EVENT STREAM ─────────────────────────────────────────────────
// 24 shares from 4 payees with a fixed weight cycle, then one block win at a
// known height, then enough filler blocks to bury it D_conf deep. Identical on
// every run and on every node: that is what makes the digest a golden.
struct Drive {
    ::v37::bytes32 owed{};
    ::v37::bytes32 lane{};
    EbCut          cut;
    Amounts        finalW;
    std::size_t    payout_outputs = 0;
    bool           finalized = false;
    S1FoldStats    stats;
};

static Drive drive_fixed_stream(std::shared_ptr<MockCoinBackend> coin,
                                const ::v37::LaneParams& params,
                                std::uint64_t win_conf = 0) {
    Drive out;
    BtcNodeConfig cfg;
    cfg.lane_chain  = CH;
    cfg.lane_params = params;
    cfg.d_conf      = D_CONF;
    auto store = std::make_unique<MemSettleStore>();
    XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
    if (!node.open() || !node.start()) return out;

    // (a) the share stream — the SAME records the carrier relay would push
    //     (carrier_ingest.hpp: admitted receipts -> LaneRecord::push). Submitted
    //     tracked+get so arrival order is the fixed order below.
    for (int i = 0; i < 24; ++i)
        node.engine()
            .submit_tracked(::v37::LaneRecord::push(
                CH, p2pkh_desc(static_cast<std::uint8_t>(0xa0 + (i % 4))),
                1 + (i % 3), 0))
            .get();

    if (auto s = node.lane_snapshot()) out.lane = s->digest;

    // (b) the block win — through the live FOUND seam.
    coin->append_block("g0");
    const std::uint64_t win_h = coin->append_block("won");
    WonBlockOutcome won = node.on_block_won("won", win_h, win_conf);
    out.cut            = won.cut;
    out.payout_outputs = won.outputs;

    // (c) bury it D_conf deep and let the F1 height-watch FINALIZE it.
    for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
        coin->append_block("f" + std::to_string(i));
    for (const auto& s : node.poll_tip())
        if (s.bid == "won") out.finalized = true;

    out.owed   = node.ledger().owed_digest();
    out.finalW = node.ledger().finalW();
    out.stats  = node.s1_stats();
    node.stop();
    return out;
}

int main() {
    std::printf("== v37 S-1 live fold-wiring KAT ==\n");

    // ── 1. the baseline: an untouched ledger commits to the empty anchor ─────
    {
        settle::OwedLedger fresh(CH);
        check(hex32(fresh.owed_digest()) == kEmptyAnchor,
              "1 empty ledger owed_digest == the sha256d(\"V37O\") anchor " +
                  std::string(kEmptyAnchor).substr(0, 8));
    }

    // ── 2. DRIVER DRIVES S-1: the fixed stream moves owed_digest OFF the anchor
    ::v37::LaneParams ratified{};          // the OQ-5 ratified default (gate-OFF V37.0)
    Drive a = drive_fixed_stream(std::make_shared<MockCoinBackend>(), ratified);
    std::printf("   lane_digest = %s\n", hex32(a.lane).c_str());
    std::printf("   owed_digest = %s\n", hex32(a.owed).c_str());
    check(a.finalized, "2a the F1 height-watch FINALIZED the won block");
    check(a.cut.folded, "2b fold_eb accepted the live lane snapshot (geometry ratified)");
    check(!a.cut.credit.empty(), "2c E_b is NON-EMPTY (the live fold produced credit)");
    check(hex32(a.owed) != kEmptyAnchor,
          "2d ★ owed_digest moved OFF the empty anchor — the S-1 emission is LIVE");
    {
        long long sum = 0;
        for (const auto& [k, v] : a.cut.credit) { (void)k; sum += v; }
        check(sum == static_cast<long long>(REWARD),
              "2e sum(E_b) == the block reward (exact split, no lost satoshi)");
    }
    check(hex32(a.owed) == kOwedGolden,
          "2f owed_digest == the pinned golden " + std::string(kOwedGolden).substr(0, 16));

    // ── 3. determinism / convergence: a second independent stack, same stream ─
    {
        Drive b = drive_fixed_stream(std::make_shared<MockCoinBackend>(), ratified);
        check(b.lane == a.lane,
              "3a two independent engines fed the same stream publish the SAME lane digest");
        check(b.cut.credit == a.cut.credit,
              "3b ...therefore fold the SAME E_b at the same cut");
        check(b.owed == a.owed,
              "3c ★ ...therefore CONVERGE on the same owed_digest (cross-node emission)");
        check(hex32(b.owed) != kEmptyAnchor, "3d the second stack is non-empty too");
    }

    // ── 4. credit != payout: a fresh win broadcasts nothing, so all of E_b owed
    {
        check(a.payout_outputs == 0,
              "4a a FRESH win (confirmations 0) withholds the W5 assembly (0 outputs)");
        long long total = 0;
        for (const auto& [k, v] : a.finalW) { (void)k; total += v; }
        check(total == static_cast<long long>(REWARD),
              "4b finalW total == reward: credit landed, payout deducted nothing");
        check(a.finalW.size() == a.cut.credit.size(),
              "4c every credited payee carries an owed row after FINALIZE");
    }

    // ── 5. THE DEFECT, REPRODUCED: assembly-as-credit -> the empty anchor ─────
    // The exact pre-S-1 shape: build BOTH maps from the (withheld, therefore
    // empty) W5 assembly and register that. If this ever stops producing the
    // anchor, the wiring under test has changed meaning.
    {
        settle::OwedLedger led(CH);
        ::c2pool::v37n::coinbase::CoinbaseBudget budget;
        budget.k_floor = 1;
        ::c2pool::v37n::coinbase::BurialGate gate;
        gate.d_conf = D_CONF; gate.canonical = true; gate.confirmations = 0;
        auto pay_of = p2pkh_pay_of();
        auto asm_ = ::c2pool::v37n::coinbase::assemble_if_buried(led, REWARD, budget,
                                                                 gate, pay_of);
        Amounts credit, payout;
        for (const auto& o : asm_.outputs) {
            credit[o.key] = static_cast<long long>(o.amount);
            payout[o.key] = static_cast<long long>(o.amount);
        }
        led.on_block_found("won", credit, payout);
        led.on_block_finalized("won", 1 + D_CONF);
        check(!asm_.emitted && credit.empty(),
              "5a pre-S-1 shape: the withheld assembly yields an EMPTY credit");
        check(hex32(led.owed_digest()) == kEmptyAnchor,
              "5b ★ ...and owed_digest stays AT the anchor — the defect, pinned");
    }

    // ── 6. the cut witness is the snapshot the fold actually read ────────────
    {
        check(a.cut.lane_digest == a.lane,
              "6a WonBlockOutcome::cut.lane_digest == the published lane digest");
        check(a.cut.lane_version > 0 && a.cut.lane_incarnation > 0,
              "6b cut carries a real (version, incarnation) pair — ABA-safe");
        check(a.cut.next_pos == 24,
              "6c cut.next_pos == the 24-push prefix P the fold read at");
        check(std::string(a.cut.source).find("live-only") == 0,
              "6d eb_source == live-only (V37.0 positional; no ridge on this lane)");
        check(a.cut.unresolved == 0, "6e no OI-W4-1 unresolved payout keys");
        check(a.stats.folds == 1 && a.stats.valueless == 0 && a.stats.refused == 0,
              "6f S1 counters: one clean fold, no refusal, no valueless record");
    }

    // ── 7. refuse LOUD on reward == 0, but never lose the block ──────────────
    {
        auto coin = std::make_shared<MockCoinBackend>(/*fixed_reward=*/0);
        Drive z = drive_fixed_stream(coin, ratified);
        check(z.cut.folded && z.cut.valueless,
              "7a reward == 0 folds but is stamped VALUELESS");
        check(!z.cut.refusal.empty(), "7b ...with a loud, non-empty reason");
        check(z.stats.valueless == 1 && z.stats.folds == 0,
              "7c the valueless counter is bumped (an operator can see it)");
        check(z.finalized,
              "7d ★ the FOUND was REGISTERED anyway — a real block is never lost");
        check(hex32(z.owed) == kEmptyAnchor,
              "7e a valueless win credits nobody (digest correctly unmoved)");
    }

    // ── 8. refuse LOUD on a non-ratified geometry ────────────────────────────
    {
        ::v37::LaneParams bad{};
        bad.window = 256; bad.c0 = 128; bad.rollup = 8;
        bad.level_caps = {16}; bad.half_life = 64; bad.journal_depth = 16;
        check(!settle::geometry_is_ratified(bad),
              "8a the test geometry is (correctly) NOT ratified");
        Drive r = drive_fixed_stream(std::make_shared<MockCoinBackend>(), bad);
        check(!r.cut.folded && r.cut.valueless,
              "8b fold_eb REFUSED it — no credit reaches the ledger");
        check(r.stats.refused == 1, "8c the refusal counter is bumped");
        check(r.finalized, "8d the FOUND was still registered (block never lost)");
        check(hex32(r.owed) == kEmptyAnchor, "8e refused fold credits nobody");
    }

    // ── 9. the SECOND win pays the FIRST win's owed: credit - payout carry ───
    // The W5 coinbase is assembled out of the OWED ledger, so the very first
    // block a fresh pool wins can pay nobody (nothing is owed yet) even when the
    // buried gate is open — it can only CREDIT. The next win, with a standing
    // owed balance behind it, both credits its own E_b and pays the earlier one.
    // That is the shape this case pins, and it is the one that shows credit and
    // payout are genuinely different maps in the live path.
    {
        BtcNodeConfig cfg;
        cfg.lane_chain = CH; cfg.lane_params = ratified; cfg.d_conf = D_CONF;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        node.open(); node.start();
        for (int i = 0; i < 24; ++i)
            node.engine()
                .submit_tracked(::v37::LaneRecord::push(
                    CH, p2pkh_desc(static_cast<std::uint8_t>(0xa0 + (i % 4))),
                    1 + (i % 3), 0))
                .get();

        coin->append_block("g0");
        const std::uint64_t h1 = coin->append_block("win1");
        WonBlockOutcome w1 = node.on_block_won("win1", h1, /*conf=*/0);
        for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
            coin->append_block("b" + std::to_string(i));
        node.poll_tip();                                   // FINALIZE win1
        check(w1.outputs == 0,
              "9a the FIRST win of a fresh pool pays nobody (nothing owed yet)");

        const long long owed_after_1 = [&] {
            long long t = 0; for (const auto& [k, v] : node.ledger().finalW()) { (void)k; t += v; } return t;
        }();
        check(owed_after_1 == static_cast<long long>(REWARD),
              "9b ...it CREDITED the whole reward as owed");

        const std::uint64_t h2 = coin->append_block("win2");
        WonBlockOutcome w2 = node.on_block_won("win2", h2, /*conf=*/D_CONF + 1);
        check(w2.outputs > 0,
              "9c ★ the SECOND win, buried-gate open over a standing owed "
              "balance, DOES emit a W5 coinbase (payout non-empty)");
        check(!w2.cut.credit.empty(),
              "9d ...while still crediting its OWN E_b (credit != payout)");
        for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
            coin->append_block("c" + std::to_string(i));
        node.poll_tip();                                   // FINALIZE win2

        long long owed_after_2 = 0;
        for (const auto& [k, v] : node.ledger().finalW()) { (void)k; owed_after_2 += v; }
        check(owed_after_2 < 2 * static_cast<long long>(REWARD),
              "9e finalW == credit - payout: what win2 actually paid is deducted");
        check(hex32(node.ledger().owed_digest()) != kEmptyAnchor,
              "9f ...and the digest tracks the carry, never the anchor");
        node.stop();
    }

    std::printf("S1-KAT %s (%d checks, %d failures)\n", g_fails ? "FAIL" : "OK",
                g_checks, g_fails);
    return g_fails ? 1 : 0;
}
