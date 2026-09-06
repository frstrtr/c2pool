// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// f1_finalize_kat_btc.cpp  —  Known-Answer Test for the F1-CORRECT finalize
// driver, BITCOIN FAMILY (DASH/LTC coin-adapter height progression).
//
// This drives the SAME coin-agnostic FinalizeDriver as the A-XMR KAT; the coin
// backend differs only in that the height integer here is fed by the v36 coin
// daemon adapter's best-height (DASH devnet/regtest embedded-SPV, LTC testnet4)
// instead of monerod's ZMQ tip, and the deterministic block-id stub carries a
// SHA-256d-flavoured marker instead of RandomX. The driver code, the w4 types,
// and every consensus quantity are identical — proving the F1 contract holds
// for the BTC family with the one driver.
//
// PROVES (against the REAL merged w4 types, stdlib-only, no engine link):
//   KA-1  in-order per-height driving == a real-time peer's owed_digest
//         (a node behind the DASH/LTC tip that catches up in one shot computes
//          the SAME consensus owed_digest as a node that saw every height live).
//   KA-2  burst-size independence: catching up in several bursts of arbitrary
//         size == the real-time peer (any adapter Extend that jumps best_height
//         is safe).
//   KA-3  restart mid-catch-up (persist SettleHW, resume_from_persisted) == the
//          real-time peer (O5.5 persisted high-water; no re-drive/re-stamp).
//   KA-4  THE FALSIFIER: a jump-to-tip driver (finalize every buried block at
//          the LIVE coin tip height) FORKS — its owed_digest differs from the
//          real-time peer, while its finalW is byte-identical. Isolates the
//          fork to the bin_height stamping (first_eligible), the exact F1 defect.
//   KA-5  O5.5: a target height below the persisted high-water is a shorter
//          branch — refused, not adopted (settlement never re-evaluated lower).
//          Models a DASH-regtest reorg to a shorter branch (the demo falsifier).
//
// The real-time peer and the correct catch-up peer must AGREE; the jump-to-tip
// peer must DISAGREE. If either flips, the test fails.
// ===========================================================================

#include <cstdio>
#include <string>
#include <vector>

#include <c2pool/v37/settle_finalize_driver.hpp>

using namespace c2pool::v37n::settle;
using ::v37::bytes32;

namespace {

int g_pass = 0, g_fail = 0;
void check(const char* name, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) ++g_pass; else ++g_fail;
}

std::string hx(const bytes32& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (auto x : b) { s.push_back(k[x >> 4]); s.push_back(k[x & 0xf]); }
    return s;
}

// A deterministic coin-block-id stub for height h, modelling the DASH/LTC
// adapter's by_height() (SHA-256d block hash). Feeds SettleHW's hw_tip leg only;
// it does NOT enter owed_digest, so it cannot mask or cause the fork.
bytes32 tip_at(std::uint64_t h) {
    bytes32 b{};
    for (int i = 0; i < 8; ++i) b[i] = std::uint8_t((h >> (8 * i)) & 0xff);
    b[8] = 0xD5; b[9] = 0x11;  // marker: "DA-SH / LTC" family (SHA-256d/Scrypt)
    return b;
}

// A single-key credit map (miner payout key).
OwedLedger::Amounts credit1(const char* who, long long v) {
    bytes32 k{};
    for (int i = 0; who[i] && i < 32; ++i) k[i] = std::uint8_t(who[i]);
    OwedLedger::Amounts a; a[k] = v; return a;
}

// The shared scenario: three pool-found blocks at DIFFERENT coin heights, so
// their correct finalize heights (found + D_conf) differ from each other and
// from the live tip — the necessary condition for a jump-to-tip driver to fork.
constexpr ::v37::ChainId CHAIN = 0;
constexpr std::uint64_t  D_CONF = 6;   // BTC-family confirmation depth (demo)
constexpr std::uint64_t  TIP = 40;     // live coin best tip when catch-up happens

struct Blk { const char* bid; std::uint64_t found_h; const char* who; long long amt; };
const std::vector<Blk> kScenario = {
    {"blk_a", 10, "miner_A", 100},   // gate 16
    {"blk_c", 12, "miner_C",  70},   // gate 18
    {"blk_b", 25, "miner_B",  50},   // gate 31
};

void register_all(FinalizeDriver& d) {
    for (const auto& b : kScenario) {
        FinalizeCandidate c;
        c.bid = b.bid;
        c.found_height = b.found_h;
        c.credit = credit1(b.who, b.amt);
        // payout empty: EffectiveOwed == finalW, so the digest isolates
        // first_eligible (the F1 quantity) cleanly.
        d.register_found(c);
    }
}

// ── Reference: the REAL-TIME peer. Sees every coin height as the adapter
// reports it: one advance_to() per single height 1..TIP.
bytes32 realtime_digest() {
    OwedLedger L(CHAIN); SettleHW HW;
    FinalizeDriver d(L, HW, CHAIN, D_CONF);
    d.set_tip_of_height(tip_at);
    register_all(d);
    for (std::uint64_t h = 1; h <= TIP; ++h) d.advance_to(h);
    return L.owed_digest();
}

// ── Correct catch-up: node was behind at height 0; the coin adapter reports
// best_height jumped to TIP in ONE Extend. The driver replays per-height.
bytes32 catchup_oneshot_digest() {
    OwedLedger L(CHAIN); SettleHW HW;
    FinalizeDriver d(L, HW, CHAIN, D_CONF);
    d.set_tip_of_height(tip_at);
    register_all(d);
    d.advance_to(TIP);                      // one shot — driver bridges per-height
    return L.owed_digest();
}

// ── Correct catch-up in several arbitrary bursts.
bytes32 catchup_bursts_digest() {
    OwedLedger L(CHAIN); SettleHW HW;
    FinalizeDriver d(L, HW, CHAIN, D_CONF);
    d.set_tip_of_height(tip_at);
    register_all(d);
    d.advance_to(3);        // before any gate
    d.advance_to(17);       // past blk_a's gate (16), before blk_c's (18)
    d.advance_to(30);       // past blk_c's gate (18), before blk_b's (31)
    d.advance_to(TIP);      // past blk_b's gate (31)
    return L.owed_digest();
}

// ── Correct catch-up with a RESTART in the middle (O5.5 persistence).
bytes32 catchup_restart_digest() {
    // First run: catch up to height 20, then persist SettleHW + tear down.
    std::string persisted;
    OwedLedger L(CHAIN);
    {
        SettleHW HW;
        FinalizeDriver d(L, HW, CHAIN, D_CONF);
        d.set_tip_of_height(tip_at);
        register_all(d);
        d.advance_to(20);               // blk_a(16), blk_c(18) finalized; blk_b pending
        persisted = HW.serialize();     // W6 LevelDB round-trip model
    }
    // Restart: rehydrate SettleHW, resume from persisted high-water, continue.
    // (The OwedLedger L survives here as the W6 RecoveryDriver would rehydrate
    // it; the point under test is that the driver does not re-drive settled
    // heights and stamps the remaining gate at its own step.)
    SettleHW HW2 = SettleHW::deserialize(persisted);
    FinalizeDriver d2(L, HW2, CHAIN, D_CONF);
    d2.set_tip_of_height(tip_at);
    // Re-register found blocks: on_block_found is idempotent per bid, and the
    // driver re-arms its finalize schedule; already-settled bids are skipped
    // (is_pending() is false), only the still-pending blk_b remains to finalize.
    register_all(d2);
    d2.resume_from_persisted();          // last_driven := hw_height (20)
    d2.advance_to(TIP);                  // finalizes blk_b at its gate (31)
    return L.owed_digest();
}

// ── THE FALSIFIER: the buggy jump-to-tip driver the F1 audit warns against.
// It moves the high-water straight to the live coin tip and finalizes EVERY
// block buried >= D_conf at the tip height. This is the reconcile()-at-current-
// tip shape wrongly copied into a live caller. It must FORK.
struct JumpToTipDriver {
    OwedLedger& L; SettleHW& HW; std::uint64_t dconf;
    std::vector<std::pair<std::string, std::uint64_t>> found;  // bid, found_h
    void register_found(const std::string& bid, std::uint64_t fh,
                        const OwedLedger::Amounts& credit) {
        L.on_block_found(bid, credit, {});
        found.push_back({bid, fh});
    }
    void jump_to_tip(std::uint64_t tip) {
        HW.advance(tip, tip_at(tip));                 // jump straight to tip
        for (auto& [bid, fh] : found) {
            if (tip < fh + dconf) continue;           // not yet buried
            if (!L.is_pending(bid)) continue;
            L.on_block_finalized(bid, tip);           // BUG: bin_height = live tip
        }
    }
};

bytes32 jump_to_tip_digest() {
    OwedLedger L(CHAIN); SettleHW HW;
    JumpToTipDriver d{L, HW, D_CONF, {}};
    for (const auto& b : kScenario)
        d.register_found(b.bid, b.found_h, credit1(b.who, b.amt));
    d.jump_to_tip(TIP);
    return L.owed_digest();
}

// finalW-only equality helper: compares the finalW maps of the correct and
// buggy peers, proving the fork is purely in first_eligible.
bool finalW_equal_correct_vs_buggy() {
    OwedLedger A(CHAIN); SettleHW HWa;
    FinalizeDriver da(A, HWa, CHAIN, D_CONF); da.set_tip_of_height(tip_at);
    register_all(da);
    for (std::uint64_t h = 1; h <= TIP; ++h) da.advance_to(h);

    OwedLedger B(CHAIN); SettleHW HWb;
    JumpToTipDriver db{B, HWb, D_CONF, {}};
    for (const auto& b : kScenario)
        db.register_found(b.bid, b.found_h, credit1(b.who, b.amt));
    db.jump_to_tip(TIP);

    return A.finalW() == B.finalW();
}

}  // namespace

int main() {
    std::printf("F1 finalize-driver KAT — BTC FAMILY (DASH/LTC adapter height)\n");
    std::printf("(same coin-agnostic driver as A-XMR; merged w4_settlement.hpp)\n");

    const bytes32 rt   = realtime_digest();
    const bytes32 one  = catchup_oneshot_digest();
    const bytes32 brst = catchup_bursts_digest();
    const bytes32 rst  = catchup_restart_digest();
    const bytes32 jump = jump_to_tip_digest();

    std::printf("  real-time     owed_digest = %s\n", hx(rt).c_str());
    std::printf("  catch-up 1x   owed_digest = %s\n", hx(one).c_str());
    std::printf("  catch-up brst owed_digest = %s\n", hx(brst).c_str());
    std::printf("  catch-up rst  owed_digest = %s\n", hx(rst).c_str());
    std::printf("  jump-to-tip   owed_digest = %s\n", hx(jump).c_str());

    // KA-1: in-order catch-up == real-time.
    check("KA-1 in-order catch-up == real-time peer", one == rt);
    // KA-2: burst-size independence.
    check("KA-2 multi-burst catch-up == real-time peer", brst == rt);
    // KA-3: restart mid-catch-up (O5.5 persisted) == real-time.
    check("KA-3 restart mid-catch-up == real-time peer", rst == rt);
    // KA-4a: the falsifier FORKS.
    check("KA-4 jump-to-tip FORKS (digest != real-time)", jump != rt);
    // KA-4b: the fork is purely in first_eligible — finalW is identical.
    check("KA-4 fork is first_eligible-only (finalW identical)",
          finalW_equal_correct_vs_buggy());
    // KA-4c: non-vacuity — the scenario genuinely distinguishes the drivers.
    check("KA-4 scenario is non-vacuous (correct != buggy)", rt != jump);

    // KA-5: O5.5 shorter-branch refusal (DASH-regtest reorg-to-shorter model).
    {
        OwedLedger L(CHAIN); SettleHW HW;
        FinalizeDriver d(L, HW, CHAIN, D_CONF);
        d.set_tip_of_height(tip_at);
        register_all(d);
        d.advance_to(31);
        const bytes32 at31 = L.owed_digest();
        const std::uint64_t refused_before = HW.refused;
        std::size_t n = d.advance_to(25);           // shorter branch → refused
        const bytes32 after = L.owed_digest();
        check("KA-5 O5.5 shorter-branch target refused (no finalize)",
              n == 0 && after == at31 && HW.refused == refused_before + 1);
    }

    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
