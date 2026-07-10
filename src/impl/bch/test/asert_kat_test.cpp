// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin ASERT DAA known-answer test (M5 -- embedded body conformance).
//
// ASERT (aserti3-2d) is BCH's per-block difficulty adjustment (CHIP-2020-05,
// activated Nov 2020) -- the single largest consensus divergence from BTC Core
// (M1 §4) and the function that governs the `bits`/target the SYNCED-state work
// template emits at any height >= the ASERT anchor. asert.hpp's CalculateASERT()
// is documented as a 1:1 fixed-point port of BCHN src/pow.cpp CalculateASERT()
// and CLAIMS validation against BCHN's gold vectors -- but NO test in this tree
// actually exercised it. Every getwork/template test (embedded_getwork_test,
// block_*_test) deliberately stays BELOW the ASERT anchor (height 100k << 661647)
// to skip the retarget, so the synced-state DAA branch shipped unverified.
//
// This KAT closes that gap by pinning CalculateASERT() and the anchor-formulated
// get_next_work_required_asert() against the canonical gold PROPERTIES of BCHN's
// asert_difficulty_test (src/test/pow_tests.cpp) and the real mainnet anchor
// constants (src/chainparams.cpp:169-172), all from BCHN @89a591f (v29.0.0):
//
//   anchor = {height 661647, nBits 0x1804dafe, prev_block_time 1605447844}
//   nASERTHalfLife = 2*24*60*60 (2 days),  nPowTargetSpacing = 600s
//
// The fixed-point exponent is exact at INTEGER halflife multiples (frac==0 =>
// factor==65536 => the result is a pure power-of-two shift of refTarget), so the
// gold relationships below are EXACT uint256 identities, not float tolerances:
//
//   * exponent 0      (on schedule)  -> target UNCHANGED          (== refTarget)
//   * exponent +1 HL  (2 days slow)  -> target DOUBLES            (== refTarget<<1)
//   * exponent -1 HL  (2 days fast)  -> target HALVES             (== refTarget>>1)
//   * exponent +2 HL                 -> target x4                 (== refTarget<<2)
//   * huge positive exponent         -> CLAMPED to powLimit
// BCHN gold: "steady 600s -> same", "Jumping forward 2 days should double the
// target", "Jumping backward 2 days should halve", "stick at min difficulty".
//
// CONFORMANCE ORACLE NOTE: p2poolBCH @6603b79 carries NO ASERT -- it defers DAA
// to bitcoind's getblocktemplate (m5-embedded-conformance). The embedded daemon
// REPLACES that bitcoind, so the embedded ASERT IS the conformance surface and
// its oracle is BCHN itself (pinned above), NOT p2poolBCH. Zero
// p2pool-merged-v36 surface: ASERT governs only the target a header must meet
// (which headers the SPV engine accepts), never PoW hash / share format /
// coinbase / PPLNS.
//
// Build-INERT / source-only (matches sibling tests): pure header-only over
// coin/asert.hpp + <core/uint256>; impl_bch stays unregistered, bch=skip-green.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/asert.hpp"
#include <core/uint256.hpp>

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

uint256 target_from_bits(uint32_t bits) {
    uint256 t;
    t.SetCompact(bits);
    return t;
}

} // namespace

int main() {
    using namespace bch::coin;

    const uint256 powLimit = bch_pow_limit();
    const int64_t spacing  = BCH_TARGET_SPACING;   // 600
    const int64_t HL       = 2 * 24 * 60 * 60;      // 172800 (mainnet 2-day halflife)

    // Reference target: the real mainnet anchor target, well below powLimit.
    const uint256 refTarget = target_from_bits(0x1804dafe);
    CHECK(refTarget > uint256::ZERO && refTarget <= powLimit);

    // CalculateASERT exponent driver: with nHeightDiff fixed, the algorithm's
    // exponent numerator is (nTimeDiff - spacing*(nHeightDiff+1)); set it to a
    // chosen `diff` by picking nTimeDiff = spacing*(nHeightDiff+1) + diff.
    auto asert = [&](int64_t nHeightDiff, int64_t diff) {
        const int64_t nTimeDiff = spacing * (nHeightDiff + 1) + diff;
        return CalculateASERT(refTarget, spacing, nTimeDiff, nHeightDiff, powLimit, HL);
    };

    // ── Gold property 1: on schedule (exponent 0) -> target UNCHANGED ────────
    CHECK(asert(/*hd=*/0,   /*diff=*/0) == refTarget);          // BCHN "steady -> same"
    CHECK(asert(/*hd=*/144, /*diff=*/0) == refTarget);          // height term wired (1 day of blocks)
    CHECK(asert(/*hd=*/2016,/*diff=*/0) == refTarget);

    // ── Gold property 2: +2 days slow (exponent +1 halflife) -> DOUBLES ──────
    CHECK(asert(/*hd=*/0, /*diff=*/+HL) == (refTarget << 1));   // BCHN "forward 2d doubles target"
    CHECK(asert(/*hd=*/7, /*diff=*/+HL) == (refTarget << 1));   // independent of height offset

    // ── Gold property 3: +2 days fast (exponent -1 halflife) -> HALVES ───────
    CHECK(asert(/*hd=*/0, /*diff=*/-HL) == (refTarget >> 1));   // BCHN "backward 2d halves target"

    // ── Gold property 4: exponent +2 halflives -> target x4 ──────────────────
    CHECK(asert(/*hd=*/0, /*diff=*/+2 * HL) == (refTarget << 2));

    // ── Gold property 5: huge positive exponent -> CLAMPED to powLimit ───────
    CHECK(asert(/*hd=*/0, /*diff=*/200 * HL) == powLimit);      // BCHN "stick at min difficulty"

    // ── Composability: two solvetimes summing to 2*spacing leave the target
    //    where it started (BCHN "1200s over two blocks -> back to initial").
    //    Net diff over the pair is 0 -> exponent 0 -> unchanged.
    CHECK(asert(/*hd=*/1, /*diff=*/0) == refTarget);

    // ── Anchor-formulated entry: get_next_work_required_asert() with the REAL
    //    mainnet anchor. Reproduces the gold relationships through the public
    //    ASERTParams API the synced-state template actually calls. ───────────
    {
        const ASERTParams p = asert_mainnet();
        CHECK(p.anchor.height == 661647);
        CHECK(p.anchor.nBits == 0x1804dafe);
        CHECK(p.anchor.prev_block_time == 1605447844);
        CHECK(p.half_life == HL);

        // On-schedule block at the anchor height: nHeightDiff 0, nTimeDiff 600
        // (one spacing past the anchor parent) -> exponent 0 -> anchor nBits.
        const int64_t anchor_h = p.anchor.height;
        const int64_t t0 = p.anchor.prev_block_time;
        CHECK(get_next_work_required_asert(anchor_h, t0 + spacing, t0 + spacing, p)
              == 0x1804dafe);

        // 2 days behind schedule at the anchor height -> target doubles.
        uint256 doubled_t = refTarget;
        doubled_t <<= 1;
        const uint32_t doubled = doubled_t.GetCompact();
        CHECK(get_next_work_required_asert(anchor_h, t0 + spacing + HL, t0 + spacing + HL, p)
              == doubled);
    }

    // ── Testnet special rule: allow_min_difficulty fires when new_time is more
    //    than 2*spacing past the tip -> emits powLimit compact (min difficulty).
    {
        const ASERTParams tp = asert_testnet3();
        CHECK(tp.allow_min_difficulty);
        const int64_t tip_h = tp.anchor.height;
        const int64_t tip_t = tp.anchor.prev_block_time + spacing;
        CHECK(get_next_work_required_asert(tip_h, tip_t, tip_t + 2 * spacing + 1, tp)
              == tp.pow_limit.GetCompact());
    }

    if (failures == 0) {
        std::cout << "asert_kat_test: ALL PASS"
                  << " (BCHN @89a591f pow_tests.cpp + chainparams.cpp:169)\n";
        return 0;
    }
    std::cerr << "asert_kat_test: " << failures << " FAILURE(S)\n";
    return 1;
}