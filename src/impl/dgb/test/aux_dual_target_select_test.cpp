// ---------------------------------------------------------------------------
// DGB+DOGE (phase DC) — dual-target SELECTION scaffold KAT.
//
// Fenced / test-only. Pins the pure DC decision contract (coin/aux_dual_target_
// select.hpp) the eventual DC wiring must satisfy, BEFORE the AUX_DOGE node seam
// is touched. Non-circular: every golden is restated by value (the fabe6d6d tag,
// the embed-when-aux+job rule, the independent threshold table, the no-op
// invariant) — it mirrors #475 (fabe6d6d builder) / #486 (embed-at-mint nullopt
// no-op) without including their (not-yet-landed) headers, so it cannot drift
// against them and stands alone on master.
//
// Pure helpers, links only core (uint256). Consumes nothing in src/impl/doge.
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a NOT_BUILT sentinel that reds master (#143 trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/aux_dual_target_select.hpp>
#include <core/uint256.hpp>

using dgb::coin::aux_mint_decision;
using dgb::coin::select_submit;
using dgb::coin::selection_is_consistent;
using dgb::coin::MM_COMMITMENT_TAG;

// 1) fabe6d6d mint anchor (#475). Non-circular literal golden — the tag the
//    real MM-commitment builder prepends. Guards against a silent tag reshape.
TEST(DGB_AuxDualTargetSelect, MmCommitmentTagIsFabe6d6d) {
    EXPECT_EQ(MM_COMMITMENT_TAG[0], 0xfa);
    EXPECT_EQ(MM_COMMITMENT_TAG[1], 0xbe);
    EXPECT_EQ(MM_COMMITMENT_TAG[2], 0x6d);
    EXPECT_EQ(MM_COMMITMENT_TAG[3], 0x6d);
}

// 2) MINT-TIME embed truth table (#486). Embed IFF aux enabled AND DOGE job.
//    The three non-embed corners are the byte-identical no-op (#486 nullopt).
TEST(DGB_AuxDualTargetSelect, MintEmbedsOnlyWhenAuxEnabledAndDogeJob) {
    EXPECT_TRUE (aux_mint_decision(/*aux*/true,  /*job*/true ).embed_commitment);
    EXPECT_FALSE(aux_mint_decision(/*aux*/true,  /*job*/false).embed_commitment);
    EXPECT_FALSE(aux_mint_decision(/*aux*/false, /*job*/true ).embed_commitment);
    EXPECT_FALSE(aux_mint_decision(/*aux*/false, /*job*/false).embed_commitment);
}

// 3) SUBMIT-TIME independent thresholds — same pow_hash, two independent targets
//    (mirrors dc_proof DualTargetIndependentThresholds). DGB-parent is the
//    harder (smaller) target; DOGE-aux is easier (larger).
TEST(DGB_AuxDualTargetSelect, SubmitFiresIndependentThresholds) {
    const uint256 DGB_TARGET  = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 DOGE_TARGET = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    const uint256 below_both = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    const uint256 doge_only  = uint256S("000000000affffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 above_both = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // below both -> both paths fire
    auto a = select_submit(below_both, DGB_TARGET, /*job*/true, DOGE_TARGET);
    EXPECT_TRUE(a.fire_dgb_parent);
    EXPECT_TRUE(a.fire_doge_aux);

    // between -> DOGE-aux fires, DGB-parent does NOT (the common case)
    auto b = select_submit(doge_only, DGB_TARGET, /*job*/true, DOGE_TARGET);
    EXPECT_FALSE(b.fire_dgb_parent);
    EXPECT_TRUE (b.fire_doge_aux);

    // above both -> neither fires
    auto c = select_submit(above_both, DGB_TARGET, /*job*/true, DOGE_TARGET);
    EXPECT_FALSE(c.fire_dgb_parent);
    EXPECT_FALSE(c.fire_doge_aux);
}

// 4) No DOGE job suppresses the DOGE-aux path even on a target hit, and leaves
//    the DGB-parent path untouched (standalone-parent default build behaviour).
TEST(DGB_AuxDualTargetSelect, NoDogeJobSuppressesAuxPathOnly) {
    const uint256 DGB_TARGET  = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 DOGE_TARGET = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 below_both  = uint256S("0000000000000000000000000000000000000000000000000000000000000001");

    auto f = select_submit(below_both, DGB_TARGET, /*job*/false, DOGE_TARGET);
    EXPECT_TRUE (f.fire_dgb_parent); // parent path independent of aux
    EXPECT_FALSE(f.fire_doge_aux);   // no job minted -> no aux win
}

// 5) LOAD-BEARING DC<->DB linkage: fire_doge_aux ==> embed_commitment. A DOGE
//    win without a minted commitment is the impossible state the guard rejects.
TEST(DGB_AuxDualTargetSelect, DogeWinRequiresMintedCommitment) {
    // reachable: aux on + job -> minted -> a DOGE fire is consistent
    EXPECT_TRUE(selection_is_consistent(
        aux_mint_decision(true, true),
        dgb::coin::DualTargetFire{true, true}));
    // reachable: no DOGE fire is always consistent regardless of mint
    EXPECT_TRUE(selection_is_consistent(
        aux_mint_decision(false, false),
        dgb::coin::DualTargetFire{true, false}));
    // impossible: DOGE fire without a minted commitment -> guard rejects
    EXPECT_FALSE(selection_is_consistent(
        aux_mint_decision(false, true),
        dgb::coin::DualTargetFire{false, true}));
}
