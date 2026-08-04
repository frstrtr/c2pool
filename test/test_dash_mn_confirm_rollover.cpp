// SPDX-License-Identifier: AGPL-3.0-or-later
/// confirmedHash rollover (sml_projection.hpp) — the height-driven MN
/// confirmation pass the verifier applies to EVERY block it connects
/// (dashcore v23.1.7 specialtxman.cpp:206-215) and the embedded template
/// builder must therefore project for the block it is templating.
///
/// THE DEFECT PINNED HERE (silent block loss, 2508008-shaped): the tip SML
/// (mnlistdiff-fed, current at prev_hash) is the verifier's PREV list. At the
/// height where a registered MN crosses nMasternodeMinimumConfirmations, the
/// verifier's rebuilt list flips that entry's confirmedHash — an SML-hashed
/// field — with NO transaction causing it, so the committed merkleRootMNList
/// must differ from the tip root at exactly that height. A builder that
/// commits the tip root verbatim produces a bad-cbtx-mnmerkleroot block, and
/// no tip-relative freshness gate can catch it (the tip SML IS current; the
/// pre-fix emit gate compared against the SAME stale root).
///
/// Oracle discipline: the reference root in every test is rebuilt
/// INDEPENDENTLY — a hand-copied SML with confirmedHash set to prev_hash on
/// the crossing entry, hashed through the vendored CalcMerkleRoot — never via
/// the projection helper under test.
///
/// The crossing arithmetic (verified against dashcore, NOT assumed):
/// nConfirmations = pindexPrev->nHeight - nRegisteredHeight, confirm when
/// >= nMasternodeMinimumConfirmations = 15 on mainnet (chainparams.cpp:177 —
/// 15, not 16). So an MN registered at R is first confirmed in block R + 16,
/// with confirmedHash = hash of block R + 15 (the prev block).

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/sml_projection.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::DeclineReport;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::NodeCoinState;
using dash::coin::QuorumManager;
using dash::coin::build_embedded_workdata;
using dash::coin::build_embedded_cbtx;
using dash::coin::encode_cbtx;
using dash::coin::compute_merkle_root_quorums;
using dash::coin::project_sml_confirmations;
using dash::coin::find_unprojectable_confirmation;
using dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::parse_cbtx;

// Dash mainnet base58 version bytes (chainparams.cpp PUBKEY_ADDRESS=76,
// SCRIPT_ADDRESS=16) — same constants the embedded_gbt capstone tests use.
static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;

// Template height well past V20 + MN_RR, matching mainnet steady state.
static constexpr uint32_t H = 2'400'000;

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

static CSimplifiedMNListEntry sml_entry(const uint256& protx,
                                        const uint256& confirmed) {
    CSimplifiedMNListEntry e;
    e.nVersion      = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash  = protx;
    e.confirmedHash = confirmed;   // uint256() == null == "not yet confirmed"
    e.netPort       = 9999;
    e.isValid       = true;
    return e;
}

static MNState mn_state(uint32_t reg_height,
                        const std::vector<unsigned char>& payout) {
    MNState s;
    s.isValid            = true;
    s.nRegisteredHeight  = reg_height;
    s.nLastPaidHeight    = 0;
    s.scriptPayout.m_data = payout;
    return s;
}

// The fixture every test shares: MN1 long-confirmed, MN2 registered recently
// (registration height parameterized), both present in the DMN view.
struct Rig {
    uint256 protx1 = raw256(0x01);
    uint256 protx2 = raw256(0x02);
    uint256 prev_hash = raw256(0xAB);
    uint32_t prev_height = H - 1;
    CSimplifiedMNList sml;
    MnStateMachine mnstates;
    QuorumManager qmgr;
    Mempool mempool;

    explicit Rig(uint32_t mn2_reg_height, bool mn2_in_dmn_view = true) {
        std::vector<CSimplifiedMNListEntry> entries;
        entries.push_back(sml_entry(protx1, raw256(0x77)));  // confirmed long ago
        entries.push_back(sml_entry(protx2, uint256()));     // awaiting rollover
        sml = CSimplifiedMNList(std::move(entries));

        std::vector<std::pair<uint256, MNState>> dmn;
        dmn.emplace_back(protx1, mn_state(2'300'000, p2pkh_script(0x30)));
        if (mn2_in_dmn_view)
            dmn.emplace_back(protx2, mn_state(mn2_reg_height, p2pkh_script(0x44)));
        mnstates.load(std::move(dmn), prev_height);
    }

    DashWorkData build() {
        return build_embedded_workdata(
            prev_height, prev_hash, mnstates, mempool,
            /*bits=*/0x1b104be3u, /*mtp=*/1'700'000'000u,
            DASH_PUBKEY_VER, DASH_P2SH_VER,
            /*curtime=*/1'700'000'100u, /*version=*/0x20000000u,
            /*underfill_tripped=*/nullptr,
            &sml, &qmgr);
    }

    // INDEPENDENT reference: the list the verifier rebuilds for block
    // prev_height+1, copied by hand — MN2's confirmedHash set to prev_hash.
    uint256 reference_root_with_rollover() const {
        CSimplifiedMNList ref = sml;
        for (auto& e : ref.mnList)
            if (e.proRegTxHash == protx2) e.confirmedHash = prev_hash;
        return ref.CalcMerkleRoot();
    }

    uint256 tip_root() const {
        CSimplifiedMNList tip = sml;
        return tip.CalcMerkleRoot();
    }
};

// ════════════════════════════════════════════════════════════════════════
// FINDING-1 defect demonstrations — these MUST FAIL on pre-fix master
// (the builder committed the tip root verbatim; the emit gate re-approved
// the same stale root).
// ════════════════════════════════════════════════════════════════════════

// At the crossing height (prev - reg == 15 >= nMasternodeMinimumConfirmations
// = 15) the committed merkleRootMNList must be the PROJECTED root, not the
// tip root.
TEST(DashMnConfirmRollover, CrossingHeightCommitsProjectedRoot) {
    Rig rig(/*mn2_reg_height=*/H - 1 - DASH_MN_MIN_CONFIRMATIONS_MAINNET);
    auto w = rig.build();

    CCbTx cb;
    ASSERT_TRUE(parse_cbtx(w.m_coinbase_payload, cb));
    const uint256 expected = rig.reference_root_with_rollover();
    ASSERT_NE(expected, rig.tip_root())
        << "fixture defect: rollover must change the root or the test proves nothing";
    EXPECT_EQ(cb.merkleRootMNList, expected)
        << "block " << H << " must commit the confirmation-pass-projected root "
        << "(specialtxman.cpp:206-215), not the tip SML root";
}

// One block BEFORE the crossing (prev - reg == 14 < 15) nothing confirms and
// the tip root is exactly right — the projection must not over-fire.
TEST(DashMnConfirmRollover, BelowThresholdCommitsTipRootUnchanged) {
    Rig rig(/*mn2_reg_height=*/H - DASH_MN_MIN_CONFIRMATIONS_MAINNET);
    auto w = rig.build();

    CCbTx cb;
    ASSERT_TRUE(parse_cbtx(w.m_coinbase_payload, cb));
    EXPECT_EQ(cb.merkleRootMNList, rig.tip_root())
        << "below the threshold no confirmation fires; the tip root is correct";
}

// The pre-emit hard gate must REJECT a template that committed the stale tip
// root at a crossing height, and ACCEPT one committing the projected root.
// Pre-fix the gate compared against the SAME stale tip root, so the stale
// template passed — this test fails there.
TEST(DashMnConfirmRollover, EmitGateRejectsStaleTipRootAtCrossing) {
    Rig rig(/*mn2_reg_height=*/H - 1 - DASH_MN_MIN_CONFIRMATIONS_MAINNET);

    NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = rig.sml;
    st.set_have_sml(true);
    st.set_sml_current_hash(rig.prev_hash);
    st.mnstates().load({{rig.protx1, mn_state(2'300'000, p2pkh_script(0x30))},
                        {rig.protx2, mn_state(H - 1 - DASH_MN_MIN_CONFIRMATIONS_MAINNET,
                                              p2pkh_script(0x44))}},
                       rig.prev_height);
    st.set_tip(rig.prev_height, rig.prev_hash, 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    // A template whose CbTx commits the RAW TIP root (build_embedded_cbtx is
    // the raw encoder — no projection — so this reproduces the pre-fix
    // builder's output byte-for-byte).
    DashWorkData stale;
    {
        CCbTx cb = build_embedded_cbtx(rig.prev_height, rig.sml, st.qmgr(),
                                       0, std::array<uint8_t, 96>{}, 0, nullptr);
        stale.m_coinbase_payload = encode_cbtx(cb);
    }
    DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(stale, &why))
        << "the emit gate re-approved the stale tip root at a crossing height";
    EXPECT_EQ(why.cause, "emit-mnlist-root-drift");

    // The projected-root template must pass the same gate.
    DashWorkData good;
    {
        CSimplifiedMNList projected = rig.sml;
        for (auto& e : projected.mnList)
            if (e.proRegTxHash == rig.protx2) e.confirmedHash = rig.prev_hash;
        CCbTx cb = build_embedded_cbtx(rig.prev_height, projected, st.qmgr(),
                                       0, std::array<uint8_t, 96>{}, 0, nullptr);
        good.m_coinbase_payload = encode_cbtx(cb);
    }
    EXPECT_TRUE(st.embedded_template_emit_ok(good, &why))
        << "cause=" << why.cause << " value=" << why.value;
}

// Fail-closed fallback (posture (b)): an SML entry awaiting rollover whose
// registration height the DMN view does NOT hold makes the pass
// unprojectable — viability must refuse with the NAMED cause instead of
// serving a root it cannot verify. Pre-fix the bundle was fully viable here.
TEST(DashMnConfirmRollover, ViabilityFailsClosedWhenRegistrationHeightUnknown) {
    Rig rig(/*mn2_reg_height=*/0, /*mn2_in_dmn_view=*/false);

    NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = rig.sml;
    st.set_have_sml(true);
    st.set_sml_current_hash(rig.prev_hash);
    st.mnstates().load({{rig.protx1, mn_state(2'300'000, p2pkh_script(0x30))}},
                       rig.prev_height);
    st.set_tip(rig.prev_height, rig.prev_hash, 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    const DeclineReport d = st.describe_decline();
    EXPECT_FALSE(d.viable)
        << "an unprojectable rollover must refuse the embedded arm";
    EXPECT_EQ(d.cause, "mn-confirm-rollover-pending");

    // And the pre-emit gate independently refuses the same condition.
    DashWorkData w;
    {
        CCbTx cb = build_embedded_cbtx(rig.prev_height, rig.sml, st.qmgr(),
                                       0, std::array<uint8_t, 96>{}, 0, nullptr);
        w.m_coinbase_payload = encode_cbtx(cb);
    }
    DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(w, &why));
    EXPECT_EQ(why.cause, "emit-mn-confirm-rollover-pending");
}

// ════════════════════════════════════════════════════════════════════════
// Projection-helper unit KATs (structural — pin the pass semantics).
// ════════════════════════════════════════════════════════════════════════

TEST(DashMnConfirmRollover, ProjectionConfirmsAtExactThresholdOnly) {
    // Exactly at threshold: confirms with confirmedHash = prev_hash.
    {
        Rig rig(H - 1 - DASH_MN_MIN_CONFIRMATIONS_MAINNET);
        auto proj = project_sml_confirmations(rig.sml, rig.prev_height,
                                              rig.prev_hash, rig.mnstates);
        ASSERT_TRUE(proj.ok);
        EXPECT_EQ(proj.confirmed, 1u);
        EXPECT_EQ(proj.sml.CalcMerkleRoot(), rig.reference_root_with_rollover());
        // Already-confirmed entry untouched.
        for (const auto& e : proj.sml.mnList)
            if (e.proRegTxHash == rig.protx1)
                EXPECT_EQ(e.confirmedHash, raw256(0x77));
    }
    // One short of threshold: nothing confirms, list byte-identical.
    {
        Rig rig(H - DASH_MN_MIN_CONFIRMATIONS_MAINNET);
        auto proj = project_sml_confirmations(rig.sml, rig.prev_height,
                                              rig.prev_hash, rig.mnstates);
        ASSERT_TRUE(proj.ok);
        EXPECT_EQ(proj.confirmed, 0u);
        EXPECT_EQ(proj.sml.CalcMerkleRoot(), rig.tip_root());
    }
    // WELL past threshold with a still-null confirmedHash (desynced-view
    // shape): the verifier's pass confirms at the NEXT rebuild regardless —
    // mirror it exactly (>=, not ==).
    {
        Rig rig(H - 100);
        auto proj = project_sml_confirmations(rig.sml, rig.prev_height,
                                              rig.prev_hash, rig.mnstates);
        ASSERT_TRUE(proj.ok);
        EXPECT_EQ(proj.confirmed, 1u);
    }
}

TEST(DashMnConfirmRollover, ProjectionFailsClosedOnUnknownRegistration) {
    // Entry absent from the DMN view entirely.
    {
        Rig rig(0, /*mn2_in_dmn_view=*/false);
        EXPECT_TRUE(find_unprojectable_confirmation(rig.sml, rig.mnstates)
                        .has_value());
        auto proj = project_sml_confirmations(rig.sml, rig.prev_height,
                                              rig.prev_hash, rig.mnstates);
        EXPECT_FALSE(proj.ok);
        EXPECT_EQ(proj.unprojectable_protx, rig.protx2);
    }
    // Present but with the 0 "never" sentinel for registration height.
    {
        Rig rig(/*mn2_reg_height=*/0, /*mn2_in_dmn_view=*/true);
        EXPECT_TRUE(find_unprojectable_confirmation(rig.sml, rig.mnstates)
                        .has_value());
        EXPECT_FALSE(project_sml_confirmations(rig.sml, rig.prev_height,
                                               rig.prev_hash, rig.mnstates)
                         .ok);
    }
    // Fully-confirmed lists never consult registration heights at all.
    {
        Rig rig(H - 100);
        for (auto& e : rig.sml.mnList) e.confirmedHash = raw256(0x77);
        MnStateMachine empty;
        EXPECT_FALSE(find_unprojectable_confirmation(rig.sml, empty)
                         .has_value());
        EXPECT_TRUE(project_sml_confirmations(rig.sml, rig.prev_height,
                                              rig.prev_hash, empty)
                        .ok);
    }
}
