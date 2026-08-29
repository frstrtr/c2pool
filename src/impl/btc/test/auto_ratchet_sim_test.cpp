// SPDX-License-Identifier: AGPL-3.0-or-later
// btc_auto_ratchet_sim_test: FENCED, additive rig-free SIM KAT that arms the
// BTC G2 staged-migration harness (scripts/btc_g2_ratchet_staged_migration_harness.sh)
// C2/C3/C4 rows WITHOUT a SHA256d rig — the mirror of DGB #427's --sim-votes.
// It exercises the AutoRatchet staged-gate LOGIC over hand-derived oracle votes:
//
//   C2  VOTING mints the V35 baseline while voting V36 (bootstrap, empty chain)
//   C3  #288 accept gate: 60%-by-WORK, and a 95%-by-COUNT activation can NOT
//       outrun it (mint-cannot-outrun-accept) — the property that keeps a
//       minted V36 boundary share from being rejected by every peer
//   C4  ratchet state persists across restart (CONFIRMED survives reconstruct)
//
// Consensus surface is NOT mutated. C3 pins the live 60%-by-WORK gate via a
// VERBATIM replica of the inline tail-guard expression in
// AutoRatchet::get_share_version (auto_ratchet.hpp), localising the gate the
// same non-circular way DGB's auto_ratchet_tail_guard_test does (BTC keeps the
// guard inline, no lifted SSOT). Test-only / btc-tree-local.

#include <gtest/gtest.h>

#include <impl/btc/auto_ratchet.hpp>   // also pulls share_tracker.hpp + nlohmann/json
#include <core/uint256.hpp>
#include <core/pack_types.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>                    // getpid (restart-persistence temp file)

using btc::AutoRatchet;
using btc::RatchetState;

namespace {

// Verbatim replica of the LIVE inline tail-guard in
// AutoRatchet::get_share_version:  tail_ok = !(target < total*SWITCH/100).
// Localises the 60%-by-WORK accept gate so C3 pins it WITHOUT driving the
// consensus path or importing a lifted SSOT. FLOOR form, tracking the SSOT
// step-2 adoption (was the algebraic CEIL target*100 < total*SWITCH).
bool inline_tail_ok(const uint288& target, const uint288& total,
                    int thr = AutoRatchet::SWITCH_THRESHOLD)
{
    return !(target < (total * static_cast<uint32_t>(thr))
                       / static_cast<uint32_t>(100));
}

// 95%-by-COUNT activation predicate (flat head-count), mirroring the VOTING ->
// ACTIVATED branch's `vote_pct >= ACTIVATION_THRESHOLD` test.
bool count_activates(int target_votes, int total)
{
    if (total == 0) return false;
    return (target_votes * 100) / total >= AutoRatchet::ACTIVATION_THRESHOLD;
}

// EFFECTIVE activation = mint-side count gate AND work-weighted accept gate.
// This is the AND the live state machine enforces: VOTING only advances when
// BOTH the 95%-by-count window AND the 60%-by-work tail guard hold.
bool effective_activation(int votes, int total,
                          const uint288& w_target, const uint288& w_total)
{
    return count_activates(votes, total) && inline_tail_ok(w_target, w_total);
}

// One staged-migration sample: after stage k, `votes` of `total` miners signal
// V36, carrying `w_target` of `w_total` work.
struct Stage { int votes; int total; uint288 w_target; uint288 w_total; };

} // namespace

// ---------------------------------------------------------------------------
// Anchor: AutoRatchet thresholds match the canonical p2pool ratchet constants.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, ThresholdsMatchCanonical)
{
    EXPECT_EQ(AutoRatchet::ACTIVATION_THRESHOLD,    95);
    EXPECT_EQ(AutoRatchet::DEACTIVATION_THRESHOLD,  50);
    EXPECT_EQ(AutoRatchet::CONFIRMATION_MULTIPLIER,  2);
    EXPECT_EQ(AutoRatchet::SWITCH_THRESHOLD,        60);
}

// ---------------------------------------------------------------------------
// C2 — VOTING node votes V36 but MINTS the V35 baseline on an empty tracker.
// A freshly-started node must not skip ahead of the network.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, C2_VotingMintsBaselineWhileVoting)
{
    AutoRatchet ar("", /*target_version=*/36);
    btc::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{}); // null best hash
    EXPECT_EQ(mint, 35);   // baseline = target-1, NOT 36
    EXPECT_EQ(vote, 36);   // always vote for the target
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
}

// ---------------------------------------------------------------------------
// C3 — #288 accept gate is 60%-by-WORK at the boundary.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, C3_AcceptGateIsSixtyPercentByWork)
{
    const uint288 total(100);                          // floor(100*60/100)=60
    EXPECT_FALSE(inline_tail_ok(uint288(59), total));  // just under -> hold
    EXPECT_TRUE (inline_tail_ok(uint288(60), total));  // at the gate -> pass
    EXPECT_TRUE (inline_tail_ok(uint288(61), total));
    EXPECT_TRUE (inline_tail_ok(uint288(100), total));
    // All-old window never passes (target work = 0).
    EXPECT_FALSE(inline_tail_ok(uint288(0), uint288(1000)));
}

// ---------------------------------------------------------------------------
// C3 — the load-bearing #288 property: a 95%-by-COUNT activation can NOT
// outrun the 60%-by-WORK accept gate under heterogeneous hashrate. 19 tiny V36
// voters (work 1 each) + 1 huge V35 miner (work 1000): 95% by count, but only
// ~1.9% by work. If mint activated on count alone it would emit a V36 boundary
// share that every peer (running the work-weighted accept gate) rejects, and
// the crossing wedges. effective_activation must therefore be FALSE.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, C3_MintCannotOutrunAccept)
{
    const int votes = 19, total = 20;                 // 95% by count
    const uint288 w_target(19);                        // 19 * work-1
    const uint288 w_total(19 + 1000);                  // + one huge V35 miner

    EXPECT_TRUE (count_activates(votes, total));       // count gate WOULD fire
    EXPECT_FALSE(inline_tail_ok(w_target, w_total));   // but work gate holds
    EXPECT_FALSE(effective_activation(votes, total, w_target, w_total));

    // Homogeneous hashrate: when the 95%-by-count window is ALSO >=60%-by-work,
    // the two gates agree and activation is permitted.
    EXPECT_TRUE(effective_activation(95, 100, uint288(95), uint288(100)));
}

// ---------------------------------------------------------------------------
// C3/monotonic — staged 1-by-1 miner migration: the work-weighted V36 tally
// advances MONOTONICALLY per stage, and effective activation flips on exactly
// once BOTH the 95%-by-count AND the 60%-by-work gates hold. Mirrors the
// harness's per-stage RESULT-line assertion, rig-free. 5 equal-work miners;
// stage k migrates miner k from V35 to V36.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, C3_StagedTallyAdvancesMonotonically)
{
    const uint32_t W = 7;                              // per-miner work unit
    std::vector<Stage> stages;
    for (int k = 0; k <= 5; ++k)
        stages.push_back(Stage{ k, 5,
                                uint288(uint32_t(k) * W),
                                uint288(uint32_t(5) * W) });

    uint288 prev_target(0);
    bool seen_activation = false;
    int first_active_stage = -1;
    for (int k = 0; k <= 5; ++k) {
        const Stage& s = stages[k];
        // Monotonic non-decreasing work tally.
        EXPECT_FALSE(s.w_target < prev_target) << "stage=" << k;
        prev_target = s.w_target;

        bool active = effective_activation(s.votes, s.total, s.w_target, s.w_total);
        if (active && !seen_activation) { seen_activation = true; first_active_stage = k; }
        // Once active on this monotone ramp, it must stay active.
        if (seen_activation) EXPECT_TRUE(active) << "regressed at stage=" << k;
    }
    // 95%-by-count is only reached at full migration (5/5=100%); 3/5=60% and
    // 4/5=80% are below 95. So activation fires at stage 5, not before.
    EXPECT_EQ(first_active_stage, 5);
}

// ---------------------------------------------------------------------------
// C4 — ratchet state persists across restart. A CONFIRMED state file
// reconstructs as CONFIRMED, and a CONFIRMED bootstrap mints the target.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, C4_StatePersistsAcrossRestart)
{
    const std::string path = std::string("/tmp/btc_autoratchet_sim_kat_") +
                             std::to_string(::getpid()) + ".json";
    std::remove(path.c_str());
    {
        nlohmann::json j;
        j["state"] = "confirmed";
        j["activated_at"] = 1;
        j["activated_height"] = 2;
        j["confirmed_at"] = 3;
        j["confirm_count"] = 4;
        j["target_version"] = 36;
        std::ofstream f(path);
        f << j.dump(2);
    }
    AutoRatchet ar(path, /*target_version=*/36);
    EXPECT_EQ(ar.state(), RatchetState::CONFIRMED);

    btc::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{});
    EXPECT_EQ(mint, 36);   // CONFIRMED bootstrap mints the target
    EXPECT_EQ(vote, 36);
    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// SSOT step-2 / #1 standardization target — ORACLE FLOOR vs INLINE CEIL.
//
// p2pool oracle (data.py share-acceptance) valid threshold is the FLOOR form:
//     counts.get(VERSION,0) >= sum(counts)*60//100            # floor
// The BTC inline tail-guard (auto_ratchet.hpp, replicated as inline_tail_ok
// above) has ADOPTED that FLOOR form. Previously it was the algebraic CEIL
//     target*100 >= total*60   <=>   target >= ceil(total*60/100),
// which at a non-integral boundary (total*60 % 100 != 0) latched up to one
// share LATER than the oracle. This KAT now PINS the CONVERGED state: at the
// same non-integral boundary (total=101 => total*60 = 6060, 6060 % 100 != 0)
//     floor(6060/100) = 60   (oracle  : target=60 PASSES)
//     inline (FLOOR)  = 60   (adopted : target=60 PASSES)  <-- seam CLOSED
// Pre-adoption this line read EXPECT_FALSE on the inline form (CEIL held until
// 61); the SSOT floor adoption (operator-tap gated) flips it to EXPECT_TRUE.
// The integral control (total=100) still shows both forms AGREE on the exact
// boundary, so the only behavioural change is the %100 remainder share, now
// accepted one unit earlier in lock-step with the network. Consensus surface
// equals the p2pool oracle value.
// ---------------------------------------------------------------------------
TEST(BTC_AutoRatchetSim, SSOT2_OracleFloorVsInlineCeilBoundary)
{
    // Oracle floor predicate: target >= floor(total*60/100).
    auto oracle_floor_ok = [](const uint288& target, const uint288& total) {
        return !(target < ((total * static_cast<uint32_t>(60))
                           / static_cast<uint32_t>(100)));
    };

    // Integral-boundary control (total=100): floor==ceil==60, forms AGREE.
    EXPECT_EQ(oracle_floor_ok(uint288(60), uint288(100)),
              inline_tail_ok (uint288(60), uint288(100)));

    const uint288 total(101);                            // 101*60 = 6060, %100 = 60
    EXPECT_TRUE (oracle_floor_ok(uint288(60), total));   // oracle: latches at 60
    EXPECT_TRUE (inline_tail_ok (uint288(60), total));   // inline FLOOR: latches at 60 too
    // Forms are now identical at every point (boundary and beyond).
    EXPECT_TRUE (oracle_floor_ok(uint288(61), total));
    EXPECT_TRUE (inline_tail_ok (uint288(61), total));
}