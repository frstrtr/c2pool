// SPDX-License-Identifier: AGPL-3.0-or-later
// ltc_auto_ratchet_sim_test: FENCED, additive rig-free SIM KAT that arms the
// LTC G2 staged-migration harness
// (scripts/ltc_g2_crossing_staged_migration_harness.sh) crossing rows WITHOUT
// a Scrypt rig or a live litecoind parent -- the C++ counterpart of that
// harness's staged-vote path. It exercises the AutoRatchet staged-gate LOGIC
// over hand-derived oracle votes:
//
//   C2  VOTING mints the LTC BASELINE (v35) while voting V36 (bootstrap, empty
//       chain) -- a freshly-started node must not skip ahead of the network
//   C3  #288 accept gate: 60%-by-WORK, and a 95%-by-COUNT activation can NOT
//       outrun it (mint-cannot-outrun-accept) -- the property that keeps a
//       minted V36 boundary share from being rejected by every peer
//   C3  staged 1-by-1 miner migration: the work-weighted V36 tally advances
//       MONOTONICALLY and effective activation flips on exactly once BOTH the
//       95%-by-count AND the 60%-by-work gates hold (the crossing-dynamics proof)
//   C4  ratchet state persists across restart (CONFIRMED survives reconstruct;
//       a fresh VOTING node mints the v35 baseline on bootstrap)
//
// LTC ORACLE PIN: LTC is the V36 REFERENCE impl and transitions its own
// v35 -> v36 against frstrtr/p2pool-merged-v36. Unlike dgb (an explicit
// base_version constructor parameter over a terminal-v35 oracle), LTC DERIVES
// the minted baseline inline as `current_version = target_version_ - 1`
// (auto_ratchet.hpp get_share_version), so the VOTING bootstrap mints 35 and
// the CONFIRMED bootstrap mints 36 with only the 2-arg ctor. LTC is also
// SINGLE-ALGO (Scrypt PoW), so this port carries NO multi-algo disposition case
// (dgb's C5 scrypt-only-by-continuity) -- every LTC share credits Scrypt work.
//
// Consensus surface is NOT mutated. C3 pins the live 60%-by-WORK gate via a
// VERBATIM replica of the inline tail-guard expression in
// AutoRatchet::get_share_version (auto_ratchet.hpp:171), localising the gate the
// same non-circular way the dgb sim/tail-guard KATs do. This target joins the
// existing `share_test` executable (already on the build.yml --target allowlist)
// so it cannot become a #143 NOT_BUILT sentinel. Test-only / ltc-tree-local.

#include <gtest/gtest.h>

#include <impl/ltc/auto_ratchet.hpp>   // also pulls share_tracker.hpp + config_pool.hpp
#include <core/uint256.hpp>            // uint288

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>                    // getpid (restart-persistence temp file)

using ltc::AutoRatchet;
using ltc::RatchetState;

namespace {

// LTC oracle: v35 -> v36 reference transition. The ratchet mints the v35
// baseline while VOTING and votes for the target. LTC derives the baseline as
// target-1 inline (no base_version ctor param), so BASE == TARGET - 1 here too.
constexpr int64_t LTC_TARGET_VERSION = 36;
constexpr int64_t LTC_BASE_VERSION   = LTC_TARGET_VERSION - 1;  // 35

// Verbatim replica of the LIVE inline work-weighted tail guard in
// AutoRatchet::get_share_version (auto_ratchet.hpp:171):
//   tail_ok = !(tail_target * uint32_t(100) < tail_total * uint32_t(SWITCH));
// Localises the 60%-by-WORK accept gate so C3 pins it WITHOUT driving the
// consensus path or importing a lifted SSOT. uint288 = work-weight accumulator.
bool inline_tail_ok(const uint288& target, const uint288& total,
                    int thr = AutoRatchet::SWITCH_THRESHOLD)
{
    return !((target * static_cast<uint32_t>(100)) <
             (total  * static_cast<uint32_t>(thr)));
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
// Anchor: AutoRatchet thresholds match the canonical p2pool ratchet constants
// (bucket-2 v36-native shared structure, standardized cross-coin).
// ---------------------------------------------------------------------------
TEST(LTC_AutoRatchetSim, ThresholdsMatchCanonical)
{
    EXPECT_EQ(AutoRatchet::ACTIVATION_THRESHOLD,    95);
    EXPECT_EQ(AutoRatchet::DEACTIVATION_THRESHOLD,  50);
    EXPECT_EQ(AutoRatchet::CONFIRMATION_MULTIPLIER,  2);
    EXPECT_EQ(AutoRatchet::SWITCH_THRESHOLD,        60);
}

// ---------------------------------------------------------------------------
// C2 — VOTING node votes V36 but MINTS the LTC baseline (v35 = target-1) on an
// empty tracker. A freshly-started node must not skip ahead of the network.
// ---------------------------------------------------------------------------
TEST(LTC_AutoRatchetSim, C2_VotingMintsBaselineWhileVoting)
{
    AutoRatchet ar("", LTC_TARGET_VERSION);
    ltc::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{}); // null best hash
    EXPECT_EQ(mint, LTC_BASE_VERSION);    // baseline = v35 (target-1), NOT 36
    EXPECT_EQ(vote, LTC_TARGET_VERSION);  // always vote for the target
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
    EXPECT_EQ(ar.target_version(), LTC_TARGET_VERSION);
}

// ---------------------------------------------------------------------------
// C3 — #288 accept gate is 60%-by-WORK at the boundary.
// ---------------------------------------------------------------------------
TEST(LTC_AutoRatchetSim, C3_AcceptGateIsSixtyPercentByWork)
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
TEST(LTC_AutoRatchetSim, C3_MintCannotOutrunAccept)
{
    const int votes = 19, total = 20;                  // 95% by count
    const uint288 w_target(19);                         // 19 * work-1
    const uint288 w_total(19 + 1000);                   // + one huge V35 miner

    EXPECT_TRUE (count_activates(votes, total));        // count gate WOULD fire
    EXPECT_FALSE(inline_tail_ok(w_target, w_total));    // but work gate holds
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
TEST(LTC_AutoRatchetSim, C3_StagedTallyAdvancesMonotonically)
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
// reconstructs as CONFIRMED, and a CONFIRMED bootstrap mints the target. The
// baseline is derived from target_version, not the JSON, so a restarted
// CONFIRMED node mints V36 regardless of its v35 base.
// ---------------------------------------------------------------------------
TEST(LTC_AutoRatchetSim, C4_StatePersistsAcrossRestart)
{
    const std::string path = std::string("/tmp/ltc_autoratchet_sim_kat_") +
                             std::to_string(::getpid()) + ".json";
    std::remove(path.c_str());
    {
        nlohmann::json j;
        j["state"] = "confirmed";
        j["activated_at"] = 1;
        j["activated_height"] = 2;
        j["confirmed_at"] = 3;
        j["confirm_count"] = 4;
        j["target_version"] = LTC_TARGET_VERSION;
        std::ofstream f(path);
        f << j.dump(2);
    }
    AutoRatchet ar(path, LTC_TARGET_VERSION);
    EXPECT_EQ(ar.state(), RatchetState::CONFIRMED);

    ltc::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{});
    EXPECT_EQ(mint, LTC_TARGET_VERSION);   // CONFIRMED bootstrap mints the target
    EXPECT_EQ(vote, LTC_TARGET_VERSION);
    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// C4/baseline — a fresh (VOTING) node with NO state file mints the LTC v35
// baseline on bootstrap, the mirror of the CONFIRMED case: persistence is what
// distinguishes "produce baseline" from "produce target" across a restart.
// ---------------------------------------------------------------------------
TEST(LTC_AutoRatchetSim, C4_FreshNodeMintsBaselineOnBootstrap)
{
    AutoRatchet ar("", LTC_TARGET_VERSION);
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
    ltc::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{});
    EXPECT_EQ(mint, LTC_BASE_VERSION);
    EXPECT_EQ(vote, LTC_TARGET_VERSION);
}

// ---------------------------------------------------------------------------
// C7/lock-once-buried — REGRESSION for the 2026-07-14 contabo PROD ratchet
// incident (LTC pool). This is the acceptance gate for the persist-activation /
// lock-once-buried fix; DISABLED_ so it does not red CI before that fix lands —
// flip the prefix off in the SAME commit as the fix.
//
// PROD FACTS: v36 activated 2026-07-11 12:30:44 (95%-by-count) and ran ~3.7d
// with the confirmation depth buried far past the 2x lock window
// (confirm_count=47331 >= confirmation_window=17280, ~2.7x); DOA ~0% and zero
// invalid-version / bad-parent rejects the whole window — the network had
// genuinely crossed. It then reverted IN-PROCESS 2026-07-14 12:23:38 on a
// single full-window tick whose desired_version tally dipped to 49% (< the 50%
// DEACTIVATION_THRESHOLD), which reset confirm_count_ to 0 and re-minted v35.
//
// ROOT CAUSE (auto_ratchet.hpp, ACTIVATED branch): the deactivation test
//     if (full_window && vote_pct < DEACTIVATION_THRESHOLD) -> revert to VOTING
// is evaluated BEFORE the buried-promotion test (which lives in the trailing
// `else if (activated_height_ > 0)` arm). So a buried activation — one whose
// confirm_count_ has already passed confirmation_window and is thus eligible to
// become permanent CONFIRMED — is still reverted by a transient sub-50% *vote*
// dip, even though the actual *share format* (share_pct) is ~100%. Activation
// is therefore not monotone: it can regress after being buried. That is the
// GLM section-C monotonicity violation.
//
// INVARIANT this KAT pins (lock-once-buried): once confirm_count_ >=
// confirmation_window AND the window is still >= ACTIVATION_THRESHOLD in ACTUAL
// v36-format shares (share_pct), the ratchet is buried and MUST lock to
// CONFIRMED — a vote-only dip below 50% cannot revert it.
//
// This drives the REAL AutoRatchet state machine over a REAL ShareTracker (no
// replica of the branch under test), so it flips from failing to passing
// exactly when the buried-promotion is ordered ahead of the deactivation
// revert. FIX ownership = v37-dev-steward. Production code is NOT touched here.
// ---------------------------------------------------------------------------
TEST(LTC_AutoRatchetSim, DISABLED_C7_BuriedActivationLocksDespiteVoteDip)
{
    // Lighter fixture: testnet chain_length = 400 (vs 8640 mainnet), same logic.
    const bool saved_testnet = ltc::PoolConfig::is_testnet;
    ltc::PoolConfig::is_testnet = true;
    struct RestoreNet {
        bool v;
        ~RestoreNet() { ltc::PoolConfig::is_testnet = v; }
    } restore_net{saved_testnet};

    const uint32_t CL = ltc::PoolConfig::chain_length();                     // 400
    const uint32_t confirmation_window =
        CL * static_cast<uint32_t>(AutoRatchet::CONFIRMATION_MULTIPLIER);    // 800

    // Persisted ACTIVATED state, buried ~2.7x past the lock window (the prod
    // 47331/17280 ratio), mirroring the incident's on-disk ratchet state.
    const std::string path = std::string("/tmp/ltc_autoratchet_c7_kat_") +
                             std::to_string(::getpid()) + ".json";
    std::remove(path.c_str());
    {
        nlohmann::json j;
        j["state"] = "activated";
        j["activated_at"] = int64_t(1);
        j["activated_height"] = int32_t(1);
        j["confirm_count"] = int32_t(confirmation_window * 27 / 10);         // ~2.7x buried
        j["target_version"] = LTC_TARGET_VERSION;
        std::ofstream(path) << j.dump();
    }

    AutoRatchet ar(path, LTC_TARGET_VERSION);
    ASSERT_EQ(ar.state(), RatchetState::ACTIVATED) << "state file did not load as ACTIVATED";

    // A full window (>= chain_length) of REAL v36-format shares whose
    // *desired_version* has dipped to exactly 49% (any contiguous 400-window is
    // 4x the mod-100 cycle => 49% vote V36 < the 50% deactivation gate), while
    // every share is ACTUALLY v36 format (static version 36 => share_pct = 100%
    // >= ACTIVATION_THRESHOLD, so the buried-promotion precondition holds).
    ltc::ShareTracker tracker;
    std::vector<In> shares;
    const uint32_t N = CL + 5;
    for (uint32_t i = 0; i < N; ++i) {
        const uint64_t dv = ((i % 100u) < 49u) ? uint64_t(LTC_TARGET_VERSION)
                                               : uint64_t(LTC_BASE_VERSION);
        shares.push_back(In{ dv, 0x1d00ffff });
    }
    const uint256 tip = seed_tracker(tracker, shares);

    auto [mint, vote] = ar.get_share_version(tracker, tip);
    EXPECT_EQ(vote, LTC_TARGET_VERSION);   // still votes the target regardless

    // INVARIANT: a buried activation locks to CONFIRMED and keeps minting v36.
    // CURRENT (buggy) behaviour reverts to VOTING and re-mints v35 (the prod
    // incident); both EXPECTs below fail until lock-once-buried lands.
    EXPECT_EQ(ar.state(), RatchetState::CONFIRMED)
        << "buried activation (confirm_count >= " << confirmation_window
        << ") regressed to VOTING on a vote-only sub-50% dip — prod incident 2026-07-14";
    EXPECT_EQ(mint, LTC_TARGET_VERSION)
        << "reverted node re-minted the v35 baseline after burial";

    std::remove(path.c_str());
}
