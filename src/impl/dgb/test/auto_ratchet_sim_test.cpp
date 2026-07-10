// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb_auto_ratchet_sim_test: FENCED, additive rig-free SIM KAT that arms the
// DGB G2 staged-migration harness
// (scripts/dgb_g2_ratchet_staged_migration_harness.sh) C2/C3/C4/C5 rows WITHOUT
// a Scrypt rig or a live digibyted parent -- the C++ counterpart of that
// harness's --sim-votes path. It exercises the AutoRatchet staged-gate LOGIC
// over hand-derived oracle votes:
//
//   C2  VOTING mints the DGB BASELINE while voting V36 (bootstrap, empty chain)
//   C3  #288 accept gate: 60%-by-WORK, and a 95%-by-COUNT activation can NOT
//       outrun it (mint-cannot-outrun-accept) -- the property that keeps a
//       minted V36 boundary share from being rejected by every peer
//   C4  ratchet state persists across restart (CONFIRMED survives reconstruct)
//   C5  SCRYPT-ONLY / 4-algos-by-continuity posture (project_v36_dgb_scrypt_only):
//       only Scrypt headers are validated; the other algos accept-by-continuity
//       (work-NEUTRAL) and so cannot move the 60%-by-work ratchet accept gate
//
// DGB ORACLE PIN (NOT the LTC v35 transition): DGB conforms to its OWN oracle
// frstrtr/p2pool-dgb-scrypt @22761e7, which mints share VERSION=35 with
// SUCCESSOR=None (data.py:636) -- a TERMINAL v35 baseline. So the VOTING-state
// output is base_version=35 (an explicit constructor parameter on DGB's port,
// NOT the ltc hardcode target-1), and the transition under test is DGB's own
// 35 -> v36, backward-compatible with that baseline during the crossing window.
//
// Consensus surface is NOT mutated. C3 pins the live 60%-by-WORK gate via a
// VERBATIM replica of the inline tail-guard expression in
// AutoRatchet::get_share_version (auto_ratchet.hpp), localising the gate the
// same non-circular way dgb_auto_ratchet_tail_guard_test does. C5 pins the
// multi-algo disposition against the consensus SSOT coin/dgb_block_algo.hpp
// (itself guarded vs upstream DigiByte Core by algo_select_test). Test-only /
// dgb-tree-local.

#include <gtest/gtest.h>

#include <impl/dgb/auto_ratchet.hpp>   // also pulls share_tracker.hpp + config_pool.hpp
#include <impl/dgb/coin/dgb_block_algo.hpp> // dgb_header_disposition, is_scrypt_header
#include <core/uint256.hpp>            // uint288

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>                    // getpid (restart-persistence temp file)

using dgb::AutoRatchet;
using dgb::RatchetState;
using dgb::coin::DgbAlgo;
using dgb::coin::HeaderDisposition;
using dgb::coin::dgb_header_disposition;
using dgb::coin::is_scrypt_header;

namespace {

// DGB oracle baseline: terminal v35, SUCCESSOR=None (p2pool-dgb-scrypt
// data.py:636). The ratchet mints this while VOTING and votes for the target.
constexpr int64_t DGB_BASE_VERSION   = 35;
constexpr int64_t DGB_TARGET_VERSION = 36;

// Verbatim replica of the LIVE inline work-weighted tail guard in
// AutoRatchet::get_share_version:
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

// One staged-migration block AS SEEN BY THE CROSSING: which algo mined it (DGB
// nVersion algo bits), whether it votes V36, and how much PoW work it carries.
// The G2 work-weighted accept gate credits work ONLY for Scrypt blocks; a
// non-Scrypt block is accept-by-continuity == work-NEUTRAL (coin/header_chain.hpp
// THIRD INVARIANT), so its work NEVER enters the ratchet tally however it votes.
struct AlgoBlock { int32_t n_version; bool votes_v36; uint32_t work; };

// Work this block credits to the V36 accept tally: the Scrypt-only,
// work-neutral-continuity posture localised for the sim. Mirrors
// header_credits_work() forwarding to is_scrypt_header().
uint288 scrypt_v36_work_credit(const AlgoBlock& b)
{
    return (is_scrypt_header(b.n_version) && b.votes_v36) ? uint288(b.work)
                                                          : uint288(0);
}
// Work this block credits to the gate denominator: again Scrypt-only, since a
// continuity header widens neither numerator nor denominator of the tail guard.
uint288 scrypt_total_work_credit(const AlgoBlock& b)
{
    return is_scrypt_header(b.n_version) ? uint288(b.work) : uint288(0);
}

} // namespace

// ---------------------------------------------------------------------------
// Anchor: AutoRatchet thresholds match the canonical p2pool ratchet constants
// (bucket-2 v36-native shared structure, standardized cross-coin).
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, ThresholdsMatchCanonical)
{
    EXPECT_EQ(AutoRatchet::ACTIVATION_THRESHOLD,    95);
    EXPECT_EQ(AutoRatchet::DEACTIVATION_THRESHOLD,  50);
    EXPECT_EQ(AutoRatchet::CONFIRMATION_MULTIPLIER,  2);
    EXPECT_EQ(AutoRatchet::SWITCH_THRESHOLD,        60);
}

// ---------------------------------------------------------------------------
// C2 — VOTING node votes V36 but MINTS the DGB baseline (v35, SUCCESSOR=None)
// on an empty tracker. A freshly-started node must not skip ahead of the
// network. Pins DGB's OWN oracle baseline, not the ltc target-1 hardcode.
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, C2_VotingMintsBaselineWhileVoting)
{
    AutoRatchet ar("", DGB_TARGET_VERSION, DGB_BASE_VERSION);
    dgb::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{}); // null best hash
    EXPECT_EQ(mint, DGB_BASE_VERSION);    // baseline = oracle v35, NOT 36
    EXPECT_EQ(vote, DGB_TARGET_VERSION);  // always vote for the target
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
    EXPECT_EQ(ar.base_version(), DGB_BASE_VERSION);
}

// ---------------------------------------------------------------------------
// C3 — #288 accept gate is 60%-by-WORK at the boundary.
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, C3_AcceptGateIsSixtyPercentByWork)
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
TEST(DGB_AutoRatchetSim, C3_MintCannotOutrunAccept)
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
TEST(DGB_AutoRatchetSim, C3_StagedTallyAdvancesMonotonically)
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
// DGB baseline is carried by the constructor, not the JSON, so a restarted
// CONFIRMED node mints V36 regardless of its v35 base.
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, C4_StatePersistsAcrossRestart)
{
    const std::string path = std::string("/tmp/dgb_autoratchet_sim_kat_") +
                             std::to_string(::getpid()) + ".json";
    std::remove(path.c_str());
    {
        nlohmann::json j;
        j["state"] = "confirmed";
        j["activated_at"] = 1;
        j["activated_height"] = 2;
        j["confirmed_at"] = 3;
        j["confirm_count"] = 4;
        std::ofstream f(path);
        f << j.dump(2);
    }
    AutoRatchet ar(path, DGB_TARGET_VERSION, DGB_BASE_VERSION);
    EXPECT_EQ(ar.state(), RatchetState::CONFIRMED);

    dgb::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{});
    EXPECT_EQ(mint, DGB_TARGET_VERSION);   // CONFIRMED bootstrap mints the target
    EXPECT_EQ(vote, DGB_TARGET_VERSION);
    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// C4/baseline — a fresh (VOTING) node with NO state file mints the DGB v35
// baseline on bootstrap, the mirror of the CONFIRMED case: persistence is what
// distinguishes "produce baseline" from "produce target" across a restart.
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, C4_FreshNodeMintsBaselineOnBootstrap)
{
    AutoRatchet ar("", DGB_TARGET_VERSION, DGB_BASE_VERSION);
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
    dgb::ShareTracker tracker;
    auto [mint, vote] = ar.get_share_version(tracker, uint256{});
    EXPECT_EQ(mint, DGB_BASE_VERSION);
    EXPECT_EQ(vote, DGB_TARGET_VERSION);
}

// ---------------------------------------------------------------------------
// C5 — SCRYPT-ONLY POSTURE PIN (project_v36_dgb_scrypt_only). V36 c2pool-dgb
// validates the SCRYPT path ONLY; the V36-deferred algos accept-by-continuity;
// unknown algo bits reject. Mirrors the per-header disposition the harness C5
// row exercises against the consensus SSOT coin/dgb_block_algo.hpp (itself
// guarded vs upstream DigiByte Core block.h by algo_select_test).
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, C5_ScryptOnlyPostureDisposition)
{
    using dgb::coin::DGB_BLOCK_VERSION_SCRYPT;
    using dgb::coin::DGB_BLOCK_VERSION_SHA256D;
    using dgb::coin::DGB_BLOCK_VERSION_GROESTL;
    using dgb::coin::DGB_BLOCK_VERSION_SKEIN;
    using dgb::coin::DGB_BLOCK_VERSION_QUBIT;
    using dgb::coin::DGB_BLOCK_VERSION_ODO;

    // Scrypt is the all-zero algo codepoint -> the ONLY validated PoW lane.
    EXPECT_TRUE(is_scrypt_header(DGB_BLOCK_VERSION_SCRYPT));
    EXPECT_EQ(dgb_header_disposition(DGB_BLOCK_VERSION_SCRYPT),
              HeaderDisposition::VALIDATE_SCRYPT);

    // The four V36-deferred algos (SHA256d, Skein, Qubit, Odocrypt) and legacy
    // Groestl accept-by-continuity (work-neutral) -- NOT validate, NOT reject.
    for (int32_t v : { DGB_BLOCK_VERSION_SHA256D, DGB_BLOCK_VERSION_SKEIN,
                       DGB_BLOCK_VERSION_QUBIT,   DGB_BLOCK_VERSION_ODO,
                       DGB_BLOCK_VERSION_GROESTL }) {
        EXPECT_FALSE(is_scrypt_header(v));
        EXPECT_EQ(dgb_header_disposition(v),
                  HeaderDisposition::ACCEPT_BY_CONTINUITY) << "version_bits=" << v;
    }

    // Algo nibbles NOT in the DGB map (1/3/5/7/9/15 << 8) reject. Note 7<<8 is
    // unknown: ALGO_ODO==7 in the id space but BLOCK_VERSION_ODO encodes 14<<8.
    for (int32_t sel : { 1, 3, 5, 7, 9, 15 }) {
        EXPECT_EQ(dgb_header_disposition(sel << 8),
                  HeaderDisposition::REJECT) << "algo_nibble=" << sel;
    }
}

// ---------------------------------------------------------------------------
// C5/work-neutral — the load-bearing G2 intersection of the Scrypt-only
// posture with the #288 accept gate: accept-by-continuity non-Scrypt blocks are
// WORK-NEUTRAL, so they cannot move the 60%-by-work ratchet accept gate however
// they vote. A crossing whose V36 vote MAJORITY (>=95% by head-count) is carried
// by non-Scrypt algos credits ZERO V36 work; the Scrypt work tally still decides
// the gate. This is the multi-algo analogue of C3_MintCannotOutrunAccept and is
// what stops a SHA256d/Skein/Qubit/Odo majority from spoofing a Scrypt-sharechain
// v35 -> v36 activation.
// ---------------------------------------------------------------------------
TEST(DGB_AutoRatchetSim, C5_ContinuityVotesCannotOutrunScryptWorkGate)
{
    using dgb::coin::DGB_BLOCK_VERSION_SCRYPT;
    using dgb::coin::DGB_BLOCK_VERSION_SHA256D;
    using dgb::coin::DGB_BLOCK_VERSION_SKEIN;
    using dgb::coin::DGB_BLOCK_VERSION_QUBIT;
    using dgb::coin::DGB_BLOCK_VERSION_ODO;

    std::vector<AlgoBlock> blocks;
    blocks.push_back({ DGB_BLOCK_VERSION_SCRYPT, /*votes_v36*/false, 1000 }); // lone Scrypt V35
    const int32_t non_scrypt[4] = { DGB_BLOCK_VERSION_SHA256D, DGB_BLOCK_VERSION_SKEIN,
                                    DGB_BLOCK_VERSION_QUBIT,   DGB_BLOCK_VERSION_ODO };
    for (int i = 0; i < 19; ++i)
        blocks.push_back({ non_scrypt[i % 4], /*votes_v36*/true, 50 }); // non-Scrypt V36 voters

    uint288 w_target(0), w_total(0);
    int v36 = 0, total = 0;
    for (const auto& b : blocks) {
        w_target = w_target + scrypt_v36_work_credit(b);
        w_total  = w_total  + scrypt_total_work_credit(b);
        if (b.votes_v36) ++v36;
        ++total;
    }
    EXPECT_EQ(total, 20);
    EXPECT_EQ(v36, 19);
    EXPECT_TRUE(count_activates(v36, total));        // 19/20 = 95% -> count gate WOULD fire
    EXPECT_TRUE(w_target == uint288(0));             // but every V36 vote is continuity
    EXPECT_TRUE(w_total  == uint288(1000));          // only the lone Scrypt block credits work
    EXPECT_FALSE(inline_tail_ok(w_target, w_total));            // work gate holds
    EXPECT_FALSE(effective_activation(v36, total, w_target, w_total)); // crossing blocked

    // Flip the lone Scrypt miner to V36: now 100% of the CREDITED (Scrypt) work
    // is V36 and the work gate passes -- only Scrypt votes ever move the gate.
    blocks[0].votes_v36 = true;
    uint288 w_t2(0), w_all2(0);
    for (const auto& b : blocks) {
        w_t2   = w_t2   + scrypt_v36_work_credit(b);
        w_all2 = w_all2 + scrypt_total_work_credit(b);
    }
    EXPECT_TRUE(w_t2   == uint288(1000));
    EXPECT_TRUE(w_all2 == uint288(1000));
    EXPECT_TRUE(inline_tail_ok(w_t2, w_all2));       // Scrypt work now 100% V36 -> gate passes
}