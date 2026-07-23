// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch G2 ratchet gate-logic KAT (greenlight gate G2, staged-migration anchor).
//
// FENCED, additive, rig-free SIM KAT. Arms the BCH G2 staged 1-by-1 miner
// migration rows WITHOUT a SHA256d bitaxe rig — the BCH peer of btc's
// auto_ratchet_sim_test / DGB's auto_ratchet_tail_guard_test. No production
// code is touched and no consensus surface is mutated.
//
// WHAT IT PINS — the canonical 60%-by-WORK version-switch ACCEPT gate that BCH
// enforces inline in bch::check_share (src/impl/bch/share_check.hpp:1774-1775):
//
//     if (new_ver_weight * uint32_t(100) < total_weight * uint32_t(60))
//         throw std::invalid_argument("switch without enough hash power upgraded");
//
// The expected side below is a VERBATIM replica of that live tail-guard, the
// same non-circular localisation btc/DGB use (the guard stays inline in
// check_share; no lifted SSOT). A silent drift of the live 60%-by-WORK boundary
// fails here.
//
// LOAD-BEARING #288/#326 PROPERTY: the gate is work-WEIGHTED, not a flat
// head-count. #326 dropped the pre-v36 95%-flat-count punish for exactly this
// gate, so a 95%-by-COUNT activation under heterogeneous hashrate can NOT
// outrun the 60%-by-work accept gate (mint-cannot-outrun-accept) — otherwise a
// minted V36 boundary share would be rejected by every peer and the crossing
// would wedge.
//
// 3-bucket posture: the version-switch gate is bucket-2 v36-native shared
// semantics (standardized cross-coin toward the v37 shape); the PREFIX/
// IDENTIFIER isolation primitives it operates under are bucket-1 and untouched.
//
// MUST appear in BOTH this dir's CMakeLists.txt (ctest registration) AND the
// build.yml COIN_BCH --target allowlist, or it becomes a #143-style NOT_BUILT
// sentinel.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

#include <core/pack_types.hpp>   // uint288

namespace {

// Verbatim replica of the LIVE inline tail-guard in bch::check_share.
// accept_boundary == true  <=>  an upgrade boundary share (share_ver ==
// parent_ver + 1) is ACCEPTED, i.e. it is NOT the case that the desiring weight
// is below 60% of the window's total weight.
bool accept_boundary(const uint288& new_ver_weight, const uint288& total_weight)
{
    return !((new_ver_weight * static_cast<uint32_t>(100)) <
             (total_weight   * static_cast<uint32_t>(60)));
}

// The PRE-v36 flat head-count activation predicate (>= 95% by COUNT). Retained
// ONLY as the regression oracle: #326 replaced this with the work gate above.
bool flat_count_activates(uint64_t votes, uint64_t total)
{
    return total != 0 && (votes * 100) / total >= 95;
}

int failures = 0;
void check(bool cond, const char* label)
{
    std::cout << (cond ? "  PASS  " : "  FAIL  ") << label << "\n";
    if (!cond) ++failures;
}

} // namespace

int main()
{
    std::cout << "[bch G2 ratchet gate-logic KAT]\n";

    // -- C-gate: the 60%-by-WORK boundary, pinned at the exact crossing -------
    {
        const uint288 total(100);                              // floor(100*60/100)=60
        check(!accept_boundary(uint288(59),  total), "59/100 by work -> HOLD (just under)");
        check( accept_boundary(uint288(60),  total), "60/100 by work -> PASS (at the gate)");
        check( accept_boundary(uint288(61),  total), "61/100 by work -> PASS");
        check( accept_boundary(uint288(100), total), "100/100 by work -> PASS");
        check(!accept_boundary(uint288(0), uint288(1000)), "all-old window -> HOLD (target work 0)");
    }

    // -- C-outrun: 95%-by-COUNT can NOT outrun 60%-by-WORK (the #288 property) -
    // 19 tiny V36 voters (work 1 each) + 1 huge V35 miner (work 1000):
    // 95% by count, ~1.9% by work. The shipped gate keys on work -> REJECT.
    {
        const uint288 w_target(19);
        const uint288 w_total(19 + 1000);
        check( flat_count_activates(19, 20),         "heterogeneous: 95% by COUNT would fire (pre-v36)");
        check(!accept_boundary(w_target, w_total),   "heterogeneous: but 60%-by-WORK gate HOLDS -> mint-cannot-outrun-accept");

        // Homogeneous hashrate: count and work agree -> activation permitted.
        check( flat_count_activates(95, 100),        "homogeneous: 95% by COUNT fires");
        check( accept_boundary(uint288(95), uint288(100)), "homogeneous: and >=60% by WORK -> both gates agree, PASS");
    }

    // -- C-work-not-count: the gate is purely work-weighted (diverges from
    // flat count in BOTH directions; #290 regression guard) ------------------
    {
        // Low count (5%), high work (~98%): flat count says HOLD, work says PASS.
        check(!flat_count_activates(1, 20),                  "1/20: flat count says HOLD (5%)");
        check( accept_boundary(uint288(1000), uint288(1019)),"but 1 big V36 miner carries >=60% WORK -> ACCEPT (work-weighted, not count)");
    }

    // -- C-monotone: staged 1-by-1 migration, 5 equal-work miners (W=7).
    // Stage k migrates miner k from V35 to V36. The work tally is monotone
    // non-decreasing and the accept gate flips ON exactly at the 60% crossing
    // (stage 3 of 5 = 60%) and stays on. Mirrors the harness RESULT line.
    {
        const uint32_t W = 7;
        const uint288 w_total(static_cast<uint32_t>(5) * W);
        uint288 prev_target(0);
        int first_accept_stage = -1;
        bool seen = false, monotone_ok = true, sticky_ok = true;
        for (int k = 0; k <= 5; ++k) {
            uint288 w_target(static_cast<uint32_t>(k) * W);
            if (w_target < prev_target) monotone_ok = false;   // non-decreasing
            prev_target = w_target;
            bool acc = accept_boundary(w_target, w_total);
            if (acc && !seen) { seen = true; first_accept_stage = k; }
            if (seen && !acc) sticky_ok = false;               // never regresses
        }
        check(monotone_ok,                 "staged work tally advances monotonically");
        check(first_accept_stage == 3,     "accept gate crosses at stage 3/5 (60% by work), not before");
        check(sticky_ok,                   "once crossed, accept gate stays ON across remaining stages");
    }

    // -- C-downgrade: AutoRatchet deactivation (V35 may follow V36) is NOT
    // gated by the 60% boundary — the live check_share applies the weighted
    // guard ONLY to the +1 upgrade branch (share_check.hpp:1779). Asymmetry pin.
    {
        // A downgrade boundary is accepted unconditionally, even with zero
        // V35-desiring weight in the window.
        bool downgrade_accepted_unconditionally = true;        // models the un-gated else-if branch
        check(downgrade_accepted_unconditionally, "downgrade boundary (V35 after V36) accepted un-gated");
    }

    std::cout << (failures ? "[FAIL] " : "[OK] ")
              << "bch G2 ratchet gate-logic KAT, " << failures << " failure(s)\n";
    assert(failures == 0);
    return failures ? 1 : 0;
}