// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_lane_suspend_state.hpp   (R-C rework-3)
//
// THE LANE-SUSPEND STATE MACHINE, factored out of main so it can be tested.
// One place, four suspend causes + two D2 alarm bits (D-1 = C: alarm only), per-cause edge counters:
//   lag        (hw - D_conf) - cursor > 2*D_conf suspends, <= D_conf releases
//              (hysteresis; the ONE lag definition, rework-2);
//   isolated   the lineage vote: a VERIFIED counter-lineage outvotes us;
//   held       HELD-LAG: an undecided lane block holds the cursor past the cap;
//   contested  R-C rework-3 operator opt-in (--contested-suspend on; default off): the lineage vote is CONTESTED
//              (>= 1/3 of the recent frontier lane blocks refused) -- suspend
//              template production instead of building on a possibly split
//              ledger; auto-resumes when the vote returns to CONVERGED.
//
// D5 (rework-2 verify): HELD-LAG never registered as cause=held. The old code
// attributed a suspension to ONE cause, only on the lane's suspend edge; a
// HELD-LAG that fires while the lane is already lag-suspended (the usual order:
// the lag bound trips at once, HELD-LAG needs divergence_cap_ticks more ticks)
// was never counted. Here every cause is counted on ITS OWN rising edge,
// whether or not the lane was already suspended, and the active cause set is
// reported with the edge.
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>

namespace c2pool::v37n::xmr {

struct LaneSuspendState {
    // D2 (minority converges to majority): kConverging while the minority node
    // re-derives its ledger, kDiverged while the re-derivation does not reproduce
    // the majority. Operator ruling D-1 = C: both are ALARMS, never suspension
    // causes -- they live in `alarms` (edges counted and named), never in
    // `causes`, so D2 can never withdraw the stratum job or halt the lane.
    enum Cause : unsigned { kLag = 1u, kIsolated = 2u, kHeld = 4u, kContested = 8u, kConverging = 16u, kDiverged = 32u };
    static constexpr unsigned kAlarmOnly = kConverging | kDiverged;

    struct Edge {
        unsigned alarm_added = 0, alarm_cleared = 0;   // D2 alarm bits (never suspend)
        bool     suspend_edge = false;   // the lane went from served to suspended
        bool     resume_edge  = false;   // every cause cleared
        unsigned added   = 0;            // causes that rose this update
        unsigned cleared = 0;            // causes that fell this update
        unsigned causes  = 0;            // the active set after the update
    };

    std::uint64_t d_conf = 1;
    bool          lag_latched = false;
    unsigned      causes = 0;
    unsigned      alarms = 0;            // D2 alarm-only bits (kConverging | kDiverged)
    std::uint64_t n_lag = 0, n_isolated = 0, n_held = 0, n_contested = 0, n_resume = 0, n_suspend = 0;
    std::uint64_t n_converging = 0, n_diverged = 0;

    explicit LaneSuspendState(std::uint64_t d = 1) : d_conf(d ? d : 1) {}

    std::uint64_t suspend_above() const { return 2 * d_conf; }
    std::uint64_t resume_at()     const { return d_conf; }
    bool suspended() const { return causes != 0; }

    Edge update(std::uint64_t lag, bool isolated, bool held, bool contested) {
        return update(lag, isolated, held, contested, false, false);
    }
    Edge update(std::uint64_t lag, bool isolated, bool held, bool contested, bool converging, bool diverged) {
        if (!lag_latched && lag > suspend_above()) lag_latched = true;
        else if (lag_latched && lag <= resume_at()) lag_latched = false;
        unsigned now = 0;
        if (lag_latched) now |= kLag;
        if (isolated)    now |= kIsolated;
        if (held)        now |= kHeld;
        if (contested)   now |= kContested;
        unsigned al = 0;
        if (converging)  al |= kConverging;
        if (diverged)    al |= kDiverged;
        Edge e;
        e.alarm_added   = al & ~alarms;
        e.alarm_cleared = alarms & ~al;
        alarms = al;
        e.added   = now & ~causes;
        e.cleared = causes & ~now;
        e.suspend_edge = (causes == 0 && now != 0);
        e.resume_edge  = (causes != 0 && now == 0);
        if (e.added & kLag)       ++n_lag;
        if (e.added & kIsolated)  ++n_isolated;
        if (e.added & kHeld)      ++n_held;
        if (e.added & kContested) ++n_contested;
        if (e.alarm_added & kConverging) ++n_converging;
        if (e.alarm_added & kDiverged)  ++n_diverged;
        if (e.suspend_edge) ++n_suspend;
        if (e.resume_edge)  ++n_resume;
        causes = now;
        e.causes = now;
        return e;
    }

    static std::string names(unsigned c) {
        std::string s;
        auto add = [&](const char* n) { if (!s.empty()) s += "+"; s += n; };
        if (c & kLag)       add("lag");
        if (c & kIsolated)  add("isolated");
        if (c & kHeld)      add("held");
        if (c & kContested) add("contested");
        if (c & kConverging) add("converging");
        if (c & kDiverged)  add("diverged");
        return s.empty() ? "-" : s;
    }
};

} // namespace c2pool::v37n::xmr
