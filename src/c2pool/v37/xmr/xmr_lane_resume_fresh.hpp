// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_lane_resume_fresh.hpp   (RESUME-FRESH)
//
// The stratum gate's per-pass step, with the resume edge ordered so that the
// first job a parked (or new) login receives after a lane suspension is built
// on the CURRENT tip.
//
// While the lane is suspended (any cause: lag, isolated, held, contested, the
// test knob) the main loop does not refresh the template provider, so its
// cached template stays on the tip the suspension started at. The listener's
// resume edge (set_lane_suspended(false)) serves every parked login from that
// cache at once; the refresh used to run later in the same loop pass, so the
// parked miners were first handed a job on a stale prev_id (RC2 smoke 09-25:
// a job for h=187 while the tip was 190, the h=191 job 46 ms later, and the
// share on the h=187 job became a real orphan block).
//
// apply_lane_gate() is called once per pass in place of
// listener.set_lane_suspended(lane_suspend). On a resume edge (the lane is no
// longer suspended but the listener gate is still closed) it first runs
// `refresh_fresh`, which must leave the provider on a template built on the
// current tip and return true, or return false when it cannot. Only then is
// the gate opened; on false the gate stays closed (the resume is HELD) and the
// next pass retries. Every other pass is exactly listener.set_lane_suspended().
//
// Returns the gate state for this pass: true = closed (suspended or held).
// ===========================================================================
#pragma once

#include <utility>

namespace c2pool::v37n::xmr {

template <class Listener, class RefreshFresh>
bool apply_lane_gate(Listener& listener, bool lane_suspend, RefreshFresh&& refresh_fresh) {
    if (!lane_suspend && listener.lane_suspended() && !std::forward<RefreshFresh>(refresh_fresh)())
        return true;   // resume HELD: no fresh template yet; the gate stays closed until one is built
    listener.set_lane_suspended(lane_suspend);
    return lane_suspend;
}

} // namespace c2pool::v37n::xmr
