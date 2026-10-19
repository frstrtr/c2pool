// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_lane_suspend_state.hpp
//
// THE LANE-SUSPEND STATE MACHINE: the causes that close the stratum gate (the
// listener's job withdrawal and login park), read from the node at its best
// tip, with per-cause edge counters:
//   hold       hold(node) (E13): the chain activated an epoch whose rules this
//              build does not implement; no template, ingestion continues;
//   fork_fuse  FORK-FUSE: the Monero hf of the next block is above the amount
//              rule this build implements; no template.
// Every cause is counted on its own rising edge, whether or not the lane was
// already suspended, and the active cause set is reported with the edge.
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>

namespace c2pool::v37n::xmr {

struct LaneSuspendState {
    enum Cause : unsigned { kHold = 1u, kForkFuse = 2u };

    struct Edge {
        bool     suspend_edge = false;   // the lane went from served to suspended
        bool     resume_edge  = false;   // every cause cleared
        unsigned added   = 0;            // causes that rose this update
        unsigned cleared = 0;            // causes that fell this update
        unsigned causes  = 0;            // the active set after the update
    };

    unsigned      causes = 0;
    std::uint64_t n_hold = 0, n_fork_fuse = 0, n_resume = 0, n_suspend = 0;

    bool suspended() const { return causes != 0; }

    Edge update(bool hold, bool fork_fuse) {
        unsigned now = 0;
        if (hold)      now |= kHold;
        if (fork_fuse) now |= kForkFuse;
        Edge e;
        e.added   = now & ~causes;
        e.cleared = causes & ~now;
        e.suspend_edge = (causes == 0 && now != 0);
        e.resume_edge  = (causes != 0 && now == 0);
        if (e.added & kHold)     ++n_hold;
        if (e.added & kForkFuse) ++n_fork_fuse;
        if (e.suspend_edge) ++n_suspend;
        if (e.resume_edge)  ++n_resume;
        causes = now;
        e.causes = now;
        return e;
    }

    static std::string names(unsigned c) {
        std::string s;
        auto add = [&](const char* n) { if (!s.empty()) s += "+"; s += n; };
        if (c & kHold)     add("hold");
        if (c & kForkFuse) add("fork-fuse");
        return s.empty() ? "-" : s;
    }
};

} // namespace c2pool::v37n::xmr
