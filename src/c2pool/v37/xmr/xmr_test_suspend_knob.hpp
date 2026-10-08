// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_test_suspend_knob.hpp   (FAULT-KNOB, TEST-ONLY)
//
// A fault-injection knob that FORCES the lane-suspend state on a live node for
// S seconds and then releases it, so a rig (the stagenet capstone fault driver)
// can prove the stratum resume path live. It never decides a suspension by
// itself: it only raises LaneSuspendState::kTest, and the daemon's ordinary
// apply_suspension() turns that into the SAME set_lane_suspended() edges (job
// withdrawn, sessions dropped, logins parked; resume serves them) that a real
// lag / isolated / held / contested cause produces.
//
//   --test-suspend-lane-seconds S   (default 0 = OFF: no signal handler is
//                                    installed, nothing changes)
//   S > 0 arms SIGUSR2: each SIGUSR2 forces the suspension for S seconds.
//   SIGUSR1 stays the relay-partition knob (--relay-test-partition-seconds).
//
// State machine (pure, time in ms from any monotonic clock):
//   OFF      seconds == 0: fire() is a no-op, active() is never true.
//   ARMED    seconds > 0, not active.
//   ACTIVE   fire(now) from ARMED: forced until now + seconds*1000.
//            fire() while ACTIVE is ignored (never extends) and counted.
//   release  poll(now >= until) returns true ONCE and goes back to ARMED.
//
// Mainnet: refusal() is non-empty for --network mainnet with S > 0; the daemon
// refuses to start on it (a test knob never runs on a real-money network).
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>

#include "c2pool/v37/xmr/xmr_lane_suspend_state.hpp"

namespace c2pool::v37n::xmr {

struct TestSuspendKnob {
    std::uint32_t seconds = 0;          // 0 = OFF
    bool          is_active = false;
    std::uint64_t until_ms = 0;
    std::uint64_t n_fired = 0, n_released = 0, n_ignored = 0;

    explicit TestSuspendKnob(std::uint32_t s = 0) : seconds(s) {}

    bool armed()  const { return seconds != 0; }
    bool active() const { return is_active; }

    // Empty = may run. Non-empty = the reason the daemon refuses to start.
    static std::string refusal(bool network_is_mainnet, std::uint32_t s) {
        if (network_is_mainnet && s != 0)
            return "--test-suspend-lane-seconds is a TEST-ONLY fault-injection knob (it forces a lane suspension on "
                   "SIGUSR2); it is refused on --network mainnet -- use regtest, testnet or stagenet";
        return {};
    }

    // A fire request (the signal). True on the fire edge (ARMED -> ACTIVE).
    bool fire(std::uint64_t now_ms) {
        if (!armed()) return false;
        if (is_active) { ++n_ignored; return false; }
        is_active = true;
        until_ms = now_ms + static_cast<std::uint64_t>(seconds) * 1000u;
        ++n_fired;
        return true;
    }

    // True exactly once, on the release edge (ACTIVE -> ARMED).
    bool poll(std::uint64_t now_ms) {
        if (!is_active || now_ms < until_ms) return false;
        is_active = false;
        ++n_released;
        return true;
    }

    std::uint64_t remaining_ms(std::uint64_t now_ms) const {
        return (is_active && until_ms > now_ms) ? until_ms - now_ms : 0;
    }

    // One main-loop pass, run right BEFORE LaneSuspendState::update() (the
    // daemon's apply_suspension): consume a pending fire request, check for the
    // release, and mirror the result onto the kTest cause. The daemon and the
    // KAT call this same function.
    struct Step { bool fired = false, ignored = false, released = false; };
    Step step(bool fire_request, std::uint64_t now_ms, LaneSuspendState& lane) {
        Step s;
        if (fire_request) {
            const std::uint64_t before = n_ignored;
            s.fired = fire(now_ms);
            s.ignored = n_ignored != before;
        }
        s.released = poll(now_ms);
        lane.test_forced = is_active;
        return s;
    }
};

} // namespace c2pool::v37n::xmr
