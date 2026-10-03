// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_adversary_knobs.hpp   (ADVERSARY KNOBS, TEST-ONLY)
//
// Fault-injection knobs that make ONE node misbehave on a test network, so a
// stagenet soak (attempt 10) can prove the pool survives a real attacker:
// honest nodes stay on one ledger, ban/refuse per the rules, and nothing the
// adversary does splits the pool or reduces an earned balance.
//
// Every knob is:
//   * HIDDEN (no --help row),
//   * OFF when its integer is 0 (zero code path change for an honest node),
//   * INTEGER-ONLY,
//   * REFUSED at start on --network mainnet (refusal() is non-empty),
//   * loud: banner() prints an ADVERSARY block at start, and each action
//     prints one `adv: <knob> ...` line a soak script can count.
//
// This header is pure scaffolding: the knob CONFIG, the mainnet refusal, the
// banner, a per-minute rate gate and a probability gate, and the action log
// lines. It holds NO consensus logic. The daemon reads these fields at its own
// seams (the publish path, the relay send pump) to decide, per action, whether
// to misbehave; the honest receive/book path is untouched.
//
// Flags (all test networks only):
//   --adv-withhold-blocks P      with probability P/100 a found block is not
//                                submitted and not announced (knob 1)
//   --adv-censor-receipts        this node's own lane cut keeps only receipts
//                                its own miners minted; it relays no others
//                                onward (knob 2)
//   --adv-garbage RATE           send malformed frames / forged shares to peers
//                                at RATE per minute (knob 3)
//   --adv-stale-replay RATE      re-send old valid frames (replay) at RATE per
//                                minute (knob 4)
//   --adv-self-pay               build lane coinbases that pay only this node
//                                (non-canonical) (knob 5)
//   --adv-wrong-epoch-ballot     mint receipts whose ballot word names an
//                                undefined epoch (knob 6)
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace c2pool::v37n::xmr {

// A per-minute emission gate: at most one `due()` edge every 60000/rate ms.
// rate == 0 is OFF (due() is never true). Pure; time is any monotonic ms.
struct AdvRateGate {
    std::uint32_t rate_per_min = 0;     // 0 = OFF
    std::uint64_t next_ms = 0;          // the next instant due() may fire
    std::uint64_t n_due = 0;

    AdvRateGate() = default;
    explicit AdvRateGate(std::uint32_t r) : rate_per_min(r) {}

    std::uint64_t interval_ms() const {
        return rate_per_min ? (60000ull / rate_per_min ? 60000ull / rate_per_min : 1ull) : 0ull;
    }
    // True at most once per interval. The first call (next_ms == 0) arms the
    // gate at now + interval and returns false, so nothing fires at t=0.
    bool due(std::uint64_t now_ms) {
        if (!rate_per_min) return false;
        if (next_ms == 0) { next_ms = now_ms + interval_ms(); return false; }
        if (now_ms < next_ms) return false;
        // advance past missed intervals without bursting (one edge per call)
        next_ms += interval_ms();
        if (next_ms <= now_ms) next_ms = now_ms + interval_ms();
        ++n_due;
        return true;
    }
};

struct AdversaryKnobs {
    std::uint32_t withhold_pct = 0;         // knob 1: 0..100, 0 = OFF
    std::uint32_t censor_receipts = 0;      // knob 2: 0/1
    std::uint32_t garbage_rate = 0;         // knob 3: frames/min, 0 = OFF
    std::uint32_t replay_rate = 0;          // knob 4: frames/min, 0 = OFF
    std::uint32_t self_pay = 0;             // knob 5: 0/1
    std::uint32_t wrong_epoch_ballot = 0;   // knob 6: 0/1

    // per-action counters (the soak reads them off the status line / logs)
    std::uint64_t n_withheld = 0;           // blocks not submitted
    std::uint64_t withheld_reward = 0;      // sum of their coinbase reward (atomic units)
    std::uint64_t n_censored = 0;           // foreign receipts dropped from our cut
    std::uint64_t n_not_relayed = 0;        // foreign receipts not relayed onward
    std::uint64_t n_garbage = 0;            // malformed frames sent
    std::uint64_t n_replay = 0;             // old frames re-sent
    std::uint64_t n_self_pay = 0;           // self-pay coinbases built
    std::uint64_t n_wrong_ballot = 0;       // wrong-epoch ballots minted

    bool any() const {
        return withhold_pct || censor_receipts || garbage_rate || replay_rate
            || self_pay || wrong_epoch_ballot;
    }

    // Empty = may run. Non-empty = the reason the daemon refuses to start.
    // Any knob set on mainnet is refused, by name, before anything starts.
    static std::string refusal(bool network_is_mainnet, const AdversaryKnobs& k) {
        if (!network_is_mainnet || !k.any()) return {};
        std::vector<std::string> on;
        if (k.withhold_pct)       on.emplace_back("--adv-withhold-blocks");
        if (k.censor_receipts)    on.emplace_back("--adv-censor-receipts");
        if (k.garbage_rate)       on.emplace_back("--adv-garbage");
        if (k.replay_rate)        on.emplace_back("--adv-stale-replay");
        if (k.self_pay)           on.emplace_back("--adv-self-pay");
        if (k.wrong_epoch_ballot) on.emplace_back("--adv-wrong-epoch-ballot");
        std::string names;
        for (std::size_t i = 0; i < on.size(); ++i) { if (i) names += ", "; names += on[i]; }
        return "ADVERSARY knobs (" + names + ") are TEST-ONLY attack injectors; they are "
               "refused on --network mainnet -- use regtest, testnet or stagenet";
    }

    // The loud start banner: printed once, when any knob is set, after the
    // mainnet refusal has already passed (so this host is a test network).
    void banner() const {
        if (!any()) return;
        std::printf("\n");
        std::printf("################################################################\n");
        std::printf("##  ADVERSARY NODE -- TEST-ONLY FAULT INJECTION IS ACTIVE      ##\n");
        std::printf("##  This node will ATTACK its own pool. Never a mainnet state. ##\n");
        std::printf("################################################################\n");
        if (withhold_pct)       std::printf("##  knob 1 withhold-blocks   P=%u%%\n", withhold_pct);
        if (censor_receipts)    std::printf("##  knob 2 censor-receipts   own-cut keeps only own miners; no onward relay\n");
        if (garbage_rate)       std::printf("##  knob 3 garbage           %u malformed frames/min\n", garbage_rate);
        if (replay_rate)        std::printf("##  knob 4 stale-replay      %u old frames/min\n", replay_rate);
        if (self_pay)           std::printf("##  knob 5 self-pay          coinbases pay only this node (non-canonical)\n");
        if (wrong_epoch_ballot) std::printf("##  knob 6 wrong-epoch-ballot ballot word names an undefined epoch\n");
        std::printf("################################################################\n\n");
        std::fflush(stdout);
    }

    // One per-action log line, format `adv: <knob> <detail>` so a soak counts
    // attacks by `grep -c 'adv: <knob>'`.
    static void log(const char* knob, const std::string& detail) {
        std::printf("adv: %s %s\n", knob, detail.c_str());
        std::fflush(stdout);
    }

    // knob 1 decision (pure): withhold iff the 0..99 draw is below P.
    bool withhold(std::uint32_t draw_0_99) const {
        return withhold_pct && draw_0_99 < withhold_pct;
    }
    // knob 2 decision (pure): keep a receipt in our own cut iff we minted it.
    bool keep_in_cut(bool is_own) const { return !censor_receipts || is_own; }
    bool relay_onward(bool is_own) const { return !censor_receipts || is_own; }
};

} // namespace c2pool::v37n::xmr
