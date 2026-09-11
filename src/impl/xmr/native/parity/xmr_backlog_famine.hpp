// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/parity/xmr_backlog_famine.hpp
//
// THE P-TPL BLIND SPOT, CLOSED.
//
// tx_backlog_count is a Regime::Measurement in TEMPLATE_FIELDS, and that is the
// right regime for it: two arms may legitimately hold different transaction
// sets at the same instant, so an equality gate on the count would fire on
// ordinary propagation skew. But a Measurement is never scored, and the
// consequence is a hole the size of the whole milestone:
//
//     A native arm that serves n_tx=0 at every height, forever, while the
//     monerod shadow arm reports a pool full of fee-paying transactions,
//     reads P-TPL CLEAN -- because the six EQUALITY fields (prev_id,
//     major_version, difficulty, seed_hash, median_weight,
//     already_generated_coins) all agree, and they agree precisely BECAUSE
//     they have nothing to do with the transaction set.
//
// That is not a hypothetical. It is what happened: the native pool's relay gate
// had no production caller, the pool refused every levin-relayed transaction,
// every template went out empty, and the parity oracle reported clean agreement
// at every height while the pool left every piconero of fee revenue on the
// table. A regression detector that cannot see the regression it was standing
// next to is not a detector.
//
// SO THE COUNT STAYS A MEASUREMENT AND THE FAMINE BECOMES A CONSTRAINT. The
// distinction that makes this safe is the SHADOW's count, not ours:
//
//     native backlog == 0  AND  shadow backlog > 0,  SUSTAINED
//
// Neither half alone is evidence of anything. A native backlog of 0 on a quiet
// chain is correct. A shadow backlog of 8 while we hold 6 is propagation skew.
// The conjunction, held across K consecutive decidable samples AND across at
// least S seconds of wall clock, is the one shape that cannot be explained by
// skew: transactions demonstrably exist on the network, the daemon sitting on
// the same wire is holding them, and we are holding none of them.
//
// TWO BOUNDS, NOT ONE, and the second is not redundant. Samples are driven by
// template refreshes, which can burst: six refreshes inside one second all
// observe the same two-second propagation window and would satisfy a
// consecutive-count bound on their own. The elapsed bound is what makes the
// word "sustained" mean sustained.
//
// UNDECIDABLE IS NOT INNOCENT. A sample where either side did not answer, or
// where the two arms are on different tips, carries no information -- so it
// neither increments the streak nor clears it. Clearing on absence would hand
// an adversary (or a flaky shadow arm) a way to keep the streak at zero
// forever, which is the same blindness wearing a different hat.
//
// THE REFUSAL IS STICKY. Once tripped, the check keeps refusing until a sample
// actually shows the condition resolved -- the native pool holding something,
// or the shadow holding nothing. A refusal that evaporates on the next
// undecidable sample would be a warning, and this is not a warning: it travels
// out as a failed CONSTRAINT, which compare_seam turns into a P-TPL FAIL.
//
// SCOPE FENCE: src/impl/xmr/ only. No consensus digest, no src/sharechain/v37.
// Header-only, STL only, no clock of its own (the caller supplies the time, so
// a test can drive years in microseconds).
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"   // NamedCheck

namespace c2pool::xmr::native::parity {

// The name the constraint travels under, in the sample note and in the P-TPL
// field table. One spelling, one place.
inline constexpr const char* kBacklogFamineCheck = "native_backlog_famine";

struct BacklogFamineConfig {
    // How many consecutive DECIDABLE samples must show the famine shape.
    std::size_t   consecutive = 6;
    // ...and across at least this much wall clock, so a burst of refreshes
    // inside one propagation window cannot satisfy the count on its own.
    std::uint64_t sustained_s = 30;
    // Off is a deliberate operator choice (a node with no shadow arm has
    // nothing to compare against and should not be told so once per refresh),
    // never a default.
    bool          enabled = true;
};

// What one sample was, once the two counts have been looked at. Exposed because
// a test that cannot see WHY a sample did not count is testing very little.
enum class BacklogSampleClass : std::uint8_t {
    Undecidable = 0,   // misaligned, or one of the two arms did not answer
    Fed,               // the native pool held something: the famine shape is absent
    ShadowEmpty,       // the shadow held nothing either: agreement, not famine
    Starved,           // native 0, shadow > 0: one unit of famine evidence
};

inline const char* to_string(BacklogSampleClass c) noexcept {
    switch (c) {
        case BacklogSampleClass::Undecidable: return "undecidable";
        case BacklogSampleClass::Fed:         return "fed";
        case BacklogSampleClass::ShadowEmpty: return "shadow-empty";
        case BacklogSampleClass::Starved:     return "starved";
    }
    return "?";
}

class BacklogFamineGuard {
public:
    struct Input {
        bool          native_known   = false;
        std::uint64_t native_backlog = 0;
        bool          shadow_known   = false;
        std::uint64_t shadow_backlog = 0;
        // The two arms are on the same (height, prev_id). A famine claim across
        // different tips would be comparing two different questions.
        bool          aligned        = false;
        // Unix seconds. Zero means "no clock was supplied"; see kDeadClock.
        std::uint64_t at_unix        = 0;
    };

    struct Observation {
        BacklogSampleClass cls          = BacklogSampleClass::Undecidable;
        std::size_t        streak       = 0;
        std::uint64_t      elapsed_s    = 0;
        bool               tripped      = false;
        NamedCheck         check;        // ready to push into CompareOptions
    };

    explicit BacklogFamineGuard(BacklogFamineConfig cfg = {}) : cfg_(cfg) {}

    const BacklogFamineConfig& config() const noexcept { return cfg_; }

    Observation observe(const Input& in) {
        Observation out;

        if (!cfg_.enabled) {
            out.check = pass_("famine guard disabled");
            return out;
        }

        const bool decidable = in.aligned && in.native_known && in.shadow_known;
        if (!decidable) {
            ++undecidable_;
            out.cls       = BacklogSampleClass::Undecidable;
            out.streak    = streak_;
            out.tripped   = tripped_;
            out.elapsed_s = elapsed_(in.at_unix);
            // No information: the streak neither grows nor clears, and an
            // existing refusal stands.
            out.check = tripped_ ? fail_(out) : pass_("no comparable backlog pair this sample");
            return out;
        }

        if (in.native_backlog > 0) {
            clear_();
            ++fed_;
            out.cls   = BacklogSampleClass::Fed;
            out.check = pass_("native pool holds " + u64_(in.native_backlog) + " tx");
            return out;
        }
        if (in.shadow_backlog == 0) {
            clear_();
            ++shadow_empty_;
            out.cls   = BacklogSampleClass::ShadowEmpty;
            out.check = pass_("both pools empty: agreement, not famine");
            return out;
        }

        // native == 0, shadow > 0.
        ++starved_;
        if (streak_ == 0) first_starved_unix_ = in.at_unix;
        ++streak_;
        last_shadow_backlog_ = in.shadow_backlog;

        out.cls       = BacklogSampleClass::Starved;
        out.streak    = streak_;
        out.elapsed_s = elapsed_(in.at_unix);

        // kDeadClock: with no clock supplied every sample carries at_unix == 0,
        // so the elapsed bound can never be met and the guard would be unable
        // to trip at all. A guard that cannot trip is worse than no guard, so
        // the count bound stands alone and the detail says so.
        const bool dead_clock = (in.at_unix == 0 && first_starved_unix_ == 0);
        const bool long_enough = dead_clock || out.elapsed_s >= cfg_.sustained_s;

        if (streak_ >= cfg_.consecutive && long_enough) tripped_ = true;
        out.tripped = tripped_;
        out.check   = tripped_ ? fail_(out, dead_clock) : pass_(progress_(out));
        return out;
    }

    // --- what the status line and the KAT read ------------------------------
    bool          tripped()     const noexcept { return tripped_; }
    std::size_t   streak()      const noexcept { return streak_; }
    std::uint64_t starved()     const noexcept { return starved_; }
    std::uint64_t fed()         const noexcept { return fed_; }
    std::uint64_t shadow_empty() const noexcept { return shadow_empty_; }
    std::uint64_t undecidable() const noexcept { return undecidable_; }

    std::string describe() const {
        return std::string(tripped_ ? "REFUSING" : "ok")
             + " streak=" + u64_(static_cast<std::uint64_t>(streak_)) + "/" + u64_(static_cast<std::uint64_t>(cfg_.consecutive))
             + " starved=" + u64_(starved_) + " fed=" + u64_(fed_)
             + " shadow-empty=" + u64_(shadow_empty_)
             + " undecidable=" + u64_(undecidable_);
    }

private:
    static std::string u64_(std::uint64_t v) {
        char b[24];
        std::snprintf(b, sizeof(b), "%llu", static_cast<unsigned long long>(v));
        return b;
    }

    std::uint64_t elapsed_(std::uint64_t at) const noexcept {
        if (streak_ == 0) return 0;
        return at > first_starved_unix_ ? (at - first_starved_unix_) : 0;
    }

    void clear_() noexcept {
        streak_ = 0;
        tripped_ = false;
        first_starved_unix_ = 0;
        last_shadow_backlog_ = 0;
    }

    NamedCheck pass_(std::string detail) const {
        NamedCheck c;
        c.name   = kBacklogFamineCheck;
        c.ok     = true;
        c.detail = std::move(detail);
        return c;
    }

    std::string progress_(const Observation& o) const {
        return "native backlog 0 while shadow holds " + u64_(last_shadow_backlog_)
             + "; " + u64_(static_cast<std::uint64_t>(o.streak)) + "/" + u64_(static_cast<std::uint64_t>(cfg_.consecutive))
             + " samples, " + u64_(o.elapsed_s) + "/" + u64_(cfg_.sustained_s) + "s";
    }

    NamedCheck fail_(const Observation& o, bool dead_clock = false) const {
        NamedCheck c;
        c.name = kBacklogFamineCheck;
        c.ok   = false;
        c.detail = "native template backlog has been 0 for " + u64_(static_cast<std::uint64_t>(o.streak))
                 + " consecutive samples (" + u64_(o.elapsed_s) + "s) while the shadow arm "
                 + "held " + u64_(last_shadow_backlog_)
                 + " transaction(s): the native pool is not ingesting relayed transactions, "
                   "so every template served is empty of fee revenue";
        if (dead_clock) c.detail += " [no clock supplied: count bound only]";
        return c;
    }

    BacklogFamineConfig cfg_;
    std::size_t   streak_              = 0;
    bool          tripped_             = false;
    std::uint64_t first_starved_unix_  = 0;
    std::uint64_t last_shadow_backlog_ = 0;
    std::uint64_t starved_             = 0;
    std::uint64_t fed_                 = 0;
    std::uint64_t shadow_empty_        = 0;
    std::uint64_t undecidable_         = 0;
};

} // namespace c2pool::xmr::native::parity
