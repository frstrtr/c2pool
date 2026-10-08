// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/chain/xmr_reorg_journal.hpp
//
// THE REORG JOURNAL: every chain switch this node made or refused, written down
// before it happens and closed after, in a bounded ring.
//
// WHY A JOURNAL AND NOT A COUNTER. A reorg is the one moment where the index
// disagrees with its own past. Three different readers need that moment to be a
// record rather than a log line:
//
//   * the settlement side (W4) refuses to move its finalize cursor backwards, so
//     when a reorg crosses the burial depth it needs to know exactly which
//     heights were disowned and which took their place -- "reorgs: 3" cannot
//     answer that;
//   * an operator seeing a refusal needs the reason, the depth and the two tips
//     to tell "a peer offered nonsense" from "our anchor is wrong", which are
//     opposite emergencies;
//   * a crash between disconnecting and re-applying leaves a chain state that
//     matches neither branch, and the only safe resume is one that can see an
//     unclosed record and roll to the fork point.
//
// PHASES ARE WRITTEN BEFORE THE WORK, NOT AFTER. `Planned` is recorded while the
// old tip is still the tip; `Applied` only after every candidate block has
// connected; `Committed` after the events are out. An entry that is still
// `Planned` or `Disconnected` at startup is the crash case above.
//
// BOUNDED, LIKE EVERYTHING ELSE HERE. The ring keeps the last N switches (64 by
// default). It is telemetry and crash-recovery, not an archive: the chain state
// itself is the record of what won.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native {

enum class ReorgPhase : std::uint8_t {
    Planned = 0,     // decided to switch; nothing touched yet
    Disconnected,    // the old branch is off; the new one is not on yet
    Applied,         // the new branch is on; events not emitted yet
    Committed,       // done
    RolledBack,      // the switch failed validation and the old branch was restored
    Refused,         // the switch was never attempted, and `why` says what stopped it
};

inline const char* to_string(ReorgPhase p) noexcept {
    switch (p) {
        case ReorgPhase::Planned:      return "Planned";
        case ReorgPhase::Disconnected: return "Disconnected";
        case ReorgPhase::Applied:      return "Applied";
        case ReorgPhase::Committed:    return "Committed";
        case ReorgPhase::RolledBack:   return "RolledBack";
        case ReorgPhase::Refused:      return "Refused";
    }
    return "?";
}

// Why a switch was refused. Each of these is a DIFFERENT operational story, so
// they are not collapsed into one "rejected".
enum class ReorgRefusal : std::uint8_t {
    None = 0,
    BelowAnchor,       // the fork point is at or under the trust root
    BelowCheckpoint,   // the fork point is under a pinned monerod checkpoint
    TooDeep,           // deeper than the bounded horizon (max_reorg)
    OutOfWindow,       // the fork point is older than the retained rows
    MissingBodies,     // a candidate block's bytes are not available to re-apply
    Unverified,        // a candidate block never passed the proof-of-work gate
    ValidationFailed,  // a candidate block failed consensus during the switch
    NotBetter,         // it simply did not carry more work (the common case)
};

inline const char* to_string(ReorgRefusal r) noexcept {
    switch (r) {
        case ReorgRefusal::None:             return "None";
        case ReorgRefusal::BelowAnchor:      return "BelowAnchor";
        case ReorgRefusal::BelowCheckpoint:  return "BelowCheckpoint";
        case ReorgRefusal::TooDeep:          return "TooDeep";
        case ReorgRefusal::OutOfWindow:      return "OutOfWindow";
        case ReorgRefusal::MissingBodies:    return "MissingBodies";
        case ReorgRefusal::Unverified:       return "Unverified";
        case ReorgRefusal::ValidationFailed: return "ValidationFailed";
        case ReorgRefusal::NotBetter:        return "NotBetter";
    }
    return "?";
}

// A refusal that means the node and the network disagree about history deeper
// than this node is willing to look. It is an ALARM, not a routine outcome: the
// design's "DEEP REORG REFUSED" line and, when a daemon oracle is armed, an
// oracle-disagreement flag.
inline constexpr bool reorg_refusal_is_alarm(ReorgRefusal r) noexcept {
    return r == ReorgRefusal::BelowAnchor || r == ReorgRefusal::BelowCheckpoint
        || r == ReorgRefusal::TooDeep     || r == ReorgRefusal::OutOfWindow;
}

struct ReorgRecord {
    std::uint64_t seq         = 0;
    ReorgPhase    phase       = ReorgPhase::Planned;
    ReorgRefusal  refusal     = ReorgRefusal::None;

    std::uint64_t fork_height = 0;    // last height common to both branches
    std::uint64_t depth       = 0;    // blocks leaving the main chain

    Hash          old_tip{};
    std::uint64_t old_height  = 0;
    U128          old_cumulative_difficulty{};

    Hash          new_tip{};
    std::uint64_t new_height  = 0;
    U128          new_cumulative_difficulty{};

    std::vector<Hash> disconnected;   // descending, as they left
    std::vector<Hash> connected;      // ascending, as they arrived

    std::string why;                  // human sentence, for the operator line
};

class ReorgJournal {
public:
    explicit ReorgJournal(std::size_t capacity = 64) : capacity_(capacity ? capacity : 1) {}

    // Open a record. The caller holds the seq and closes it; an unclosed record
    // is exactly the crash evidence this class exists for.
    std::uint64_t plan(const ReorgRecord& r) {
        ReorgRecord rec = r;
        rec.seq   = ++seq_;
        rec.phase = ReorgPhase::Planned;
        records_.push_back(std::move(rec));
        trim_();
        return seq_;
    }

    ReorgRecord* find(std::uint64_t seq) {
        for (auto it = records_.rbegin(); it != records_.rend(); ++it)
            if (it->seq == seq) return &*it;
        return nullptr;
    }

    void set_phase(std::uint64_t seq, ReorgPhase p) {
        if (ReorgRecord* r = find(seq)) r->phase = p;
    }

    void close_committed(std::uint64_t seq) {
        if (ReorgRecord* r = find(seq)) {
            r->phase = ReorgPhase::Committed;
            ++committed_;
            if (r->depth > deepest_) deepest_ = r->depth;
        }
    }

    void close_rolled_back(std::uint64_t seq, ReorgRefusal why_code, const std::string& why) {
        if (ReorgRecord* r = find(seq)) {
            r->phase   = ReorgPhase::RolledBack;
            r->refusal = why_code;
            r->why     = why;
            ++rolled_back_;
        }
    }

    // A switch that never started. Recorded with the same shape so that the
    // operator reads one table, not two.
    std::uint64_t refuse(const ReorgRecord& r, ReorgRefusal code, const std::string& why) {
        ReorgRecord rec = r;
        rec.seq     = ++seq_;
        rec.phase   = ReorgPhase::Refused;
        rec.refusal = code;
        rec.why     = why;
        records_.push_back(std::move(rec));
        trim_();
        ++refused_;
        if (reorg_refusal_is_alarm(code)) ++alarms_;
        return seq_;
    }

    // The crash case: any record left open by a previous run.
    std::vector<const ReorgRecord*> open_records() const {
        std::vector<const ReorgRecord*> out;
        for (const ReorgRecord& r : records_)
            if (r.phase == ReorgPhase::Planned || r.phase == ReorgPhase::Disconnected
                || r.phase == ReorgPhase::Applied)
                out.push_back(&r);
        return out;
    }

    const std::deque<ReorgRecord>& records() const noexcept { return records_; }

    std::uint64_t committed()    const noexcept { return committed_; }
    std::uint64_t rolled_back()  const noexcept { return rolled_back_; }
    std::uint64_t refused()      const noexcept { return refused_; }
    std::uint64_t alarms()       const noexcept { return alarms_; }
    std::uint64_t deepest()      const noexcept { return deepest_; }

    // One line per record, oldest first: what a status command prints and what a
    // persisted journal keeps. Deliberately text, and deliberately not a format
    // anything parses for consensus.
    std::string describe() const {
        std::string out;
        for (const ReorgRecord& r : records_) {
            out += "reorg#" + std::to_string(r.seq) + " " + to_string(r.phase)
                 + " fork=" + std::to_string(r.fork_height)
                 + " depth=" + std::to_string(r.depth)
                 + " old=" + std::to_string(r.old_height)
                 + " new=" + std::to_string(r.new_height);
            if (r.refusal != ReorgRefusal::None) {
                out += " refusal=";
                out += to_string(r.refusal);
            }
            if (!r.why.empty()) out += " (" + r.why + ")";
            out += "\n";
        }
        return out;
    }

private:
    void trim_() {
        while (records_.size() > capacity_) records_.pop_front();
    }

    std::deque<ReorgRecord> records_;
    std::size_t             capacity_;
    std::uint64_t           seq_         = 0;
    std::uint64_t           committed_   = 0;
    std::uint64_t           rolled_back_ = 0;
    std::uint64_t           refused_     = 0;
    std::uint64_t           alarms_      = 0;
    std::uint64_t           deepest_     = 0;
};

} // namespace c2pool::xmr::native
