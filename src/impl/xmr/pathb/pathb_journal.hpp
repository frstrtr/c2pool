// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_journal.hpp
// Path B rewind journal: the records of the newest `depth` carrier positions
// (depth = J, K27, local). Position x holds the record appended when the chain
// reached x; base is the newest position the journal no longer holds.
//   append(r)          record of position tip + 1; the oldest record leaves
//                      when more than depth are held
//   rewind_to(x)       x > tip            -> ForkAboveTip, nothing changes
//                      x <  base          -> RebuildRequired, nothing changes
//                      base <= x <= tip   -> Rewound: the records of positions
//                                            tip .. x + 1 move out newest first
//   rebuild_from(s)    empty journal with base = tip = s (after a rebuild from
//                      a snapshot at position s)
// Generic over the record type (movable).
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

namespace c2pool::xmr::pathb {

enum class RewindVerdict : std::uint8_t { Rewound, RebuildRequired, ForkAboveTip };

template <class Record>
class RewindJournal {
public:
    explicit RewindJournal(std::uint64_t depth, std::uint64_t base_position = 0)
        : depth_(depth), base_(base_position) {}

    std::uint64_t depth() const noexcept { return depth_; }
    std::uint64_t base_position() const noexcept { return base_; }
    std::uint64_t tip_position() const noexcept { return base_ + records_.size(); }
    std::size_t size() const noexcept { return records_.size(); }
    bool holds(std::uint64_t position) const noexcept { return position > base_ && position <= tip_position(); }

    // Precondition: holds(position).
    const Record& at(std::uint64_t position) const { return records_[position - base_ - 1]; }

    void append(Record r) {
        records_.push_back(std::move(r));
        while (records_.size() > depth_) {
            records_.pop_front();
            ++base_;
        }
    }

    // The verdict rewind_to(fork_position) would return, without changing anything.
    RewindVerdict verdict_for(std::uint64_t fork_position) const noexcept {
        if (fork_position > tip_position()) return RewindVerdict::ForkAboveTip;
        if (fork_position < base_) return RewindVerdict::RebuildRequired;
        return RewindVerdict::Rewound;
    }

    RewindVerdict rewind_to(std::uint64_t fork_position, std::vector<Record>& undone) {
        const RewindVerdict v = verdict_for(fork_position);
        if (v != RewindVerdict::Rewound) return v;
        while (tip_position() > fork_position) {
            undone.push_back(std::move(records_.back()));
            records_.pop_back();
        }
        return v;
    }

    void rebuild_from(std::uint64_t snapshot_position) {
        records_.clear();
        base_ = snapshot_position;
    }

private:
    std::uint64_t depth_;
    std::uint64_t base_;
    std::deque<Record> records_;
};

}  // namespace c2pool::xmr::pathb
