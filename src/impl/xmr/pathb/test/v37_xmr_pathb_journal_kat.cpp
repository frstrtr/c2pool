// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_journal_kat.cpp
// Rewind journal of depth J = journal_depth(ruled parameters) = 1,152:
//   (1) 2,000 appends hold the newest 1,152 records; base 848, tip 2,000;
//   (2) fork point at depth J: Rewound, 1,152 records out newest first;
//       fork point at depth J + 1: RebuildRequired, nothing changes; fork
//       point above the tip: ForkAboveTip, nothing changes;
//   (3) rewind + replay of a heavier branch gives the same state digest as a
//       node that applied the heavier branch from the start; a fork at depth
//       J + 1 goes through rebuild_from(snapshot) to the same digest;
//   (4) a journal restarted from a snapshot cannot rewind below it;
//   (5) generic over the record type: a move-only record.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_journal.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

// A placement: position, payee, work.
struct Placement {
    std::uint64_t pos = 0;
    std::uint32_t payee = 0;
    std::uint64_t work = 0;
};

// Lane state: work per payee; digest = the ordered map.
struct LaneState {
    std::map<std::uint32_t, std::uint64_t> work;
    void apply(const Placement& p) { work[p.payee] += p.work; }
    void undo(const Placement& p) {
        auto it = work.find(p.payee);
        it->second -= p.work;
        if (it->second == 0) work.erase(it);
    }
    std::string digest() const {
        std::string s;
        for (const auto& [k, v] : work) s += std::to_string(k) + ":" + std::to_string(v) + ";";
        return s;
    }
};

Placement trunk(std::uint64_t pos) { return Placement{pos, static_cast<std::uint32_t>(pos % 17), 18180 + pos % 5}; }
Placement branch(std::uint64_t pos) { return Placement{pos, static_cast<std::uint32_t>(100 + pos % 13), 20000 + pos % 3}; }

// A node: journal + state, applying records in position order.
struct Node {
    pb::RewindJournal<Placement> j;
    LaneState st;
    explicit Node(std::uint64_t depth) : j(depth) {}
    void extend(const Placement& p) {
        st.apply(p);
        j.append(p);
    }
};

}  // namespace

int main() {
    std::printf("v37_xmr_pathb_journal_kat\n");
    const std::uint64_t J = pb::journal_depth(pb::kRuledLaneParams);
    check(J == 1152, "J = 1,152");

    // (1)
    Node n(J);
    for (std::uint64_t pos = 1; pos <= 2000; ++pos) n.extend(trunk(pos));
    check(n.j.size() == J, "journal holds J records");
    check(n.j.tip_position() == 2000 && n.j.base_position() == 2000 - J, "tip 2,000, base 848");
    check(n.j.holds(849) && !n.j.holds(848) && n.j.at(849).pos == 849 && n.j.at(2000).pos == 2000,
          "positions 849..2,000 held");

    // (2)
    check(n.j.verdict_for(2000 - J) == pb::RewindVerdict::Rewound, "fork at depth J: rewind");
    check(n.j.verdict_for(2000 - J - 1) == pb::RewindVerdict::RebuildRequired, "fork at depth J + 1: rebuild");
    check(n.j.verdict_for(2001) == pb::RewindVerdict::ForkAboveTip, "fork above the tip refused");
    {
        Node copy = n;
        std::vector<Placement> undone;
        check(copy.j.rewind_to(2000 - J - 1, undone) == pb::RewindVerdict::RebuildRequired && undone.empty()
                      && copy.j.size() == J && copy.j.tip_position() == 2000,
              "rebuild verdict changes nothing");
        check(copy.j.rewind_to(2001, undone) == pb::RewindVerdict::ForkAboveTip && undone.empty(),
              "fork above tip changes nothing");
        check(copy.j.rewind_to(2000 - J, undone) == pb::RewindVerdict::Rewound && undone.size() == J
                      && undone.front().pos == 2000 && undone.back().pos == 2000 - J + 1 && copy.j.size() == 0
                      && copy.j.tip_position() == 2000 - J,
              "rewind to depth J: J records out newest first");
        check(copy.j.rewind_to(copy.j.tip_position(), undone) == pb::RewindVerdict::Rewound && undone.size() == J,
              "rewind to the tip itself moves nothing");
    }

    // (3) rewind + replay == fresh node; deeper fork via rebuild
    {
        const std::uint64_t fork = 1500;  // depth 500 < J
        Node a = n;
        std::vector<Placement> undone;
        check(a.j.rewind_to(fork, undone) == pb::RewindVerdict::Rewound && undone.size() == 500, "rewind 500");
        for (const Placement& p : undone) a.st.undo(p);
        for (std::uint64_t pos = fork + 1; pos <= 2100; ++pos) a.extend(branch(pos));

        Node fresh(J);
        for (std::uint64_t pos = 1; pos <= fork; ++pos) fresh.extend(trunk(pos));
        for (std::uint64_t pos = fork + 1; pos <= 2100; ++pos) fresh.extend(branch(pos));
        check(a.st.digest() == fresh.st.digest(), "rewind + replay: same digest as a fresh node");
        check(a.j.tip_position() == 2100 && a.j.size() == J, "journal after replay: tip 2,100, J records");

        const std::uint64_t deep_fork = 2000 - J - 1;  // depth J + 1
        Node b = n;
        std::vector<Placement> out;
        check(b.j.rewind_to(deep_fork, out) == pb::RewindVerdict::RebuildRequired, "depth J + 1: rebuild required");
        // rebuild from a snapshot at or below the fork point
        const std::uint64_t snapshot = 500;
        LaneState snap;
        for (std::uint64_t pos = 1; pos <= snapshot; ++pos) snap.apply(trunk(pos));
        b.st = snap;
        b.j.rebuild_from(snapshot);
        for (std::uint64_t pos = snapshot + 1; pos <= deep_fork; ++pos) b.extend(trunk(pos));
        for (std::uint64_t pos = deep_fork + 1; pos <= 2050; ++pos) b.extend(branch(pos));
        Node fresh2(J);
        for (std::uint64_t pos = 1; pos <= deep_fork; ++pos) fresh2.extend(trunk(pos));
        for (std::uint64_t pos = deep_fork + 1; pos <= 2050; ++pos) fresh2.extend(branch(pos));
        check(b.st.digest() == fresh2.st.digest(), "depth J + 1 via rebuild: same digest as a fresh node");
    }

    // (4) restart from a snapshot
    {
        pb::RewindJournal<Placement> r(J, 10000);
        for (std::uint64_t pos = 10001; pos <= 10010; ++pos) r.append(trunk(pos));
        check(r.verdict_for(10000) == pb::RewindVerdict::Rewound, "restart: rewind to the snapshot position");
        check(r.verdict_for(9999) == pb::RewindVerdict::RebuildRequired,
              "restart: below the snapshot needs a rebuild though within J");
    }

    // (5) move-only record
    {
        pb::RewindJournal<std::unique_ptr<std::uint64_t>> m(3);
        for (std::uint64_t i = 1; i <= 5; ++i) m.append(std::make_unique<std::uint64_t>(i * 10));
        check(m.size() == 3 && m.base_position() == 2 && *m.at(3) == 30, "move-only: newest 3 held");
        std::vector<std::unique_ptr<std::uint64_t>> out;
        check(m.rewind_to(3, out) == pb::RewindVerdict::Rewound && out.size() == 2 && *out[0] == 50 && *out[1] == 40,
              "move-only: rewind moves records out");
        pb::RewindJournal<std::uint64_t> z(0);
        z.append(1);
        check(z.size() == 0 && z.verdict_for(0) == pb::RewindVerdict::RebuildRequired, "depth 0 holds nothing");
    }

    return finish("v37_xmr_pathb_journal_kat");
}
