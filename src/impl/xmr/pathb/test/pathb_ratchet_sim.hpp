// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_ratchet_sim.hpp
// A lockstep chain of carriers for the ratchet KATs: one builder writes the
// carrier at x (its rules_epoch, the S it commits and its ballot), every node
// judges x from its own S_{x-1} and table, as the ratchet model's Extend /
// Res. Nodes keep a journal of depth J and an activation record.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"
#include "pathb_kat_check.hpp"

namespace ratchet_sim {

namespace pb = ::c2pool::xmr::pathb;
using pb::Hash32;

inline Hash32 dg(std::uint8_t b) {
    Hash32 h{};
    h.fill(b);
    return h;
}

// Synthetic digests: G, two releases' digests for epoch 1, one for epoch 2.
inline const Hash32 kG = dg(0x47);
inline const Hash32 kR1 = dg(0xa1);
inline const Hash32 kR2 = dg(0xb1);
inline const Hash32 kQ2 = dg(0xa2);
inline const Hash32 kQ3 = dg(0xc2);

inline pb::Deployment vote(const pb::RatchetParams& p, std::uint16_t e, const Hash32& d, std::uint64_t start) {
    return pb::Deployment{e, d, pb::kKindVote, start, start + pb::ratchet_vote_windows(p) * p.window, 0};
}

inline pb::Deployment fixed2(std::uint16_t e, const Hash32& d, std::uint64_t start, std::uint64_t fixed) {
    return pb::Deployment{e, d, pb::kKindFixed, start, 0, fixed};
}

// A table whose compiled epochs are G plus the digests of its own attempts
// (a release implements what it compiles).
inline pb::EpochTable release(std::vector<pb::Deployment> attempts, std::vector<pb::CompiledEpoch> extra = {}) {
    pb::EpochTable T;
    T.compiled.push_back(pb::CompiledEpoch{0, kG, std::nullopt});
    T.attempts = std::move(attempts);
    for (const pb::Deployment& a : T.attempts)
        if (pb::own_attempt(T, a.epoch_no) == &a && a.kind == pb::kKindVote)
            T.compiled.push_back(pb::CompiledEpoch{a.epoch_no, a.rules_digest, std::nullopt});
    for (const pb::CompiledEpoch& c : extra) T.compiled.push_back(c);
    return T;
}

struct Node {
    std::string name;
    pb::EpochTable T;
    pb::RatchetState S;  // S_{h-1}
    std::uint64_t h = 0;  // the next position judged
    pb::ActivationRecord ar;
    std::deque<std::pair<std::uint64_t, pb::RatchetState>> journal;  // (x, S_x), newest last
    std::uint64_t J = 1152;
    std::uint64_t strikes = 0, defers = 0, jobs = 0;
    bool live = true;
    std::optional<std::uint64_t> first_hold;  // the first x it held at

    Node(std::string n, pb::EpochTable t, std::uint64_t journal_depth = 1152)
        : name(std::move(n)), T(std::move(t)), S(pb::genesis_ratchet_state(kG)), J(journal_depth) {}

    std::uint64_t hold_at(const pb::RatchetParams& p) const { return pb::h_hold(p, S, h, T); }
    bool held(const pb::RatchetParams& p) const { return h >= hold_at(p); }

    std::optional<pb::RatchetState> journal_state(std::uint64_t x) const {
        for (const auto& [px, s] : journal)
            if (px == x) return s;
        return std::nullopt;
    }
};

struct Placed {
    std::uint64_t work = 1;
    std::uint16_t ballot = 0;
};

struct Verdicts {
    std::vector<pb::FrameVerdict> v;  // per node, in Sim::nodes order
};

struct Sim {
    pb::RatchetParams p;
    std::vector<Node*> nodes;
    std::uint64_t pos = 0;
    bool keep_chain = false;
    std::vector<std::vector<pb::RatchetPlacement>> chain;  // placements per position (keep_chain)

    explicit Sim(const pb::RatchetParams& params) : p(params) {}

    // Judges x on node n for a carrier with rules_epoch re that commits `fold`.
    pb::FrameVerdict judge(Node& n, std::uint64_t x, std::uint32_t re, const pb::RatchetState& fold,
                           const std::vector<pb::RatchetPlacement>& placed) {
        if (!n.live) return pb::FrameVerdict::Defer;
        if (n.h != x) {
            ++n.defers;
            return pb::FrameVerdict::Defer;
        }
        const std::uint64_t hh = pb::h_hold(p, n.S, x, n.T);
        const pb::FrameVerdict fv = pb::frame_epoch_verdict(x, re, hh, pb::epoch_at_held(p, n.S, x, n.T));
        if (fv == pb::FrameVerdict::Defer) {
            ++n.defers;
            if (!n.first_hold) n.first_hold = x;
            return fv;
        }
        if (fv == pb::FrameVerdict::Strike || !(fold == n.S)) {
            ++n.strikes;
            return pb::FrameVerdict::Strike;
        }
        const pb::StepAt st = pb::rs_step_at(p, n.S, x, placed, n.T);
        n.S = st.s;
        if (st.row) n.ar.append(*st.row);
        n.journal.emplace_back(x, n.S);
        while (n.journal.size() > n.J) {
            n.journal.pop_front();
            n.ar.note_journal_trim(n.journal.front().first);
        }
        ++n.h;
        if (!n.held(p)) ++n.jobs;
        return fv;
    }

    // The builder writes the carrier at x = pos: its ballot (or `ballot`), work,
    // and the extra placements; every node judges it.
    Verdicts extend(Node& b, std::optional<std::uint16_t> ballot = std::nullopt, std::uint64_t work = 1,
                    const std::vector<Placed>& extra = {}) {
        const std::uint64_t x = pos;
        const std::optional<Hash32> a = pb::act(p, b.S, x, b.T);
        const std::uint32_t re = b.S.epoch_cur + (a ? 1u : 0u);
        const pb::RatchetState fold = b.S;
        const std::uint16_t bal = ballot.value_or(pb::ballot_to_write(p, b.S, x, b.T, std::nullopt, false).ballot);
        std::vector<pb::RatchetPlacement> placed{{work, bal}};
        for (const Placed& e : extra) placed.push_back({e.work, e.ballot});
        if (keep_chain) chain.push_back(placed);
        Verdicts out;
        for (Node* n : nodes) out.v.push_back(judge(*n, x, re, fold, placed));
        ++pos;
        return out;
    }

    // Runs the chain to `until` (exclusive) with builder b; yes(x) decides the
    // carrier's ballot: b's own ballot when true, b's epoch_cur when false.
    // false: the builder held before `until`.
    bool run(Node& b, std::uint64_t until, const std::function<bool(std::uint64_t)>& yes,
             const std::function<std::vector<Placed>(std::uint64_t)>& extra = {}) {
        while (pos < until) {
            if (b.h != pos || b.held(p)) return false;
            const std::uint64_t x = pos;
            std::optional<std::uint16_t> bal;
            if (!yes(x)) bal = pb::make_ballot(b.S.epoch_cur, false);
            extend(b, bal, 1, extra ? extra(x) : std::vector<Placed>{});
        }
        return true;
    }

    // As run(), with an explicit ballot per position (nullopt: the builder's own).
    bool run_ballots(Node& b, std::uint64_t until, const std::function<std::optional<std::uint16_t>(std::uint64_t)>& bal) {
        while (pos < until) {
            if (b.h != pos || b.held(p)) return false;
            extend(b, bal(pos));
        }
        return true;
    }

    // Rewinds every node to fork position f (positions > f removed) from its journal.
    bool rewind(std::uint64_t f) {
        for (Node* n : nodes) {
            if (n->h <= f + 1) continue;
            const std::optional<pb::RatchetState> s = n->journal_state(f);
            if (!s) return false;
            while (!n->journal.empty() && n->journal.back().first > f) n->journal.pop_back();
            n->S = *s;
            n->h = f + 1;
            n->ar.rewind(f);
        }
        pos = f + 1;
        if (keep_chain) chain.resize(f + 1);
        return true;
    }

    // S_x recomputed from genesis over the kept chain with table T.
    std::vector<pb::RatchetState> replay(const pb::EpochTable& T) const {
        std::vector<pb::RatchetState> out;
        pb::RatchetState s = pb::genesis_ratchet_state(kG);
        for (std::uint64_t x = 0; x < chain.size(); ++x) {
            s = pb::rs_step_at(p, s, x, chain[x], T).s;
            out.push_back(s);
        }
        return out;
    }
};

}  // namespace ratchet_sim
