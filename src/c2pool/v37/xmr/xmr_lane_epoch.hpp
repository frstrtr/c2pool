// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_lane_epoch.hpp   (LANE-EPOCH, E1)
//
// ONE STRUCTURE PER COIN (operator direction 09-26). The structure is the
// pool_tag (lane_tag + the network-default pool genesis, POOL-LINEAGE); it is
// never re-created per run. Inside it, a LINEAGE is one chain of ledger states
// (owed_digest roots) and lane spines; an EPOCH is a lineage with an explicit
// on-chain identity, committed by every gate-ON lane block in the V37E field
// (xmr_credit_cut.hpp): (epoch_seq, epoch_version, parent_digest). A block
// without the field is read as epoch 0 (the implicit lineage).
//
// THE PROBLEM this answers: a node that meets lane blocks whose lineage no
// reachable peer can serve (fresh state on a chain that already carries lane
// blocks of the SAME structure: capstone attempt-3 false start) could only
// HOLD them forever (lane-root-unknown / relay repair exhausted): cursor
// frozen, lane suspended, the structure dead.
//
// THE RULE (a pure function of canonical chain data; never peer availability,
// wall clock, store age or whether this node holds rows). For an Own-tagged
// block B at height h, with V37E field f (absent => {0, v1, 0^32}) and the
// epoch state S folded from every Own block below h, in chain order:
//   (a) V37E malformed / f.version not in the compiled table -> UNKNOWN (+fuse)
//   (b) f.seq == S.cur_seq, same version + parent           -> SAME-EPOCH: booked as today
//       f.seq == S.cur_seq, other version or parent          -> SIBLING (never credited)
//   (c) f.seq == S.cur_seq + 1                                -> OPENER iff
//         c1 DEAD : h - S.last_h >= N (no Own block of the current epoch in the
//                   last N heights; with no such block at all, the view must
//                   cover N heights below h),
//         c2      : f.parent == sha256d('V37EP' || u32 cur_seq || last_bid || last_root)
//                   (0^32 when the current epoch has no block in the view),
//         c3      : f.version == S.cur_version (upgrade openers: next slice),
//         c4 (E1) : the 0x03 root is the EMPTY ledger's root and the V37C cut is present;
//       else INVALID-OPENER (never credited)
//   (d) f.seq <  S.cur_seq                                    -> STALE (never credited)
//   (e) f.seq >  S.cur_seq + 1                                -> UNKNOWN (+fuse: this view missed an opener)
// SAME-EPOCH and OPENER blocks advance S (last_h/last_bid/last_root; an
// opener also moves cur_seq/cur_version/cur_parent). Every other verdict
// leaves S untouched and is never HELD: its payout is a node-local liability
// and the finalize cursor moves on (FinalizeConnect "epoch-" outcomes).
//
// At a valid OPENER every node (holder or fresh) closes its ledger (the rows
// are recorded and stay provable against the last root on chain) and books the
// new epoch from the empty state, so a node that held the old history and a
// node that never saw it reach the SAME state at the SAME block (M3). E1
// discloses: owed of the closed epoch is NOT credited in the new one.
//
// Two live partitions of one structure on one chain never satisfy DEAD (each
// keeps landing lane blocks), so neither can open an epoch.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32, ::v37::sha256d
#include "xmr_credit_cut.hpp"            // credit::EpochField / EpochParse

namespace c2pool::v37n::xmr::epoch {

using bytes32 = ::v37::bytes32;
namespace credit = ::c2pool::v37n::xmr::credit;

// The compiled epoch-version table (ADD-ONLY). Version 1 = V37E v1 + the E1
// dead-lineage opener. A later version row (with a per-network activation
// height) is the in-structure protocol-upgrade vehicle (deferred: it needs the
// continuation opener).
inline constexpr std::uint32_t kEpochRuleVersion = 1;
inline bool version_known(std::uint32_t v) { return v == kEpochRuleVersion; }

// N, the inactivity bound (heights). network = the relay HELLO byte
// (0 mainnet, 1 testnet, 2 stagenet, 3 regtest). Mainnet 2160 = 3 days = 36 *
// D_conf(60); stagenet/testnet 720 (1 day); regtest 40 (= 4 * D_conf 10, the floor).
inline std::uint64_t default_n_dead(std::uint8_t network) {
    switch (network) {
        case 0:  return 2160;
        case 1:  return 720;
        case 2:  return 720;
        default: return 40;
    }
}
// The floor every configured N must meet: a reorg shallower than D_conf can
// then never turn an invalid (too early) opener valid, and an honest builder
// suspended at the 2*D_conf lag bound plus the 4*D_conf stale-root window
// never looks dead.
inline std::uint64_t min_n_dead(std::uint64_t d_conf) { return 4 * (d_conf ? d_conf : 1); }

inline bytes32 parent_digest(std::uint32_t seq, const bytes32& last_bid, const bytes32& last_root) {
    std::vector<std::uint8_t> b = {'V', '3', '7', 'E', 'P'};
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(seq >> (8 * i)));
    b.insert(b.end(), last_bid.begin(), last_bid.end());
    b.insert(b.end(), last_root.begin(), last_root.end());
    return ::v37::sha256d(b);
}

// The synthetic event id under which a holder closes its ledger at an opener
// (FOUND credit = -row, FINALIZE: every row to 0, through the event log).
inline bytes32 close_event_id(std::uint32_t new_seq, const bytes32& opener_bid) {
    std::vector<std::uint8_t> b = {'V', '3', '7', 'E', 'C'};
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(new_seq >> (8 * i)));
    b.insert(b.end(), opener_bid.begin(), opener_bid.end());
    return ::v37::sha256d(b);
}

// One canonical block as the rule reads it.
struct ChainFact {
    std::uint64_t        h = 0;
    bytes32              bid{};
    bool                 own = false;            // V37P == our pool_tag AND a 03 21 00 tail
    credit::EpochParse   ep = credit::EpochParse::Absent;
    credit::EpochField   f{};                    // valid iff ep == Present
    bool                 has_root = false;
    bytes32              root{};                 // the on-chain 0x03 root
    bool                 has_cut = false;        // a V37C credit cut is present
};

enum class Verdict : std::uint8_t { NotOwn, SameEpoch, Opener, InvalidOpener, Stale, Sibling, Unknown };

inline const char* to_string(Verdict v) {
    switch (v) {
        case Verdict::NotOwn:        return "not-own";
        case Verdict::SameEpoch:     return "same-epoch";
        case Verdict::Opener:        return "opener";
        case Verdict::InvalidOpener: return "invalid-opener";
        case Verdict::Stale:         return "stale";
        case Verdict::Sibling:       return "sibling";
        case Verdict::Unknown:       return "unknown";
    }
    return "?";
}

struct State {
    std::uint32_t cur_seq = 0;
    std::uint32_t cur_version = kEpochRuleVersion;
    bytes32       cur_parent{};
    bool          opened = false;          // cur_seq was opened by an opener inside the view
    std::uint64_t open_h = 0;
    bytes32       opener_bid{};
    bool          has_last = false;        // the current epoch has a lane block in the view
    std::uint64_t last_h = 0;
    bytes32       last_bid{};
    bytes32       last_root{};
    bool operator==(const State&) const = default;
};

struct Decision {
    Verdict            v = Verdict::NotOwn;
    bool               fuse = false;       // this view cannot read the structure's current epoch
    credit::EpochField f{};                // the effective field
    std::string        why;
};

struct Rule {
    std::uint64_t n_dead = 40;
    bytes32       empty_root{};            // mm root of the empty ledger (sha256d('V37Q'))
    std::uint64_t origin_h = 0;            // the lowest height the view covers
};

inline credit::EpochField effective_field(const ChainFact& c) {
    if (c.ep == credit::EpochParse::Present) return c.f;
    return credit::EpochField{0, kEpochRuleVersion, bytes32{}};
}

inline bool dead_at(const Rule& r, const State& s, std::uint64_t h) {
    if (s.has_last) return h >= s.last_h + r.n_dead;
    return h >= r.origin_h + r.n_dead;
}

inline bytes32 expected_parent(const State& s) {
    return s.has_last ? parent_digest(s.cur_seq, s.last_bid, s.last_root) : bytes32{};
}

inline Decision classify(const Rule& r, const State& s, const ChainFact& c) {
    Decision d;
    d.f = effective_field(c);
    if (!c.own) { d.v = Verdict::NotOwn; return d; }
    if (c.ep == credit::EpochParse::Malformed) {
        d.v = Verdict::Unknown; d.fuse = true; d.why = "malformed V37E field (unknown field version)"; return d;
    }
    if (!version_known(d.f.version)) {
        d.v = Verdict::Unknown; d.fuse = true;
        d.why = "epoch version " + std::to_string(d.f.version) + " is not in this build's version table"; return d;
    }
    if (d.f.seq == s.cur_seq) {
        if (d.f.version == s.cur_version && d.f.parent == s.cur_parent) { d.v = Verdict::SameEpoch; return d; }
        d.v = Verdict::Sibling; d.why = "seq " + std::to_string(d.f.seq) + " with another version/parent than the current epoch's";
        return d;
    }
    if (d.f.seq < s.cur_seq) {
        d.v = Verdict::Stale; d.why = "epoch " + std::to_string(d.f.seq) + " was closed by the opener of epoch " +
                                      std::to_string(s.cur_seq) + " at h=" + std::to_string(s.open_h);
        return d;
    }
    if (d.f.seq > s.cur_seq + 1) {
        d.v = Verdict::Unknown; d.fuse = true;
        d.why = "future epoch " + std::to_string(d.f.seq) + " (current " + std::to_string(s.cur_seq) +
                "): an opener this view did not process";
        return d;
    }
    // (c) OPENER candidate
    std::string bad;
    if (!dead_at(r, s, c.h))
        bad += s.has_last ? " c1:not-dead(last lane block h=" + std::to_string(s.last_h) + ", " +
                                std::to_string(c.h - s.last_h) + " < N=" + std::to_string(r.n_dead) + ")"
                          : " c1:undecidable(view covers " + std::to_string(c.h > r.origin_h ? c.h - r.origin_h : 0) +
                                " < N=" + std::to_string(r.n_dead) + " heights)";
    if (!(d.f.parent == expected_parent(s))) bad += " c2:parent-mismatch";
    if (d.f.version != s.cur_version) bad += " c3:version";
    if (!c.has_root || !(c.root == r.empty_root)) bad += " c4:root-not-empty";
    if (!c.has_cut) bad += " c4:no-credit-cut";
    if (bad.empty()) { d.v = Verdict::Opener; return d; }
    d.v = Verdict::InvalidOpener; d.why = "opener of epoch " + std::to_string(d.f.seq) + " invalid:" + bad;
    return d;
}

inline void apply(State& s, const ChainFact& c, const Decision& d) {
    if (d.v == Verdict::SameEpoch) {
        s.has_last = true; s.last_h = c.h; s.last_bid = c.bid; s.last_root = c.has_root ? c.root : bytes32{};
    } else if (d.v == Verdict::Opener) {
        s.cur_seq = d.f.seq; s.cur_version = d.f.version; s.cur_parent = d.f.parent;
        s.opened = true; s.open_h = c.h; s.opener_bid = c.bid;
        s.has_last = true; s.last_h = c.h; s.last_bid = c.bid; s.last_root = c.has_root ? c.root : bytes32{};
    }
}

// ---------------------------------------------------------------------------
// EpochView: the per-node derived index. Facts for every canonical height the
// node has scanned, in [origin, complete_to]; the state at any height is the
// fold of the Own facts below it. Reorgs replace a height's fact (put) or cut
// the view back (truncate_above); the fold is recomputed, so an orphaned
// opener is undone exactly like the pending set.
// ---------------------------------------------------------------------------
class EpochView {
public:
    EpochView() = default;
    EpochView(std::uint64_t n_dead, const bytes32& empty_root) { m_rule.n_dead = n_dead; m_rule.empty_root = empty_root; }

    void set_origin(std::uint64_t h) { m_rule.origin_h = h; m_origin_set = true; }
    bool origin_set() const { return m_origin_set; }
    const Rule& rule() const { return m_rule; }
    std::uint64_t origin() const { return m_rule.origin_h; }

    // true when the height's fact changed (new height or another block there)
    bool put(const ChainFact& c) {
        if (m_origin_set && c.h < m_rule.origin_h) return false;
        auto it = m_facts.find(c.h);
        if (it != m_facts.end() && it->second.bid == c.bid) return false;
        m_facts[c.h] = c;
        return true;
    }
    void truncate_above(std::uint64_t h) { m_facts.erase(m_facts.upper_bound(h), m_facts.end()); }
    const ChainFact* at(std::uint64_t h) const { auto it = m_facts.find(h); return it == m_facts.end() ? nullptr : &it->second; }
    std::size_t size() const { return m_facts.size(); }

    // highest H with every height in [origin, H] recorded (origin - 1 if none)
    std::uint64_t complete_to() const {
        std::uint64_t h = m_pruned ? m_pruned_to + 1 : m_rule.origin_h;
        auto it = m_facts.find(h);
        if (it == m_facts.end()) return h ? h - 1 : 0;
        for (; it != m_facts.end() && it->first == h; ++it, ++h) {}
        return h - 1;
    }

    // The fold of the Own facts strictly below h.
    State state_before(std::uint64_t h, std::uint64_t* fuse_h = nullptr) const {
        State s;
        for (auto it = m_facts.begin(); it != m_facts.end() && it->first < h; ++it) {
            if (!it->second.own) continue;
            const Decision d = classify(m_rule, s, it->second);
            if (d.fuse && fuse_h) *fuse_h = it->first;
            apply(s, it->second, d);
        }
        return s;
    }
    Decision decide(std::uint64_t h) const {
        const ChainFact* c = at(h);
        if (!c) return Decision{};
        return classify(m_rule, state_before(h), *c);
    }

    // Every Own fact's verdict in chain order: "h:verdict:seq" -- the M3
    // cross-node comparison string (holder vs fresh must print the same).
    std::string classification() const {
        State s; std::string out;
        for (const auto& [h, c] : m_facts) {
            if (!c.own) continue;
            const Decision d = classify(m_rule, s, c);
            apply(s, c, d);
            if (!out.empty()) out += ' ';
            out += std::to_string(h) + ":" + epoch::to_string(d.v) + ":" + std::to_string(d.f.seq);
        }
        return out;
    }

    // The builder's plan for the NEXT height.
    struct Plan {
        enum class Mode : std::uint8_t { Continue, Open, Wait, Fuse } mode = Mode::Wait;
        credit::EpochField f{};
        std::uint64_t next_h = 0;
        std::string why;
    };
    static const char* to_string(Plan::Mode m) {
        switch (m) {
            case Plan::Mode::Continue: return "continue";
            case Plan::Mode::Open:     return "open";
            case Plan::Mode::Wait:     return "wait";
            case Plan::Mode::Fuse:     return "fuse";
        }
        return "?";
    }
    // holds_lineage: this node's ledger is ON the current epoch's lineage (it
    // can commit a root the other nodes of the epoch know). POLICY input only:
    // it decides whether this node BUILDS, never how any block is classified.
    Plan plan(std::uint64_t next_h, bool holds_lineage) const {
        Plan p; p.next_h = next_h;
        if (!m_origin_set || complete_to() + 1 < next_h) {
            p.mode = Plan::Mode::Wait;
            p.why = "epoch view incomplete (complete to " + std::to_string(complete_to()) + ", next height " + std::to_string(next_h) + ")";
            return p;
        }
        std::uint64_t fuse_h = 0;
        const State s = state_before(next_h, &fuse_h);
        if (fuse_h && next_h <= fuse_h + 2 * m_rule.n_dead) {
            p.mode = Plan::Mode::Fuse;
            p.why = "an Own block at h=" + std::to_string(fuse_h) + " carries an epoch this build cannot read";
            return p;
        }
        if (dead_at(m_rule, s, next_h)) {
            p.mode = Plan::Mode::Open;
            p.f = credit::EpochField{s.cur_seq + 1, s.cur_version, expected_parent(s)};
            p.why = s.has_last ? "epoch " + std::to_string(s.cur_seq) + " dead since h=" + std::to_string(s.last_h) +
                                     " (N=" + std::to_string(m_rule.n_dead) + ")"
                               : "no lane block of epoch " + std::to_string(s.cur_seq) + " in the view's " +
                                     std::to_string(next_h - m_rule.origin_h) + " heights (N=" + std::to_string(m_rule.n_dead) + ")";
            return p;
        }
        if (!s.has_last || holds_lineage) {
            p.mode = Plan::Mode::Continue;
            p.f = credit::EpochField{s.cur_seq, s.cur_version, s.cur_parent};
            return p;
        }
        p.mode = Plan::Mode::Wait;
        p.why = "epoch " + std::to_string(s.cur_seq) + " is alive (last lane block h=" + std::to_string(s.last_h) +
                ") but this node does not hold its history: bootstrap needed; an opener is valid from h=" +
                std::to_string(s.last_h + m_rule.n_dead);
        return p;
    }

    // Drop the NON-Own facts below `keep_from` (bounds memory). Own facts are
    // never dropped here (the fold needs them) and the rule's origin never
    // moves, so no verdict changes; only the completeness walk starts later.
    void prune(std::uint64_t keep_from) {
        if (keep_from == 0 || keep_from - 1 > complete_to()) return;
        for (auto it = m_facts.begin(); it != m_facts.end() && it->first < keep_from;)
            it = it->second.own ? std::next(it) : m_facts.erase(it);
        m_pruned = true; m_pruned_to = keep_from - 1;
    }

private:
    Rule m_rule;
    bool m_origin_set = false;
    bool m_pruned = false;
    std::uint64_t m_pruned_to = 0;
    std::map<std::uint64_t, ChainFact> m_facts;
};

// ---------------------------------------------------------------------------
// The booking-side outcomes (shared by main's book_from_chain_ex and the KATs).
// ---------------------------------------------------------------------------
// A verdict that is DECIDED without booking: the FinalizeConnect "epoch-" why
// (never retried, never held, not a vote observation). nullopt = book it.
inline std::optional<std::string> decided_why(const Decision& d) {
    switch (d.v) {
        case Verdict::Stale: case Verdict::InvalidOpener: case Verdict::Sibling: case Verdict::Unknown:
            return std::string("epoch-") + to_string(d.v) + ": " + d.why;
        default: return std::nullopt;
    }
}
inline bool undecided_booking(const std::string& why) {
    return why.rfind("lane-root-unknown:", 0) == 0 || why.rfind("lane-root-refused:", 0) == 0 ||
           why.rfind("cut-pending:", 0) == 0;
}
// A SAME-EPOCH block this node could not book (its root is not in this node's
// history, or the lane view at its cut is unobtainable) whose lineage is
// CLOSED (a valid opener above it in the view) or DEAD (N silent heights at the
// view's complete frontier). The structure continues through the opener; the
// block is decided "epoch-closed:" / "epoch-dead:" instead of HELD forever.
// nullopt = keep today's outcome (a live lineage: retry / hold / bootstrap).
inline std::optional<std::string> undecided_to_decided(const EpochView& v, const Decision& d, const std::string& why) {
    if (d.v != Verdict::SameEpoch || !undecided_booking(why)) return std::nullopt;
    const std::uint64_t ct = v.complete_to();
    const State ts = v.state_before(ct + 1);
    if (ts.cur_seq != d.f.seq)
        return "epoch-closed: lineage of epoch " + std::to_string(d.f.seq) + " closed by the opener at h=" +
               std::to_string(ts.open_h) + " (" + why.substr(0, 60) + ")";
    if (dead_at(v.rule(), ts, ct + 1))
        return "epoch-dead: epoch " + std::to_string(d.f.seq) + " has no lane block since h=" + std::to_string(ts.last_h) +
               " (N=" + std::to_string(v.rule().n_dead) + ") and this node cannot resolve it (" + why.substr(0, 60) + ")";
    return std::nullopt;
}

} // namespace c2pool::v37n::xmr::epoch
