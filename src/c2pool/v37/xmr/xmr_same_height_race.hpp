// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_same_height_race.hpp   (c2pool#1551 — the same-height
//                                                double-block refusal, decided
//                                                prefer-own WITHIN BOUNDS)
//
// THE SITUATION. Two Monero blocks exist at the same parent height. One of them
// carries OUR c2pool K_fair settlement coinbase and settles our ledger; the
// other is a stranger's -- a competing template, a P2Pool aux block, a control
// peer's generateblocks -- and settles us nothing. Monero will eventually bury
// exactly one of them. Until it does, a pool's accounting has to answer a
// question the chain has not answered yet: who gets credited?
//
// THE RULE, AND WHERE IT STOPS. The race is decided by OUR benefit, so every
// lever WE control is biased toward our own block. There are exactly three of
// them and they are all local:
//
//   (1) WHAT WE BUILD ON. At EQUAL cumulative difficulty the native fork choice
//       adopts our own block over a stranger's (D-14, xmr_fork_choice.hpp:76).
//       Monero's rule there is first-seen; equal work means the network has not
//       decided, so choosing our own tip is a local preference inside the space
//       consensus left open, not an override of it.
//   (2) WHAT WE RE-ANNOUNCE. A contested height is a relay race, and the block
//       that reaches more of the network first is the one more of it builds on.
//   (3) WHAT WE NOMINATE. The accounting says out loud, per height, which block
//       it expects to be credited -- so an operator can see a contest happening
//       instead of finding out from a missing payout.
//
// And there the bias stops, because the fourth thing is not ours to bias:
//
//   (a) WE CANNOT OVERRIDE MONERO CONSENSUS. If the network buries the rival,
//       that is the chain. No policy in this file can make a block canonical.
//   (b) CREDIT REQUIRES BURIAL. Our block is credited only once it is buried
//       D_conf deep on the best chain. There is NO orphan-credit: a block
//       Monero discarded is never credited, however ours it was.
//   (c) NO DOUBLE-CREDIT (R-7). A height credits at most one block, once, and
//       a later reorg cannot move that credit or mint a second one.
//
// THE SHAPE THAT MAKES (a)/(b)/(c) CHECKABLE. The two outputs of this module are
// deliberately separated:
//
//     nominate()  -- POLICY-DEPENDENT. The lever. PreferOwn nominates ours;
//                    FirstSeen nominates whatever arrived first (monerod's own
//                    rule, kept so a parity run can turn the bias off).
//     decide()    -- POLICY-INDEPENDENT. The credit. A pure function of
//                    (own candidates, other candidates, burial, canonicality),
//                    identical under BOTH policies.
//
// So "prefer-own never buys credit" is not a claim in a comment: it is a
// property a KAT pins by running the same fixture under both policies and
// asserting the verdicts are byte-identical while the nominations differ.
//
// WHAT THE REFUSAL ACTUALLY REFUSES. While a contested height is unburied the
// verdict is DeferUnburied for EVERY candidate -- ours included. The naive
// alternatives are both wrong in the same direction: crediting on arrival pays
// out on a block the chain may still discard (an R-7 regression), and disposing
// our own candidate the moment a rival appears throws away credit Monero was
// about to award us. Refusing to decide, while nominating ours and pushing it,
// is the only posture that is both honest and self-interested.
//
// SCOPE FENCE: consumer tree, header-only, STL-only. No consensus digest is
// defined or altered here; nothing under src/sharechain/ is touched. This module
// SEQUENCES and AUDITS calls that the merged OwedLedger and the F1 finalize
// driver already own -- it never mutates a ledger itself.
// ===========================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace c2pool::v37n::xmr {

// ---------------------------------------------------------------------------
// The policy knob. A flag and not a constant because a parity run against
// monerod wants the bias OFF -- first-seen is the behaviour being compared --
// and because an operator who disagrees with the bias should be able to say so
// without running a different binary.
//
// The SAME value drives the native fork choice's D-14 tie-break, so "what we
// build on" and "what we nominate" can never disagree with each other.
// ---------------------------------------------------------------------------
enum class SameHeightTieBreak : std::uint8_t { FirstSeen = 0, PreferOwn = 1 };

inline const char* to_string(SameHeightTieBreak t) noexcept {
    return t == SameHeightTieBreak::PreferOwn ? "prefer-own" : "first-seen";
}

// Parse the CLI spelling. Returns false (and leaves `out` alone) on anything
// else, so the daemon can refuse rather than silently pick a side.
inline bool parse_tie_break(const std::string& s, SameHeightTieBreak& out) noexcept {
    if (s == "prefer-own" || s == "prefer_own" || s == "own") { out = SameHeightTieBreak::PreferOwn; return true; }
    if (s == "first-seen" || s == "first_seen" || s == "firstseen") { out = SameHeightTieBreak::FirstSeen; return true; }
    return false;
}

struct SameHeightPolicy {
    // The lever (1)+(3). Never reaches decide().
    SameHeightTieBreak tie_break = SameHeightTieBreak::PreferOwn;

    // Burial depth required before a found block may be credited. The same
    // D_conf the F1 finalize driver steps on (XmrNodeConfig::d_conf); carried
    // here so the accounting gate and the driver cannot drift apart.
    std::uint64_t d_conf = 60;

    // How many times a nominated-but-not-yet-adopted own block may be
    // re-announced per height (lever (2)). 0 disables the re-announce. Bounded
    // on purpose: an unbounded re-push of a block the network has already
    // rejected is a self-inflicted denial of service on our own peers.
    std::uint32_t max_renotify = 3;

    // NOT KNOBS. Written as named constants rather than left implicit so that a
    // reader looking for the escape hatch can see there is none: no
    // configuration makes an unburied or an orphaned block creditable.
    static constexpr bool credit_requires_burial = true;
    static constexpr bool orphan_credit_allowed  = false;
};

// ---------------------------------------------------------------------------
// The decision table, as an enum. Every row is reachable and every row is
// pinned by the KAT.
// ---------------------------------------------------------------------------
enum class RaceVerdict : std::uint8_t {
    // Nothing is known at this height at all.
    NoCandidate = 0,
    // Only a block that is not ours is known here. An aux/stranger block settles
    // our ledger nothing, so there is nothing to credit -- and nothing to refuse
    // either, because we never had a claim. Distinguished from NoCandidate so an
    // operator can tell "we mined nothing here" from "we lost this height".
    OtherOnly = 1,
    // We hold at least one candidate, and the height is NOT yet buried D_conf
    // deep. Credit is REFUSED for everyone until burial resolves it. This is the
    // same-height double-block refusal.
    DeferUnburied = 2,
    // Buried, and the chain carries one of OUR candidates at this height.
    CreditOwn = 3,
    // Buried, and the chain carries something else (or nothing we can see) at
    // this height: our candidate lost. NO credit. Bound (a) and bound (b).
    RefuseOrphaned = 4,
    // This height has already been credited. The decision is frozen: a later
    // reorg may not mint a second credit nor move the first (bound (c), R-7).
    AlreadyCredited = 5,
};

inline const char* to_string(RaceVerdict v) noexcept {
    switch (v) {
        case RaceVerdict::NoCandidate:     return "no-candidate";
        case RaceVerdict::OtherOnly:       return "other-only";
        case RaceVerdict::DeferUnburied:   return "defer-unburied";
        case RaceVerdict::CreditOwn:       return "credit-own";
        case RaceVerdict::RefuseOrphaned:  return "refuse-orphaned";
        case RaceVerdict::AlreadyCredited: return "already-credited";
    }
    return "?";
}

// True iff this verdict authorises a settlement credit. Exactly one row does.
inline bool verdict_credits(RaceVerdict v) noexcept { return v == RaceVerdict::CreditOwn; }

// ---------------------------------------------------------------------------
// THE CREDIT RULE, as a pure function of four booleans/counts and NOTHING else.
//
// It takes no policy argument, and that absence is the point: there is no
// parameter a caller could pass to make an unburied or non-canonical block
// creditable. SameHeightRaceLedger::decide() computes its verdict through this
// function and cross-checks itself against it, so the table a reader checks here
// is the table the daemon runs.
// ---------------------------------------------------------------------------
inline RaceVerdict credit_rule(std::size_t own_candidates,
                               std::size_t other_candidates,
                               bool already_credited,
                               bool buried,
                               bool one_of_ours_is_canonical) noexcept {
    if (already_credited) return RaceVerdict::AlreadyCredited;
    if (own_candidates == 0)
        return other_candidates == 0 ? RaceVerdict::NoCandidate : RaceVerdict::OtherOnly;
    if (!buried) return RaceVerdict::DeferUnburied;
    return one_of_ours_is_canonical ? RaceVerdict::CreditOwn : RaceVerdict::RefuseOrphaned;
}

// ---------------------------------------------------------------------------
// One candidate at one height.
// ---------------------------------------------------------------------------
struct RaceCandidate {
    std::string   bid;                 // 64 lowercase hex, the OwedLedger key
    bool          own = false;         // did WE find and settle-coinbase it?
    std::uint64_t seen_seq = 0;        // monotone arrival counter (first-seen)
    std::uint64_t seen_unix_s = 0;     // wall clock, for the journal only
    std::uint32_t renotified = 0;      // lever (2) budget already spent
};

struct RaceNomination {
    std::string bid;          // empty when there is nothing at this height
    bool        is_own = false;
    const char* why    = "nothing known at this height";
};

struct RaceDecision {
    RaceVerdict verdict = RaceVerdict::NoCandidate;
    // Non-empty ONLY for CreditOwn / AlreadyCredited: the block that is (or was)
    // credited. Deliberately not filled on any refusal row, so a caller cannot
    // accidentally read a bid out of a decision that did not authorise one.
    std::string credit_bid;
    RaceNomination nomination;
    bool        contested = false;      // >= 2 distinct candidates known here
    bool        own_vs_other = false;   // contested, and at least one of each side
    std::size_t own_candidates = 0;
    std::size_t other_candidates = 0;
    std::uint64_t height = 0;
    std::uint64_t need_hw = 0;          // height + d_conf, the burial bar
};

// ---------------------------------------------------------------------------
// SameHeightRaceLedger — the per-height race book and the gate over it.
//
// It is an ACCOUNTING object: it observes, it decides, and it records what was
// credited. It never mutates the OwedLedger, never talks to the network, and
// never answers the canonicality question itself -- that comes in as a callback
// bound to the SAME chain the F1 finalize driver asks, because a tiebreak that
// consulted a different oracle than the one that finalizes would be a second,
// disagreeing consensus.
//
// Single-threaded by contract (the daemon's main loop), like the finalize driver
// and the OwedLedger it sits beside.
// ---------------------------------------------------------------------------
class SameHeightRaceLedger {
public:
    using CanonicalFn = std::function<bool(std::uint64_t height, const std::string& bid_hex)>;

    struct Stats {
        std::uint64_t own_observed        = 0;
        std::uint64_t other_observed      = 0;
        std::uint64_t contests_opened     = 0;   // heights that reached >= 2 candidates
        std::uint64_t own_vs_other_opened = 0;   // ... with at least one of each side
        std::uint64_t credited            = 0;
        std::uint64_t refused_orphaned    = 0;
        std::uint64_t refused_other_only  = 0;
        std::uint64_t deferred            = 0;   // DeferUnburied decisions taken
        std::uint64_t double_credit_blocked = 0; // R-7 guard fired
        std::uint64_t renotify_requested  = 0;
    };

    explicit SameHeightRaceLedger(SameHeightPolicy p = {}) : m_p(p) {}

    void set_policy(const SameHeightPolicy& p) { m_p = p; }
    const SameHeightPolicy& policy() const noexcept { return m_p; }
    const Stats& stats() const noexcept { return m_stats; }

    // ── observation ────────────────────────────────────────────────────────
    // A block WE found at `height` carrying our settlement coinbase. Returns
    // true when it was new here. Idempotent per (height, bid).
    bool observe_own(std::uint64_t height, const std::string& bid, std::uint64_t unix_s = 0) {
        return observe_(height, bid, /*own=*/true, unix_s);
    }

    // A block at `height` that is NOT ours: seen on the chain, in the alt pool,
    // or as an orphan. Idempotent. A bid already recorded as ours STAYS ours --
    // our own block comes back to us through the chain and through the alt pool
    // and must not be re-labelled a stranger's by its own echo.
    bool observe_other(std::uint64_t height, const std::string& bid, std::uint64_t unix_s = 0) {
        return observe_(height, bid, /*own=*/false, unix_s);
    }

    // ── the decision ───────────────────────────────────────────────────────
    // `hw_height` is the best-chain high-water the settlement path is working
    // against (SettleHW::hw_height). `canonical` answers "does the best chain
    // carry this bid at this height" -- the same predicate the F1 driver runs.
    RaceDecision decide(std::uint64_t height, std::uint64_t hw_height,
                        const CanonicalFn& canonical) const {
        RaceDecision d;
        d.height  = height;
        d.need_hw = height + m_p.d_conf;

        const auto it = m_book.find(height);
        const std::vector<RaceCandidate>* cands = (it == m_book.end()) ? nullptr : &it->second.cands;

        std::size_t own_n = 0, other_n = 0;
        if (cands)
            for (const RaceCandidate& c : *cands) { if (c.own) ++own_n; else ++other_n; }
        d.own_candidates   = own_n;
        d.other_candidates = other_n;
        d.contested        = (own_n + other_n) >= 2;
        d.own_vs_other     = own_n >= 1 && other_n >= 1;
        d.nomination       = nominate_(cands);

        const auto cr = m_credited.find(height);
        const bool already = (cr != m_credited.end());

        const bool buried = hw_height >= d.need_hw;

        // Ask the chain only when the answer can matter. Bound (a): this is the
        // ONLY input that decides between CreditOwn and RefuseOrphaned, and it
        // is Monero's answer, not ours.
        std::string canonical_own;
        if (!already && own_n > 0 && buried && canonical && cands) {
            for (const RaceCandidate& c : *cands) {
                if (!c.own) continue;
                if (canonical(height, c.bid)) { canonical_own = c.bid; break; }
            }
        }

        d.verdict = credit_rule(own_n, other_n, already, buried, !canonical_own.empty());
        if (d.verdict == RaceVerdict::CreditOwn)          d.credit_bid = canonical_own;
        else if (d.verdict == RaceVerdict::AlreadyCredited) d.credit_bid = cr->second;
        return d;
    }

    // ── the credit record (bound (c), R-7) ─────────────────────────────────
    // Record that `bid` was credited at `height`. Returns false and counts a
    // blocked double-credit when the height already carries a credit -- whether
    // for the same bid (a replay) or a different one (a reorg trying to move
    // it). The caller treats false as "do not credit"; the merged OwedLedger's
    // own is_settled() idempotence is the second belt.
    bool note_credited(std::uint64_t height, const std::string& bid) {
        const auto it = m_credited.find(height);
        if (it != m_credited.end()) {
            ++m_stats.double_credit_blocked;
            return false;
        }
        m_credited.emplace(height, bid);
        ++m_stats.credited;
        return true;
    }

    // What was credited at this height, if anything.
    const std::string* credited_at(std::uint64_t height) const {
        const auto it = m_credited.find(height);
        return it == m_credited.end() ? nullptr : &it->second;
    }

    // The whole credited set, for a cross-node convergence diff: two nodes that
    // watched the same race must agree on this map exactly.
    const std::map<std::uint64_t, std::string>& credited() const noexcept { return m_credited; }

    // Count a decision that the caller acted on, so the stats reflect the run
    // rather than however many times a status line happened to ask.
    void account(const RaceDecision& d) {
        switch (d.verdict) {
            case RaceVerdict::DeferUnburied:  ++m_stats.deferred; break;
            case RaceVerdict::RefuseOrphaned: ++m_stats.refused_orphaned; break;
            case RaceVerdict::OtherOnly:      ++m_stats.refused_other_only; break;
            default: break;
        }
    }

    // ── lever (2): the bounded re-announce ─────────────────────────────────
    // Should we re-push our nominated block at this height right now? True at
    // most `max_renotify` times per height, and only while the height is
    // genuinely contested against a rival, unburied, and our nominee is not the
    // block the chain currently carries. Consumes one unit of the budget.
    bool take_renotify(std::uint64_t height, const RaceDecision& d, const CanonicalFn& canonical) {
        if (m_p.max_renotify == 0) return false;
        if (m_p.tie_break != SameHeightTieBreak::PreferOwn) return false;
        if (d.verdict != RaceVerdict::DeferUnburied) return false;
        if (!d.own_vs_other) return false;
        if (!d.nomination.is_own || d.nomination.bid.empty()) return false;
        if (canonical && canonical(height, d.nomination.bid)) return false;  // already ours
        const auto it = m_book.find(height);
        if (it == m_book.end()) return false;
        for (RaceCandidate& c : it->second.cands) {
            if (c.bid != d.nomination.bid) continue;
            if (c.renotified >= m_p.max_renotify) return false;
            ++c.renotified;
            ++m_stats.renotify_requested;
            return true;
        }
        return false;
    }

    // ── read seams ─────────────────────────────────────────────────────────
    std::vector<std::uint64_t> heights() const {
        std::vector<std::uint64_t> out;
        out.reserve(m_book.size());
        for (const auto& kv : m_book) out.push_back(kv.first);
        return out;
    }

    // Heights holding >= 2 candidates with at least one of each side: the real
    // races, as opposed to a height where we simply found two of our own.
    std::vector<std::uint64_t> contested_heights() const {
        std::vector<std::uint64_t> out;
        for (const auto& kv : m_book) {
            std::size_t own_n = 0, other_n = 0;
            for (const RaceCandidate& c : kv.second.cands) { if (c.own) ++own_n; else ++other_n; }
            if (own_n >= 1 && other_n >= 1) out.push_back(kv.first);
        }
        return out;
    }

    // The heights a gate actually has to walk: one we hold a candidate of our
    // own at, or one carrying more than one candidate at all. A height where the
    // chain simply delivered one stranger's block is not a race and does not
    // need deciding every tick -- and on a node that has been up for a week,
    // walking every height it has ever seen is the difference between a gate and
    // a leak.
    std::vector<std::uint64_t> heights_of_interest() const {
        std::vector<std::uint64_t> out;
        for (const auto& kv : m_book) {
            std::size_t own_n = 0;
            for (const RaceCandidate& c : kv.second.cands) if (c.own) ++own_n;
            if (own_n >= 1 || kv.second.cands.size() >= 2) out.push_back(kv.first);
        }
        return out;
    }

    const std::vector<RaceCandidate>* candidates_at(std::uint64_t height) const {
        const auto it = m_book.find(height);
        return it == m_book.end() ? nullptr : &it->second.cands;
    }

    bool holds_own(std::uint64_t height, const std::string& bid) const {
        const auto it = m_book.find(height);
        if (it == m_book.end()) return false;
        for (const RaceCandidate& c : it->second.cands)
            if (c.own && c.bid == bid) return true;
        return false;
    }

    // Forget heights strictly below `floor`. The book is bounded by the same
    // retention the settlement path already keeps; a node that ran for a month
    // must not carry a candidate list for every height it ever saw. Credited
    // records are kept for `credit_keep` heights below the floor so the R-7
    // guard still answers for anything a reorg could plausibly reach.
    std::size_t prune_below(std::uint64_t floor, std::uint64_t credit_keep = 0) {
        std::size_t n = 0;
        for (auto it = m_book.begin(); it != m_book.end();) {
            if (it->first < floor) { it = m_book.erase(it); ++n; } else break;
        }
        const std::uint64_t cfloor = floor > credit_keep ? floor - credit_keep : 0;
        for (auto it = m_credited.begin(); it != m_credited.end();) {
            if (it->first < cfloor) it = m_credited.erase(it); else break;
        }
        return n;
    }

    std::size_t book_size() const noexcept { return m_book.size(); }

private:
    // The per-height book, plus the two "counted already" latches. Without them
    // a contest would be counted again every time a candidate was re-observed
    // or promoted, and the run's contest count is evidence -- it has to mean
    // "races that happened", not "times we looked".
    struct HeightBook {
        std::vector<RaceCandidate> cands;
        bool contest_counted = false;   // reached >= 2 candidates
        bool ovo_counted     = false;   // reached >= 1 own AND >= 1 other
    };

    bool observe_(std::uint64_t height, const std::string& bid, bool own, std::uint64_t unix_s) {
        if (bid.size() != 64) return false;          // never key on a malformed id
        HeightBook& hb = m_book[height];

        bool added = true;
        bool promoted = false;
        for (RaceCandidate& c : hb.cands) {
            if (c.bid != bid) continue;
            added = false;
            // Promotion is one-way: a block we found is ours forever, even when
            // the chain hands it back to us as an ordinary block.
            if (own && !c.own) { c.own = true; promoted = true; }
            break;
        }
        if (added) {
            RaceCandidate c;
            c.bid = bid;
            c.own = own;
            c.seen_seq = ++m_seq;
            c.seen_unix_s = unix_s;
            hb.cands.push_back(std::move(c));
        }
        if (added || promoted) {
            if (own) ++m_stats.own_observed; else ++m_stats.other_observed;
        }
        note_contest_(hb);
        return added;
    }

    // Count a contest exactly once, at the moment it opens.
    void note_contest_(HeightBook& hb) {
        std::size_t own_n = 0, other_n = 0;
        for (const RaceCandidate& c : hb.cands) { if (c.own) ++own_n; else ++other_n; }
        if (!hb.contest_counted && own_n + other_n >= 2) {
            hb.contest_counted = true;
            ++m_stats.contests_opened;
        }
        if (!hb.ovo_counted && own_n >= 1 && other_n >= 1) {
            hb.ovo_counted = true;
            ++m_stats.own_vs_other_opened;
        }
    }

    // THE LEVER. This is the only place the policy is read.
    RaceNomination nominate_(const std::vector<RaceCandidate>* cands) const {
        RaceNomination n;
        if (!cands || cands->empty()) return n;

        const RaceCandidate* first_own   = nullptr;
        const RaceCandidate* first_other = nullptr;
        const RaceCandidate* earliest    = nullptr;
        for (const RaceCandidate& c : *cands) {
            if (c.own) { if (!first_own || c.seen_seq < first_own->seen_seq) first_own = &c; }
            else       { if (!first_other || c.seen_seq < first_other->seen_seq) first_other = &c; }
            if (!earliest || c.seen_seq < earliest->seen_seq) earliest = &c;
        }

        if (m_p.tie_break == SameHeightTieBreak::PreferOwn && first_own) {
            n.bid = first_own->bid;
            n.is_own = true;
            n.why = first_other ? "prefer-own: our settlement block over the rival"
                                : "our settlement block, unopposed so far";
            return n;
        }
        if (earliest) {
            n.bid = earliest->bid;
            n.is_own = earliest->own;
            n.why = (m_p.tie_break == SameHeightTieBreak::FirstSeen)
                        ? "first-seen (bias off: monerod's own rule)"
                        : "first-seen: we hold no candidate of our own here";
        }
        return n;
    }

    SameHeightPolicy m_p;
    std::map<std::uint64_t, HeightBook>   m_book;      // height -> candidates
    std::map<std::uint64_t, std::string>  m_credited;  // height -> credited bid
    std::uint64_t m_seq = 0;
    Stats         m_stats;
};

// ---------------------------------------------------------------------------
// One journal line per verdict TRANSITION, in a shape two nodes can diff.
// Cross-node convergence after burial is exactly "these files agree on every
// height either of them credited", which is a claim a `diff` settles.
// ---------------------------------------------------------------------------
inline std::string race_journal_line(const RaceDecision& d, std::uint64_t hw_height) {
    std::string s = "h=" + std::to_string(d.height)
                  + " verdict=" + to_string(d.verdict)
                  + " hw=" + std::to_string(hw_height)
                  + " need=" + std::to_string(d.need_hw)
                  + " own=" + std::to_string(d.own_candidates)
                  + " other=" + std::to_string(d.other_candidates)
                  + " contested=" + (d.own_vs_other ? "own-vs-other" : (d.contested ? "own-vs-own" : "no"))
                  + " nominated=" + (d.nomination.bid.empty() ? std::string("-") : d.nomination.bid)
                  + " nominated_own=" + (d.nomination.is_own ? "1" : "0")
                  + " credit=" + (d.credit_bid.empty() ? std::string("-") : d.credit_bid);
    return s;
}

} // namespace c2pool::v37n::xmr
