// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_kstep.hpp
// Path B roundabouts, slice C-3: the depth of a bin, the K-step list of a tip,
// the persisted K-step book.
//
//   depth(e)     epoch 0: 0, whether or not its list is held (the network's
//                list, K17 = 1); epoch e >= 1: log2(K17) of the compiled
//                entry of e (its digest equal to the one given, when one is
//                given); unknown (nullopt) when the entry or its list is
//                absent or K17 is not a power of two. Never 0 for unknown.
//   K step       an activation whose epoch's depth differs from the depth of
//                the epoch before it; at_bin = H(h_act - 1) + 1 + Fresh.
//   the gate     table_has_k_step: some compiled epoch e >= 1 has an unknown
//                depth or a depth other than 0. False: no site syncs a book and
//                no list is asked (K = 1).
//   tip_acts     the activations in force at x = pos(t) + 1 on t's own chain:
//                held (S_{pos(t)} on t's branch): the AR rows at or below
//                c = max(f, p0 - 1) (c = f on a full chain), the activation
//                fields of t's chain in (c, pos(t)], the activation at x;
//                fork-local: the AR rows at or below min(x, pos(best)), plus
//                the lock-in seen from the best tip that activates in
//                (pos(best), x]. f and best are derived (the store's best tip;
//                f the newest ancestor of t on the store's best chain). The
//                self-check: the first row is the seed row (a joined state) or
//                epoch 1 (a full chain), the epochs ascend by one, the last
//                equals epoch_at's value; else the list is a gap.
//   ksteps_at    (1) inconsistent, or not Epoch: a gap knowing no bin;
//                (2) every epoch 0 .. e_t of one known depth: no step, no gap;
//                (3) a joined state: epochs 0 .. e_s of one known depth, or a
//                gap from at_bin_of(H(p0 - 1)) (H read on t's view, else the
//                store's adopt bound - Fresh); depth0 = depth(e_s);
//                (4) each pair of consecutive rows with two known depths that
//                differ is a step; its at_bin from t's view when H(h_act - 1)
//                is held there, else from the book, else a gap knowing no bin.
//                An unknown depth: a gap knowing no bin.
//   kbook_sync   the one writer of a book: the entries above `above` erased;
//                every non-seed AR row above `above` whose pair is a known
//                step put with at_bin from the best chain's record.
//   m(b), j(b), sigma: the depth of bin b; the merge depth of the steps with
//                b < at_bin <= top (top = the window's start bin + 1);
//                max(0, max(j(b) - m(b))) over the reach; depth_start = the
//                depth at top.
//   kstep_calls  one process-wide counter of the calls of tip_acts, ksteps_at,
//                kbook_sync, depth_of_bin, merge_delta and sigma (relaxed).
//
// Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "pathb_bin_store.hpp"
#include "pathb_fork_choice.hpp"
#include "pathb_lane_rules.hpp"
#include "pathb_ratchet_activation.hpp"

#ifdef V37_XMR_RING_TEST_EPOCHS
#include <functional>

#include "pathb_ring.hpp"       // kRingDepthBound
#include "pathb_ring_rule.hpp"  // RingRule, kRingStepMin
#endif

namespace c2pool::xmr::pathb {

struct KStep {
    std::uint64_t at_bin = 0;
    std::uint8_t depth_before = 0;
    std::uint8_t depth_after = 0;

    friend bool operator==(const KStep&, const KStep&) = default;
};
using KStepList = std::vector<KStep>;  // ascending at_bin

// One K step of the best chain, written with its activation row (node-local).
struct KStepRecord {
    std::uint16_t epoch = 0;
    std::uint64_t h_act = 0;
    std::uint64_t at_bin = 0;

    friend bool operator==(const KStepRecord&, const KStepRecord&) = default;
};
using KStepBook = std::map<std::uint64_t, KStepRecord>;  // by h_act; one per lane state

struct KStepOps {
    std::vector<std::uint64_t> del;  // h_act of the entries erased and not put again
    std::vector<KStepRecord> put;
};

struct KSteps {
    bool gap = false;                  // a depth change is known to exist and its at_bin is not known
    std::uint64_t known_from_bin = 0;  // with gap: every bin >= this has a known depth
    std::uint8_t depth0 = 0;           // the depth below the first listed step
    KStepList list;

    friend bool operator==(const KSteps&, const KSteps&) = default;
};

struct TipActs {
    EpochAtKind kind = EpochAtKind::Epoch;  // Defer / Claimed: no list
    std::vector<ActivationRow> rows;        // ascending h_act
    std::optional<std::uint64_t> seed_p0;   // a joined state's p0; rows[0] is then the seed row
    bool consistent = true;                 // the self-check
};

// A gap that knows the depth of no bin.
inline constexpr std::uint64_t kNoKnownBin = std::numeric_limits<std::uint64_t>::max();

namespace detail_kstep {
inline std::atomic<std::uint64_t> g_calls{0};
inline void count() noexcept { g_calls.fetch_add(1, std::memory_order_relaxed); }

#ifdef V37_XMR_RING_TEST_EPOCHS
// Test builds only: a KAT hides a walked node's activation field from tip_acts.
inline std::function<bool(const CarrierNode&)> g_test_hide_activation;
#endif

// The depth of a list's K17; nullopt unless K17 is a power of two.
inline constexpr std::optional<std::uint8_t> depth_of_k17(std::uint8_t k) noexcept {
    if (k == 0 || (k & (k - 1)) != 0) return std::nullopt;
    std::uint8_t d = 0;
    for (std::uint8_t v = k; v > 1; v = static_cast<std::uint8_t>(v >> 1)) ++d;
    return d;
}
}  // namespace detail_kstep

// The depth of epoch 0 (the network's list, K17 = kPaymentGroups).
inline constexpr std::uint8_t kEpoch0Depth = *detail_kstep::depth_of_k17(kPaymentGroups);

inline std::uint64_t kstep_calls() noexcept { return detail_kstep::g_calls.load(std::memory_order_relaxed); }

// at_bin = H(h_act - 1) + 1 + Fresh: the first bin of the new depth.
inline std::uint64_t at_bin_of(std::uint64_t h_of_hact_minus_1, std::uint64_t fresh_max) noexcept {
    return h_of_hact_minus_1 + 1 + fresh_max;
}

inline std::optional<std::uint8_t> depth_of_rules(const PathbLaneRules& r) noexcept {
    return detail_kstep::depth_of_k17(r.payment_groups);
}

inline std::optional<std::uint8_t> depth_of_epoch(const EpochTable& T, std::uint16_t e, std::optional<Hash32> digest) {
    if (e == 0) return kEpoch0Depth;
    for (const CompiledEpoch& c : T.compiled) {
        if (c.epoch_no != e) continue;
        if (!c.rules || (digest && c.digest != *digest)) return std::nullopt;
        return depth_of_rules(*c.rules);
    }
    return std::nullopt;
}

inline bool table_has_k_step(const EpochTable& T) {
    for (const CompiledEpoch& c : T.compiled) {
        if (c.epoch_no == 0) continue;
        const std::optional<std::uint8_t> d = c.rules ? depth_of_rules(*c.rules) : std::nullopt;
        if (!d || *d != kEpoch0Depth) return true;
    }
    return false;
}

namespace detail_kstep {
// The depth of the epoch of an AR row (looked up with the row's digest).
inline std::optional<std::uint8_t> depth_of_row(const EpochTable& T, const ActivationRow& r) {
    return depth_of_epoch(T, r.epoch, r.rules_digest);
}

// H(x) on t's view when the view holds it.
inline std::optional<std::uint64_t> held_record(const LaneView& v, const BinStore& store, std::uint64_t x) {
    if (!v.ok() || x > v.pos()) return std::nullopt;
    if (x <= v.fork_pos() && x < store.first_record_pos()) return std::nullopt;
    return v.record(x);
}
}  // namespace detail_kstep

// The activations in force at x = pos(t) + 1 on t's own chain; nullopt: the store's best tip or t's fork with the
// best chain is not found (node-internal).
inline std::optional<TipActs> tip_acts(const RatchetParams& rp, const EpochTable& T, const CarrierTree& tree,
                                       const BinStore& store, const ActivationRecord& ar, const CarrierNode& t,
                                       bool held) {
    detail_kstep::count();
    const CarrierNode* best = tree.find(store.best_tip());
    if (best == nullptr) return std::nullopt;
    const std::optional<Hash32> fp = tree.newest_ancestor_where(t.id, [&](const Hash32& id, std::uint64_t pos) {
        const std::optional<Hash32> on_best = store.best_at(pos);
        return on_best.has_value() && *on_best == id;
    });
    if (!fp) return std::nullopt;
    const CarrierNode* fnode = tree.find(*fp);
    if (fnode == nullptr) return std::nullopt;
    const std::uint64_t f = fnode->pos;
    const std::uint64_t x = t.pos + 1;
    TipActs out;
    const EpochAt ea = epoch_at(rp, T, held ? std::optional<RatchetState>(t.rs) : std::nullopt, ar, best->pos, best->rs, f, x);
    out.kind = ea.kind;
    if (ea.kind != EpochAtKind::Epoch) return out;
    out.seed_p0 = ar.joiner_p0();
    if (held) {
        // the cut: c = max(f, p0 - 1) (c = f on a full chain)
        std::uint64_t c = f;
        if (out.seed_p0 && *out.seed_p0 - 1 > c) c = *out.seed_p0 - 1;
        for (const ActivationRow& a : ar.rows())
            if (a.h_act <= c) out.rows.push_back(a);
        std::vector<ActivationRow> walked;
        for (const CarrierNode* n = &t; n->pos > c;) {
            bool hidden = false;
#ifdef V37_XMR_RING_TEST_EPOCHS
            hidden = detail_kstep::g_test_hide_activation && detail_kstep::g_test_hide_activation(*n);
#endif
            if (n->activation && !hidden) walked.push_back(*n->activation);
            const CarrierNode* parent = tree.find(n->parent);
            if (parent == nullptr) return std::nullopt;
            n = parent;
        }
        out.rows.insert(out.rows.end(), walked.rbegin(), walked.rend());
        if (const std::optional<Hash32> a = act(rp, t.rs, x, T))
            out.rows.push_back(ActivationRow{static_cast<std::uint16_t>(t.rs.epoch_cur + 1), x, *a});
    } else {
        const std::uint64_t lim = std::min(x, best->pos);
        for (const ActivationRow& a : ar.rows())
            if (a.h_act <= lim) out.rows.push_back(a);
        const std::uint64_t xb = best->pos + 1;
        if (locked(rp, best->rs, xb, T)) {
            const std::optional<std::uint64_t> y = h_act(rp, best->rs, xb, T);
            if (y && *y > best->pos && *y <= x)
                out.rows.push_back(ActivationRow{static_cast<std::uint16_t>(best->rs.epoch_cur + 1), *y,
                                                 next_attempt(best->rs, T)->rules_digest});
        }
    }
    // the self-check: anchored at the seed row (a joined state) or at epoch 1 (a full chain), ascending by one,
    // ending at epoch_at's value
    if (out.seed_p0) {
        out.consistent = !out.rows.empty() && out.rows.front() == ar.rows().front();
    } else {
        out.consistent = out.rows.empty() || out.rows.front().epoch == 1;
    }
    for (std::size_t i = 1; out.consistent && i < out.rows.size(); ++i)
        out.consistent = out.rows[i].epoch == out.rows[i - 1].epoch + 1;
    const std::uint16_t last = out.rows.empty() ? 0 : out.rows.back().epoch;
    out.consistent = out.consistent && last == ea.epoch;
    return out;
}

// The K-step list of t at x = pos(t) + 1. Precondition: view_t is t's view and Ok.
inline KSteps ksteps_at(const TipActs& acts, const EpochTable& T, const BinStore& store, const LaneView& view_t,
                        const KStepBook& book, std::uint64_t fresh_max) {
    detail_kstep::count();
    KSteps out;
    const auto no_bin = [&out]() {
        out.gap = true;
        out.known_from_bin = kNoKnownBin;
        out.list.clear();
        return out;
    };
    // (1)
    if (!acts.consistent || acts.kind != EpochAtKind::Epoch || !view_t.ok()) return no_bin();
    // an epoch in a row is looked up with the row's digest; one in no row (hidden below a seed) by its number alone
    std::map<std::uint16_t, Hash32> digest_of;
    for (const ActivationRow& r : acts.rows) digest_of[r.epoch] = r.rules_digest;
    const auto depth_of = [&](std::uint16_t e) -> std::optional<std::uint8_t> {
        const auto it = digest_of.find(e);
        return depth_of_epoch(T, e, it == digest_of.end() ? std::nullopt : std::optional<Hash32>(it->second));
    };
    // epochs 0 .. e of one known depth
    const auto one_depth = [&](std::uint16_t e, std::uint8_t want) {
        for (std::uint32_t k = 0; k <= e; ++k) {
            const std::optional<std::uint8_t> d = depth_of(static_cast<std::uint16_t>(k));
            if (!d || *d != want) return false;
        }
        return true;
    };
    // (2)
    const std::uint16_t e_t = acts.rows.empty() ? 0 : acts.rows.back().epoch;
    if (one_depth(e_t, kEpoch0Depth)) {
        out.depth0 = kEpoch0Depth;
        return out;
    }
    // (3)
    std::size_t first = 0;  // the first non-seed row
    out.depth0 = kEpoch0Depth;
    if (acts.seed_p0) {
        if (acts.rows.empty()) return no_bin();
        first = 1;
        const std::uint16_t e_s = acts.rows.front().epoch;
        const std::optional<std::uint8_t> m_s = depth_of(e_s);
        if (!m_s) return no_bin();
        out.depth0 = *m_s;
        if (!one_depth(e_s, *m_s)) {
            const std::uint64_t p0m1 = *acts.seed_p0 - 1;
            std::optional<std::uint64_t> h = detail_kstep::held_record(view_t, store, p0m1);
            if (!h) {
                const std::optional<std::uint64_t> ab = store.adopt_bound();
                if (!ab || *ab < fresh_max) return no_bin();
                h = *ab - fresh_max;
            }
            out.gap = true;
            out.known_from_bin = at_bin_of(*h, fresh_max);
        }
    }
    // (4)
    for (std::size_t i = first; i < acts.rows.size(); ++i) {
        const ActivationRow& r = acts.rows[i];
        const std::optional<std::uint8_t> before =
                i == 0 ? std::optional<std::uint8_t>(kEpoch0Depth) : detail_kstep::depth_of_row(T, acts.rows[i - 1]);
        const std::optional<std::uint8_t> after = detail_kstep::depth_of_row(T, r);
        if (!before || !after) return no_bin();
        if (*before == *after) continue;
        std::optional<std::uint64_t> at_bin;
        if (const std::optional<std::uint64_t> h = detail_kstep::held_record(view_t, store, r.h_act - 1)) {
            at_bin = at_bin_of(*h, fresh_max);  // (a) t's own view
        } else if (const auto it = book.find(r.h_act); it != book.end() && it->second.epoch == r.epoch) {
            at_bin = it->second.at_bin;  // (b) the book
        }
        if (!at_bin) return no_bin();  // (c)
        out.list.push_back(KStep{*at_bin, *before, *after});
    }
    return out;
}

// The one writer of a book. nullopt: a step's h_act - 1 lies below the store's first record (the caller poisons).
inline std::optional<KStepOps> kbook_sync(KStepBook& book, const ActivationRecord& ar, const EpochTable& T,
                                          const BinStore& best, std::uint64_t fresh_max, std::uint64_t above) {
    detail_kstep::count();
    const std::vector<ActivationRow>& rows = ar.rows();
    const std::size_t first = ar.joiner_p0() ? 1 : 0;
    std::optional<LaneView> bv;  // the best chain's view, read only for a step
    std::vector<KStepRecord> put;
    for (std::size_t i = first; i < rows.size(); ++i) {
        const ActivationRow& r = rows[i];
        if (r.h_act <= above) continue;
        const std::optional<std::uint8_t> before =
                i == 0 ? std::optional<std::uint8_t>(kEpoch0Depth) : detail_kstep::depth_of_row(T, rows[i - 1]);
        const std::optional<std::uint8_t> after = detail_kstep::depth_of_row(T, r);
        if (!before || !after || *before == *after) continue;  // no record for an unknown depth or an equal pair
        if (!bv) bv = best.view_at(best.best_tip());
        if (!bv->ok() || r.h_act - 1 < best.first_record_pos() || r.h_act - 1 > bv->pos()) return std::nullopt;
        put.push_back(KStepRecord{r.epoch, r.h_act, at_bin_of(bv->record(r.h_act - 1), fresh_max)});
    }
    KStepOps ops;
    std::set<std::uint64_t> again;
    for (const KStepRecord& p : put) again.insert(p.h_act);
    for (auto it = book.upper_bound(above); it != book.end();) {
        if (again.count(it->first) == 0) ops.del.push_back(it->first);
        it = book.erase(it);
    }
    for (const KStepRecord& p : put) book[p.h_act] = p;
    ops.put = std::move(put);
    return ops;
}

// m(b): the depth_after of the last step with at_bin <= b; with none, depth0.
inline std::uint8_t depth_of_bin(const KStepList& list, std::uint64_t b, std::uint8_t depth0) {
    detail_kstep::count();
    std::uint8_t d = depth0;
    for (const KStep& s : list)
        if (s.at_bin <= b) d = s.depth_after;
    return d;
}

namespace detail_kstep {
// j(b) without the count; a sum above one byte throws, never wrapped.
inline std::uint8_t merge_depth(const KStepList& list, std::uint64_t top, std::uint64_t b) {
    std::uint64_t j = 0;
    for (const KStep& s : list)
        if (b < s.at_bin && s.at_bin <= top && s.depth_before > s.depth_after) j += s.depth_before - s.depth_after;
    if (j > std::numeric_limits<std::uint8_t>::max()) throw std::out_of_range("merge_delta: the merge depth exceeds one byte");
    return static_cast<std::uint8_t>(j);
}
}  // namespace detail_kstep

// j(b): the merge depth of the steps with b < at_bin <= top; top = the window's start bin + 1.
inline std::uint8_t merge_delta(const KStepList& list, std::uint64_t top, std::uint64_t b) {
    detail_kstep::count();
    return detail_kstep::merge_depth(list, top, b);
}

// sigma = max(0, max(j(b) - m(b))) over reach_low <= b <= top, one value per segment between the at_bins;
// top = the window's start bin + 1; steps with b < at_bin <= top; depth_start = the depth at top; m(b) from
// depth_start back through the steps in (b, top].
inline std::uint8_t sigma(const KStepList& list, std::uint64_t top, std::uint64_t reach_low, std::uint8_t depth_start) {
    detail_kstep::count();
    if (reach_low > top) return 0;
    std::vector<std::uint64_t> starts{reach_low};
    for (const KStep& s : list)
        if (reach_low < s.at_bin && s.at_bin <= top) starts.push_back(s.at_bin);
    std::uint8_t out = 0;
    for (const std::uint64_t b : starts) {
        std::uint8_t m = depth_start;
        std::optional<std::uint64_t> earliest;
        for (const KStep& s : list)
            if (b < s.at_bin && s.at_bin <= top && (!earliest || s.at_bin < *earliest)) {
                earliest = s.at_bin;
                m = s.depth_before;
            }
        const std::uint8_t j = detail_kstep::merge_depth(list, top, b);
        if (j > m) out = std::max(out, static_cast<std::uint8_t>(j - m));
    }
    return out;
}

#ifdef V37_XMR_RING_TEST_EPOCHS
// A test rule set: `base` with K17 = payment_groups, every other field kept.
inline PathbLaneRules ring_test_rules(const PathbLaneRules& base, std::uint8_t payment_groups) {
    PathbLaneRules r = base;
    r.payment_groups = payment_groups;
    return r;
}

// The ring rules of a compiled table (test builds; start-up step 5 after lane_rules_valid).
inline StartupCheck ring_rules_valid(LaneNet net, const EpochTable& T) {
    if (const StartupCheck c = lane_rules_valid(net, T); !c.ok) return c;
    auto refuse = [](std::string why) { return StartupCheck{false, std::move(why)}; };
    const auto ep = [](std::uint16_t e) { return "compiled epoch " + std::to_string(e) + ": "; };
    const auto abs_diff = [](std::uint8_t a, std::uint8_t b) {
        return a > b ? static_cast<std::uint8_t>(a - b) : static_cast<std::uint8_t>(b - a);
    };
    for (std::size_t i = 1; i < T.compiled.size(); ++i) {
        const CompiledEpoch& c = T.compiled[i];
        const CompiledEpoch& prev = T.compiled[i - 1];
        const std::uint16_t e = c.epoch_no;
        const std::uint8_t k = c.rules->payment_groups;
        const bool prev_compiled = prev.epoch_no + 1 == e;
        if (k == kPaymentGroups) {
            // a K17 = 1 epoch after a K17 != 1 epoch: the merge step against the earlier epoch's rule
            if (!prev_compiled || prev.epoch_no == 0 || prev.rules->payment_groups == kPaymentGroups) continue;
            const auto pr = T.ring_rules.find(prev.epoch_no);
            const std::optional<std::uint8_t> mp = depth_of_rules(*prev.rules);
            if (pr == T.ring_rules.end() || !pr->second.step_max || !mp) continue;  // refused at its own epoch
            const std::uint8_t s = abs_diff(kEpoch0Depth, *mp);
            if (s > *pr->second.step_max)
                return refuse(ep(e) + "depth step " + std::to_string(s) + " above step_max " +
                              std::to_string(*pr->second.step_max));
            continue;
        }
        const std::optional<std::uint8_t> m = depth_of_rules(*c.rules);
        if (!m) return refuse(ep(e) + "payment_groups " + std::to_string(k) + " is not a power of two");  // R-1
        const auto rr = T.ring_rules.find(e);
        if (rr == T.ring_rules.end()) return refuse(ep(e) + "no ring rule");  // R-2
        const RingRule& rule = rr->second;
        if (!rule.depth_max) return refuse(ep(e) + "ring rule field depth_max unset");  // R-3
        if (!rule.step_max) return refuse(ep(e) + "ring rule field step_max unset");
        if (*rule.depth_max > kRingDepthBound)  // R-4
            return refuse(ep(e) + "ring rule field depth_max = " + std::to_string(*rule.depth_max) +
                          ": not built (K17 is one byte)");
        if (*rule.step_max < kRingStepMin)  // R-5
            return refuse(ep(e) + "ring rule field step_max = " + std::to_string(*rule.step_max) + ": below " +
                          std::to_string(kRingStepMin));
        if (*rule.step_max > *rule.depth_max)
            return refuse(ep(e) + "ring rule field step_max = " + std::to_string(*rule.step_max) + " above depth_max " +
                          std::to_string(*rule.depth_max));
        if (*m > *rule.depth_max)  // R-6
            return refuse(ep(e) + "depth " + std::to_string(*m) + " above depth_max " + std::to_string(*rule.depth_max));
        if (!prev_compiled) return refuse(ep(e) + "the epoch before it is not compiled");  // R-7
        const std::optional<std::uint8_t> mp = depth_of_epoch(T, prev.epoch_no, prev.digest);
        if (!mp) return refuse(ep(e) + "the epoch before it is not compiled");
        const std::uint8_t s = abs_diff(*m, *mp);
        if (s > *rule.step_max)  // R-8
            return refuse(ep(e) + "depth step " + std::to_string(s) + " above step_max " + std::to_string(*rule.step_max));
    }
    for (const auto& [e, rule] : T.ring_rules) {  // R-9
        bool compiled = false;
        for (const CompiledEpoch& c : T.compiled) compiled = compiled || c.epoch_no == e;
        if (!compiled) return refuse("ring rule for epoch " + std::to_string(e) + ": no compiled epoch");
    }
    return StartupCheck{};
}
#endif

}  // namespace c2pool::xmr::pathb
